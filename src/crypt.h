#ifndef __CRYPT_H__
#define __CRYPT_H__

#include <stdio.h>

struct rsa_keys {
    char*  private_key;
    size_t private_key_length;

    char*  public_key;
    size_t public_key_length;
};

struct file_content {
    unsigned char* data;
    size_t         data_len;
};

void generate_keys();
struct file_content* encrypt_file(const struct file_content*);
char* get_private_key();
void free_keys();

#endif
