#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "logs.h"
#include "strings.h"

#define SIZE_OF(x)      (sizeof(x) / sizeof(x[0]))

const unsigned char STRING_DECODE_KEY[] = {0xb4, 0xbe, 0x15, 0x50, 0x40, 0x7f, 0x01, 0x53, 0xfa, 0xc0, 0xfe, 0x17};
const unsigned short STRING_DECODE_KEY_LEN = 12;

unsigned char* app_strings;
size_t app_strings_len;

int init_strings(const char* self)
{
    FILE* fp;
    size_t start_offset, last_offset;

    fp = fopen(self, "rb");
    fseek(fp, 0, SEEK_END);
    last_offset = ftell(fp) - sizeof(size_t);
    fseek(fp, last_offset, SEEK_SET);
    fread(&start_offset, sizeof(size_t), 1, fp);

    fseek(fp, start_offset, SEEK_SET);

    app_strings_len = last_offset - start_offset + 1;

    app_strings = malloc(app_strings_len);
    fread(app_strings, app_strings_len - 1, 1, fp);
    app_strings[app_strings_len-1] = 0;

    fclose(fp);

    return 0;
}

void free_strings()
{
    free(app_strings);
}

char* get_string(const unsigned short key)
{
    size_t offset;
    short counter;

    if (key == 0)
        return app_strings;

    offset = counter = 0;
    while (offset < app_strings_len && counter < key)
    {
        if (app_strings[offset] == 0)
            counter++;
        offset++;
    }

    if (counter > key)
        return NULL;

    return &app_strings[offset];
}

void unlock_app_strings()
{
    size_t i;

    for (i = 0; i < app_strings_len; i++)
        app_strings[i] ^= STRING_DECODE_KEY[i % STRING_DECODE_KEY_LEN];
}

void lock_app_strings()
{
    unlock_app_strings();
}
