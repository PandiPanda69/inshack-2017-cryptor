#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RESOURCE_FILE "rsrc/strings.rc"
#define BINARY_FILE "cryptor"

unsigned char ENCRYPTION_KEY[] = {0xb4, 0xbe, 0x15, 0x50, 0x40, 0x7f, 0x01, 0x53, 0xfa, 0xc0, 0xfe, 0x17};
const unsigned short ENCRYPTION_KEY_LENGTH = 12;

size_t __read_resource(unsigned char** buffer)
{
    FILE* fp;
    size_t len;

    fp = fopen(RESOURCE_FILE, "r");
    if (fp == NULL)
        return -1;

    fseek(fp, 0, SEEK_END);
    len = ftell(fp) + 1;
    fseek(fp, 0, SEEK_SET);

    *buffer = calloc(len, sizeof(char));
    fread(*buffer, len, 1, fp);

    fclose(fp);

    return len;
};

void __append_to_binary(unsigned char* data, size_t len)
{
    FILE *fp;
    size_t offset;

    fp = fopen(BINARY_FILE, "a");
    if (fp == NULL)
    {
        printf("Can't read the binary to patch.\n");
        return;
    }

    offset = ftell(fp);

    fwrite(data, len, 1, fp);
    fwrite(&offset, sizeof(size_t), 1, fp);

    fclose(fp);

    printf("%d\n", offset);
}

void __transform_string(unsigned char *input)
{
    char *ptr = input;

    while (*ptr)
    {
        if (*ptr == '\n')       *ptr = 0;
        else if (*ptr == '>')   *ptr = '\n';
        else if (*ptr == '<')   *ptr = '\r';
        ptr++;
    }
}

int main(int argc, char** argv)
{
    unsigned char* input, *ptr;
    int ret, i;

    ret = __read_resource(&input);
    if (ret < 0)
    {
        printf("Cannot read resource.");
        return 1;
    }

    printf("%d bytes\n%s\n", ret, input);

    __transform_string(input);

    printf("Transformed: %s\n", input);

    for (i = 0; i < ret; i++)
    {
        input[i] ^= ENCRYPTION_KEY[i % ENCRYPTION_KEY_LENGTH];
    }

    __append_to_binary(input, ret);

    free(input);
}
