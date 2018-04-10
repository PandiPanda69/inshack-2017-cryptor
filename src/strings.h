#ifndef __STRINGS_H__
#define __STRINGS_H__

#define __STRING_FILE_TO_CRYPT_NOT_EXIST    0
#define __STRING_E_KEY_VALUE                1
#define __STRING_ERROR_GENERATING_KEY       2
#define __STRING_INSA_FLAG                  3
#define __STRING_CNC_ADDRESS                4
#define __STRING_HTTP_HEADER                5
#define __STRING_HTTP_PAYLOAD               6
#define __STRING_FINAL_MESSAGE              7
#define __STRING_FILE_TO_CRYPT              8
#define __STRING_FILE_TO_DECRYPT            9
#define __STRING_HTTP_PAYLOAD_ENVELOPE      10
#define __STRING_NULL                       11

int init_strings(const char*);
void free_strings();
char* get_string(const unsigned short);

void unlock_app_strings();
void lock_app_strings();

#endif
