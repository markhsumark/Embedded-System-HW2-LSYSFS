#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


#define AES_KEY_SIZE 32

extern unsigned char map_key[256][32];
extern unsigned char map_iv[256][32];


char * decrypt(unsigned char* encrypted_data, int file_idx);   
unsigned char * encrypt(unsigned char* plaintext, int file_idx);
void genKey(unsigned char** key);