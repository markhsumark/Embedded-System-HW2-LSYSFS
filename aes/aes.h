#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

extern const unsigned char aes_key[];
extern const unsigned char aes_iv[];

unsigned char * decrypt(unsigned char* encrypted_data);   
unsigned char * encrypt(unsigned char* plaintext);