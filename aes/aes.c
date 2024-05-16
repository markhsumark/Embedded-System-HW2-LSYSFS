#include "aes.h"

// 16 bytes密鑰
// const unsigned char aes_key[] = "0123456789abcdef0123456789abcdef";
// const unsigned char aes_iv[] = "0123456789abcdef0123456789abcdef";

unsigned char map_key[256][32];
unsigned char map_iv[256][32];

void genKey(unsigned char** key){
    // 使用 OpenSSL 生成隨機數填充 aes_key
    if (RAND_bytes(*key, AES_KEY_SIZE) != 1) {
        fprintf(stderr, "Error generating random key\n");
        return;
    }

    // 打印生成的 AES 密鑰
    printf("Generated AES key: ");
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02x ", (*key)[i]);
    }
    printf("\n");
}

unsigned char * encrypt(unsigned char* plaintext, int file_idx){

    unsigned char* aes_key = malloc(sizeof(unsigned char)*AES_KEY_SIZE);
	unsigned char* aes_iv = malloc(sizeof(unsigned char)*AES_KEY_SIZE);
	genKey(&aes_key);
	genKey(&aes_iv);
	memcpy(map_key[file_idx], aes_key, AES_KEY_SIZE);
	memcpy(map_iv[file_idx], aes_iv, AES_KEY_SIZE);
    if(strlen(plaintext) == 0)
        return plaintext;
    int plaintext_len = strlen(plaintext);
    int encrypted_len = 0;
    
    // 創建 EVP 加密上下文
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create EVP context\n");
    }
    
    // 初始化 AES 加密
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv) != 1) {
        fprintf(stderr, "Failed to initialize AES encryption\n");
        EVP_CIPHER_CTX_free(ctx);
    }
    
    // 計算加密後資料的大小
    encrypted_len = plaintext_len + EVP_CIPHER_CTX_block_size(ctx);
    
    // 加密資料
    unsigned char *encrypted_data = malloc(encrypted_len + sizeof(unsigned char));
    if (encrypted_data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_CIPHER_CTX_free(ctx);
    }
    int len;
    if (EVP_EncryptUpdate(ctx, encrypted_data, &len, (unsigned char*)plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Encryption failed\n");
        free(encrypted_data);
        EVP_CIPHER_CTX_free(ctx);
    }
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, encrypted_data + len, &final_len) != 1) {
        fprintf(stderr, "Encryption finalization failed\n");
        free(encrypted_data);
        EVP_CIPHER_CTX_free(ctx);
    }
    encrypted_len = len + final_len;
    
    // 輸出加密後的資料
    printf("Encrypted data: ");
    for (int i = 0; i < encrypted_len; i++) {
        printf("%02x", encrypted_data[i]);
    }
    printf("\n");
    encrypted_data[encrypted_len] = '\0';
    free(aes_key);
	free(aes_iv);
    return encrypted_data;
}
char * decrypt(unsigned char* encrypted_data,int file_idx){    
    unsigned char* aes_key = map_key[file_idx];
	unsigned char* aes_iv = map_iv[file_idx];
    if(strlen(encrypted_data) == 0)
        return encrypted_data;
     // 創建 EVP 加密上下文
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // 初始化 AES 解密
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv) != 1) {
        fprintf(stderr, "Failed to initialize AES decryption\n");
        EVP_CIPHER_CTX_free(ctx);
    }
    int encrypted_len = strlen((char*)encrypted_data);
    printf("encrypted_len is : %d\n", encrypted_len);
    // 計算解密後資料的大小
    int decrypted_len = encrypted_len + EVP_CIPHER_CTX_block_size(ctx);
    
    // 解密資料
    char *decrypted_data = malloc(decrypted_len);
    if (decrypted_data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_CIPHER_CTX_free(ctx);
    }
    int len;
    // 真正解密的地方
    if (EVP_DecryptUpdate(ctx, decrypted_data, &len, encrypted_data, encrypted_len) != 1) {
        fprintf(stderr, "Decryption failed\n");
        free(decrypted_data);
        EVP_CIPHER_CTX_free(ctx);
    }
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted_data + len, &final_len) != 1) {
        fprintf(stderr, "Decryption finalization failed\n");
        free(decrypted_data);
        EVP_CIPHER_CTX_free(ctx);
    }
    decrypted_len = len + final_len;
    decrypted_data[decrypted_len] = '\0';
    // 輸出解密後的資料
    printf("Decrypted data: %s\n", decrypted_data);
    return decrypted_data;
}


// int main()
// {
//     // 要加密的資料
//     const char *plaintext = "1";
//     // AES 加密的長度必須是 16 的倍數
//     unsigned char * encrypted_data = encrypt(plaintext);
//     unsigned char * decrypted_data = decrypt(encrypted_data);


//     ///-----------解密--------------///
    
    
//     return 0;
// }
