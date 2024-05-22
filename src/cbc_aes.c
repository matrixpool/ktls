#include <openssl/aes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define KEY_SIZE    16      // AES-128位密钥大小
#define BLOCK_SIZE  16      // AES块大小
#define IV_SIZE     BLOCK_SIZE

int main() {
    unsigned char key[KEY_SIZE] = { /* 填充密钥 */ };
    unsigned char iv[IV_SIZE] = { /* 填充IV */ };
    unsigned char plaintext[BLOCK_SIZE] = { /* 填充明文数据 */ };
    unsigned char ciphertext[BLOCK_SIZE + AES_BLOCK_SIZE]; // 留出空间以存储填充后的密文
    int ciphertext_len = 0;
    EVP_CIPHER_CTX *ctx;

    // 初始化加密上下文
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new");
        return 1;
    }

    // 初始化加密操作
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        perror("EVP_EncryptInit_ex");
        return 1;
    }

    // 对明文进行加密
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, BLOCK_SIZE)) {
        perror("EVP_EncryptUpdate");
        return 1;
    }

    // 最终化加密操作
    int len = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len)) {
        perror("EVP_EncryptFinal_ex");
        return 1;
    }
    ciphertext_len += len;

    // 清理加密上下文
    EVP_CIPHER_CTX_free(ctx);

    // 打印输出
    printf("Key: ");
    for (size_t i = 0; i < KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    printf("IV: ");
    for (size_t i = 0; i < IV_SIZE; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    printf("Ciphertext: ");
    for (size_t i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}