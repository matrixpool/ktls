#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define SM4_KEY_SIZE 16
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define SM4_KEY_SIZE 16
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16





int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag,
            unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    // 创建并初始化上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed.\n");
        return -1;
    }

    // 初始化解密操作
    if (1 != EVP_DecryptInit_ex(ctx, EVP_sm4_gcm(), NULL, NULL, NULL)) {
        fprintf(stderr, "EVP_DecryptInit_ex failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 设置密钥和 IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        fprintf(stderr, "EVP_DecryptInit_ex set key and IV failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 解密数据
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "EVP_DecryptUpdate failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // 设置期望的认证标签值
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag)) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl SET_TAG failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 完成解密操作
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    // 释放上下文
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        fprintf(stderr, "EVP_DecryptFinal_ex failed.\n");
        return -1;
    }
}

int main() {

    // 明文数据
    unsigned char plaintext[13] = {
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
        0x61, 0x61, 0x61, 0x61, 0x61
    };
    
    // 密钥和 IV
    unsigned char key[] = {
        0x30, 0x90, 0x55, 0xba, 0xc0, 0x80, 0x12, 0xbb, 
        0x12, 0x00, 0xc4, 0xfc, 0x14, 0xd3, 0x08, 0x40, 
        0xac, 0xce, 0x90, 0xd3, 0x69, 0x99, 0x99, 0xf2, 
        0xcd, 0x30, 0x16, 0x1f, 0x26, 0xc9, 0x2d, 0x5d, 
    };
    unsigned char iv[] = {
        0xac, 0x8d, 0xe0, 0xfd, 0xf6, 0x9a, 0x03, 0x06, 0x69, 0x3a, 0xfc, 0xc2, 
    };

    unsigned char aad[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
        0x17, 0x03, 0x03, 0x00, 0x0d
    };
    unsigned char ciphertext[32] = {0};
    int len = 0, ciphertext_len;
    
    // 初始化上下文
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed.\n");
        return 1;
    }
    
    // 初始化加密操作
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        fprintf(stderr, "EVP_EncryptInit_ex failed.\n");
        return 1;
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);

    // 设置密钥和 IV
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        fprintf(stderr, "EVP_EncryptInit_ex set key and IV failed.\n");
        return 1;
    }

    //关联数据
    if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad))) {
        fprintf(stderr, "import auth data failed.\n");
        return 1;
    }

    // 加密数据
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext))) {
        fprintf(stderr, "EVP_EncryptUpdate failed.\n");
        return 1;
    }
    ciphertext_len = len;
    
    // 完成加密操作
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed.\n");
        return 1;
    }
    ciphertext_len += len;
    
    // 获取认证标签
    unsigned char tag[GCM_TAG_SIZE];
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag)) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl GET_TAG failed.\n");
        return 1;
    }
    
    printf("%d\n", ciphertext_len);

    // 打印密文
    printf("Ciphertext is:\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("0x%02x ", ciphertext[i]);
    }
    printf("\n");
    
    // 打印认证标签
    printf("Tag is:\n");
    for (int i = 0; i < GCM_TAG_SIZE; i++) {
        printf("0x%02x ", tag[i]);
    }
    printf("\n");

    // unsigned char plaintext[17];
    // memset(plaintext, 0x61, sizeof(plaintext));
    // unsigned char ciphertext[sizeof(plaintext)];
    // unsigned char decryptedtext[sizeof(plaintext)];
    // int ciphertext_len, decryptedtext_len;

    // decryptedtext_len = decrypt(ciphertext, ciphertext_len, tag, key, iv, decryptedtext);
    // printf("decryptedtext is:\n");
    // for (int i = 0; i < decryptedtext_len; i++) {
    //     printf("%02x", decryptedtext[i]);
    // }
    // printf("\n");
    
    // 清理
    EVP_CIPHER_CTX_free(ctx);
    
    return 0;
}
