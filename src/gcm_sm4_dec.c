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
#include "util.h"

#define SM4_KEY_SIZE 16
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16

int main() {
    int len, plain_len;

    unsigned char iv[] = {
        0xf8, 0x09, 0xda, 0xe9, 0x0f, 0x70, 0x46, 0xc5, 
        0x4c, 0x57, 0xac, 0xa9
    };
    unsigned char cipher[] = {
        0xbb, 0x8d, 0xbf, 0x30, 0xe3, 0x8c, 0x69, 0x8a, 
        0x9a, 0x79, 0x19, 0xc1, 0x50, 0x45, 0x81, 0x78
    };
    unsigned char plain[16] = {0};
    unsigned char tag[] = {
        0x4c, 0xa9, 0x17, 0xfc, 0x2e, 0xbc, 0x86, 0x66, 
        0xe4, 0xe6, 0xaf, 0x12, 0x11, 0xc3, 0xfa, 0xf5
    };
    unsigned char key[] = {
        0x6e, 0x89, 0xcf, 0x95, 0xb4, 0x0d, 0xcb, 0xc7, 
        0x7c, 0x5d, 0x55, 0x72, 0xa5, 0xf6, 0x57, 0x45,
    };

    unsigned char aad[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x16, 0x01, 0x01, 0x00, 0x10
    };
    

    // 初始化上下文
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed.\n");
        return 1;
    }
    

    // 初始化加密操作
    if (!EVP_DecryptInit_ex(ctx, EVP_sm4_gcm(), NULL, NULL, NULL)) {
        fprintf(stderr, "EVP_DecryptInit_ex failed.\n");
        return 1;
    }
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);

    // 设置密钥和 IV
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        fprintf(stderr, "EVP_DecryptInit_ex set key and IV failed.\n");
        return 1;
    }

    //关联数据
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad))) {
        fprintf(stderr, "import auth data failed.\n");
        return 1;
    }

    // 加密数据
    if (!EVP_DecryptUpdate(ctx, plain, &len, cipher, sizeof(cipher))) {
        fprintf(stderr, "EVP_EncryptUpdate failed.\n");
        return 1;
    }
    plain_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), (void *)tag) != 1) {
        fprintf(stderr, "Setting tag failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // 完成加密操作
    if (!EVP_DecryptFinal_ex(ctx, cipher + len, &len)) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed.\n");
        return 1;
    }
    plain_len += len;
    
    hex_dump(plain, plain_len, "PLAIN");

    // 清理
    EVP_CIPHER_CTX_free(ctx);
    
    return 0;
}

// 输出
// 14 00 00 0c 0b bb 3f 55 ab c9 8f 62 6f 3e bf a3 
// finished 0b bb 3f 55 ab c9 8f 62 6f 3e bf a3