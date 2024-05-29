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
       0x8e, 0x62, 0xe9, 0x6f, 0xce, 0x3c, 0xaf, 0xa3, 
       0x69, 0xbd, 0xdb, 0xaf, 
    };
    unsigned char cipher[] = {
        0xde, 0xa0, 0xf0, 0xe2, 0x8c, 0x6b, 0x5e, 0x50,
        0x7d, 0x2f, 0x7f, 0xdf, 0xb0, 0x06, 0x07, 0x18,
    };
    unsigned char plain[16] = {0};
    unsigned char tag[] = {
        0x0b, 0x75, 0xf5, 0xe9, 0xd5, 0x8e, 0x68, 0xb7,
        0x4c, 0xd5, 0x14, 0x89, 0x35, 0x1a, 0xd0, 0x5d,
    };
    unsigned char key[] = {
        0xdc, 0x11, 0x4f, 0x7f, 0xfb, 0xfc, 0xea, 0x8e, 
        0x2c, 0xb4, 0x9a, 0xa5, 0x8f, 0xf2, 0x0c, 0xbc,
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
// 14 00 00 0c b8 6a fb f1 09 35 1c 34 41 cf ed 3a