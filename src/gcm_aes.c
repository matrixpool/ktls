#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *key, const unsigned char *iv, int iv_len,
                    unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // 创建并初始化上下文
    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

    // 初始化加密操作
    if(1 != EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, 1)) return -1;

    // 设置IV长度，如果不同于默认的12字节
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) return -1;

    // 初始化密钥和IV
    if(1 != EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1)) return -1;

    // 提供AAD数据
    if(aad && aad_len > 0) {
        if(1 != EVP_CipherUpdate(ctx, NULL, &len, aad, aad_len)) return -1;
    }

    // 提供要加密的消息，并得到加密后的输出
    if(1 != EVP_CipherUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
    ciphertext_len = len;

    // 完成加密操作
    if(1 != EVP_CipherFinal_ex(ctx, ciphertext + len, &len)) return -1;
    ciphertext_len += len;

    // 获取认证标签
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) return -1;

    // 清理
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int main() {
    unsigned char tag[16] = {0};
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
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x17, 0x03, 0x03, 0x00, 0x25
    };

    // 缓冲区用于存储密文
    unsigned char ciphertext[sizeof(plaintext)];

    // 执行加密
    int ciphertext_len = aes_gcm_encrypt(plaintext, sizeof(plaintext), aad, sizeof(aad), key, iv, sizeof(iv), ciphertext, tag);

    if (ciphertext_len < 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    // 输出加密结果
    printf("Ciphertext is:\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    printf("Tag is:\n");
    for (int i = 0; i < sizeof(tag); i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");

    return 0;
}
