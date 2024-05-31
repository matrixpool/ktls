#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "util.h"

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void cbc_decrypt_data1(){
    EVP_CIPHER_CTX *ctx;
    unsigned char plain[128] = {0};
    int plainlen, len;

    uint8_t iv[16] = {
        0x37, 0xdc, 0x27, 0xf5, 0xe9, 0x33, 0x0f, 0x29, 
        0x6a, 0x05, 0x44, 0x8c, 0xb4, 0xf8, 0x22, 0xab,
    };

    uint8_t key[16] = {
        0x37, 0xa7, 0xb6, 0xea, 0xa9, 0xcc, 0x8c, 0x08, 
        0x72, 0x70, 0x86, 0x4b, 0xee, 0x57, 0x03, 0x65, 
    };

    uint8_t ciphertext[] = {
        0xeb, 0xf2, 0xa4, 0xc0, 0xe2, 0xd1, 0x2e, 0x43, 
        0x9b, 0xb8, 0x70, 0x37, 0xca, 0xa6, 0x59, 0x88,
        0x67, 0x69, 0x01, 0x8d, 0x31, 0x5e, 0x67, 0x23, 
        0x55, 0x51, 0x99, 0xf9, 0x71, 0x02, 0xac, 0x55,
        0x72, 0xd2, 0x2b, 0x4c, 0x0b, 0x59, 0x87, 0xb4, 
        0x8e, 0x84, 0x0d, 0x19, 0xbf, 0x0f, 0x5f, 0x6d,
    };

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // 初始化加密操作，这里我们使用 CBC 模式的 SM4
    if (1 != EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv))
        handleErrors();

    // 提供数据进行加密
    if (1 != EVP_DecryptUpdate(ctx, plain, &len, ciphertext, 48))
        handleErrors();
    plainlen = len;

    // 完成加密操作
    if (1 != EVP_DecryptFinal_ex(ctx, plain + len, &len)) handleErrors();
    plainlen += len;

    hex_dump(plain, plainlen, "DATA1 PLAIN");
}


void hmac_sm3_data1(){
    uint8_t plain[] ={
        0x4d, 0x9f, 0xe3, 0xf0, 0x4d, 0xf2, 0xe2, 0x2d, 
        0x54, 0x8e, 0x64, 0xe6, 0xfe, 0x1b, 0x33, 0xc8, 
        0x4e, 0x20, 0xea, 0x6c, 0x25, 0xb2, 0xf3, 0x04, 
        0x74, 0x9c, 0xeb, 0x0a, 0x13, 0xb0, 0x1b, 0xb5, 
        0x0f, 
    };
    uint8_t aad[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x17, 0x01, 0x01, 0x00, 0x00, 
    };
    uint8_t mackey[] = {
        0x34, 0xd1, 0x8b, 0x85, 0xdf, 0xa7, 0x15, 0xdb, 
        0xb9, 0x93, 0x2d, 0x16, 0x7e, 0x6f, 0xa3, 0xc4, 
        0xdb, 0xe8, 0x4b, 0x73, 0xa1, 0x7b, 0x37, 0x92, 
        0x91, 0x98, 0xa5, 0x65, 0x2b, 0x59, 0x4b, 0xe3, 
    };

    uint8_t mac[32] = {0};
    int hmac_len;

    HMAC(EVP_sm3(), mackey, sizeof(mackey), aad, sizeof(aad), mac, &hmac_len);
    hex_dump(mac, hmac_len, "DATA2 HMAC");
}

void cbc_decrypt_data2(){
    EVP_CIPHER_CTX *ctx;
    unsigned char plain[128] = {0};
    int plainlen, len;

    uint8_t iv[16] = {
        // 0x37, 0xdc, 0x27, 0xf5, 0xe9, 0x33, 0x0f, 0x29, 
        // 0x6a, 0x05, 0x44, 0x8c, 0xb4, 0xf8, 0x22, 0xab,
        0x90, 0x23, 0x10, 0x52, 0xfc, 0x63, 0xa7, 0x19, 
        0xd3, 0xfb, 0xf7, 0x7c, 0xdb, 0xac, 0xcd, 0x38,
    };

    uint8_t key[16] = {
        0x37, 0xa7, 0xb6, 0xea, 0xa9, 0xcc, 0x8c, 0x08, 
        0x72, 0x70, 0x86, 0x4b, 0xee, 0x57, 0x03, 0x65, 
    };

    uint8_t ciphertext[] = {
 0x96, 0xbd, 0x4b, 0x9b, 0x6e, 0xf5, 0x64, 0x49, 0x72, 0xd4, 0xf8, 0xa3, 0xa2, 0xa3, 0x4e, 0x79,
 0x01, 0x5d, 0x24, 0x19, 0xc5, 0xf7, 0x63, 0xaa, 0xb1, 0x1c, 0xdd, 0x1e, 0x3b, 0xb4, 0x48, 0x8b,
 0x3f, 0x5b, 0x50, 0x1b, 0x7c, 0xe7, 0xb8, 0xd6, 0x1e, 0x61, 0xd0, 0x04, 0x88, 0x27, 0x24, 0x2e,
 0xfc, 0x10, 0x03, 0x04, 0x5f, 0x89, 0xd8, 0xb4, 0x96, 0x6f, 0xf0, 0xaa, 0xce, 0x0c, 0x4f, 0x4c,
        // 0xeb, 0xf2, 0xa4, 0xc0, 0xe2, 0xd1, 0x2e, 0x43, 
        // 0x9b, 0xb8, 0x70, 0x37, 0xca, 0xa6, 0x59, 0x88,
        // 0x67, 0x69, 0x01, 0x8d, 0x31, 0x5e, 0x67, 0x23, 
        // 0x55, 0x51, 0x99, 0xf9, 0x71, 0x02, 0xac, 0x55,
        // 0x72, 0xd2, 0x2b, 0x4c, 0x0b, 0x59, 0x87, 0xb4, 
        // 0x8e, 0x84, 0x0d, 0x19, 0xbf, 0x0f, 0x5f, 0x6d,
    };
    int cipherlen = 64;


    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // 初始化加密操作，这里我们使用 CBC 模式的 SM4
    if (1 != EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv))
        handleErrors();

    // 提供数据进行加密
    if (1 != EVP_DecryptUpdate(ctx, plain, &len, ciphertext, cipherlen))
        handleErrors();
    plainlen = len;


    // 完成加密操作
    if (1 != EVP_DecryptFinal_ex(ctx, plain + len, &len)) handleErrors();
    plainlen += len;

    hex_dump(plain, plainlen, "DATA2 PLAIN");
}

void hmac_sm3_data2(){
    uint8_t plain[] ={
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
        0x61, 0x10, 0xa3, 0x6f, 0x16, 0x1d, 0xaf, 0xcf, 
        0x81, 0xc4, 0xe5, 0x67, 0x4b, 0x4e, 0x87, 0xba, 
        0x1d, 0x91, 0x8f, 0xdc, 0xf8, 0x78, 0x8c, 0x49, 
        0xc9, 0x25, 0x26, 0x7d, 0x24, 0xbc, 0x12, 0x4c, 
        0xad, 0x0e,
    };
    uint8_t aad[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x17, 0x01, 0x01, 0x00, 0x11, 
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
        0x61,
    };
    uint8_t mackey[] = {
        0x34, 0xd1, 0x8b, 0x85, 0xdf, 0xa7, 0x15, 0xdb, 
        0xb9, 0x93, 0x2d, 0x16, 0x7e, 0x6f, 0xa3, 0xc4, 
        0xdb, 0xe8, 0x4b, 0x73, 0xa1, 0x7b, 0x37, 0x92, 
        0x91, 0x98, 0xa5, 0x65, 0x2b, 0x59, 0x4b, 0xe3, 
    };

    uint8_t mac[32] = {0};
    int hmac_len;

    HMAC(EVP_sm3(), mackey, sizeof(mackey), aad, sizeof(aad), mac, &hmac_len);
    hex_dump(mac, hmac_len, "DATA2 HMAC");
}

int main(){
    cbc_decrypt_data1();
    hmac_sm3_data1();

    cbc_decrypt_data2();
    hmac_sm3_data2();

    return 0;
}



// the first application data
// ================================

// - metadata
// 0000   37 dc 27 f5 e9 33 0f 29 6a 05 44 8c b4 f8 22 ab
// 0010   eb f2 a4 c0 e2 d1 2e 43 9b b8 70 37 ca a6 59 88
// 0020   67 69 01 8d 31 5e 67 23 55 51 99 f9 71 02 ac 55
// 0030   72 d2 2b 4c 0b 59 87 b4 8e 84 0d 19 bf 0f 5f 6d

// - IV
//     37 dc 27 f5 e9 33 0f 29 6a 05 44 8c b4 f8 22 ab

// - CIPHER
//     eb f2 a4 c0 e2 d1 2e 43 9b b8 70 37 ca a6 59 88
//     67 69 01 8d 31 5e 67 23 55 51 99 f9 71 02 ac 55
//     72 d2 2b 4c 0b 59 87 b4 8e 84 0d 19 bf 0f 5f 6d


// the second application data
// =================================

// - metadata
// 0000   90 23 10 52 fc 63 a7 19 d3 fb f7 7c db ac cd 38
// 0010   96 bd 4b 9b 6e f5 64 49 72 d4 f8 a3 a2 a3 4e 79
// 0020   01 5d 24 19 c5 f7 63 aa b1 1c dd 1e 3b b4 48 8b
// 0030   3f 5b 50 1b 7c e7 b8 d6 1e 61 d0 04 88 27 24 2e
// 0040   fc 10 03 04 5f 89 d8 b4 96 6f f0 aa ce 0c 4f 4c

// - IV
//     90 23 10 52 fc 63 a7 19 d3 fb f7 7c db ac cd 38

// - CIPHER
//     96 bd 4b 9b 6e f5 64 49 72 d4 f8 a3 a2 a3 4e 79
//     01 5d 24 19 c5 f7 63 aa b1 1c dd 1e 3b b4 48 8b
//     3f 5b 50 1b 7c e7 b8 d6 1e 61 d0 04 88 27 24 2e
//     fc 10 03 04 5f 89 d8 b4 96 6f f0 aa ce 0c 4f 4c

// WORK KEY 
// ============================
// - client write mackey
// fb bc 1d 4a 55 09 91 e4 28 19 b8 07 61 4b f2 19 
// ce 99 e6 d7 06 c6 c4 f0 7d 87 58 2a e9 90 b0 45 

// - server write mackey
// 34 d1 8b 85 df a7 15 db b9 93 2d 16 7e 6f a3 c4 
// db e8 4b 73 a1 7b 37 92 91 98 a5 65 2b 59 4b e3 

// - client write key
// 31 5c 97 0f 17 39 5b 70 18 86 23 5a 61 a6 af 4d 

// - server write key
// 37 a7 b6 ea a9 cc 8c 08 72 70 86 4b ee 57 03 65 