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

static unsigned char hmac_key[32] = "0123456789abcdef"; // HMAC 密钥
static unsigned char *plaintext = (unsigned char *)"Hello, World!";
static unsigned char key[16] = "0123456789abcdef"; // 16字节密钥
static unsigned char iv[16] = "0123456789abcdef";  // 16字节IV
static unsigned char aad[16] = "0123456789abcdef";  // 16字节AAD

static void cbc_decrypt(const unsigned char *cipher, int cipherlen);

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void encrypt_openssl() {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len, hmac_len = 32;
    unsigned char ciphertext[16] ={ 0};
    unsigned char mac[32] ={ 0};

    // 创建并初始化上下文
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // 初始化加密操作，这里我们使用 CBC 模式的 SM4
    if (1 != EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv))
        handleErrors();
    
    // 提供数据进行加密
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen(plaintext)))
        handleErrors();
    ciphertext_len = len;

    // 完成加密操作
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    hex_dump(ciphertext, ciphertext_len, "CIPHER OPENSSL");
    HMAC(EVP_sm3(), hmac_key, sizeof(hmac_key), ciphertext, ciphertext_len, mac, &hmac_len);
    hex_dump(mac, hmac_len, "HMAC OPENSSL");

    cbc_decrypt(ciphertext, 16);


    // 清理上下文
    EVP_CIPHER_CTX_free(ctx);
}

void cbc_decrypt(const unsigned char *cipher, int cipherlen){
    EVP_CIPHER_CTX *ctx;
    unsigned char plain[32] = {0};
    int plainlen, len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // 初始化加密操作，这里我们使用 CBC 模式的 SM4
    if (1 != EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv))
        handleErrors();

    // 提供数据进行加密
    if (1 != EVP_DecryptUpdate(ctx, plain, &len, cipher, cipherlen))
        handleErrors();
    plainlen = len;


    // 完成加密操作
    if (1 != EVP_DecryptFinal_ex(ctx, plain + len, &len)) handleErrors();
    plainlen += len;

    hex_dump(plain, plainlen, "DECRYPT PLAIN");
}

void decrypt_afalg(uint8_t *cipher, unsigned int cipherlen){
    int tfmfd, opfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    struct sockaddr_alg alg = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authenc(hmac(sm3),cbc(sm4))" 
    };
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct msghdr msg = {0};
    int ivlen = 16;
    uint8_t ciphertext[16 + 32 + 16] = {0};
    char cbuf[
        CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct af_alg_iv) + 16) + CMSG_SPACE(sizeof(int))] = {0};
    ssize_t len;
    int ret = 0;
    struct rtattr *rt;
    int rta_len = RTA_LENGTH(48 + 4);
    unsigned char plain[32] = {0};
    unsigned char *akey = malloc(rta_len);
    memset(akey, 0, rta_len);
    rt = (struct rtattr *)akey;
    rt->rta_type = 1;
    rt->rta_len = 8;
    *((char *)RTA_DATA(rt) + 3) = 16;
    memcpy(RTA_DATA(rt) + 4, hmac_key, sizeof(hmac_key));
    memcpy(RTA_DATA(rt) + 32 + 4, key, sizeof(key));

    memcpy(plain, aad, sizeof(aad));
    memcpy(plain + sizeof(aad), plaintext, strlen(plaintext));

    plain[31] = 0x03;
    plain[30] = 0x03;
    plain[29] = 0x03;

    bind(opfd, (struct sockaddr *)&alg, sizeof(alg));
    ret = setsockopt(opfd, SOL_ALG, ALG_SET_KEY, akey, rta_len);
    tfmfd = accept(opfd, NULL, 0);

    iov.iov_base = cipher;
    iov.iov_len = cipherlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + ivlen);
    *(int *)CMSG_DATA(cmsg) = ivlen;
    strncpy((char *)CMSG_DATA(cmsg) + 4, iv, ivlen);

    printf("======================================================\n");
    hex_dump(msg.msg_control, msg.msg_controllen, "CBUF");
    hex_dump(msg.msg_iov->iov_base, msg.msg_iov->iov_len, "CIPHERTEXT");

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = 16;

    len = sendmsg(tfmfd, &msg, 0);
    if (len == -1) {
        perror("sendmsg");
        return;
    }

    len = recv(tfmfd, plain, sizeof(plain), 0);
    if (len == -1) {
        perror("recv");
        return;
    }
    hex_dump(plain, sizeof(plain), "PLAIN");

    free(akey);

    close(tfmfd);
    close(opfd);

}

void encrypt_afalg() {
    int tfmfd, opfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    struct sockaddr_alg alg = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authenc(hmac(sm3),cbc(sm4))" 
    };
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct msghdr msg = {0};
    int ivlen = 16;
    uint8_t ciphertext[16 + 32 + 16] = {0};
    char cbuf[
        CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct af_alg_iv) + 16) + CMSG_SPACE(sizeof(int))] = {0};
    ssize_t len;
    int ret = 0;
    struct rtattr *rt;
    int rta_len = RTA_LENGTH(48 + 4);
    unsigned char plain[32] = {0};
    unsigned char *akey = malloc(rta_len);
    memset(akey, 0, rta_len);

    rt = (struct rtattr *)akey;
    rt->rta_type = 1;
    rt->rta_len = 8;
    *((char *)RTA_DATA(rt) + 3) = 16;
    memcpy(RTA_DATA(rt) + 4, hmac_key, sizeof(hmac_key));
    memcpy(RTA_DATA(rt) + 32 + 4, key, sizeof(key));

    hex_dump(akey, rta_len, "KEY");

    memcpy(plain, aad, sizeof(aad));
    memcpy(plain + sizeof(aad), plaintext, strlen(plaintext));

    plain[31] = 0x03;
    plain[30] = 0x03;
    plain[29] = 0x03;

    bind(opfd, (struct sockaddr *)&alg, sizeof(alg));
    ret = setsockopt(opfd, SOL_ALG, ALG_SET_KEY, akey, rta_len);
    tfmfd = accept(opfd, NULL, 0);

    iov.iov_base = plain;
    iov.iov_len = sizeof(plain);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + ivlen);
    *(int *)CMSG_DATA(cmsg) = ivlen;
    strncpy((char *)CMSG_DATA(cmsg) + 4, iv, ivlen);

    hex_dump(msg.msg_control, msg.msg_controllen, "CBUF");
    hex_dump(msg.msg_iov->iov_base, msg.msg_iov->iov_len, "PLAINTEXT");

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = 16;

    len = sendmsg(tfmfd, &msg, 0);
    if (len == -1) {
        perror("sendmsg");
        return;
    }

    len = recv(tfmfd, ciphertext, sizeof(ciphertext), 0);
    if (len == -1) {
        perror("recv");
        return;
    }
    hex_dump(ciphertext, sizeof(ciphertext), "CIPHERTEXT");

    free(akey);

    ret = close(tfmfd);
    ret = close(opfd);

    sleep(1);
    decrypt_afalg(ciphertext, sizeof(ciphertext));
}

int main(void) {
    uint8_t ciphertext[] ={
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
        0xf9, 0x79, 0x4f, 0x87, 0x66, 0x04, 0x78, 0xd5, 
        0xf0, 0xc3, 0xed, 0xde, 0x49, 0xf8, 0x23, 0x97, 
        0x1d, 0x27, 0xfa, 0x82, 0x43, 0x08, 0x52, 0xc8, 
        0x36, 0x13, 0xf4, 0x81, 0x47, 0x83, 0x7f, 0xbd, 
        0x42, 0xc5, 0x65, 0x58, 0x5c, 0x9c, 0x25, 0xdf, 
        0x83, 0xaa, 0xfe, 0xb7, 0x12, 0x68, 0x7e, 0x85,
    };
    // encrypt_openssl();
    // encrypt_afalg();
    // sleep(1);

    decrypt_afalg(ciphertext, sizeof(ciphertext));

    return 0;
}
