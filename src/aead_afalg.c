#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

int aead_hmac_cbc(const uint8_t *key, const uint8_t *iv, const uint8_t *hmac_key, int calc_count){
    int tfmfd, opfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    struct sockaddr_alg alg = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authenc(hmac(sha256),cbc(aes))",
    };

    int ret = 0;
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct msghdr msg = {0};
    uint8_t plaintext[1024];
    uint8_t ciphertext[1024 + 32] = {0};
    uint8_t hmac[32];
    int plaintext_len = sizeof(plaintext);
    int hmac_output_len;
    char cbuf[CMSG_SPACE(32)];
    ssize_t len;

    memset(plaintext, 0x11, sizeof(plaintext));
    ret = bind(opfd, (struct sockaddr *)&alg, sizeof(alg));
    printf("bind: %d\n", ret);

    tfmfd = accept(opfd, NULL, 0);
    printf("accept: %d\n", tfmfd);

    ret = setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, 16);
    printf("setsockopt 1: %d %s\n", ret, strerror(errno));

    // ret = setsockopt(tfmfd, SOL_ALG, ALG_SET_IV, iv, 12);
    // printf("setsockopt 2: %d %s\n", ret, strerror(errno));

    iov.iov_base = plaintext;
    iov.iov_len = 1024;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(strlen("aead"));
    strcpy((char *)CMSG_DATA(cmsg), "aead");
    msg.msg_controllen = cmsg->cmsg_len;

    while (calc_count--)
    {
        len = sendmsg(opfd, &msg, 0);
        if (len == -1) {
            perror("sendmsg");
            return 1;
        }
        len = recv(opfd, ciphertext, sizeof(ciphertext), 0);
        if (len == -1) {
            perror("recv");
            return 1;
        }
    }
    
    close(tfmfd);
    close(opfd);

    return 0;
}

int gcm_sm4(const uint8_t *key, const uint8_t *iv, const uint8_t *hmac_key, int calc_count){
    int tfmfd, opfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    struct sockaddr_alg alg = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "gcm(sm4)" 
    };
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct msghdr msg = {0};
    uint8_t plaintext[1024];
    uint8_t ciphertext[1024 + 32] = {0};
    uint8_t hmac[32];
    int plaintext_len = sizeof(plaintext);
    int hmac_output_len;
    char cbuf[CMSG_SPACE(32)];
    ssize_t len;
    int ret = 0;

    memset(plaintext, 0x11, sizeof(plaintext));
    bind(opfd, (struct sockaddr *)&alg, sizeof(alg));
    tfmfd = accept(opfd, NULL, 0);
    ret = setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, 16);
    printf("%d %d\n", tfmfd, ret);
    // setsockopt(tfmfd, SOL_ALG, ALG_SET_IV, key, 16);

    iov.iov_base = plaintext;
    iov.iov_len = 1024;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(strlen("aead"));
    strcpy((char *)CMSG_DATA(cmsg), "aead");
    msg.msg_controllen = cmsg->cmsg_len;

    while (calc_count--)
    {
        len = sendmsg(opfd, &msg, 0);
        if (len == -1) {
            perror("sendmsg");
            return 1;
        }
        len = recv(opfd, ciphertext, sizeof(ciphertext), 0);
        if (len == -1) {
            perror("recv");
            return 1;
        }
    }
    
    close(tfmfd);
    close(opfd);

    return 0;
}

float calc_speed(int num, clock_t interval){
    uint64_t bits = (uint64_t)num * 1024 * 8;
    uint64_t mbits =  8 * 1024 * 1024;
    float time = (float)interval / CLOCKS_PER_SEC;

    float speed = (float)bits / time;
    
    return speed / mbits;
}

int main(){
    uint8_t *key = "your-256-bit-key";
    uint8_t *iv = "your-16-byte-iv";
    clock_t start, end;
    float time;
    int encrypted_count = 1;

    start = clock();
    aead_hmac_cbc(key, iv, NULL, encrypted_count);
    end = clock();

    time = end - start;
    printf("authenc(sm3,sm4) time: %05fS\n", time / CLOCKS_PER_SEC);
    printf("authenc(sm3,sm4) speed: %06fMbps\n", calc_speed(encrypted_count, end - start));

    start = clock();
    gcm_sm4(key, iv, NULL, encrypted_count);
    end = clock();

    time = end - start;
    printf("gcm(sm4) time: %05fS\n", time / CLOCKS_PER_SEC);
    printf("gcm(sm4) speed: %06fMbps\n", calc_speed(encrypted_count, end - start));

    return 0;
}