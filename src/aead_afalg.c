#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include "util.h"

int gcm_sm4(){
    int tfmfd, opfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    struct sockaddr_alg alg = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "gcm(sm4)" 
    };
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct msghdr msg = {0};
    uint8_t ciphertext[13+13+16] = {0};
    char cbuf[
        CMSG_SPACE(sizeof(int)) +
				  CMSG_SPACE(sizeof(struct af_alg_iv) + 12) + 
                  CMSG_SPACE(sizeof(int))] = {0};

    ssize_t len;
    int ret = 0;

    unsigned char plaintext[] = {
        //aad
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
        0x17, 0x03, 0x03, 0x00, 0x0d,
        //plain
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
        0x61, 0x61, 0x61, 0x61, 0x61
    };
    
    unsigned char key[] = {
        0x30, 0x90, 0x55, 0xba, 0xc0, 0x80, 0x12, 0xbb, 
        0x12, 0x00, 0xc4, 0xfc, 0x14, 0xd3, 0x08, 0x40, 
    };
    unsigned char iv[] = {
        0xac, 0x8d, 0xe0, 0xfd, 0xf6, 0x9a, 0x03, 0x06, 0x69, 0x3a, 0xfc, 0xc2, 
    };
    unsigned char aad[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
        0x17, 0x03, 0x03, 0x00, 0x0d
    };

    bind(opfd, (struct sockaddr *)&alg, sizeof(alg));
    ret = setsockopt(opfd, SOL_ALG, ALG_SET_KEY, key, sizeof(key));
    tfmfd = accept(opfd, NULL, 0);

    iov.iov_base = plaintext;
    iov.iov_len = sizeof(plaintext);
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
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + 12);
    *(int *)CMSG_DATA(cmsg) = 12;
    strncpy((char *)CMSG_DATA(cmsg) + 4, iv, 12);

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = 13;

    len = sendmsg(tfmfd, &msg, 0);
    if (len == -1) {
        perror("sendmsg");
        return 1;
    }

    len = recv(tfmfd, ciphertext, sizeof(ciphertext), 0);
    if (len == -1) {
        perror("recv");
        return 1;
    }
    hex_dump(ciphertext, sizeof(ciphertext), NULL);

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
    clock_t start, end;
    float time;
    int encrypted_count = 1;

    start = clock();
    gcm_sm4();
    end = clock();

    time = end - start;
    printf("gcm(sm4) time: %05fS\n", time / CLOCKS_PER_SEC);
    printf("gcm(sm4) speed: %06fMbps\n", calc_speed(encrypted_count, end - start));

    // start = clock();
    // aead_hmac_cbc(key, iv, NULL, encrypted_count);
    // end = clock();

    // time = end - start;
    // printf("authenctls(sm3,sm4) time: %05fS\n", time / CLOCKS_PER_SEC);
    // printf("authenctls(sm3,sm4) speed: %06fMbps\n", calc_speed(encrypted_count, end - start));



    return 0;
}