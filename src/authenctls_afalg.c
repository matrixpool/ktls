#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include "util.h"

void authenctls_sm3_sm4(){
    uint8_t iv[16] = {
        0x90, 0x23, 0x10, 0x52, 0xfc, 0x63, 0xa7, 0x19, 
        0xd3, 0xfb, 0xf7, 0x7c, 0xdb, 0xac, 0xcd, 0x38,
    };
    uint8_t key[16] = {
        0x37, 0xa7, 0xb6, 0xea, 0xa9, 0xcc, 0x8c, 0x08, 
        0x72, 0x70, 0x86, 0x4b, 0xee, 0x57, 0x03, 0x65, 
    };
    uint8_t aad[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x17, 0x01, 0x01, 0x00, 0x11,
    };
    uint8_t plaintext[] = {
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
        0x61, 
    };

    uint8_t hmac_key[] = {
        0x34, 0xd1, 0x8b, 0x85, 0xdf, 0xa7, 0x15, 0xdb, 
        0xb9, 0x93, 0x2d, 0x16, 0x7e, 0x6f, 0xa3, 0xc4, 
        0xdb, 0xe8, 0x4b, 0x73, 0xa1, 0x7b, 0x37, 0x92, 
        0x91, 0x98, 0xa5, 0x65, 0x2b, 0x59, 0x4b, 0xe3, 
    };


    // uint8_t data[] = {
    //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    //     0x17, 0x01, 0x01, 0x00, 0x11, 
    //     0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
    //     0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
    //     0x61,
    // };
    // uint8_t key[] = {
    //     0x34, 0xd1, 0x8b, 0x85, 0xdf, 0xa7, 0x15, 0xdb, 
    //     0xb9, 0x93, 0x2d, 0x16, 0x7e, 0x6f, 0xa3, 0xc4, 
    //     0xdb, 0xe8, 0x4b, 0x73, 0xa1, 0x7b, 0x37, 0x92, 
    //     0x91, 0x98, 0xa5, 0x65, 0x2b, 0x59, 0x4b, 0xe3, 
    // };

    int tfmfd, opfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    struct sockaddr_alg alg = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authenctls(hmac(sm3),cbc(sm4))" 
    };
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct msghdr msg = {0};
    int ivlen = 16;
    uint8_t ciphertext[13 + 32 + 32] = {0};
    char cbuf[
        CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct af_alg_iv) + 16) + CMSG_SPACE(sizeof(int))] = {0};
    ssize_t len;
    int ret = 0;
    struct rtattr *rt;
    int rta_len = RTA_LENGTH(48 + 4);
    unsigned char plain[64] = {0};
    unsigned char *akey = malloc(rta_len);
    rt = (struct rtattr *)akey;
    rt->rta_type = 1;
    rt->rta_len = 8;
    *((char *)RTA_DATA(rt) + 3) = 16;
    memcpy(RTA_DATA(rt) + 4, hmac_key, sizeof(hmac_key));
    memcpy(RTA_DATA(rt) + 32 + 4, key, sizeof(key));

    memcpy(plain, aad, sizeof(aad));
    memcpy(plain + sizeof(aad), plaintext, strlen(plaintext));

    bind(opfd, (struct sockaddr *)&alg, sizeof(alg));
    ret = setsockopt(opfd, SOL_ALG, ALG_SET_KEY, akey, rta_len);
    tfmfd = accept(opfd, NULL, 0);

    iov.iov_base = plain;
    iov.iov_len = sizeof(aad) + sizeof(plaintext);
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
    *(int *)CMSG_DATA(cmsg) = sizeof(aad);

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

    system("dmesg -c");

    free(akey);

    close(tfmfd);
    close(opfd);
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
    authenctls_sm3_sm4();
    end = clock();

    time = end - start;
    printf("authenctls(hmac(sm3),cbc(sm4)) time: %05fS\n", time / CLOCKS_PER_SEC);
    printf("authenctls(hmac(sm3),cbc(sm4)) speed: %06fMbps\n", calc_speed(encrypted_count, end - start));

    // start = clock();
    // aead_hmac_cbc(key, iv, NULL, encrypted_count);
    // end = clock();

    // time = end - start;
    // printf("authenctls(sm3,sm4) time: %05fS\n", time / CLOCKS_PER_SEC);
    // printf("authenctls(sm3,sm4) speed: %06fMbps\n", calc_speed(encrypted_count, end - start));

    return 0;
}