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

static uint8_t iv[16] = {
    0x90, 0x23, 0x10, 0x52, 0xfc, 0x63, 0xa7, 0x19, 
    0xd3, 0xfb, 0xf7, 0x7c, 0xdb, 0xac, 0xcd, 0x38,
};

static uint8_t key[16] = {
    0x37, 0xa7, 0xb6, 0xea, 0xa9, 0xcc, 0x8c, 0x08, 
    0x72, 0x70, 0x86, 0x4b, 0xee, 0x57, 0x03, 0x65, 
};

static uint8_t hmac_key[] = {
    0x34, 0xd1, 0x8b, 0x85, 0xdf, 0xa7, 0x15, 0xdb, 
    0xb9, 0x93, 0x2d, 0x16, 0x7e, 0x6f, 0xa3, 0xc4, 
    0xdb, 0xe8, 0x4b, 0x73, 0xa1, 0x7b, 0x37, 0x92, 
    0x91, 0x98, 0xa5, 0x65, 0x2b, 0x59, 0x4b, 0xe3, 
};
static uint8_t aad[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x17, 0x01, 0x01, 0x00, 0x11,
};

static int authenctls_create(){
    int tfmfd, opfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    struct sockaddr_alg alg = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authenctls(hmac(sm3),cbc(sm4))" 
    };
    int ret = 0;
    struct rtattr *rt;
    int rta_len = RTA_LENGTH(48 + 4);
    unsigned char *akey = malloc(rta_len);
    memset(akey, 0, rta_len);

    rt = (struct rtattr *)akey;
    rt->rta_type = 1;
    rt->rta_len = 8;
    *((char *)RTA_DATA(rt) + 3) = sizeof(key);
    memcpy(RTA_DATA(rt) + 4, hmac_key, sizeof(hmac_key));
    memcpy(RTA_DATA(rt) + 32 + 4, key, sizeof(key));

    bind(opfd, (struct sockaddr *)&alg, sizeof(alg));
    ret = setsockopt(opfd, SOL_ALG, ALG_SET_KEY, akey, rta_len);
    if(ret){
        perror("setsockopt");
        close(opfd);
        return -1;
    }

    free(akey);
    return opfd;
}

static int authenctls_accept(int fd){
    int tfmd = accept(fd, NULL, 0);
    if(tfmd == -1){
        perror("accept");
    }
    return tfmd;
}


static int authenctls_send(int tfmd, int op, uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen){
    struct iovec iov[2];
    struct cmsghdr *cmsg;
    struct msghdr msg = {0};
    char cbuf[
        CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct af_alg_iv) + 16) + CMSG_SPACE(sizeof(int))] = {0};
    int ivlen = 16, len;
    int recvlen, paddinglen = inlen % 16;
    if(op == ALG_OP_ENCRYPT){
        recvlen = sizeof(aad) + inlen + 32 + 16 - paddinglen;
        iov[0].iov_base = aad;
        iov[0].iov_len = sizeof(aad);
        iov[1].iov_base = in;
        iov[1].iov_len = inlen;
        msg.msg_iov = iov;
        msg.msg_iovlen = 2;
    }else{
        iov[0].iov_base = in;
        iov[0].iov_len = inlen;
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        recvlen = inlen;
    }

    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    // *(int *)CMSG_DATA(cmsg) = op ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
    *(int *)CMSG_DATA(cmsg) = op;

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + ivlen);
    *(int *)CMSG_DATA(cmsg) = ivlen;
    strncpy((char *)CMSG_DATA(cmsg) + 4, iv, ivlen);

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = sizeof(aad);

    len = sendmsg(tfmd, &msg, 0);
    if (len == -1) {
        perror("sendmsg");
        return -1;
    }

    len = recv(tfmd, out, recvlen, 0);
    if (len == -1) {
        perror("recv");
        return -1;
    }
    
    *outlen = len;

    return 0;
}


int authenctls_encrypt_sm3_sm4(int tfmfd){
    size_t len = 16384;
    // uint8_t plaintext[5000] = {
    //     0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
    //     0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 
    //     0x61, 
    // };
    uint8_t *plain = calloc(0x1, len);
    uint8_t *cipher = calloc(0x1, len + 100);
    uint8_t *nplain = calloc(0x1, len + 100);
    size_t cipher_len = len + 100, nlen;
    memset(plain, 0x61, len);

    authenctls_send(tfmfd, ALG_OP_ENCRYPT, plain, len, cipher, &cipher_len);
    // hex_dump(cipher, cipher_len, "CIPHERTEXT");
    authenctls_send(tfmfd, ALG_OP_DECRYPT, cipher, cipher_len, nplain, &len);
    // hex_dump(nplain, len, "PLAINTEXT");

    free(nplain);
    free(cipher);
    free(plain);
    return cipher_len;
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
    int encrypted_count = 1000000;
    int sock, tfmfd;

    sock = authenctls_create();
    tfmfd = authenctls_accept(sock);

    start = clock();
    while(encrypted_count--){
        authenctls_encrypt_sm3_sm4(tfmfd);
    }
    // authenctls_decrypt_sm3_sm4();
    end = clock();

    time = end - start;
    printf("authenctls(sm3,sm4) time: %05fS\n", time / CLOCKS_PER_SEC);
    printf("authenctls(sm3,sm4) speed: %06fMbps\n", calc_speed(encrypted_count, end - start));

    close(tfmfd);
    close(sock);


    // start = clock();
    // aead_hmac_cbc(key, iv, NULL, encrypted_count);
    // end = clock();


    return 0;
}