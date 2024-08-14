#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include "util.h"

int main(int argc, char *argv[]) {
    //变量定义
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl;
    int sock;

    if(argc <= 2){
        printf("please input tls server addr\n");
        return 0;
    }
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(NTLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Error creating SSL context\n");
        return 1;
    }
    SSL_CTX_enable_ntls(ctx);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    // SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

    if(strncmp(argv[2], "cbc", strlen("cbc")) == 0){
        SSL_CTX_set_ciphersuites(ctx, "ECC_SM4_CBC_SM3");
    }
    else{
        SSL_CTX_set_ciphersuites(ctx, "ECC_SM4_GCM_SM3");
    }

    // SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433); // 使用非标准端口 4433
    inet_pton(AF_INET, argv[1], &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        // unsigned char random[64] = {0}, mkey[128] = {0};
        // size_t len;
        // len = SSL_get_client_random(ssl, random, 64);
        // if(len > 0){
        //     hex_dump(random, len, "CLIENT RANDOM");
        // }
        // memset(random, 0, 64);
        // len = SSL_get_server_random(ssl, random, 64);
        // if(len > 0){
        //     hex_dump(random, len, "SERVER RANDOM");
        // }
        
        // SSL_SESSION *session = SSL_get_session(ssl);
        // SSL_SESSION_get_master_key(session, mkey, 128);
        // if(len > 0){
        //     hex_dump(mkey, 128, "MASTER KEY");
        // }
        ERR_print_errors_fp(stderr);
    } else {
        char buf[17] = {0}, buf1[5001] = {0};
        int err;
        long int is_ktls_send = BIO_get_ktls_send(SSL_get_wbio(ssl));
        long int is_ktls_recv = BIO_get_ktls_recv(SSL_get_rbio(ssl));
        printf("ktls send: %ld. ktls recv: %ld\n", is_ktls_send, is_ktls_recv);
        memset(buf, 0x61, sizeof(buf));
        // while(1){
            SSL_write(ssl, buf, sizeof(buf));
        //     err = SSL_read(ssl, buf1, sizeof(buf1));
        // }
        // printf("Received from server: %s\n", buf1);
    }
        sleep(10000);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}