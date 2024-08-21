#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <fcntl.h>
#include "util.h"

#define SERVER_SIGN_CERT "/ktls/certs/sign.crt"
#define SERVER_SIGN_KEY "/ktls/certs/sign.key"
#define SERVER_ECC_CERT "/ktls/certs/enc.crt"
#define SERVER_ECC_KEY "/ktls/certs/enc.key"

int main() {
    //变量定义
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int listen_sock, conn_sock, ret, flags1, flags2;
    pid_t pid;

    printf("server process pid: %d\n", getpid());

    //双证书相关server的各种定义
    meth = NTLS_server_method();
    //生成上下文
    ctx = SSL_CTX_new(meth);
    //允许使用国密双证书功能
    SSL_CTX_enable_ntls(ctx);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

    flags1 = SSL_CTX_get_options(ctx);
    flags2 = SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);

    if (SSL_CTX_use_sign_PrivateKey_file(ctx, SERVER_SIGN_KEY, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_sign_certificate_file(ctx, SERVER_SIGN_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_enc_certificate_file(ctx, SERVER_ECC_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_enc_PrivateKey_file(ctx, SERVER_ECC_KEY, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading certificate or private key file\n");
        return 1;
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433); // 使用非标准端口 4433
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(listen_sock, 5) < 0) {
        perror("listen");
        return 1;
    }

    printf("Server listening on port 4433...\n");

    while (1) {
        conn_sock = accept(listen_sock, NULL, NULL);
        if (conn_sock < 0) {
            perror("accept");
            break;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, conn_sock);
        long int is_ktls_send = BIO_get_ktls_send(SSL_get_wbio(ssl));
        long int is_ktls_recv = BIO_get_ktls_recv(SSL_get_rbio(ssl));
        printf("ktls send: %ld. ktls recv: %ld\n", is_ktls_send, is_ktls_recv);
        if (SSL_accept(ssl) <= 0) {
            unsigned char mkey[SSL_MAX_MASTER_KEY_LENGTH]= {0}, crnd[16] = {0}, srnd[16] = {0};

            SSL_SESSION *session = SSL_get_session(ssl);
            SSL_SESSION_get_master_key(session, mkey, SSL_MAX_MASTER_KEY_LENGTH);
            SSL_get_client_random(ssl, crnd, 16);
            SSL_get_server_random(ssl, srnd, 16);

            hex_dump(mkey, SSL_MAX_MASTER_KEY_LENGTH, "MASTER KEY");
            hex_dump(crnd, 16, "CLIENT RND");
            hex_dump(srnd, 16, "SERVER RND");
            ERR_print_errors_fp(stderr);
        } else {
            char buf1[33] = {0}, buf2[32] = {0};
            memset(buf2, 0x62, sizeof(buf2));

            // unsigned char mkey[SSL_MAX_MASTER_KEY_LENGTH]= {0}, crnd[16] = {0}, srnd[16] = {0};

            // SSL_SESSION *session = SSL_get_session(ssl);
            // SSL_SESSION_get_master_key(session, mkey, SSL_MAX_MASTER_KEY_LENGTH);
            // SSL_get_client_random(ssl, crnd, 16);
            // SSL_get_server_random(ssl, srnd, 16);

            // hex_dump(mkey, SSL_MAX_MASTER_KEY_LENGTH, "MASTER KEY");
            // hex_dump(crnd, 16, "CLIENT RND");
            // hex_dump(srnd, 16, "SERVER RND");
            // ERR_print_errors_fp(stderr);

            // while(1){
                SSL_read(ssl, buf1, sizeof(buf1));
                printf("receive data: %s\n", buf1);
                SSL_write(ssl, buf2, sizeof(buf2));
            // }
        }

        // sleep(10);

        // SSL_shutdown(ssl);
        // SSL_free(ssl);
        // close(conn_sock);
    }

    close(listen_sock);
    SSL_CTX_free(ctx);

    return 0;
}