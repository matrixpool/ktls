#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_SIGN_CERT "/ktls/certs/sign.crt"
#define SERVER_SIGN_KEY "/ktls/certs/sign.key"
#define SERVER_ECC_CERT "/ktls/certs/enc.crt"
#define SERVER_ECC_KEY "/ktls/certs/enc.key"

int main() {
    //变量定义
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int listen_sock, conn_sock, ret;

    //双证书相关server的各种定义
    meth = NTLS_server_method();
    //生成上下文
    ctx = SSL_CTX_new(meth);
    //允许使用国密双证书功能
    SSL_CTX_enable_ntls(ctx);

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

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char buffer[10];
            memset(buffer, 0x61, sizeof(buffer));
            SSL_write(ssl, buffer, sizeof(buffer));
        }

        long int is_ktls_send = BIO_get_ktls_send(SSL_get_wbio(ssl));
        long int is_ktls_recv = BIO_get_ktls_recv(SSL_get_rbio(ssl));
        printf("ktls send: %ld. ktls recv: %ld\n", is_ktls_send, is_ktls_recv);
        
        // sleep(60);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(conn_sock);
    }

    close(listen_sock);
    SSL_CTX_free(ctx);

    return 0;
}