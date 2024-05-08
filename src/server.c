#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// #define SERVER_CERT "/ktls/certs/sign.crt"
// #define SERVER_KEY "/ktls/certs/sign.key"

#define SERVER_CERT "/ktls/certs/ecc.crt"
#define SERVER_KEY "/ktls/certs/ecc.key"

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int listen_sock, conn_sock;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "Error creating SSL context\n");
        return 1;
    }

    // SSL_CTX_enable_sm_tls13_strict(ctx);
    // SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3");
    // SSL_CTX_set1_curves_list(ctx, "SM2:X25519:prime256v1");

    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
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
            ERR_print_errors_fp(stderr);
        } else {
            SSL_write(ssl, "Hello, client!\n", 15);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(conn_sock);
    }

    close(listen_sock);
    SSL_CTX_free(ctx);

    return 0;
}
