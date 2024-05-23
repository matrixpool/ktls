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

#define SERVER_CERT "/ktls/certs/ecc.crt"
#define SERVER_KEY "/ktls/certs/ecc.key"

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int listen_sock, conn_sock, ret;

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
    
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    // SSL_CTX_set_cipher_list(ctx, "TLS_AES_128_GCM_SHA256");

    // if (SSL_CTX_use_sign_PrivateKey_file(ctx, SERVER_SIGN_KEY, SSL_FILETYPE_PEM) <= 0 ||
    //     SSL_CTX_use_sign_certificate_file(ctx, SERVER_SIGN_CERT, SSL_FILETYPE_PEM) <= 0 ||
    //     SSL_CTX_use_enc_certificate_file(ctx, SERVER_ECC_CERT, SSL_FILETYPE_PEM) <= 0 ||
    //     SSL_CTX_use_enc_PrivateKey_file(ctx, SERVER_ECC_KEY, SSL_FILETYPE_PEM) <= 0) {
    //     fprintf(stderr, "Error loading certificate or private key file\n");
    //     return 1;
    // }

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

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char buffer[13];
            char buffer1[32] = {0};
            int ret = 0, len = sizeof(buffer);

            memset(buffer, 0x61, len);
            // buffer[len - 1] = '\0';
            SSL_write(ssl, buffer, len);
            // SSL_read(ssl, buffer1, 32);
            // printf("client: %s\n", buffer1);

            // ret = SSL_write(ssl, "hello, openssl client\n", sizeof("hello, openssl client\n"));
            // ret = SSL_write(ssl, "hello, openssl client\n", sizeof("hello, openssl client\n"));
            // ret = SSL_write(ssl, "hello, openssl client\n", sizeof("hello, openssl client\n"));
            // ret = SSL_write(ssl, "hello, openssl client\n", sizeof("hello, openssl client\n"));
            // ret = SSL_write(ssl, "hello, openssl client\n", sizeof("hello, openssl client\n"));
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

