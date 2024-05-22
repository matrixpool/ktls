#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Error creating SSL context\n");
        return 1;
    }
    SSL_CTX_enable_ntls(ctx);

    // SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    // SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_ciphersuites(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256");

    // SSL_CTX_set_cipher_list(ctx, "SM4-GCM");
    // SSL_CTX_enable_sm_tls13_strict(ctx);
    // SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3");
    // SSL_CTX_set1_curves_list(ctx, "SM2:X25519:prime256v1");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433); // 使用非标准端口 4433
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    // inet_pton(AF_INET, "192.168.43.128", &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    printf("1 bio flags: 0x%06x\n", BIO_get_flags(SSL_get_wbio(ssl)));
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        char buf[4096];
        char buf1[17];
        memset(buf1, 0x62, 17);
        printf("2 bio flags: 0x%06x\n", BIO_get_flags(SSL_get_wbio(ssl)));
        long int is_ktls_send = BIO_get_ktls_send(SSL_get_wbio(ssl));
        long int is_ktls_recv = BIO_get_ktls_recv(SSL_get_rbio(ssl));
        printf("ktls send: %ld. ktls recv: %ld\n", is_ktls_send, is_ktls_recv);

        // SSL_write(ssl, buf1, sizeof(buf1));
        SSL_read(ssl, buf, sizeof(buf));
        printf("Received from server: %s\n", buf);

        // SSL_read(ssl, buf, sizeof(buf));
        // printf("Received from server: %s\n", buf);

        // SSL_read(ssl, buf, sizeof(buf));
        // printf("Received from server: %s\n", buf);
    }

    // sleep(60);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
