#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int create_socket(int port) {
    int s;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }
    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }
    return s;
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

// SSL_CTX *create_context() {
//     const SSL_METHOD *method;
//     SSL_CTX *ctx;
//     method = SSLv23_server_method();
//     ctx = SSL_CTX_new(method);
//     if (!ctx) {
//         perror("Unable to create SSL context");
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
//     return ctx;
// }

SSL_CTX *configure_context() {
    const SSL_METHOD *meth = NULL;
    SSL_CTX *cctx = NULL;
    const char *sign_key_file = "/ktls/certs/sign.key";
    const char *sign_cert_file = "/ktls/certs/sign.crt";
    const char *enc_key_file = "/ktls/certs/enc.key";
    const char *enc_cert_file = "/ktls/certs/enc.crt";

    //双证书相关client的各种定义
    meth = NTLS_client_method();
    //生成上下文
    cctx = SSL_CTX_new(meth);
    //允许使用国密双证书功能
    SSL_CTX_enable_ntls(cctx);

    //设置算法套件为ECC-SM2-WITH-SM4-SM3或者ECDHE-SM2-WITH-SM4-SM3
    //这一步并不强制编写，默认ECC-SM2-WITH-SM4-SM3优先
    if(SSL_CTX_set_cipher_list(cctx, "ECDHE-SM2-SM4-GCM-SM3") <= 0)
        goto err;

    //加载签名证书，加密证书，仅ECDHE-SM2-WITH-SM4-SM3套件需要这一步,
    //该部分流程用...begin...和...end...注明
    // ...begin...
    if (sign_key_file) {
        if (!SSL_CTX_use_sign_PrivateKey_file(cctx, sign_key_file,
                                              SSL_FILETYPE_PEM))
            goto err;
    }

    if (sign_cert_file) {
        if (!SSL_CTX_use_sign_certificate_file(cctx, sign_cert_file,
                                               SSL_FILETYPE_PEM))
            goto err;
    }

    if (enc_key_file) {
        if (!SSL_CTX_use_enc_PrivateKey_file(cctx, enc_key_file,
                                             SSL_FILETYPE_PEM))
            goto err;
    }

    if (enc_cert_file) {
        if (!SSL_CTX_use_enc_certificate_file(cctx, enc_cert_file,
                                              SSL_FILETYPE_PEM))
            goto err;
    }

    return cctx;
    // ...end...
err:
    if(cctx)
       SSL_CTX_free(cctx);

    printf("load cert occur failed\n");
}

int main(int argc, char **argv) {
    int sock;
    SSL_CTX *ctx;
    init_openssl();
    ctx = configure_context();
    sock = create_socket(4433); // 4433 是示例端口，根据需要可以更改

    /* Handle connections */
    while (1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "Hello, World!\n";
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            SSL_write(ssl, reply, strlen(reply));
        }
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}