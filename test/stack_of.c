#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

int main() {
    // 初始化 OpenSSL 库
    SSL_library_init();
    SSL_load_error_strings();

    // 创建一个 STACK_OF(X509) 结构
    STACK_OF(X509) *cert_stack = sk_X509_new_null();
    if (!cert_stack) {
        printf("Error creating certificate stack.\n");
        return 1;
    }

    // 读取 PEM 格式的证书文件，并将证书存入 STACK_OF(X509) 结构中
    FILE *fp = fopen("/ktls/certs/cert.crt", "r");
    if (!fp) {
        printf("Error opening certificate file.\n");
        return 1;
    }

    X509 *cert;
    while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(cert_stack, cert);
    }

    fclose(fp);

    // 输出 STACK_OF(X509) 中的证书数量
    printf("Number of certificates in stack: %d\n", sk_X509_num(cert_stack));

    // 遍历 STACK_OF(X509) 中的每个证书，并输出证书的主题
    int num_certs = sk_X509_num(cert_stack);
    for (int i = 0; i < num_certs; i++) {
        X509 *cert = sk_X509_value(cert_stack, i);
        X509_NAME *subject = X509_get_subject_name(cert);
        char name[256];
        X509_NAME_oneline(subject, name, sizeof(name));
        printf("Certificate %d subject: %s\n", i+1, name);
    }

    // 清理资源
    sk_X509_pop_free(cert_stack, X509_free);

    // 清理 OpenSSL 库
    // ERR_free_strings();
    EVP_cleanup();

    return 0;
}
