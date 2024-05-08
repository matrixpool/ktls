#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

int main(int argc, char **argv)
{
    struct sockaddr_in addr;
    unsigned int addr_len = sizeof(addr);
    const SSL_METHOD *method;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1, conn_fd = -1;
    char *txbuf = NULL;
    size_t txcap = 0;
    int txlen;
    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;
    char *server_ip = "127.0.0.1";
    char *server_port = "443";
    int server_running = 1;
    int optval = 1;

    if (argc == 2) {
        server_ip = argv[1];
        server_port = strstr(argv[1], ":");
        if (server_port != NULL)
            *server_port++ = '\0';
        else
            server_port = "443";
    }

    method = NTLS_server_method();
    ssl_ctx = SSL_CTX_new(method);
    if (ssl_ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_enable_ntls(ssl_ctx);

    /* Set the key and cert */
    if (!SSL_CTX_use_sign_certificate_file(ssl_ctx, "/ktls/certs/sign.crt",
                                           SSL_FILETYPE_PEM)
        || !SSL_CTX_use_sign_PrivateKey_file(ssl_ctx, "/ktls/certs/sign.key",
                                             SSL_FILETYPE_PEM)
	    || !SSL_CTX_use_enc_certificate_file(ssl_ctx, "/ktls/certs/enc.crt",
                                              SSL_FILETYPE_PEM)
	    || !SSL_CTX_use_enc_PrivateKey_file(ssl_ctx, "/ktls/certs/enc.key",
                                             SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // if(SSL_CTX_set_cipher_list(ssl_ctx, "ECC-SM2-SM4-GCM-SM3") <= 0){
    //     perror("SSL_CTX_set_cipher_list failed\n");
    //     exit(EXIT_FAILURE);
    // }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    inet_pton(AF_INET, server_ip, &addr.sin_addr.s_addr);
    addr.sin_port = htons(atoi(server_port));

    /* Reuse the address; good for quick restarts */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        exit(EXIT_FAILURE);
    }

    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(fd, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    printf("We are the server on port: %d\n\n", atoi(server_port));
    /*
     * Loop to accept clients.
     * Need to implement timeouts on TCP & SSL connect/read functions
     * before we can catch a CTRL-C and kill the server.
     */
    while (server_running) {
        int ret, flags;
        BIO *bio;
        /* Wait for TCP connection from client */
        conn_fd= accept(fd, (struct sockaddr*) &addr, &addr_len);
        if (conn_fd < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        printf("Client TCP connection accepted\n");

        /* Create server SSL structure using newly accepted client socket */
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, conn_fd);
        // SSL_set_options(ssl, SSL_OP_ENABLE_KTLS);
        // ret = BIO_get_ktls_send(SSL_get_wbio(ssl));

        // printf("0x%08x 0x%08x\n", BIO_get_flags(SSL_get_wbio(ssl)), BIO_get_flags(SSL_get_rbio(ssl)));

        // printf("BIO_get_ktls_send: %d\n", ret);
        // ret = BIO_get_ktls_recv(SSL_get_rbio(ssl));
        // printf("BIO_get_ktls_recv: %d\n", ret);

        /* Wait for SSL connection from the client */
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            server_running = 0;
        } else {

            printf("Client TLCP connection accepted\n\n");

            /* Echo loop */
            while (1) {
                /* Get message from client; will fail if client closes connection */
                if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
                    if (rxlen == 0) {
                        printf("Client closed connection\n");
                    }
                    ERR_print_errors_fp(stderr);
                    break;
                }
                /* Insure null terminated input */
                rxbuf[rxlen] = 0;
                /* Look for kill switch */
                if (strcmp(rxbuf, "kill\n") == 0) {
                    /* Terminate...with extreme prejudice */
                    printf("Server received 'kill' command\n");
                    server_running = 0;
                    break;
                }
                /* Show received message */
                printf("Received: %s", rxbuf);
                /* Echo it back */
                if (SSL_write(ssl, rxbuf, rxlen) <= 0) {
                    ERR_print_errors_fp(stderr);
                }
            }
        }
        if (server_running) {
            /* Cleanup for next client */
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(conn_fd);
	        conn_fd = -1;
        }
    }
    printf("Server exiting...\n");

exit:
    /* Close up */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (conn_fd != -1)
        close(conn_fd);
    if (fd != -1)
        close(fd);

    if (txbuf != NULL && txcap > 0)
        free(txbuf);

    return 0;
}
// gcc server.c  -I/opt/tongsuo/include/ -L/opt/tongsuo/lib64/ -lssl -lcrypto -Wl,-rpath=/opt/tongsuo/lib64 -o server
