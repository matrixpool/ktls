/*
 * Copyright 2013-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <linux/socket.h>
#include <netdb.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>

union sockaddr_t {
    struct sockaddr_in  saddr;
    struct sockaddr_in6 saddr6;
};

int main(int argc, char **argv)
{
    BIO *bio = NULL, *out = NULL;
    int i, len, rv;
    char tmpbuf[1024];
    SSL_CTX *ctx = NULL;
    SSL_CONF_CTX *cctx = NULL;
    SSL *ssl = NULL;
    CONF *conf = NULL;
    STACK_OF(CONF_VALUE) *sect = NULL;
    CONF_VALUE *cnf;
    const char *connect_str = "localhost:433";
    long errline = -1;

    conf = NCONF_new(NULL);

    if (NCONF_load(conf, "/ktls/src/connect.cnf", &errline) <= 0) {
        if (errline <= 0)
            fprintf(stderr, "Error processing config file\n");
        else
            fprintf(stderr, "Error on line %ld\n", errline);
        goto end;
    }

    sect = NCONF_get_section(conf, "default");

    if (sect == NULL) {
        fprintf(stderr, "Error retrieving default section\n");
        goto end;
    }

    ctx = SSL_CTX_new(TLS_client_method());
    cctx = SSL_CONF_CTX_new();
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);

    for (i = 0; i < sk_CONF_VALUE_num(sect); i++) {
        cnf = sk_CONF_VALUE_value(sect, i);
        rv = SSL_CONF_cmd(cctx, cnf->name, cnf->value);
        if (rv > 0)
            continue;
        if (rv != -2) {
            fprintf(stderr, "Error processing %s = %s\n",
                    cnf->name, cnf->value);
            ERR_print_errors_fp(stderr);
            goto end;
        }
        if (strcmp(cnf->name, "Connect") == 0) {
            connect_str = cnf->value;
        } else {
            fprintf(stderr, "Unknown configuration option %s\n", cnf->name);
            goto end;
        }
    }

    if (!SSL_CONF_CTX_finish(cctx)) {
        fprintf(stderr, "Finish error\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /*
     * We'd normally set some stuff like the verify paths and * mode here
     * because as things stand this will connect to * any server whose
     * certificate is signed by any CA.
     */

    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        goto end;
    }

    /* We might want to do other things with ssl here */

    BIO_set_conn_hostname(bio, connect_str);
    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* Connect to host first so enable KTLS can be success */

    int sock;
    union sockaddr_t sa;
    char ipaddr[64];
    int is_ipv6 = 0;
    struct sockaddr *sa_ptr;
    socklen_t socklen;
    int rc = -1;
    sock = BIO_get_fd(bio, 0);
    close(sock);
    unsigned long l = strtoul(BIO_get_conn_port(bio), NULL, 10);
    char host[256];
    strcpy(host, BIO_get_conn_hostname(bio));
    struct hostent *hosts = gethostbyname(host);
    if (hosts == NULL)
        goto end;
    is_ipv6 = (hosts->h_addrtype == AF_INET6)? 1 : 0;
    sa_ptr = (is_ipv6)? (struct sockaddr *)&sa.saddr6 : (struct sockaddr *)&sa.saddr;
    socklen = (is_ipv6)? sizeof(sa.saddr6) : sizeof(sa.saddr);
    if (inet_ntop(hosts->h_addrtype, hosts->h_addr_list[0], ipaddr, socklen) == NULL)
    {
        rc = errno;
        goto end;
    }
    printf("Connecting to %s (%s:%lu) ...\n", host, ipaddr, l);
    if (is_ipv6)
    {
        sa.saddr6.sin6_family = AF_INET6;
        memcpy(&sa.saddr6.sin6_addr, hosts->h_addr_list[0], hosts->h_length);
        sa.saddr6.sin6_port = htons(l);
    } else
    {
        sa.saddr.sin_family = AF_INET;
        memcpy(&sa.saddr.sin_addr, hosts->h_addr_list[0], hosts->h_length);
        sa.saddr.sin_port = htons(l);
    }
    sock = socket(hosts->h_addrtype, SOCK_STREAM, IPPROTO_TCP);
    rc = connect(sock, sa_ptr, socklen);
    if (rc)
    {
        printf("Error connecting to server\n");
        goto end;
    }

    /* Enable KTLS */
    SSL_set_fd(ssl, sock);
    SSL_set_options(ssl, SSL_OP_ENABLE_KTLS);

    /* Start KTLS */
    if ((rc = BIO_do_connect(bio)) <= 0) {
        printf("Error connecting to server (2)\n");
        goto end;
    }

    sleep(100);
    printf("0x%08x 0x%08x\n", BIO_get_flags(SSL_get_wbio(ssl)), BIO_get_flags(SSL_get_rbio(ssl)));
    /* Read file */

    int fd;
    char *filename;
    int is_sendfile = 0;
    ssize_t filesize, rsize;

    if (argc > 1)
    {
        filename = argv[1];
        is_sendfile = 1;
    }
    else
        goto view_status;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        printf("Failed to open file '%s', fallback to send HTTP GET\n", filename);
        is_sendfile = 0;
        goto view_status;
    }

    /* Get file size */
    filesize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    printf("Success open file '%s' (%ld bytes).\n", filename, filesize);

view_status:
    /* Status */
    char cipher_ver[32];
    char cipher_name[32];
    long int is_ktls_send = BIO_get_ktls_send(SSL_get_wbio(ssl));
    long int is_ktls_recv = BIO_get_ktls_recv(SSL_get_rbio(ssl));



    strcpy(cipher_ver, SSL_get_cipher_version(ssl));
    strcpy(cipher_name, SSL_get_cipher_name(ssl));
    printf(
        "--------------------------------------\n"
        "Cipher version: %s\n"
        "Cipher name: %s\n"
        "KTLS send: %ld\n"
        "KTLS recv: %ld\n"
        "--------------------------------------\n\n",
        cipher_ver,
        cipher_name,
        is_ktls_send,
        is_ktls_recv
    );

    /* Could examine ssl here to get connection info */
    if (is_sendfile)
    {
        if (is_ktls_send)
        {
            rc = SSL_sendfile(ssl, fd, 0, filesize, 0);
            if (rc <= 0)
                goto end;
        }
        else
        {
            char *buf = calloc(filesize, 1);
            rc = read(fd, buf, filesize);
            if (rc < 0)
                goto end;
            rc = SSL_write(ssl, buf, filesize);
            if (rc <= 0)
                goto end;
        }
    }
    else
        BIO_puts(bio, "GET / HTTP/1.0\n\n");

    for (;;) {
        len = BIO_read(bio, tmpbuf, 1024);
        if (len <= 0)
            break;

        BIO_write(out, tmpbuf, len);
    }
end:
    close(fd);
    SSL_CONF_CTX_free(cctx);
    BIO_free_all(bio);
    BIO_free(out);
    NCONF_free(conf);
    if (rc < 0)
        err(rc, NULL);
    return 0;
}
