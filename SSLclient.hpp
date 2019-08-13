#ifndef _SSLclient_hpp
#define SSLclient_hpp

#include <iostream>
#include <string>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <csignal>
#include <fstream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace std;

#define CA_LIST "root.pem"
#define KEYFILE "client.pem"
#define PASSWORD "password"
#define HOST "localhost"

extern BIO *bio_err;
int berr_exit(const char *string);
int err_exit(const char *string);

SSL_CTX *initialize_ctx(const char *keyfile, const char *password);
void destroy_ctx(SSL_CTX *ctx);

int tcp_connect(int PORT);
void check_cert_chain(SSL *ssl, const char *host);
void read_write(SSL *ssl, int sock, int BUFSIZE);

void ssl_write(SSL *ssl, char *character, int size);

int checkResponse(SSL *ssl);
void sendMessage(SSL *ssl, int sock, string msg, int BUFSIZE);
string getMessage(SSL *ssl, int s, int BUFSIZE);
void ShutdownSSL(SSL *ssl, int sock, SSL_CTX *ctx);

#ifndef ALLOW_OLD_VERSIONS
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
#error "Must use OpenSSL 0.9.6 or later"
#endif
#endif

#endif
