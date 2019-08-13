#include "SSLclient.hpp"

const int PORT = 54345;
const int BUFSIZE = 16384;

using namespace std;


int main(void){
  // prepare for SSL
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  int sock;
  
  // create SSL context.
  ctx = initialize_ctx(KEYFILE, PASSWORD);

  sock = tcp_connect(PORT);

  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock, BIO_NOCLOSE);
  SSL_set_bio(ssl, sbio, sbio);

  if(SSL_connect(ssl) <= 0)
    berr_exit("SSL connect error...");

  check_cert_chain(ssl, HOST);


  // send message to server.
  string msg = "Hello World!!";
  sendMessage(ssl, sock, msg, BUFSIZE);
  cout << "Send message to server: " << msg << endl;

  // get message from server.
  msg = getMessage(ssl, sock, BUFSIZE);
  cout << "Get message from server: " << msg << endl;



  

  // close SSL contexts.
  ShutdownSSL(ssl, sock, ctx);  

  return 0;
}
