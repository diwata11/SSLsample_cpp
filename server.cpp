#include "SSLserver.hpp"

#define PORT 54345
#define BUFSIZE 65536

static int s_server_session_id_context = 1;

using namespace std;

int main(void){
  int sock, s;
  BIO *sbio;
  SSL_CTX *ctx;
  SSL *ssl;
  int r;
  string jString, err;

  // create SSL context.
  ctx = initialize_ctx(KEYFILE, PASSWORD);
  //load_dh_params(ctx, DHFILE); // 必要性が理解できなかった.要確認
  //generate_eph_rsa_key(ctx);

  SSL_CTX_set_session_id_context(ctx, (const unsigned char *)&s_server_session_id_context,
                                 sizeof s_server_session_id_context);
  sock = tcp_listen(PORT);


  if((s = accept(sock, 0, 0)) < 0)
    err_exit("Problem accepting...");

  sbio = BIO_new_socket(s, BIO_NOCLOSE);
  ssl = SSL_new(ctx);
  SSL_set_bio(ssl, sbio, sbio);

  if((r = SSL_accept(ssl)) <= 0)
    berr_exit("SSL accept error...");


  // get message from client.
  string msg;
  msg = getMessage(ssl, s, BUFSIZE);
  cout << "Get message from client: " << msg << endl;

  msg = "Hello server!!";
  sendMessage(ssl, s, msg, BUFSIZE);
  cout << "Send message to client: " << msg << endl;
  


  // close SSL contexts.
  ShutdownSSL(s, ctx, ssl);

  return 0;
}

