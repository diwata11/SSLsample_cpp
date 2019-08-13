#include "SSLclient.hpp"

BIO *bio_err = 0;
const static char *pass;
char ENDMARK[] = "*** END OF MESSAGE ***";
char OK_RESPONSE[] = "OK";
char END_RESPONSE[] = "END";

static int password_cb(char * buf, int num, int rwflag, void *userdata);
static void sigpipe_handle(int x);

// 単純なエラーと終了ルーチン。
int err_exit(const char *string){
  fprintf(stderr, "%s\n", string);
  exit(0);
}

// SSLエラーを表示して終了する。
int berr_exit(const char *string){
  BIO_printf(bio_err, "%s\n", string);
  ERR_print_errors(bio_err);
  exit(0);
}

// Passはスレッドセーフでない。
static int password_cb(char *buf, int num, int rwflag, void *userdata){
  if(num < int(strlen(pass)+1))  return(0);
  
  strcpy(buf, pass);
  return(strlen(pass));
}


static void sigpipe_handle(int x){
}

// ref: https://kotaeta.com/54483596
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx){
  return preverify_ok;
}


SSL_CTX *initialize_ctx(const char *keyfile, const char *password){
  SSL_CTX *ctx;
  
  if(!bio_err){
    // グローバルなシステムの初期化
    SSL_library_init();
    SSL_load_error_strings();
    
    // エラーの書き込みコンテクスト
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  }
  
  // SIGPIPEハンドラをセットアップ
  signal(SIGPIPE, sigpipe_handle);
  
  // コンテキストを作成
  // ref: https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_new.html
  //ctx = SSL_CTX_new(SSLv23_client_method());
  ctx = SSL_CTX_new(TLS_client_method());

  // 証明書をロードする
  //if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
  if(!(SSL_CTX_use_certificate_file(ctx, keyfile, SSL_FILETYPE_PEM))){
    berr_exit("Could not read certificate file... ");
  }
  
  // 秘密鍵をロードする
  pass = password;
  SSL_CTX_set_default_passwd_cb(ctx, password_cb);
  if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)))
    berr_exit("Could not read key file... ");
    
  // CA証明書をロードする
  if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST, 0)))
    berr_exit("Could not read CA list...");
  
  // 証明書検証機能の有効化
  // ref: https://blogs.yahoo.co.jp/udumge/19232934.html
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

  // 証明書チェーンの深さをチェックする。
  // ref: https://www.gleas.jp/news/column/certificate-chain
  SSL_CTX_set_verify_depth(ctx, 9);
  
  return ctx;
}


void destroy_ctx(SSL_CTX *ctx){
  SSL_CTX_free(ctx);
}


int tcp_connect(int PORT){
  struct hostent *hp;
  struct sockaddr_in addr;
  int sock;

  if(!(hp = gethostbyname(HOST))){
    berr_exit("Could not resolve host...");
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_addr = *(struct in_addr*) hp -> h_addr_list[0];
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);

  if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    err_exit("Could not create socket...");

  if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    err_exit("Could not connect socket...");

  return sock;
}

// Common Nameがホスト名一致することを確認する。
void check_cert_chain(SSL *ssl, const char *host){
  X509 *peer;
  char peer_CN[256];

  // SSL_get_verify_result(): 証明書の検証結果を返す。X509_V_OKならハンドシェイク&検証成功。
  if(SSL_get_verify_result(ssl) != X509_V_OK)
    berr_exit("Certificate does not verify...");

  // サーバ証明書のCommon nameが接続しようとしたサーバと同一か確認する。
  // OpenSSLでは、Common nameの検証機能を提供していないため、この処理が必要になる。
  // チェーンの長さはctxで深さを設定したときにOpensslによって自動的にチェックされる。
  // ref: http://blog.kazuhooku.com/2014/01/ssltls.html
  peer = SSL_get_peer_certificate(ssl); // サーバ証明書の取得
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

  if(strcasecmp(peer_CN, host))
    err_exit("Common name does not match host name...");
}


/*
 * キーボードから読み取り、サーバーに書き込む。
 * サーバーから読み取り、キーボードに書き込む。
 * select()を使用し、多重化を行う。
 */
void read_write(SSL *ssl, int sock, int BUFSIZE){
  int width;
  int r, c2sl = 0, c2s_offset = 0;
  fd_set readfds, writefds;
  int shutdown_wait = 0;
  char c2s[BUFSIZ], s2c[BUFSIZE];
  int ofcmode;

  // まず、ソケットを非ブロックにする。
  ofcmode = fcntl(sock, F_GETFL, 0);
  ofcmode |= O_NDELAY;
  if(fcntl(sock, F_SETFL, ofcmode))
    err_exit("Could not make socket nonblocking...");

  width = sock + 1;
  while(1){
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    FD_SET(sock, &readfds);

    // 書き込むデータがまだある場合、読み取りを行わない。
    if(c2sl)
      FD_SET(sock, &writefds);
    else
      FD_SET(fileno(stdin), &readfds);

    r = select(width, &readfds, &writefds, 0, 0);
    if(r==0)
      continue;

    //読み取るデータが存在するか確認する。
    if(FD_ISSET(sock, &readfds)){
      do{
	r = SSL_read(ssl, s2c, BUFSIZE);

	switch(SSL_get_error(ssl, r)){
	case SSL_ERROR_NONE:
	  fwrite(s2c, 1, r, stdout);
	  break;

	case SSL_ERROR_ZERO_RETURN:
	  // データ終了
	  if(!shutdown_wait)
	    SSL_shutdown(ssl);

	  goto end;
	  break;

	case SSL_ERROR_WANT_READ:
	  break;

	default:
	  berr_exit("SSL read problem...");
	}
      }while(SSL_pending(ssl));
    }

    // コンソールからの入力をチェックする。
    // ここ要チェック！！
    if(FD_ISSET(fileno(stdin), &readfds)){
      c2sl = read(fileno(stdin), c2s, BUFSIZE);

      if(c2sl == 0){
	shutdown_wait = 1;

	if(SSL_shutdown(ssl))
	  return;
      }

      c2s_offset = 0;
    }

    // 書き込むデータがある場合は、書き込みを試行する。
    if(c2sl && FD_ISSET(sock, &writefds)){
      r = SSL_write(ssl, c2s + c2s_offset, c2sl);

      switch(SSL_get_error(ssl, r)){
	// 何かを書き込んだ
      case SSL_ERROR_NONE:
	c2sl -= r;
	c2s_offset += r;
	break;

	// ブロックされた
      case SSL_ERROR_WANT_WRITE:
	break;

	// その他のエラー
      default:
	berr_exit("SSL write problem...");
      }
    }

  }

 end:
  SSL_free(ssl);
  close(sock);
  return;
}


void ssl_write(SSL *ssl, char *character, int size){
  int r = SSL_write(ssl, character, size);

  if(SSL_get_error(ssl, r) != 0)
    berr_exit("SSL write problem...");
}


int checkResponse(SSL *ssl){
  int r;
  char get_char[10];
  
  while(1){
    memset(get_char, '\0', sizeof(get_char));
    
    r = SSL_read(ssl, get_char, 10);

    switch(SSL_get_error(ssl, r))
      {
      case SSL_ERROR_NONE:
	if(string(get_char) == "OK")
	  return 1;
	else if(string(get_char) == "END"){
	  return 0;
	}
	else{
	  err_exit("fail to send json message...");
	}
      default:
	break;
      }
  }
  
  return 0;
}


void sendMessage(SSL *ssl, int sock, string msg, int BUFSIZE){
  int ofcmode;
  int length = (int)msg.size();
  int start = 0;
  char post_char[BUFSIZE];

  // まず、ソケットを非ブロックにする。
  ofcmode = fcntl(sock, F_GETFL, 0);
  ofcmode |= O_NDELAY;
  if(fcntl(sock, F_SETFL, ofcmode))
    err_exit("Could not make socket nonblocking...");

  do{
    if(length > (BUFSIZE-5)){ // (BUFSIZE-5)bitずつJSON(string)を送信する。
      memset(post_char, '\0', sizeof(post_char));

      for(int i=start; i<start+(BUFSIZE-5); i++)
	post_char[i-start] = msg[i];

      ssl_write(ssl, post_char, int(strlen(post_char)));

      start += (BUFSIZE-5);
      length -= (BUFSIZE-5);
    }
    else if(length == 0 && start == (int)msg.size()) // ファイル終了マークの送信
      ssl_write(ssl, ENDMARK, int(strlen(ENDMARK)));
    else{ // (BUFSIZE-5)bit未満のmsg を送信する。
      memset(post_char, '\0', sizeof(post_char));

      for(int i=0; i<length; i++)
	post_char[i] = msg[start+i];

      ssl_write(ssl, post_char, int(strlen(post_char)));

      start += length;
      length -= length;
    }
  }while(checkResponse(ssl) == 1);
}


string getMessage(SSL *ssl, int s, int BUFSIZE){
  char get_char[BUFSIZE];
  int r, flag = 0;
  string msg = "";

  while(flag == 0){
    memset(get_char, '\0', sizeof(get_char));
    
    // データを読み取る。
    r = SSL_read(ssl, get_char, BUFSIZE);

    switch(SSL_get_error(ssl, r))
      {
      case SSL_ERROR_NONE:
	if(string(get_char) == string(ENDMARK)){
	  flag = 1;
	  ssl_write(ssl, END_RESPONSE, int(strlen(END_RESPONSE)));
	  }
	else{
	  msg += string(get_char);
	  ssl_write(ssl, OK_RESPONSE, int(strlen(OK_RESPONSE)));
	}

	break;

      case SSL_ERROR_ZERO_RETURN:
	err_exit("closed...");

      default:
	break;
      }
  }
  
  return msg;
}


void ShutdownSSL(SSL *ssl, int sock, SSL_CTX *ctx){
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sock);
  destroy_ctx(ctx);
}

