#include <ssl.h>
#include <stdio.h>

#define svrCertFile    "certs/server-cert.pem"
#define svrKeyFile     "certs/serrver-key.pem"

void main(){

  wolfSSL_Debugging_ON();

  SSL_CTX *ctx;
  /* SSL *ssl; */
  EVP_PKEY *pkey;
  const char* ourCert    = svrCertFile;
  const char* ourKey     = svrKeyFile;

  ctx = SSL_CTX_new(wolfSSLv23_server_method());

  printf("enter chain file\n");
  SSL_CTX_use_certificate_chain_file(ctx, ourCert);
  printf("enter key file\n");
  SSL_CTX_use_PrivateKey_file(ctx,ourKey,SSL_FILETYPE_PEM);

  printf("enter get key");
  pkey = SSL_get_privatekey(ssl);

  printf("%s\n",pkey->pkey.ptr);

}
