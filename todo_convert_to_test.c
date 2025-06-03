
// gcc todo_convert_to_test.c -lcrypto -o test_openssl -I/usr/local/include/  -g

// ./configure --enable-opensslall --enable-keygen
// gcc todo_convert_to_test.c -L./src/.libs/ -lwolfssl -o test_wolfssl -Iwolfssl  -I./ -g -DWOLF

#ifdef WOLF
#include <options.h>
#include <ssl.h>
#endif 

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>
int main() {
  EVP_MD_CTX *sign_hash = NULL;
  EVP_MD_CTX *vrfy_hash = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY_CTX *sign_ctx = NULL;
  EVP_PKEY_CTX *vrfy_ctx = NULL;
  EVP_PKEY *pkey = NULL;
  const unsigned char *data = "This is the data to be signed";
  size_t data_len = strlen((const char *)data);
  unsigned char *signature = NULL;
  size_t signature_len = 0;

  int modulus_bits = 2048;
  const uint32_t exponent = 0x10001;

  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (ctx == NULL) {
    fprintf(stderr, "Could not create a context for RSA_PSS");
    return 1;
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    fprintf(stderr, "Could not initialize the RSA context");
    return 1;
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, modulus_bits) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_bits failed");
    return 1;
  }

/*
  BIGNUM* exponent_bn = BN_new();
  BN_set_word(exponent_bn, exponent);
  if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, exponent_bn) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_pubexp failed");
    return 1;
  }
*/

  if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
    fprintf(stderr, "EVP_PKEY_keygen failed");
    return 1;
  }

  sign_hash = EVP_MD_CTX_new();
  if (sign_hash == NULL) {
    fprintf(stderr, "Error creating allocating hash ctx\n");
    return 1;
  }

  if (EVP_DigestSignInit(sign_hash, &sign_ctx, EVP_sha256(), NULL, pkey) == 0) {
    fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
    return 1;
  }

  if (sign_ctx == NULL) {
    fprintf(stderr, "sign_ctx is NULL\n");
    return 1;
  }

  // Set the padding scheme to PSS
  if (EVP_PKEY_CTX_set_rsa_padding(sign_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
    fprintf(stderr, "Error setting RSA padding\n");
    return 1;
  }

  // Set the digest algo for the signature
  if (EVP_PKEY_CTX_set_signature_md(sign_ctx, EVP_sha256()) <= 0) {
    fprintf(stderr, "Error setting signature digest algo.\n");
    return 1;
  }

  // Set the RSA-MGF1 digest (e.g., SHA-256)
  if (EVP_PKEY_CTX_set_rsa_mgf1_md(sign_ctx, EVP_sha256()) <= 0) {
    fprintf(stderr, "Error setting RSA-MGF1 digest\n");
    return 1;
  }

  // Feed the data in.
  if (EVP_DigestSignUpdate(sign_hash, data, data_len) != 1) {
    fprintf(stderr, "Error signing data (1)\n");
    return 1;
  }

  // Figure out signature size.
  if (EVP_DigestSignFinal(sign_hash, NULL, &signature_len) <= 0) {
    fprintf(stderr, "Error signing data\n");
    return 1;
  }

  // Allocate memory for the signature
  signature = (unsigned char *)OPENSSL_malloc(signature_len);
  if (signature == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    return 1;
  }

  if (EVP_DigestSignFinal(sign_hash, signature, &signature_len) != 1) {
    fprintf(stderr, "Error signing data (2)\n");
  }

  // Print the signature (for demonstration)
  printf("Signature length: %zu\n", signature_len);
  printf("Signature:\n");
  for (size_t i = 0; i < signature_len; i++) {
    printf("%02x", signature[i]);
  }
  printf("\n");

  vrfy_hash = EVP_MD_CTX_new();
  if (vrfy_hash == NULL) {
    fprintf(stderr, "Error creating allocating hash ctx\n");
    return 1;
  }

  if (EVP_DigestVerifyInit(vrfy_hash, &vrfy_ctx, EVP_sha256(), NULL, pkey) == 0) {
    fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
    return 1;
  }

  if (vrfy_ctx == NULL) {
    fprintf(stderr, "sign_ctx is NULL\n");
    return 1;
  }

  // Set the padding scheme to PSS
  if (EVP_PKEY_CTX_set_rsa_padding(vrfy_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
    fprintf(stderr, "Error setting RSA padding\n");
    return 1;
  }

  // Set the digest algo for the signature
  if (EVP_PKEY_CTX_set_signature_md(vrfy_ctx, EVP_sha256()) <= 0) {
    fprintf(stderr, "Error setting signature digest algo.\n");
    return 1;
  }

  // Set the RSA-MGF1 digest (e.g., SHA-256)
  if (EVP_PKEY_CTX_set_rsa_mgf1_md(vrfy_ctx, EVP_sha256()) <= 0) {
    fprintf(stderr, "Error setting RSA-MGF1 digest\n");
    return 1;
  }

  if (EVP_DigestVerifyUpdate(vrfy_hash, data, data_len) != 1) {
    fprintf(stderr, "Error verifying data (1)\n");
    return 1;
  }

  if (EVP_DigestVerifyFinal(vrfy_hash, signature, signature_len) != 1) {
    fprintf(stderr, "Error verifying data (1)\n");
    return 1;
  }


  fprintf(stderr, "Woo hoo!!\n");

  // Clean up
  OPENSSL_free(signature);
  EVP_MD_CTX_free(sign_hash);
  EVP_MD_CTX_free(vrfy_hash);
  EVP_PKEY_CTX_free(ctx);

  /* sign_ctx and vrfy_ctx owned by their hash context. No free required. */
  EVP_PKEY_free(pkey);
  pkey = NULL; //free?
  return 0;
}
