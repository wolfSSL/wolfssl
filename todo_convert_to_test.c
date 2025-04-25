#include <openssl/evp.h>
#include <openssl/rsa.h>

int main() {
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey; // Your RSA private key
  const unsigned char *data = "This is the data to be signed";
  size_t data_len = strlen((const char *)data);
  unsigned char *signature = NULL;
  size_t signature_len;

  // 1. Create a PKEY context
  ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (ctx == NULL) {
    fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
    return 1;
  }

  // 2. Initialize the context for signing
  if (EVP_PKEY_sign_init(ctx) <= 0) {
    fprintf(stderr, "Error initializing EVP_PKEY_CTX for signing\n");
    EVP_PKEY_CTX_free(ctx);
    return 1;
  }

  // 3. Set the RSA-MGF1 digest (e.g., SHA-256)
  if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
    fprintf(stderr, "Error setting RSA-MGF1 digest\n");
    EVP_PKEY_CTX_free(ctx);
    return 1;
  }

  // 4. Set the padding scheme (e.g., PSS)
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
    fprintf(stderr, "Error setting RSA padding\n");
    EVP_PKEY_CTX_free(ctx);
    return 1;
  }

  // 5. Sign the data
  if (EVP_PKEY_sign(ctx, NULL, &signature_len, data, data_len) <= 0) {
    fprintf(stderr, "Error signing data\n");
    EVP_PKEY_CTX_free(ctx);
    return 1;
  }

  // 6. Allocate memory for the signature
  signature = (unsigned char *)OPENSSL_malloc(signature_len);
  if (signature == NULL) {
    fprintf(stderr, "Memory allocation failed\n");
    EVP_PKEY_CTX_free(ctx);
    return 1;
  }

  // 7. Perform the signature again to write the signature
  if (EVP_PKEY_sign(ctx, signature, &signature_len, data, data_len) <= 0) {
    fprintf(stderr, "Error signing data (again)\n");
    OPENSSL_free(signature);
    EVP_PKEY_CTX_free(ctx);
    return 1;
  }

  // 8. Print the signature (for demonstration)
  printf("Signature length: %zu\n", signature_len);
  printf("Signature:\n");
  for (size_t i = 0; i < signature_len; i++) {
    printf("%02x", signature[i]);
  }
  printf("\n");

  // 9. Clean up
  OPENSSL_free(signature);
  EVP_PKEY_CTX_free(ctx);
  return 0;
}
