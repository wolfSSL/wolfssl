
#ifdef OPENSSL_EXTRA

#define OPENSSL_TEST_ERROR -10000

static int openssl_test_ex(void)
{

  /* Test: AES_encrypt/decrypt/set Key */

  AES_KEY enc;
#ifdef HAVE_AES_DECRYPT
  AES_KEY dec;
#endif

  byte cipher[AES_BLOCK_SIZE * 4];
  byte plain [AES_BLOCK_SIZE * 4];

  int  ret = 0;

#ifdef HAVE_AES_CBC
  const byte msg[] = { /* "Now is the time for all " w/o trailing 0 */
      0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
      0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
      0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
  };

  const byte verify[] =
  {
      0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
      0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
  };

  byte encKey[] = "0123456789abcdef   ";  /* align */
  byte decKey[] = "0123456789abcdef   ";  /* align */
  byte iv[]     = "1234567890abcdef   ";  /* align */


  printf("openSSL extra test\n") ;

  ret = AES_set_encrypt_key(encKey, sizeof(encKey)*8, &enc);
  if (ret != 0)
      return OPENSSL_TEST_ERROR-1001;

#ifdef HAVE_AES_DECRYPT
  printf("test AES_decrypt\n");
  ret = AES_set_decrypt_Key(decKey, sizeof(decKey)*8, &dec);
  if (ret != 0)
      return OPENSSL_TEST_ERROR-1002;
#endif

  AES_encrypt(&enc, cipher, msg);

#ifdef HAVE_AES_DECRYPT
  AES_decrypt(&dec, plain, cipher);
  if (XMEMCMP(plain, msg, AES_BLOCK_SIZE))
      return OPENSSL_TEST_ERROR--60;
#endif /* HAVE_AES_DECRYPT */

  if (XMEMCMP(cipher, verify, AES_BLOCK_SIZE))
      return OPENSSL_TEST_ERROR--61;

  return 0;
}
