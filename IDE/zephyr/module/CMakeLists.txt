zephyr_interface_library_named(wolfSSL)

if(CONFIG_WOLFSSL_BUILTIN)
  target_compile_definitions(wolfSSL INTERFACE
	WOLFSSL_OPTIONS_FILE="${CONFIG_WOLFSSL_OPTIONS_FILE}"
	)

  target_include_directories(wolfSSL INTERFACE
	${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/include
	${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/settings
	)

  zephyr_library()
  zephyr_library_sources(zephyr_init.c)

  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/src/crl.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/src/internal.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/src/keys.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/src/ocsp.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/src/sniffer.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/src/ssl.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/src/tls13.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/src/tls.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/src/wolfio.c)

  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/aes.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/arc4.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/asm.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/asn.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/async.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/blake2b.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/camellia.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/chacha20_poly1305.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/chacha.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/cmac.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/coding.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/compress.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/cpuid.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/cryptocb.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/curve25519.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/des3.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/dh.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/dsa.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/ecc.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/ecc_fp.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/ed25519.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/error.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/fe_low_mem.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/fe_operations.c)
  #zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/fips.c)
  #zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/fips_test.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/ge_low_mem.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/ge_operations.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/hash.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/hc128.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/hmac.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/idea.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/integer.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/logging.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/md2.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/md4.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/md5.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/memory.c)
  #zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/misc.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/pkcs12.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/pkcs7.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/poly1305.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/pwdbased.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/rabbit.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/random.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/ripemd.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/rsa.c)
  #zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/selftest.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sha256.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sha3.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sha512.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sha.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/signature.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sp_arm32.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sp_arm64.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sp_armthumb.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sp_c32.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sp_c64.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sp_cortexm.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sp_int.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/sp_x86_64.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/srp.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/tfm.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/wc_encrypt.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/wc_pkcs11.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/wc_port.c)
  #zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/wolfcrypt_first.c)
  #zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/wolfcrypt_last.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/wolfevent.c)
  zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library/wolfcrypt/src/wolfmath.c)

  zephyr_library_link_libraries(wolfSSL)

  add_definitions(-DWOLFSSL_USER_SETTINGS)
  add_definitions(-DWOLFSSL_ZEPHYR)
  include_directories("${ZEPHYR_CURRENT_MODULE_DIR}/wolfssl/library")
else()
  assert(CONFIG_WOLFSSL_LIBRARY "wolfSSL was enabled, but neither BUILTIN or LIBRARY was selected.")

  # NB: CONFIG_WOLFSSL_LIBRARY is not regression tested and is
  # therefore susceptible to bit rot

  target_include_directories(wolfSSL INTERFACE
	${CONFIG_WOLFSSL_INSTALL_PATH}
	)

  zephyr_link_libraries(
    wolfssl_external
    -L${CONFIG_WOLFSSL_INSTALL_PATH}
    gcc
    )
  # Lib wolfssl depends on libgcc so to allow
  # wolfssl to link with gcc we need to ensure it is placed
  # after wolfssl_external on the linkers command line.
endif()

target_link_libraries(wolfSSL INTERFACE zephyr_interface)
