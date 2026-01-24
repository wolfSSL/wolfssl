/* cryptocb_loader.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 * Loader for the external crypto callback provider.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLF_CRYPTO_CB_TEST_PROVIDER

#include <wolfssl/wolfcrypt/cryptocb.h>

#include <dlfcn.h>
#include <stdio.h>

#include "cryptocb_loader.h"

#ifndef CRYPTOCB_PROVIDER_PATH
    #define CRYPTOCB_PROVIDER_PATH \
        "tests/cryptocb-provider/libcryptocbprovider.so"
#endif

typedef int (*cryptocb_provider_callback_fn)(int, wc_CryptoInfo*, void*);

/* File-scope static variables for cleanup access */
static void *gExtProviderHandle = NULL;
static cryptocb_provider_callback_fn gExtProviderCallback = NULL;

/* Load and register the external crypto callback provider and return its devId
 * */
int wc_CryptoCb_InitTestCryptoCbProvider(void) {
  /* Only load the shared library once, but always re-register the device
   * since wolfCrypt_Cleanup() may have unregistered it */
  if (gExtProviderHandle == NULL) {
    gExtProviderHandle = dlopen(CRYPTOCB_PROVIDER_PATH, RTLD_NOW | RTLD_LOCAL);
    if (gExtProviderHandle == NULL) {
      printf("Warning: could not load external provider: %s\n", dlerror());
      return INVALID_DEVID;
    }
    gExtProviderCallback = (cryptocb_provider_callback_fn)dlsym(
        gExtProviderHandle, "external_provider_callback");
    if (gExtProviderCallback == NULL) {
      printf("Warning: external provider missing symbols\n");
      dlclose(gExtProviderHandle);
      gExtProviderHandle = NULL;
      return INVALID_DEVID;
    }
  }

  wc_CryptoCb_RegisterDevice(WOLF_CRYPTO_CB_TEST_PROVIDER_ID, gExtProviderCallback,
                             NULL);
  printf("External crypto provider loaded (devId=0x%x)\n",
         WOLF_CRYPTO_CB_TEST_PROVIDER_ID);
  return WOLF_CRYPTO_CB_TEST_PROVIDER_ID;
}

/* Cleanup the external crypto callback provider */
void wc_CryptoCb_CleanupTestCryptoCbProvider(void) {
  if (gExtProviderHandle != NULL) {
    wc_CryptoCb_UnRegisterDevice(WOLF_CRYPTO_CB_TEST_PROVIDER_ID);
    dlclose(gExtProviderHandle);
    gExtProviderHandle = NULL;
    gExtProviderCallback = NULL;
  }
}

#endif /* WOLF_CRYPTO_CB_TEST_PROVIDER */
