/* config-wolfSSL.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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
 */


/**** wolfSSL Configuration ****/

#define __CORTEX_M3__

// <<< Use Configuration Wizard in Context Menu >>>
// <h> wolfSSL Configuration

//     <h>SSL (Included by default)
//     </h>

//      <e>TLS 
#define MDK_CONF_TLS 1
#if MDK_CONF_TLS == 0
#define NO_TLS
#endif
//  </e>

//      <e>CRL
#define MDK_CONF_DER_LOAD 0
#if MDK_CONF_DER_LOAD == 1
#define WOLFSSL_DER_LOAD
#endif
//  </e>
//      <e>OpenSSL Extra
#define MDK_CONF_OPENSSL_EXTRA 1
#if MDK_CONF_OPENSSL_EXTRA == 1
#define OPENSSL_EXTRA
#endif
//  </e>
//</h>

//  <h>Cert/Key Generation
//      <e>CertGen
#define MDK_CONF_CERT_GEN 0
#if MDK_CONF_CERT_GEN == 1
#define WOLFSSL_CERT_GEN
#endif
//  </e>
//      <e>KeyGen
#define MDK_CONF_KEY_GEN 0
#if MDK_CONF_KEY_GEN == 1
#define WOLFSSL_KEY_GEN
#endif
//  </e>
//</h>

//  <h>Others

//      <h>Debug
//              <e>Debug Message
#define MDK_CONF_DebugMessage 0
#if MDK_CONF_DebugMessage == 1
#define DEBUG_WOLFSSL
#endif
//         </e>
//              <e>Check malloc
#define MDK_CONF_CheckMalloc 1
#if MDK_CONF_CheckMalloc == 1
#define WOLFSSL_MALLOC_CHECK
#define USE_WOLFSSL_MEMORY
#endif
//         </e>


//  </h>


// <<< end of configuration section >>>
