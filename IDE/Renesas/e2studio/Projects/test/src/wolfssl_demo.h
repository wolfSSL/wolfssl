/*
 * wolfssl_demo.h
 *
 *  Created on: 2019/07/28
 *      Author: darkb
 */

#ifndef WOLFSSL_DEMO_H_
#define WOLFSSL_DEMO_H_

#define FREQ 10000 /* Hz */

//#define CRYPT_TEST
//#define BENCHMARK
//#define TLS_CLIENT
#define USE_TSIP_TLS
#define TLS_SERVER

void wolfSSL_TLS_client_init();
void wolfSSL_TLS_client();
void wolfSSL_TLS_server_init();
void wolfSSL_TLS_server();

#endif /* WOLFSSL_DEMO_H_ */
