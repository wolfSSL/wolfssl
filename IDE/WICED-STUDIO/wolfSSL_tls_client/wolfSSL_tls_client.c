/*
 * Copyright 2018, Cypress Semiconductor Corporation or a subsidiary of 
 * Cypress Semiconductor Corporation. All Rights Reserved.
 * 
 * This software, associated documentation and materials ("Software"),
 * is owned by Cypress Semiconductor Corporation
 * or one of its subsidiaries ("Cypress") and is protected by and subject to
 * worldwide patent protection (United States and foreign),
 * United States copyright laws and international treaty provisions.
 * Therefore, you may use this Software only as provided in the license
 * agreement accompanying the software package from which you
 * obtained this Software ("EULA").
 * If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 * non-transferable license to copy, modify, and compile the Software
 * source code solely for use in connection with Cypress's
 * integrated circuit products. Any reproduction, modification, translation,
 * compilation, or representation of this Software except as specified
 * above is prohibited without the express written permission of Cypress.
 *
 * Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 * reserves the right to make changes to the Software without notice. Cypress
 * does not assume any liability arising out of the application or use of the
 * Software or any product or circuit described in the Software. Cypress does
 * not authorize its products for use in any products where a malfunction or
 * failure of the Cypress product may reasonably be expected to result in
 * significant property damage, injury or death ("High Risk Product"). By
 * including Cypress's product in a High Risk Product, the manufacturer
 * of such system or application assumes all risk of such use and in doing
 * so agrees to indemnify Cypress against all liability.
 */

/** @file
 *
 * TLS Client Application
 *
 * This application snippet demonstrates how to connect to a Wi-Fi
 * network and communicate with a TLS server.
 *
 * Features demonstrated
 *  - Wi-Fi client mode
 *  - DHCP client
 *  - TCP transmit and receive
 *  - TLS transmit and receive using wolfSSL
 *
 * Application Instructions
 *   1. Modify the CLIENT_AP_SSID/CLIENT_AP_PASSPHRASE Wi-Fi credentials
 *      in the wifi_config_dct.h header file to match your Wi-Fi access point
 *   2. Ensure your computer is connected to the same Wi-Fi access point.
 *   3. Determine the computer's IP address for the Wi-Fi interface.
 *   4. Change the #define TCP_SERVER_IP_ADDRESS in the code below to match
 *      the computer's IP address
 *   5. Open a command shell and navigate to the wolfSSL master directory.
 *      You may fork this repository at https://github.com/wolfSSL/wolfssl.
 *   6. Run the TLS example server on port 50007. See the wolfSSL manual at
 *      https://www.wolfssl.com/docs/ to build and configure the server.
 *       - Ensure your firewall is not blocking the connection.
 *   7. Connect a PC terminal to the serial port of the WICED Eval board,
 *      then build and download the application as described in the WICED
 *      Quick Start Guide
 *   8. Setup instructions can be found at IDE/WICED_STUDIO in the wolfSSL library.
 *
 * Every TCP_CLIENT_INTERVAL seconds, the app establishes a connection
 * with the remote TLS server, sends a message "Hello from WICED" and
 * receives a message "I hear you fa shizzle!" in response. The response is
 * printed on the serial console.
 *
 * The network to be used can be changed by the #define WICED_NETWORK_INTERFACE
 * in wifi_config_dct.h. In the case of using AP or STA mode, change the AP_SSID
 * and AP_PASSPHRASE accordingly.
 *
 *
 * The default policy for the client is to verify the server, this means
 * that if you don't load CAs to verify the server you'll get a connect error,
 * no signer error to confirm failure (-188).  If you want to mimic OpenSSL
 * behavior of having SSL_connect succeed even if verifying the server fails and
 * reducing security you can do this by calling:
 *
 * wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
 *
 * You will also need to define WOLFSSL_WICED_NO_VERIFY_CERTIFICATE.
 *
 * You may also register a callback for this function as in
 *         wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, my_callback)
 *
 * Please refer to the wolfSSL documentation for more specific information at:
 *         https://www.wolfssl.com/docs/
 *
 * For wolfSSL debug and WICED security debug uncomment the debug options
 *     DEBUG_WOLFSSL in wolfSSL user_settings.h and WPRINT_ENABLE_SECURITY_DEBUG
 *     in include/wiced_defaults.h.
 *
 *
 */



#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
#include "wiced.h"
#include "wiced_tls.h"
#include <unistd.h>



/******************************************************
 *                      Macros
 ******************************************************/

#define TCP_PACKET_MAX_DATA_LENGTH        30
#define TCP_CLIENT_INTERVAL               2
#define TCP_SERVER_PORT                   50007
#define TCP_CLIENT_CONNECT_TIMEOUT        500
#define TCP_CLIENT_RECEIVE_TIMEOUT        300
#define TCP_CONNECTION_NUMBER_OF_RETRIES  3


/* Change the server IP address to match the TCP echo server address */
#define TCP_SERVER_IP_ADDRESS MAKE_IPV4_ADDRESS(192,168,1,161)


/******************************************************
 *                    Constants
 ******************************************************/

#define TX_BUFFER 50
#define RX_BUFFER 50


/******************************************************
 *                   Enumerations
 ******************************************************/

/******************************************************
 *                 Type Definitions
 ******************************************************/

/******************************************************
 *                    Structures
 ******************************************************/

/******************************************************
 *               Static Function Declarations
 ******************************************************/

static wiced_result_t tcp_client();

/******************************************************
 *               Variable Definitions
 ******************************************************/

static const wiced_ip_setting_t device_init_ip_settings =
{
    INITIALISER_IPV4_ADDRESS( .ip_address, MAKE_IPV4_ADDRESS(192,168,  0,  1) ),
    INITIALISER_IPV4_ADDRESS( .netmask,    MAKE_IPV4_ADDRESS(255,255,255,  0) ),
    INITIALISER_IPV4_ADDRESS( .gateway,    MAKE_IPV4_ADDRESS(192,168,  0,  1) ),
};

/*
* Refer to wolfSSL tests/test.conf for a list of flags, certificates, and keys
*       to use with the cipher suites. Refer to wolfSSL src/internal.c for a
*       complete list of cipher suites.
*
* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
*       ECDHE-ECDSA-AES128-SHA
* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
*       ECDHE-ECDSA-AES128-GCM-SHA256
* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
*       ECDHE-ECDSA-AES256-SHA384
* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
*       ECDHE-ECDSA-AES256-GCM-SHA384
* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
*       ECDHE-ECDSA-CHACHA20-POLY1305
* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
*       ECDHE-RSA-AES128-SHA
* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
*       ECDHE-RSA-AES128-GCM-SHA256
* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
*       ECDHE-RSA-AES256-SHA
* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
*       ECDHE-RSA-AES256-GCM-SHA384
* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
*       ECDHE-RSA-CHACHA20-POLY1305
* TLS_RSA_WITH_AES_128_CBC_SHA      -v 1
*       AES128-SHA
* TLS_RSA_WITH_AES_128_GCM_SHA256
*       AES128-GCM-SHA256
* TLS_RSA_WITH_AES_256_CBC_SHA256
*       AES256-SHA256
* TLS_RSA_WITH_AES_256_GCM_SHA384
*       AES256-GCM-SHA384
*/

/* Cipher suite order should be arranged from most secure to least secure. */
static char* cipherSuiteList =  "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-SHA:ECDHE-RSA-CHACHA20-POLY1305:AES128-GCM-SHA256:"
        "AES256-SHA256:AES256-GCM-SHA384:AES128-SHA";

static wiced_tcp_socket_t  tcp_client_socket;
//static wiced_tls_context_t     context;
static wiced_timed_event_t tcp_client_event;

/******************************************************
 *               Function Definitions
 ******************************************************/

void application_start(void)
{
    /* Declarations */
    wiced_interface_t       interface;
    wiced_result_t          result;
    wiced_tls_context_t     context;
    wiced_tls_identity_t    *identity;
    const char              peer_cn;
    /* JB TODO: Load multiple certificates. Right now, just load one. */
    /* RSA certs */
    const char unsigned*    rsaCaCert = ca_cert_der_2048;
    const int               rsaCaCertLen = sizeof_ca_cert_der_2048;
    /* ECC certs */
    //const char unsigned*    eccCaCert = ca_ecc_cert_der_256;
    //const int               eccCaCertLen = sizeof_ca_ecc_cert_der_256;



    /* Initialise the device and WICED framework */
    if (wiced_init( ) != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ("Initializing wiced failed.\n") );
    }

    /* Bring up the network interface */
    if (wiced_network_up_default( &interface, &device_init_ip_settings )
                                                      != WICED_SUCCESS )
    {
        WPRINT_APP_INFO( ("Bringing up network interface failed !\n") );
        return;
    }

    /* Create a TCP socket */
    if (wiced_tcp_create_socket( &tcp_client_socket, interface )
                                              != WICED_SUCCESS )
    {
        WPRINT_APP_INFO( ("TCP socket creation failed\n") );
        return;
    }

    /* Bind to the socket */
    if (wiced_tcp_bind( &tcp_client_socket, TCP_SERVER_PORT ) != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ("TCP socket bind failed\n") );
        return;
    }

    /* TLS initialization.  */
    /* Load the correct certs for the algorithm. */
    result = wiced_tls_init_root_ca_certificates((const char*)rsaCaCert,
                                        (const uint32_t)rsaCaCertLen );
    if (result != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ("ERROR initializing root ca certs.\n") );
        return;
    }

    identity = (wiced_tls_identity_t*) malloc(sizeof(wiced_tls_identity_t) );
    if (identity == NULL)
    {
        WPRINT_APP_INFO( ("ERROR creating identity.\n") );
    }


    if (wiced_tls_init_context(&context, identity, &peer_cn) != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ("ERROR initializing context.\n" ) );
        return;
    }

    if (wiced_tcp_enable_tls( &tcp_client_socket, (void*)&context )
                                                  != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ("ERROR enabling tls.\n") );
        return;
    }


    if (wiced_network_is_up( interface ) == WICED_TRUE)
    {
        WPRINT_APP_INFO( ("Network is up.\n") );
    }

    wiced_rtos_register_timed_event( &tcp_client_event, WICED_NETWORKING_WORKER_THREAD,
                                 &tcp_client, TCP_CLIENT_INTERVAL * SECONDS, 0 );

    WPRINT_APP_INFO(("Connecting to the remote TCP server every %d seconds ...\n",
                                                           TCP_CLIENT_INTERVAL));

}


wiced_result_t tcp_client( void* arg )
{

    wiced_result_t           result;
    char*                    tx_data;
    char*                    rx_data;
    const wiced_ip_address_t INITIALISER_IPV4_ADDRESS( server_ip_address,
                                                    TCP_SERVER_IP_ADDRESS );
    int                      connection_retries;
    UNUSED_PARAMETER( arg );

    connection_retries = 0;

    /* Write the message into tx_data  */
    tx_data = (char*)malloc(TX_BUFFER);
    rx_data = (char*)malloc(RX_BUFFER);
    sprintf(tx_data, "%s", "Hello from WICED");

     wolfSSL_Debugging_ON();

     wiced_set_cipher_list(cipherSuiteList);


    /* Connect to the remote server, try several times. */
    do
    {

        result = wiced_tcp_connect( &tcp_client_socket, &server_ip_address,
                              TCP_SERVER_PORT, TCP_CLIENT_CONNECT_TIMEOUT );
        connection_retries++;
    } while ( ( result != WICED_SUCCESS ) &&
            ( connection_retries < TCP_CONNECTION_NUMBER_OF_RETRIES ) );

    /* Check return code for successful TCP connection and CTX setup. */
    if ( result != WICED_SUCCESS)
    {
        WPRINT_APP_INFO(("Unable to connect to the server!\n"));
        return WICED_ERROR;
    }

    /* Send the TCP packet. If using wolfSSL and NetX Duo, this will create and
     * send the packet.
     */

    if (wiced_tcp_send_packet(&tcp_client_socket, tx_data) != WICED_SUCCESS)
    {
        WPRINT_APP_INFO(("TCP packet send failed\n"));
        /* Close the connection */
        wiced_tcp_disconnect(&tcp_client_socket);
        return WICED_ERROR;
    }

    /*Receive a response from the server and print it out to the serial console.
     * If using wolfSSL and NetX Duo, this will create and
     * send the packet.
     */
    result = wiced_tcp_receive(&tcp_client_socket, rx_data, RX_BUFFER);

    if( result != WICED_SUCCESS )
    {
        WPRINT_APP_INFO(("TCP packet reception failed\n"));
        /* Delete packet, since the receive failed */

        /* Close the connection */
        wiced_tcp_disconnect(&tcp_client_socket);
        return WICED_ERROR;
    }

    /* Null terminate the received string and print it. */
    rx_data[RX_BUFFER - 1] = '\x0';
    WPRINT_APP_INFO(("%s\n", rx_data));

    /* terminate the connection */
    wiced_tcp_disconnect(&tcp_client_socket);

    return WICED_SUCCESS;

}


