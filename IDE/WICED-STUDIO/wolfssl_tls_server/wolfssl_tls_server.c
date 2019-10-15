 /* Copyright (C) 2006-2019 wolfSSL Inc.
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

/**
 *
 * TLS Server Application
 *
 * This application snippet demonstrates how to used the WICED
 * TCP/TLS API to implement a TLS server
 *
 * Features demonstrated
 *  - DHCP client
 *  - TCP transmit and receive
 *  - TLS transmit and receive
 *
 * Application Instructions
 *   1. Modify the CLIENT_AP_SSID/CLIENT_AP_PASSPHRASE Wi-Fi credentials
 *      in the wifi_config_dct.h header file to match your Wi-Fi access point
 *   2. Ensure your computer is connected to the same Wi-Fi access point.
 *   3. Connect a PC terminal to the serial port of the WICED Eval board,
 *      then build and download the application as described in the WICED
 *      Quick Start Guide
 *   4. After the WICED board connects to your AP, look at the terminal
 *      output to find the IP address it received
 *   5. Run the application against the wolfSSL client application using
 *          ./examples/client/client -h <IPv4> -p 50007 -d
 *          **You will need to use the IPv4 address that is assigned to the server.
 *      Feel free to try out TLS 1.3. Include -v 4 in the client parameter list.
 *
 *
 *
 * When the TLS client runs on your computer, it sends a message
 * to the WICED TLS server, the server then responds with a message of its own.
 * When the message is received, it is printed to the WICED serial port and
 * appears on the terminal.
 *
 * If the TCP keep alive flag is set, the client keeps the TCP connection
 * open after the message is sent, otherwise the connection is closed.
 *
 * The network to be used can be changed by the #define WICED_NETWORK_INTERFACE
 * in wifi_config_dct.h. In the case of using AP or STA mode, change the AP_SSID
 * and AP_PASSPHRASE accordingly.
 *
 * RSA certs are loaded in the server by default. If you want to change the
 * certificates, you can do it in wiced_tls.c.
 *
 */

#ifdef WOLFSSL_WICED
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
#endif

#include "wiced.h"
#include "wiced_tls.h"

/******************************************************
 *                      Macros
 ******************************************************/

#define TCP_PACKET_MAX_DATA_LENGTH          (30)
#define TCP_SERVER_LISTEN_PORT              (50007)
#define TCP_SERVER_THREAD_PRIORITY          (WICED_DEFAULT_LIBRARY_PRIORITY)
/* Stack size should cater for printf calls */
#define TCP_SERVER_STACK_SIZE               (3200 * 2)
#define TCP_SERVER_COMMAND_MAX_SIZE         (10)
#define TCP_PACKET_MAX_DATA_LENGTH          (30)


/* Keepalive will be sent every 2 seconds */
#define TCP_SERVER_KEEP_ALIVE_INTERVAL      (2)
/* Retry 10 times */
#define TCP_SERVER_KEEP_ALIVE_PROBES        (5)
/* Initiate keepalive check after 5 seconds of silence on a tcp socket */
#define TCP_SERVER_KEEP_ALIVE_TIME          (5)
#define TCP_SILENCE_DELAY                   (30)




/******************************************************
 *                    Constants
 ******************************************************/
#define RX_BUFFER 50
#define TX_BUFFER 50
/******************************************************
 *                   Enumerations
 ******************************************************/

/******************************************************
 *                 Type Definitions
 ******************************************************/
typedef struct
{
    wiced_bool_t quit;
    wiced_tcp_socket_t socket;
}tcp_server_handle_t;
/******************************************************
 *                    Structures
 ******************************************************/

/******************************************************
 *               Static Function Declarations
 ******************************************************/
static void tcp_server_thread_main(uint32_t arg);

static wiced_result_t tcp_server_process(  tcp_server_handle_t* server,
                                             char* rx_packet );

/******************************************************
 *               Variable Definitions
 ******************************************************/

const char unsigned*    serverCert = server_cert_der_2048;
const int*               serverCertLen = &sizeof_server_cert_der_2048;
const char unsigned*    serverKey = server_key_der_2048;
const int*               serverKeyLen = &sizeof_server_key_der_2048;


static const wiced_ip_setting_t device_init_ip_settings =
{
    INITIALISER_IPV4_ADDRESS( .ip_address, MAKE_IPV4_ADDRESS(192,168,  0,  1) ),
    INITIALISER_IPV4_ADDRESS( .netmask,    MAKE_IPV4_ADDRESS(255,255,255,  0) ),
    INITIALISER_IPV4_ADDRESS( .gateway,    MAKE_IPV4_ADDRESS(192,168,  0,  1) ),
};

static wiced_thread_t      tcp_thread;
static tcp_server_handle_t tcp_server_handle;
/******************************************************
 *               Function Definitions
 ******************************************************/

void application_start(void)
{
    wiced_interface_t interface;
    wiced_result_t result;
    wiced_tls_context_t context;

    /* CA cert */
    const char unsigned*      caCert = ca_cert_der_2048;
    const int                 caCertLen = sizeof_ca_cert_der_2048;

    /* Initialize the device and WICED framework */
    wiced_init( );
    wolfSSL_Debugging_ON();

    /* Bring up the network interface */
    result = wiced_network_up_default( &interface, &device_init_ip_settings );

    if( result != WICED_SUCCESS )
    {
        WPRINT_APP_INFO( ("Bringing up network interface failed !\n") );
    }

    /* Create a TCP server socket */
    if (wiced_tcp_create_socket(&tcp_server_handle.socket, interface)
                                        != WICED_SUCCESS)
    {
        WPRINT_APP_INFO(("TCP socket creation failed\n"));
    }

    result = wiced_tls_init_context ( &context, NULL, NULL );
    if (result != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ("ERROR init context.\n") );
        return;
    }

    /* Enable TLS */
    result = wiced_tcp_enable_tls ( &tcp_server_handle.socket, &context );
    if (result != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ("ERROR enabling TLS.\n") );
        return;
    }

    if (wiced_network_is_up( interface ) == WICED_TRUE)
    {
        WPRINT_APP_INFO( ("Network is up.\n") );
    }

    if (wiced_tcp_listen( &tcp_server_handle.socket, TCP_SERVER_LISTEN_PORT )
                                   != WICED_SUCCESS)
    {
        WPRINT_APP_INFO(("TCP server socket initialization failed\n"));
        wiced_tcp_delete_socket(&tcp_server_handle.socket);
        return;
    }

    /************************************************************************
     *                  TLS SERVER CODE                                     *
     * *********************************************************************/

    /* Optional wiced_init_root_ca_certificates() */
    /* TLS initialization.  */

    result = wiced_tls_init_root_ca_certificates(
            (const char*)caCert, (const uint32_t)caCertLen );
    if (result != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ("ERROR initializing root ca certs.\n") );
        return;
    }

    /* Start a tcp server thread */
    WPRINT_APP_INFO(("Creating tcp server thread \n"));
    wiced_rtos_create_thread(&tcp_thread, TCP_SERVER_THREAD_PRIORITY,
                            "Demo tcp server", tcp_server_thread_main,
                            TCP_SERVER_STACK_SIZE, &tcp_server_handle);

}


static wiced_result_t tcp_server_process(
                tcp_server_handle_t* server, char* rx_packet )
{
    char*           request;
    uint16_t        request_length;
    uint16_t        available_data_length;
    char*           tx_packet;
    tx_packet = (char*)malloc(TX_BUFFER);
    sprintf(tx_packet, "%s", "Hello from WICED\0");

    wiced_packet_get_data( (wiced_packet_t*)rx_packet, 0, (uint8_t**) &request,
                            &request_length, &available_data_length );

    if (request_length != available_data_length)
    {
        WPRINT_APP_INFO(("Fragmented packets not supported\n"));
        return WICED_ERROR;
    }

    /* Null terminate the received string */
    rx_packet[RX_BUFFER] = '\x0';
    WPRINT_APP_INFO(("Received data: %s \n", rx_packet));

    /* Send the TCP packet */
    if (wiced_tcp_send_packet(&server->socket, tx_packet) != WICED_SUCCESS)
    {
        WPRINT_APP_INFO(("TCP packet send failed\n"));

        /* Delete packet, since the send failed */
        wiced_packet_delete((wiced_packet_t*)tx_packet);

        server->quit=WICED_TRUE;
        return WICED_ERROR;
    }
    WPRINT_APP_INFO(("Echo data: %s\n", tx_packet));

    return WICED_SUCCESS;
}

static void tcp_server_thread_main(uint32_t arg)
{
    tcp_server_handle_t* server = (tcp_server_handle_t*) arg;
    wiced_result_t result;

    /* Uncomment if using the heap. */
    /*  char*                    temp_packet;  */
    /*  temp_packet = (char*)malloc(50*sizeof(char));  */

    /* Uncomment if using the stack. */
    char temp_packet[RX_BUFFER];

    while ( server->quit != WICED_TRUE )
    {
        /* Initialize structures. */
        XMEMSET(temp_packet, 0, RX_BUFFER);

        /* Wait for a connection */
        result = wiced_tcp_accept( &server->socket );

        if ( result == WICED_SUCCESS )
        {
            /* Receive the query from the TCP client */
            if (wiced_tcp_receive(&server->socket, (void*)temp_packet, RX_BUFFER)
                                      == WICED_SUCCESS)
            {
                /* Process the client request */
                tcp_server_process( server, temp_packet );
            }
            else
            {
                /* Send failed or connection has been lost,
                 * close the existing connection and
                 * get ready to accept the next one
                 */
                wiced_tcp_disconnect( &server->socket );
            }
        }
    }
    WPRINT_APP_INFO(("Disconnect\n"));

    wiced_tcp_disconnect( &server->socket );

    /* Uncomment if using the heap. */
    /*  XFREE(temp_packet, 0, 0);  */

    WICED_END_OF_CURRENT_THREAD( );
}
