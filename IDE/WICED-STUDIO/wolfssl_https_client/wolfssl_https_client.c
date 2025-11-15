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

/*
 *
 * www.examples.com client application
 *
 * This application snippet demonstrates how to use the WICED HTTP Client API
 * to connect to https://www.example.com using wolfSSL.
 *
 * Features demonstrated
 *  - Wi-Fi client mode
 *  - DNS lookup
 *  - Secure HTTPS client connection
 *
 * Application Instructions
 * 1. Modify the CLIENT_AP_SSID/CLIENT_AP_PASSPHRASE Wi-Fi credentials
 *    in the wifi_config_dct.h header file to match your Wi-Fi access point
 * 2. Connect a PC terminal to the serial port of the WICED Eval board,
 *    then build and download the application as described in the WICED
 *    Quick Start Guide
 *
 * After the download completes, the application :
 *  - Connects to the Wi-Fi network specified
 *  - Resolves the www.example.com IP address using a DNS lookup
 *  - Sends multiple GET requests to https://www.example.com
 *  - Prints the results to the UART
 *
 * You may also run this application against the wolfSSL example server to do
 * that make sure you have installed wolfSSL from https://github.com/wolfssl.
 *     Documentation can be found at:
 *          https://www.wolfssl.com/docs/
 *
 *     ./examples/server/server -b -d -r -g -p 443
 *     ./examples/server/server -h for more options.
 *
 * If you are using TLS 1.3 include the version number
 *     ./examples/server/server -b -d -r -g -v 4 -p 443
 *
 * Please refer to the wolfSSL documentation for more specific information at:
 *         https://www.wolfssl.com/docs/
 *
 * For wolfSSL debug and WICED security debug uncomment the debug options
 *    DEBUG_WOLFSSL in wolfSSL user_settings.h and WPRINT_ENABLE_SECURITY_DEBUG
 *    in include/wiced_defaults.h.
 *
 */

#include <stdlib.h>
#include "wiced.h"
#include "wiced_tls.h"
#include "http_client.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/certs_test.h>


/******************************************************
 *                      Macros
 ******************************************************/
/* Set IP for the server if using wolfSSL server, otherwise ignore this. */
#define TCP_SERVER_IP_ADDRESS MAKE_IPV4_ADDRESS(192,168,1,1)

/******************************************************
 *                    Constants
 ******************************************************/
#if 1
    #define SERVER_HOST       "www.example.com"
#else
    /*
     * You can also use the simple server in the wolfSSL examples
     * directory, instructions on how to configure the server are
     * provided in the instruction set above.
     */
    #define SERVER_HOST     "www.wolfssl.com"
#endif

#define SERVER_PORT        ( 443 )
#define DNS_TIMEOUT_MS     ( 10000 )
#define CONNECT_TIMEOUT_MS ( 3000 )
#define TOTAL_REQUESTS     ( 2 )

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

static void  event_handler( http_client_t*, http_event_t, http_response_t* );
static void  print_data   ( char*, uint32_t);
static void  print_content( char*, uint32_t);
static void  print_header ( http_header_field_t*, uint32_t);

/******************************************************
 *               Variable Definitions
 ******************************************************/

#ifdef USE_WOLF_SERVER
#if defined(WOLF_STATIC_CA)
static const char unsigned*    http_root_ca_certificate = ca_cert_der_2048;
static const int*     http_root_ca_certificate_lg = &sizeof_ca_cert_der_2048;
#endif
static const wiced_ip_setting_t device_init_ip_settings =
{
    INITIALISER_IPV4_ADDRESS( .ip_address, MAKE_IPV4_ADDRESS(192,168,  0,  1) ),
    INITIALISER_IPV4_ADDRESS( .netmask,    MAKE_IPV4_ADDRESS(255,255,255,  0) ),
    INITIALISER_IPV4_ADDRESS( .gateway,    MAKE_IPV4_ADDRESS(192,168,  0,  1) ),
};

#else
#ifdef WOLF_STATIC_CA
static const char http_root_ca_certificate[] =
        "-----BEGIN CERTIFICATE-----"
        "MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh"
        "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3"
        "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD"
        "QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT"
        "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg"
        "U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB"
        "ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83"
        "nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd"
        "KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f"
        "/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX"
        "kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0"
        "/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C"
        "AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY"
        "aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6"
        "Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1"
        "oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD"
        "QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v"
        "d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh"
        "xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB"
        "CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl"
        "5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA"
        "8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC"
        "2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit"
        "c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0"
        "j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz"
        "-----END CERTIFICATE-----"
        "-----BEGIN CERTIFICATE-----"
        "MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh"
        "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3"
        "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD"
        "QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT"
        "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j"
        "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG"
        "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB"
        "CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97"
        "nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt"
        "43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P"
        "T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4"
        "gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO"
        "BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR"
        "TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw"
        "DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr"
        "hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg"
        "06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF"
        "PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls"
        "YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk"
        "CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4="
        "-----END CERTIFICATE-----";

static const int   http_root_ca_certificate_lg
            = sizeof(http_root_ca_certificate);
#endif

#endif  /* USE_WOLF_SERVER */

/* Cipher suite order should be arranged from most secure to least secure.
 *
 *  Refer to wolfSSL tests/test.conf for a list of flags, certificates, and keys
 *  to use with the cipher suites. Refer to wolfSSL src/internal.c for a
 *  complete list of cipher suites.
 *
 */
#ifdef TLSv13

char* cipherSuiteList = "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384"
        "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES128-CCM-SHA256";

#else

char* cipherSuiteList =  "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA:"
 "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:"
 "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-GCM-SHA384:"
 "ECDHE-RSA-AES256-SHA:ECDHE-RSA-CHACHA20-POLY1305:AES128-GCM-SHA256:"
 "AES256-SHA256:AES256-GCM-SHA384:AES128-SHA";

#endif

/******************************************************
 *               Function Definitions
 ******************************************************/

static http_client_t  client;
static http_request_t requests[TOTAL_REQUESTS];
static http_client_configuration_info_t client_configuration;

static const char* request_uri = "/index.html";

void application_start( void )
{
#ifndef USE_WOLF_SERVER
    wiced_ip_address_t  ip_address;
#endif
    wiced_result_t      result;
    http_header_field_t header[2];

    wiced_init( );
    wolfSSL_Debugging_ON();

    if ( (result = wiced_network_up(
            WICED_STA_INTERFACE, WICED_USE_EXTERNAL_DHCP_SERVER, NULL) )
                            != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ( "STA unable to join AP \n"
                        "result = %d\n", result ) );
        return;
    }

#ifdef USE_WOLF_SERVER
    const wiced_ip_address_t INITIALISER_IPV4_ADDRESS(
                             ip_address, TCP_SERVER_IP_ADDRESS );
#else
    WPRINT_APP_INFO( ( "Resolving IP address of %s\n", SERVER_HOST ) );
    if ((result = wiced_hostname_lookup( SERVER_HOST, &ip_address,
            DNS_TIMEOUT_MS, WICED_STA_INTERFACE )) != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ("Error in hostname lookup: %d\n", result) );
        return;
    }
    WPRINT_APP_INFO( ( "%s is at %u.%u.%u.%u\n", SERVER_HOST,
                                   (uint8_t)(GET_IPV4_ADDRESS(ip_address) >> 24),
                                   (uint8_t)(GET_IPV4_ADDRESS(ip_address) >> 16),
                                   (uint8_t)(GET_IPV4_ADDRESS(ip_address) >> 8),
                                   (uint8_t)(GET_IPV4_ADDRESS(ip_address) >> 0)));
#endif

    /* Initialize the root CA certificate */
    if ( wiced_tls_init_root_ca_certificates( (const char*)
            http_root_ca_certificate, (uint32_t)http_root_ca_certificate_lg )
                                            != WICED_SUCCESS )
    {
        WPRINT_APP_INFO( ("Error: Root CA certificate failed to initialize: "
                                         "%u\n", result) );
        return;
    }

    if ( http_client_init( &client, WICED_STA_INTERFACE, event_handler, NULL )
            != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ( "Error initializing client http.\n") );
    }

    client_configuration.flag = (http_client_configuration_flags_t)
        (HTTP_CLIENT_CONFIG_FLAG_SERVER_NAME | HTTP_CLIENT_CONFIG_FLAG_MAX_FRAGMENT_LEN);
    client_configuration.server_name = (uint8_t*) SERVER_HOST;
    client_configuration.max_fragment_length = TLS_FRAGMENT_LENGTH_512;

    if (http_client_configure(&client, &client_configuration) != WICED_SUCCESS)
    {
        WPRINT_APP_INFO( ("Error in http_client_configure.\n") );
    }

    /* if you set hostname, library will make sure subject name in the server
     * certificate is matching with host name you are trying to connect.
     * Pass NULL if you don't want to enable this check
     *
     * (uint8_t*)SERVER_HOST or NULL
     */
    client.peer_cn = (uint8_t*)SERVER_HOST;

    WPRINT_APP_INFO( ( "Connecting to: %s\n", SERVER_HOST) );

    if ( ( result = http_client_connect( &client, (const wiced_ip_address_t*)
            &ip_address, SERVER_PORT, HTTP_USE_TLS, CONNECT_TIMEOUT_MS ) )
                            != WICED_SUCCESS )
    {
        WPRINT_APP_INFO( ( "Error: failed to connect to server: %u\n", result) );
        return;
    }

    /* Demonstrates multiple client request handling. If using the wolfSSL
     * examples server, only one request is sent.
     */
    header[0].field        = HTTP_HEADER_HOST;
    header[0].field_length = sizeof( HTTP_HEADER_HOST ) - 1;
    header[0].value        = SERVER_HOST;
    header[0].value_length = sizeof( SERVER_HOST ) - 1;
    http_request_init( &requests[0], &client, HTTP_GET, request_uri, HTTP_1_1);
    http_request_write_header( &requests[0], &header[0], 1 );
    http_request_write_end_header( &requests[0] );
    http_request_flush( &requests[0] );
#ifndef USE_WOLF_SERVER
    header[1].field        = HTTP_HEADER_HOST;
    header[1].field_length = sizeof( HTTP_HEADER_HOST ) - 1;
    header[1].value        = SERVER_HOST;
    header[1].value_length = sizeof( SERVER_HOST ) - 1;
    http_request_init( &requests[1], &client, HTTP_GET, request_uri, HTTP_1_1);
    http_request_write_header( &requests[1], &header[1], 1 );
    http_request_write_end_header( &requests[1] );
    http_request_flush( &requests[1] );
#endif
}

static void event_handler(
        http_client_t* client, http_event_t event, http_response_t* response )
{
    switch( event )
    {
        case HTTP_CONNECTED:
            WPRINT_APP_INFO(( "Connected to %s\n", SERVER_HOST ));
            break;

        case HTTP_DISCONNECTED:
        {
            WPRINT_APP_INFO(( "Disconnected from %s\n", SERVER_HOST ));
            http_request_deinit( &requests[0] );
            http_request_deinit( &requests[1] );
            break;
        }

        case HTTP_DATA_RECEIVED:
        {
            if ( response->request == &requests[0] )
            {
                /* Response to first request. Simply print the result */
                WPRINT_APP_INFO( ( "\nRecieved response for request #1. "
                                        "Content received:\n" ) );

                /* print only HTTP header */
                if(response->response_hdr != NULL)
                {
                    WPRINT_APP_INFO(
                            ("\n HTTP Header Information for response1 : \n" ));
                    print_content( (char*) response->response_hdr,
                                           response->response_hdr_length );
                }

                /* Print payload information that comes as response body */
                WPRINT_APP_INFO( ( "Payload Information for response1 : \n" ) );

                print_content( (char*) response->payload,
                                       response->payload_data_length );

                if(response->remaining_length == 0)
                {
                    WPRINT_APP_INFO(
                            ( "Received total payload data for response1 \n" ) );
                }
            }
            else if ( response->request == &requests[1] )
            {
                /* Response to 2nd request. Simply print the result */
                WPRINT_APP_INFO( ( "\nRecieved response for request #2. "
                                      "Content received:\n" ) );

                /* Response to second request. Parse header for
                 * "Date" and "Content-Length"
                 */
                http_header_field_t header_fields[2];
                uint32_t size =
                        sizeof( header_fields )/sizeof(http_header_field_t);

                /* only process HTTP header when response contains it */
                if(response->response_hdr != NULL)
                {
                    WPRINT_APP_INFO(
                            ("\n HTTP Header Information for response2 : \n" ));
                    print_content( (char*) response->response_hdr,
                                           response->response_hdr_length );

                    header_fields[ 0 ].field        = HTTP_HEADER_DATE;
                    header_fields[ 0 ].field_length = sizeof(
                                                        HTTP_HEADER_DATE ) - 1;
                    header_fields[ 0 ].value        = NULL;
                    header_fields[ 0 ].value_length = 0;
                    header_fields[ 1 ].field        = HTTP_HEADER_CONTENT_LENGTH;
                    header_fields[ 1 ].field_length = sizeof(
                                               HTTP_HEADER_CONTENT_LENGTH ) - 1;
                    header_fields[ 1 ].value        = NULL;
                    header_fields[ 1 ].value_length = 0;

                    if ( http_parse_header( response->response_hdr,
                            response->response_hdr_length, header_fields, size )
                                        == WICED_SUCCESS )
                    {
                        WPRINT_APP_INFO( ( "\nParsing response of request #2 for "
                            "\"Date\" and \"Content-Length\". Fields found:\n"));
                        print_header( header_fields, size );
                    }
                }

                /* Print payload information that comes as response body */
                WPRINT_APP_INFO( ( "Payload Information for response2 : \n" ) );
                print_content( (char*) response->payload,
                                       response->payload_data_length );

                if(response->remaining_length == 0)
                {
                    WPRINT_APP_INFO(
                            ( "Received total payload data for response2 \n" ) );
                }
            }
        break;
        }
        default:
        break;
    }
}

static void print_data( char* data, uint32_t length )
{
    uint32_t a;

    for ( a = 0; a < length; a++ )
    {
        WPRINT_APP_INFO( ( "%c", data[a] ) );
    }
}

static void print_content( char* data, uint32_t length )
{
    WPRINT_APP_INFO(( "==============================================\n" ));
    print_data( (char*)data, length );
    WPRINT_APP_INFO(( "\n==============================================\n" ));
}

static void print_header( http_header_field_t* header_fields,
                                      uint32_t number_of_fields )
{
    uint32_t a;

    WPRINT_APP_INFO(( "==============================================\n" ));
    for ( a = 0; a < 2; a++ )
    {
        print_data( header_fields[a].field, header_fields[a].field_length );
        WPRINT_APP_INFO(( " : " ));
        print_data( header_fields[a].value, header_fields[a].value_length );
        WPRINT_APP_INFO(( "\n" ));
    }
    WPRINT_APP_INFO(( "==============================================\n" ));
}
