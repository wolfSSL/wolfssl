/* wolfssl_server.ino
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
Tested with:

1) Intel Galileo acting as the Client, with a laptop acting as a server using
   the server example provided in examples/server.
   Legacy Arduino v1.86 was used to compile and program the Galileo

2) Espressif ESP32 WiFi

3) Arduino Due, Nano33 IoT, Nano RP-2040
*/

/*
 * Note to code editors: the Arduino client and server examples are edited in
 * parallel for side-by-side comparison between examples.
 */

/* If you have a private include, define it here, otherwise edit WiFi params */
#define MY_PRIVATE_CONFIG "/workspace/my_private_config.h"

/* set REPEAT_CONNECTION to a non-zero value to continually run the example. */
#define REPEAT_CONNECTION 1

/* Edit this with your other TLS host server address to connect to: */
/* #define WOLFSSL_TLS_SERVER_HOST "192.168.1.34" */

/* wolfssl TLS examples communicate on port 11111 */
#define WOLFSSL_PORT 11111

/* Choose a monitor serial baud rate: 9600, 14400, 19200, 57600, 74880, etc. */
#define SERIAL_BAUD 115200

/* We'll wait up to 2000 milliseconds to properly shut down connection */
#define SHUTDOWN_DELAY_MS 2000

/* Number of times to retry connection.  */
#define RECONNECT_ATTEMPTS 20

/* Optional stress test. Define to consume memory until exhausted: */
/* #define MEMORY_STRESS_TEST */

/* Choose client or server example, not both. */
/* #define WOLFSSL_CLIENT_EXAMPLE */
#define WOLFSSL_SERVER_EXAMPLE

#if defined(MY_PRIVATE_CONFIG)
    /* the /workspace directory may contain a private config
     * excluded from GitHub with items such as WiFi passwords */
    #include MY_PRIVATE_CONFIG
    static const char* ssid PROGMEM = MY_ARDUINO_WIFI_SSID;
    static const char* password PROGMEM = MY_ARDUINO_WIFI_PASSWORD;
#else
    /* when using WiFi capable boards: */
    static const char* ssid PROGMEM  = "your_SSID";
    static const char* password PROGMEM = "your_PASSWORD";
#endif

#define BROADCAST_ADDRESS "255.255.255.255"

/* There's an optional 3rd party NTPClient library by Fabrice Weinberg.
 * If it is installed, uncomment define USE_NTP_LIB here: */
/* #define USE_NTP_LIB */
#ifdef USE_NTP_LIB
    #include <NTPClient.h>
#endif

#include <wolfssl.h>
/* Important: make sure settings.h appears before any other wolfSSL headers */
#include <wolfssl/wolfcrypt/settings.h>
/* Reminder: settings.h includes user_settings.h
 * For ALL project wolfSSL settings, see:
 * [your path]/Arduino\libraries\wolfSSL\src\user_settings.h   */
#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Define DEBUG_WOLFSSL in user_settings.h for more verbose logging. */
#if defined(DEBUG_WOLFSSL)
    #define PROGRESS_DOT F("")
#else
    #define PROGRESS_DOT F(".")
#endif

/* Convert a macro to a string */
#define xstr(x) str(x)
#define str(x) #x

/* optional board-specific networking includes */
#if defined(ESP32)
    #define USING_WIFI
    #include <WiFi.h>
    #include <WiFiUdp.h>
    #ifdef USE_NTP_LIB
        WiFiUDP ntpUDP;
    #endif
    /* Ensure the F() flash macro is defined */
    #ifndef F
        #define F
    #endif
    WiFiClient client;
    WiFiServer server(WOLFSSL_PORT);
#elif defined(ESP8266)
    #define USING_WIFI
    #include <ESP8266WiFi.h>
    WiFiClient client;
    WiFiServer server(WOLFSSL_PORT);
#elif defined(ARDUINO_SAM_DUE)
    #include <SPI.h>
    /* There's no WiFi/Ethernet on the Due. Requires Ethernet Shield.
    /* Needs "Ethernet by Various" library to be installed. Tested with V2.0.2 */
    #include <Ethernet.h>
    EthernetClient client;
    EthernetClient server(WOLFSSL_PORT);
#elif defined(ARDUINO_SAMD_NANO_33_IOT)
    #define USING_WIFI
    #include <SPI.h>
    #include <WiFiNINA.h> /* Needs Arduino WiFiNINA library installed manually */
    WiFiClient client;
    WiFiServer server(WOLFSSL_PORT);
#elif defined(ARDUINO_ARCH_RP2040)
    #define USING_WIFI
    #include <SPI.h>
    #include <WiFiNINA.h>
    WiFiClient client;
    WiFiServer server(WOLFSSL_PORT);
#elif defined(USING_WIFI)
    #define USING_WIFI
    #include <WiFi.h>
    #include <WiFiUdp.h>
    #ifdef USE_NTP_LIB
        WiFiUDP ntpUDP;
    #endif
    WiFiClient client;
    WiFiServer server(WOLFSSL_PORT);
/* TODO
#elif defined(OTHER_BOARD)
*/
#else
    #define USING_WIFI
    WiFiClient client;
    WiFiServer server(WOLFSSL_PORT);
#endif

/* Only for syntax highlighters to show interesting options enabled: */
#if defined(HAVE_SNI)                           \
   || defined(HAVE_MAX_FRAGMENT)                  \
   || defined(HAVE_TRUSTED_CA)                    \
   || defined(HAVE_TRUNCATED_HMAC)                \
   || defined(HAVE_CERTIFICATE_STATUS_REQUEST)    \
   || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) \
   || defined(HAVE_SUPPORTED_CURVES)              \
   || defined(HAVE_ALPN)                          \
   || defined(HAVE_SESSION_TICKET)                \
   || defined(HAVE_SECURE_RENEGOTIATION)          \
   || defined(HAVE_SERVER_RENEGOTIATION_INFO)
#endif


/* we expect our IP address from DHCP */

static WOLFSSL_CTX* ctx = NULL;
static WOLFSSL* ssl = NULL;
static char* wc_error_message = (char*)malloc(80 + 1);
static char errBuf[80];

#if defined(MEMORY_STRESS_TEST)
    #define MEMORY_STRESS_ITERATIONS 100
    #define MEMORY_STRESS_BLOCK_SIZE 1024
    #define MEMORY_STRESS_INITIAL (4*1024)
    static char* memory_stress[MEMORY_STRESS_ITERATIONS]; /* typically 1K per item */
    static int mem_ctr        = 0;
#endif

static int EthernetSend(WOLFSSL* ssl, char* msg, int sz, void* ctx);
static int EthernetReceive(WOLFSSL* ssl, char* reply, int sz, void* ctx);
static int reconnect = RECONNECT_ATTEMPTS;
static int lng_index PROGMEM = 0; /* 0 = English */

#if defined(__arm__)
    #include <malloc.h>
    extern char _end;
    extern "C" char *sbrk(int i);
    static char *ramstart=(char *)0x20070000;
    static char *ramend=(char *)0x20088000;
#endif

/*****************************************************************************/
/* fail_wait - in case of unrecoverable error                                */
/*****************************************************************************/
int fail_wait(void) {
    show_memory();

    Serial.println(F("Failed. Halt."));
    while (1) {
        delay(1000);
    }
    return 0;
}

/*****************************************************************************/
/* show_memory() to optionally view during debugging.                         */
/*****************************************************************************/
int show_memory(void)
{
#if defined(__arm__)
    struct mallinfo mi = mallinfo();

    char *heapend=sbrk(0);
    register char * stack_ptr asm("sp");
    #if defined(DEBUG_WOLFSSL_VERBOSE)
        Serial.print("    arena=");
        Serial.println(mi.arena);
        Serial.print("  ordblks=");
        Serial.println(mi.ordblks);
        Serial.print(" uordblks=");
        Serial.println(mi.uordblks);
        Serial.print(" fordblks=");
        Serial.println(mi.fordblks);
        Serial.print(" keepcost=");
        Serial.println(mi.keepcost);
    #endif

    #if defined(DEBUG_WOLFSSL) || defined(MEMORY_STRESS_TEST)
        Serial.print("Estimated free memory: ");
        Serial.print(stack_ptr - heapend + mi.fordblks);
        Serial.println(F(" bytes"));
    #endif

    #if (0)
        /* Experimental: not supported on all devices: */
        Serial.print("RAM Start %lx\n", (unsigned long)ramstart);
        Serial.print("Data/Bss end %lx\n", (unsigned long)&_end);
        Serial.print("Heap End %lx\n", (unsigned long)heapend);
        Serial.print("Stack Ptr %lx\n",(unsigned long)stack_ptr);
        Serial.print("RAM End %lx\n", (unsigned long)ramend);

        Serial.print("Heap RAM Used: ",mi.uordblks);
        Serial.print("Program RAM Used ",&_end - ramstart);
        Serial.print("Stack RAM Used ",ramend - stack_ptr);

        Serial.print("Estimated Free RAM: %d\n\n",stack_ptr - heapend + mi.fordblks);
    #endif
#else
    Serial.println(F("show_memory() not implemented for this platform"));
#endif
    return 0;
}

/*****************************************************************************/
/* EthernetSend() to send a message string.                                  */
/*****************************************************************************/
int EthernetSend(WOLFSSL* ssl, char* message, int sz, void* ctx) {
    int sent = 0;
    (void)ssl;
    (void)ctx;

    sent = client.write((byte*)message, sz);
    return sent;
}

/*****************************************************************************/
/* EthernetReceive() to receive a reply string.                              */
/*****************************************************************************/
int EthernetReceive(WOLFSSL* ssl, char* reply, int sz, void* ctx) {
    int ret = 0;
    (void)ssl;
    (void)ctx;

    while (client.available() > 0 && ret < sz) {
        reply[ret++] = client.read();
    }
    return ret;
}

/*****************************************************************************/
/* Arduino setup_hardware()                                                  */
/*****************************************************************************/
int setup_hardware(void) {
    int ret = 0;

#if defined(ARDUINO_SAMD_NANO_33_IOT)
    Serial.println(F("Detected known tested and working Arduino Nano 33 IoT"));
#elif defined(ARDUINO_ARCH_RP2040)
    Serial.println(F("Detected known tested and working Arduino RP-2040"));
#elif defined(__arm__) && defined(ID_TRNG) && defined(TRNG)
    /* need to manually turn on random number generator on Arduino Due, etc. */
    pmc_enable_periph_clk(ID_TRNG);
    trng_enable(TRNG);
    Serial.println(F("Enabled ARM TRNG"));
#endif

    show_memory();
    randomSeed(analogRead(0));
    return ret;
}

/*****************************************************************************/
/* Arduino setup_datetime()                                                  */
/*   The device needs to have a valid date within the valid range of certs.  */
/*****************************************************************************/
int setup_datetime(void) {
    int ret = 0;
    int ntp_tries = 20;

    /* we need a date in the range of cert expiration */
#ifdef USE_NTP_LIB
    #if defined(ESP32)
        NTPClient timeClient(ntpUDP, "pool.ntp.org");

        timeClient.begin();
        timeClient.update();
        delay(1000);
        while (!timeClient.isTimeSet() && (ntp_tries > 0)) {
            timeClient.forceUpdate();
            Serial.println(F("Waiting for NTP update"));
            delay(2000);
            ntp_tries--;
        }
        if (ntp_tries <= 0) {
            Serial.println(F("Warning: gave up waiting on NTP"));
        }
        Serial.println(timeClient.getFormattedTime());
        Serial.println(timeClient.getEpochTime());
    #endif
#endif

#if defined(ESP32)
    /* see esp32-hal-time.c */
    ntp_tries = 5;
    /* Replace "pool.ntp.org" with your preferred NTP server */
    configTime(0, 0, "pool.ntp.org");

    /* Wait for time to be set */
    while ((time(nullptr) <= 100000) && ntp_tries > 0) {
        Serial.println(F("Waiting for time to be set..."));
        delay(2000);
        ntp_tries--;
    }
#endif

    return ret;
} /* setup_datetime */

/*****************************************************************************/
/* Arduino setup_network()                                                   */
/*****************************************************************************/
int setup_network(void) {
    int ret = 0;

#if defined(USING_WIFI)
    int status = WL_IDLE_STATUS;

    /* The ESP8266 & ESP32 support both AP and STA. We'll use STA: */
    #if defined(ESP8266) || defined(ESP32)
        WiFi.mode(WIFI_STA);
    #else
        String fv;
        if (WiFi.status() == WL_NO_MODULE) {
            Serial.println("Communication with WiFi module failed!");
            /* don't continue if no network */
            while (true) ;
        }

        fv = WiFi.firmwareVersion();
        if (fv < WIFI_FIRMWARE_LATEST_VERSION) {
            Serial.println("Please upgrade the firmware");
        }
    #endif

    Serial.print(F("Connecting to WiFi "));
    Serial.print(ssid);
    status = WiFi.begin(ssid, password);
    while (status != WL_CONNECTED) {
        delay(1000);
        Serial.print(F("."));
        Serial.print(status);
        status = WiFi.status();
    }

    Serial.println(F(" Connected!"));
#else
    /* Newer Ethernet shields have a
     * MAC address printed on a sticker on the shield */
    byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
    IPAddress ip(192, 168, 1, 42);
    IPAddress myDns(192, 168, 1, 1);
    Ethernet.init(10); /* Most Arduino shields */
    /* Ethernet.init(5);   * MKR ETH Shield */
    /* Ethernet.init(0);   * Teensy 2.0 */
    /* Ethernet.init(20);  * Teensy++ 2.0 */
    /* Ethernet.init(15);  * ESP8266 with Adafruit FeatherWing Ethernet */
    /* Ethernet.init(33);  * ESP32 with Adafruit FeatherWing Ethernet */
    Serial.println(F("Initialize Ethernet with DHCP:"));
    if (Ethernet.begin(mac) == 0) {
        Serial.println(F("Failed to configure Ethernet using DHCP"));
        /* Check for Ethernet hardware present */
        if (Ethernet.hardwareStatus() == EthernetNoHardware) {
            Serial.println(F("Ethernet shield was not found."));
            while (true) {
                delay(1); /* do nothing */
            }
        }
        if (Ethernet.linkStatus() == LinkOFF) {
            Serial.println(F("Ethernet cable is not connected."));
        }
        /* try to configure using IP address instead of DHCP : */
        Ethernet.begin(mac, ip, myDns);
    }
    else {
        Serial.print(F("  DHCP assigned IP "));
        Serial.println(Ethernet.localIP());
    }
    /* We'll assume the Ethernet connection is ready to go. */
#endif

    Serial.println(F("********************************************************"));
    Serial.print(F("      wolfSSL Example Server IP = "));
#if defined(USING_WIFI)
    Serial.println(WiFi.localIP());
#else
    Serial.println(Ethernet.localIP());
#endif
    /* In server mode, there's no host definition. */
    /* See companion example: wolfssl_client.ino */
    Serial.println(F("********************************************************"));
    Serial.println(F("Setup network complete."));

    return ret;
}

/*****************************************************************************/
/* Arduino setup_wolfssl()                                                   */
/*****************************************************************************/
int setup_wolfssl(void) {
    int ret = 0;
    WOLFSSL_METHOD* method;

    /* Show a revision of wolfssl user_settings.h file in use when available: */
#if defined(WOLFSSL_USER_SETTINGS_ID)
    Serial.print(F("WOLFSSL_USER_SETTINGS_ID: "));
    Serial.println(F(WOLFSSL_USER_SETTINGS_ID));
#else
    Serial.println(F("No WOLFSSL_USER_SETTINGS_ID found."));
#endif

#if defined(NO_WOLFSSL_SERVER)
    Serial.println(F("wolfSSL server code disabled to save space."));
#endif
#if defined(NO_WOLFSSL_CLIENT)
    Serial.println(F("wolfSSL client code disabled to save space."));
#endif

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
    Serial.println(F("wolfSSL Debugging is On!"));
#else
    Serial.println(F("wolfSSL Debugging is Off! (enable with DEBUG_WOLFSSL)"));
#endif

    /* See ssl.c for TLS cache settings. Larger cache = use more RAM. */
#if defined(NO_SESSION_CACHE)
    Serial.println(F("wolfSSL TLS NO_SESSION_CACHE"));
#elif defined(MICRO_SESSION_CACHEx)
    Serial.println(F("wolfSSL TLS MICRO_SESSION_CACHE"));
#elif defined(SMALL_SESSION_CACHE)
    Serial.println(F("wolfSSL TLS SMALL_SESSION_CACHE"));
#elif defined(MEDIUM_SESSION_CACHE)
    Serial.println(F("wolfSSL TLS MEDIUM_SESSION_CACHE"));
#elif defined(BIG_SESSION_CACHE)
    Serial.println(F("wolfSSL TLS BIG_SESSION_CACHE"));
#elif defined(HUGE_SESSION_CACHE)
    Serial.println(F("wolfSSL TLS HUGE_SESSION_CACHE"));
#elif defined(HUGE_SESSION_CACHE)
    Serial.println(F("wolfSSL TLS HUGE_SESSION_CACHE"));
#else
    Serial.println(F("WARNING: Unknown or no TLS session cache setting."));
    /* See wolfssl/src/ssl.c for amount of memory used.
     * It is best on embedded devices to choose a TLS session cache size. */
#endif

    ret = wolfSSL_Init();
    if (ret == WOLFSSL_SUCCESS) {
        Serial.println("Successfully called wolfSSL_Init");
    }
    else {
        Serial.println("ERROR: wolfSSL_Init failed");
    }

    /* See companion server example with wolfSSLv23_server_method here.
     * method = wolfSSLv23_client_method());   SSL 3.0 - TLS 1.3.
     * method = wolfTLSv1_2_client_method();   only TLS 1.2
     * method = wolfTLSv1_3_client_method();   only TLS 1.3
     *
     * see Arduino\libraries\wolfssl\src\user_settings.h */

    Serial.println("Here we go!");

    method = wolfSSLv23_server_method();
    if (method == NULL) {
        Serial.println(F("unable to get wolfssl server method"));
        fail_wait();
    }
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        Serial.println(F("unable to get ctx"));
        fail_wait();
    }

    return ret;
}

/*****************************************************************************/
/* Arduino setup_certificates()                                              */
/*****************************************************************************/
int setup_certificates(void) {
    int ret = 0;

    Serial.println(F("Initializing certificates..."));
    show_memory();

    /* Use built-in validation, No verification callback function: */
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    /* Certificate */
    Serial.println("Initializing certificates...");
    ret = wolfSSL_CTX_use_certificate_buffer(ctx,
                                             CTX_SERVER_CERT,
                                             CTX_SERVER_CERT_SIZE,
                                             CTX_CA_CERT_TYPE);
    if (ret == WOLFSSL_SUCCESS) {
        Serial.print("Success: use certificate: ");
        Serial.println(xstr(CTX_SERVER_CERT));
    }
    else {
        Serial.print("Error: wolfSSL_CTX_use_certificate_buffer failed: ");
        wc_ErrorString(ret, wc_error_message);
        Serial.println(wc_error_message);
        fail_wait();
    }

    /* Setup private server key */
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                                            CTX_SERVER_KEY,
                                            CTX_SERVER_KEY_SIZE,
                                            CTX_SERVER_KEY_TYPE);
    if (ret == WOLFSSL_SUCCESS) {
        Serial.print("Success: use private key buffer: ");
        Serial.println(xstr(CTX_SERVER_KEY));
    }
    else {
        Serial.print("Error: wolfSSL_CTX_use_PrivateKey_buffer failed: ");
        wc_ErrorString(ret, wc_error_message);
        Serial.println(wc_error_message);
        fail_wait();
    }

    return ret;
} /* Arduino setup */

/*****************************************************************************/
/*****************************************************************************/
/* Arduino setup()                                                           */
/*****************************************************************************/
/*****************************************************************************/
void setup(void) {
    int i = 0;
    Serial.begin(SERIAL_BAUD);
    while (!Serial && (i < 10)) {
        /* wait for serial port to connect. Needed for native USB port only */
        delay(1000);
        i++;
    }

    Serial.println(F(""));
    Serial.println(F(""));
    Serial.println(F("wolfSSL TLS Server Example Startup."));

    /* define DEBUG_WOLFSSL in wolfSSL user_settings.h for diagnostics */
#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

    /* Optionally pre-allocate a large block of memory for testing */
#if defined(MEMORY_STRESS_TEST)
    Serial.println(F("WARNING: Memory Stress Test Active!"));
    Serial.print(F("Allocating extra memory: "));
    Serial.print(MEMORY_STRESS_INITIAL);
    Serial.println(F(" bytes..."));
    memory_stress[mem_ctr] = (char*)malloc(MEMORY_STRESS_INITIAL);
    show_memory();
#endif

    setup_hardware();

    setup_network();

    setup_datetime();

    setup_wolfssl();

    setup_certificates();

    /* Initialize wolfSSL using callback functions. */
    wolfSSL_SetIOSend(ctx, EthernetSend);
    wolfSSL_SetIORecv(ctx, EthernetReceive);

#if defined THIS_USER_SETTINGS_VERSION
    Serial.print(F("This user_settings.h version:"))
    Serial.println(THIS_USER_SETTINGS_VERSION)
#endif

    /* Start the server
     * See https://www.arduino.cc/reference/en/libraries/ethernet/server.begin/
     */

    Serial.println(F("Completed Arduino setup()"));

    server.begin();
    Serial.println("Begin Server... (waiting for remote client to connect)");

    /* See companion wolfssl_client.ino code */
    return;
} /* Arduino setup */

/*****************************************************************************/
/* wolfSSL error_check()                                                     */
/*****************************************************************************/
int error_check(int this_ret, bool halt_on_error,
                      const __FlashStringHelper* message) {
    int ret = 0;
    if (this_ret == WOLFSSL_SUCCESS) {
        Serial.print(F("Success: "));
        Serial.println(message);
    }
    else {
        Serial.print(F("ERROR: return = "));
        Serial.print(this_ret);
        Serial.print(F(": "));
        Serial.println(message);
        Serial.println(wc_GetErrorString(this_ret));
        if (halt_on_error) {
            fail_wait();
        }
    }
    show_memory();

    return ret;
} /* error_check */

/*****************************************************************************/
/* wolfSSL error_check_ssl                                                   */
/*   Parameters:                                                             */
/*     ssl           is the current WOLFSSL object pointer                   */
/*     halt_on_error set to true to suspend operations for critical error    */
/*     message       is expected to be a memory-efficient F("") macro string */
/*****************************************************************************/
int error_check_ssl(WOLFSSL* ssl, int this_ret, bool halt_on_error,
                           const __FlashStringHelper* message) {
    int err = 0;

    if (ssl == NULL) {
        Serial.println(F("ssl is Null; Unable to allocate SSL object?"));
#ifndef DEBUG_WOLFSSL
        Serial.println(F("Define DEBUG_WOLFSSL in user_settings.h for more."));
#else
        Serial.println(F("See wolfssl/wolfcrypt/error-crypt.h for codes."));
#endif
        Serial.print(F("ERROR: "));
        Serial.println(message);
        show_memory();
        if (halt_on_error) {
            fail_wait();
        }
    }
    else {
        err = wolfSSL_get_error(ssl, this_ret);
        if (err == WOLFSSL_SUCCESS) {
            Serial.print(F("Success m: "));
            Serial.println(message);
        }
        else {
            if (err < 0) {
                wolfSSL_ERR_error_string(err, errBuf);
                Serial.print(F("WOLFSSL Error: "));
                Serial.print(err);
                Serial.print(F("; "));
                Serial.println(errBuf);
            }
            else {
                Serial.println(F("Success: ssl object."));
            }
        }
    }

    return err;
}

/*****************************************************************************/
/*****************************************************************************/
/* Arduino loop()                                                            */
/*****************************************************************************/
/*****************************************************************************/
void loop() {
    char errBuf[80]    = "(no error";
    char reply[80]     = "(no reply)";
    const char msg[]   = "I hear you fa shizzle!";
    const char* cipherName;
    int input          = 0;
    int replySz        = 0;
    int retry_shutdown = SHUTDOWN_DELAY_MS; /* max try, once per millisecond */
    int ret            = 0;
    IPAddress broadcast_address(255, 255, 255, 255);

    /* Listen for incoming client requests. */
    client = server.available();
    if (client)  {
       Serial.println("Have Client");
       while (!client.connected()) {
           /* wait for the client to actually connect */
           delay(10);
       }
        Serial.print("Client connected from remote IP: ");
        Serial.println(client.remoteIP());

        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            Serial.println("Unable to allocate SSL object");
            fail_wait();
        }

        ret = wolfSSL_accept(ssl);
        if (ret != WOLFSSL_SUCCESS) {
            ret = wolfSSL_get_error(ssl, 0);
            wolfSSL_ERR_error_string(ret, errBuf);
            Serial.print("TLS Accept Error: ");
            Serial.println(errBuf);
        }

        cipherName = wolfSSL_get_cipher(ssl);
        Serial.print("SSL cipher suite is ");
        Serial.println(cipherName);

        Serial.print("Server Read: ");
        while (!client.available()) {
            /* wait for data */
        }

        /* read data */
        while (wolfSSL_pending(ssl)) {
            input = wolfSSL_read(ssl, reply, sizeof(reply) - 1);
            if (input < 0) {
                ret = wolfSSL_get_error(ssl, 0);
                wolfSSL_ERR_error_string(ret, errBuf);
                Serial.print("TLS Read Error: ");
                Serial.println(errBuf);
                break;
            }
            else if (input > 0) {
                replySz = input;
                reply[input] = '\0';
                Serial.print(reply);
            }
            else {
                Serial.println("<end of reply, input == 0>");
            }
        }

        /* Write our message into reply buffer to send */
        memset(reply, 0, sizeof(reply));
        memcpy(reply, msg, sizeof(msg));
        replySz = strnlen(reply, sizeof(reply));

        Serial.println("Sending reply...");
        if ((wolfSSL_write(ssl, reply, replySz)) != replySz) {
            ret = wolfSSL_get_error(ssl, 0);
            wolfSSL_ERR_error_string(ret, errBuf);
            Serial.print("TLS Write Error: ");
            Serial.println(errBuf);
        }
        else {
            Serial.println("Reply sent!");
        }

        Serial.println("Shutdown!");
        do {
            delay(1);
            retry_shutdown--;
            ret = wolfSSL_shutdown(ssl);
        } while ((ret == WOLFSSL_SHUTDOWN_NOT_DONE) && (retry_shutdown > 0));

        if (retry_shutdown <= 0) {
            /* if wolfSSL_free is called before properly shutting down the
             * ssl object, undesired results may occur. */
            Serial.println("Warning! Shutdown did not properly complete.");
        }

        wolfSSL_free(ssl);
        Serial.println("Connection complete.");
        if (REPEAT_CONNECTION) {
            Serial.println();
            Serial.println("Waiting for next connection.");
        }
        else {
            client.stop();
            Serial.println("Done!");
            while (1) {
                /* wait forever if not repeating */
                delay(100);
            }
        }
    }
    else {
        /* Serial.println("Client not connected. Trying again..."); */
    }

    delay(100);
} /* Arduino loop repeats */
