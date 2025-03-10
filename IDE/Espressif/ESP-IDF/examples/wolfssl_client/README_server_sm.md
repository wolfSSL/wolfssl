# SM Cipher Notes


### Install SM
```
cd /mnt/c/workspace/wolfsm-$USER
./install.sh ../wolfssl-$USER
```


### Build Linux SM Examples
```
./autogen.sh
./configure --enable-sm3 --enable-sm4-gcm --enable-sm2         \
            --enable-sm4-ecb --enable-sm4-cbc --enable-sm4-ctr \
            --enable-sm4-gcm --enable-sm4-ccm
make clean && make
```

### TLS 1.3 Server

```
./examples/server/server -v 4 -b -d -p 11111 -c ./certs/sm2/server-sm2.pem -k ./certs/sm2/server-sm2-priv.pem -A ./certs/sm2/client-sm2.pem -V
```

### TLS 1.3 Client

```
./examples/client/client  -h 127.0.0.1 -v 4 -l TLS13-SM4-CCM-SM3 -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem -A ./certs/sm2/root-sm2.pem -C
```

### TLS 1.2 Client to Local Linux Server

```
./examples/client/client  -h 192.168.25.186 -v 3 -l ECDHE-ECDSA-SM4-CBC-SM3  \
                      -c ./certs/sm2/client-sm2.pem                 \
                      -k ./certs/sm2/client-sm2-priv.pem            \
                      -A ./certs/sm2/root-sm2.pem -C
```

###  TLS 1.2 Client to ESP32 Server

```
./examples/client/client  -h 192.168.25.186 -v 3 -l ECDHE-ECDSA-SM4-CBC-SM3  \
                      -c ./certs/sm2/client-sm2.pem                 \
                      -k ./certs/sm2/client-sm2-priv.pem            \
                      -A ./certs/sm2/root-sm2.pem -C
```
### Others...

```
# Success: Linux Client to ESP32 Server TLS1.2
./examples/client/client  -h 192.168.1.113 -v 3 -l ECDHE-ECDSA-SM4-CBC-SM3 -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem -A ./certs/sm2/root-sm2.pem -C
./examples/client/client  -h 192.168.1.113 -v 3 -l ECDHE-ECDSA-SM4-GCM-SM3 -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem -A ./certs/sm2/root-sm2.pem -C
./examples/client/client  -h 192.168.1.113 -v 3 -l ECDHE-ECDSA-SM4-CCM-SM3 -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem -A ./certs/sm2/root-sm2.pem -C

# Success: Linux Client to ESP32 Server TLS1.3

# Reported as TLS_SM4_GCM_SM3, but parameter is TLS13-SM4-GCM-SM3
./examples/client/client  -h 192.168.1.113 -v 4 -l TLS13-SM4-GCM-SM3 -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem -A ./certs/sm2/root-sm2.pem -C

# Reported as TLS-SM4-CCM-SM3, but parameter is TLS13-SM4-CCM-SM3
./examples/client/client  -h 192.168.1.113 -v 4 -l TLS13-SM4-CCM-SM3 -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem -A ./certs/sm2/root-sm2.pem -C

./examples/client/client  -h 192.168.1.113 -v 4 -l TLS13-SM4-CBC-SM3 -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem -A ./certs/sm2/root-sm2.pem -C

```

```
ESP32-to-ESP32
TLS_ECDHE_ECDSA_WITH_SM4_CBC_SM3
TLS_ECDHE_ECDSA_WITH_SM4_GCM_SM3
TLS_ECDHE_ECDSA_WITH_SM4_CCM_SM3
```

Tried both PEM and DER format.

The latest server is PEM format, triple-checked to have the embedded server
be the same as the Linux server files.


|  Usage |            Certificate             |        Key                          |   Certificate Authority file, default ./certs/client-cert.pem |
| -----  | ---------------------------------- | ----------------------------------- | --------------------------------- |
| server | -c ./certs/sm2/server-sm2.pem      | -k ./certs/sm2/server-sm2-priv.pem  | -A ./certs/sm2/client-sm2.pem -V  |
| client | -c ./certs/sm2/client-sm2.pem      | -k ./certs/sm2/client-sm2-priv.pem  | -A ./certs/sm2/root-sm2.pem -C    |
| emdedded:
| server | wolfSSL_CTX_use_certificate_buffer<br/> server_sm2 | wolfSSL_CTX_use_PrivateKey_buffer<br/> server_sm2_priv | wolfSSL_CTX_load_verify_buffer<br/> client-sm2  |

### Code

See [source code](https://github.com/gojimmypi/wolfssl/blob/2c4f443aec7b151f945cb9dfe2dad6ee30449cf0/IDE/Espressif/ESP-IDF/examples/wolfssl_server/main/server-tls.c#L187):

![code](./code.png)


### Linux client talking to embedded server:

```
/examples/client/client  -h 192.168.1.108 -v 3 -l ECDHE-ECDSA-SM4-CBC-SM3  -c ./certs/sm2/client-sm2.pem -k ./certs/sm2/client-sm2-priv.pem     -A ./certs/sm2/root-sm2.pem -C
wolfSSL_connect error -188, ASN no signer error to confirm failure
wolfSSL error: wolfSSL_connect failed
```

Output:
```
ets Jul 29 2019 12:21:46

rst:0x3 (SW_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)
configsip: 0, SPIWP:0xee
clk_drv:0x00,q_drv:0x00,d_drv:0x00,cs0_drv:0x00,hd_drv:0x00,wp_drv:0x00
mode:DIO, clock div:2
load:0x3fff0030,len:7000
load:0x40078000,len:15452
ho 0 tail 12 room 4
load:0x40080400,len:3840
entry 0x4008064c
I (29) boot: ESP-IDF v5.0-dirty 2nd stage bootloader
I (29) boot: compile time 13:40:31
I (29) boot: chip revision: v3.0
I (32) boot_comm: chip revision: 3, min. bootloader chip revision: 0
I (39) boot.esp32: SPI Speed      : 40MHz
I (44) boot.esp32: SPI Mode       : DIO
I (48) boot.esp32: SPI Flash Size : 2MB
I (53) boot: Enabling RNG early entropy source...
I (58) boot: Partition Table:
I (62) boot: ## Label            Usage          Type ST Offset   Length
I (69) boot:  0 nvs              WiFi data        01 02 00009000 00006000
I (77) boot:  1 phy_init         RF data          01 01 0000f000 00001000
I (84) boot:  2 factory          factory app      00 00 00010000 00177000
I (92) boot: End of partition table
I (96) boot_comm: chip revision: 3, min. application chip revision: 0
I (103) esp_image: segment 0: paddr=00010020 vaddr=3f400020 size=338d8h (211160) map
I (188) esp_image: segment 1: paddr=00043900 vaddr=3ffb0000 size=03b78h ( 15224) load
I (194) esp_image: segment 2: paddr=00047480 vaddr=40080000 size=08b98h ( 35736) load
I (209) esp_image: segment 3: paddr=00050020 vaddr=400d0020 size=c591ch (809244) map
I (501) esp_image: segment 4: paddr=00115944 vaddr=40088b98 size=0c230h ( 49712) load
I (522) esp_image: segment 5: paddr=00121b7c vaddr=50000000 size=00010h (    16) load
I (533) boot: Loaded app from partition at offset 0x10000
I (533) boot: Disabling RNG early entropy source...
I (545) cpu_start: Pro cpu up.
I (545) cpu_start: Starting app cpu, entry point is 0x400812f4
I (532) cpu_start: App cpu up.
I (561) cpu_start: Pro cpu start user code
I (561) cpu_start: cpu freq: 160000000 Hz
I (561) cpu_start: Application information:
I (566) cpu_start: Project name:     wolfssl_server
I (571) cpu_start: App version:      v5.6.3-stable-1088-g560c84b2b-d
I (578) cpu_start: Compile time:     Jul 19 2023 22:20:09
I (585) cpu_start: ELF file SHA256:  3e6e571c9e87bf44...
I (591) cpu_start: ESP-IDF:          v5.0-dirty
I (596) heap_init: Initializing. RAM available for dynamic allocation:
I (603) heap_init: At 3FFAE6E0 len 00001920 (6 KiB): DRAM
I (609) heap_init: At 3FFBDA68 len 00022598 (137 KiB): DRAM
I (615) heap_init: At 3FFE0440 len 00003AE0 (14 KiB): D/IRAM
I (622) heap_init: At 3FFE4350 len 0001BCB0 (111 KiB): D/IRAM
I (628) heap_init: At 40094DC8 len 0000B238 (44 KiB): IRAM
I (636) spi_flash: detected chip: generic
I (639) spi_flash: flash io: dio
W (643) spi_flash: Detected size(4096k) larger than the size in the binary image header(2048k). Using the
size in the binary image header.
I (657) cpu_start: Starting scheduler on PRO CPU.
I (0) cpu_start: Starting scheduler on APP CPU.
I (725) tls_server: ESP_WIFI_MODE_STA
I (735) wifi:wifi driver task: 3ffcb738, prio:23, stack:6656, core=0
I (735) system_api: Base MAC address is not set
I (735) system_api: read default base MAC address from EFUSE
I (755) wifi:wifi firmware version: 0d470ef
I (755) wifi:wifi certification version: v7.0
I (755) wifi:config NVS flash: enabled
I (755) wifi:config nano formatting: disabled
I (755) wifi:Init data frame dynamic rx buffer num: 32
I (765) wifi:Init management frame dynamic rx buffer num: 32
I (765) wifi:Init management short buffer num: 32
I (775) wifi:Init dynamic tx buffer num: 32
I (775) wifi:Init static rx buffer size: 1600
I (775) wifi:Init static rx buffer num: 10
I (785) wifi:Init dynamic rx buffer num: 32
I (785) wifi_init: rx ba win: 6
I (795) wifi_init: tcpip mbox: 32
I (795) wifi_init: udp mbox: 6
I (795) wifi_init: tcp mbox: 6
I (805) wifi_init: tcp tx win: 5744
I (805) wifi_init: tcp rx win: 5744
I (815) wifi_init: tcp mss: 1440
I (815) wifi_init: WiFi IRAM OP enabled
I (815) wifi_init: WiFi RX IRAM OP enabled
I (825) phy_init: phy_version 4670,719f9f6,Feb 18 2021,17:07:07
I (925) wifi:mode : sta (24:d7:eb:41:7b:68)
I (935) wifi:enable tsf
I (935) tls_server: wifi_init_sta finished.
I (945) wifi:new:<4,0>, old:<1,0>, ap:<255,255>, sta:<4,0>, prof:1
I (945) wifi:state: init -> auth (b0)
I (945) wifi:state: auth -> assoc (0)
I (955) wifi:state: assoc -> run (10)
W (955) wifi:<ba-add>idx:0 (ifx:0, c8:d7:19:cd:00:17), tid:0, ssn:0, winSize:64
I (985) wifi:connected with testbench, aid = 1, channel 4, BW20, bssid = c8:d7:19:cd:00:17
I (985) wifi:security: WPA2-PSK, phy: bgn, rssi: -45
I (995) wifi:pm start, type: 1

I (1065) wifi:AP's beacon interval = 102400 us, DTIM period = 1
I (3225) esp_netif_handlers: sta ip: 192.168.1.108, mask: 255.255.255.0, gw: 192.168.1.10
I (3225) tls_server: got ip:192.168.1.108
I (3235) Time Helper: sntp_setservername:
I (3235) Time Helper: pool.ntp.org
I (3245) Time Helper: time.nist.gov
I (3245) Time Helper: utcnist.colorado.edu
I (3255) Time Helper: sntp_init done.
TLS13-AES128-GCM-SHA256:TLS13-CHACHA20-POLY1305-SHA256:TLS13-SM4-GCM-SM3:TLS13-SM4-CCM-SM3:ECDHE-RSA-AES12
8-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDS
A-DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECD
SA-AES128-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305-OLD
:ECDHE-ECDSA-CHACHA20-POLY1305-OLD:ECDHE-ECDSA-SM4-CBC-SM3:ECDHE-ECDSA-SM4-GCM-SM3:ECDHE-ECDSA-SM4-CCM-SM3
:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-GCM-SHA256:PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305
I (3315) wolfssl: Start wolfSSL_Init()
I (3315) wolfssl: wolfSSL Entering wolfSSL_Init
I (3325) wolfssl: wolfSSL Entering wolfCrypt_Init
I (3325) wolfssl: start socket())
I (3335) wolfssl: Create and initialize WOLFSSL_CTX
I (3335) wolfssl: wolfSSL Entering wolfSSLv23_server_method_ex
I (3345) wolfssl: wolfSSL Entering wolfSSL_CTX_new_ex
I (3345) wolfssl: wolfSSL Entering wolfSSL_CertManagerNew
I (3355) wolfssl: wolfSSL Leaving wolfSSL_CTX_new_ex, return 0
I (3365) tls_server: Start SM2

I (3365) wolfssl: wolfSSL Entering wolfSSL_CTX_set_cipher_list
I (3375) tls_server: Set cipher list: ECDHE-ECDSA-SM4-CBC-SM3

TLS13-AES128-GCM-SHA256:TLS13-CHACHA20-POLY1305-SHA256:TLS13-SM4-GCM-SM3:TLS13-SM4-CCM-SM3:ECDHE-RSA-AES12
8-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDS
A-DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECD
SA-AES128-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305-OLD
:ECDHE-ECDSA-CHACHA20-POLY1305-OLD:ECDHE-ECDSA-SM4-CBC-SM3:ECDHE-ECDSA-SM4-GCM-SM3:ECDHE-ECDSA-SM4-CCM-SM3
:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-GCM-SHA256:PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305
I (3435) wolfssl: Loading certificate...
I (3435) wolfssl: wolfSSL Entering wolfSSL_CTX_use_certificate_buffer
I (3445) wolfssl: wolfSSL Entering PemToDer
I (3455) wolfssl: Checking cert signature type
I (3455) wolfssl: wolfSSL Entering GetExplicitVersion
I (3465) wolfssl: wolfSSL Entering wc_GetSerialNumber
I (3465) wolfssl: Got Cert Header
I (3475) wolfssl: wolfSSL Entering GetObjectId
I (3475) wolfssl: Got Algo ID
I (3475) wolfssl: Getting Name
I (3485) wolfssl: Getting Cert Name
I (3485) wolfssl: Getting Name
I (3495) wolfssl: Getting Cert Name
I (3495) wolfssl: Got Subject Name
I (3495) wolfssl: wolfSSL Entering GetAlgoId
I (3505) wolfssl: wolfSSL Entering GetObjectId
I (3505) wolfssl: wolfSSL Entering GetObjectId
I (3515) wolfssl: Got Key
I (3515) wolfssl: ECDSA/ED25519/ED448 cert signature
I (3525) wolfssl: wolfSSL Leaving wolfSSL_CTX_use_certificate_buffer, return 1
I (3535) tls_server: Loaded server_sm2

I (3535) wolfssl: Loading key info...
I (3535) wolfssl: wolfSSL Entering wolfSSL_CTX_use_PrivateKey_buffer
I (3545) wolfssl: wolfSSL Entering PemToDer
I (3555) wolfssl: wolfSSL Entering GetAlgoId
I (3555) wolfssl: wolfSSL Entering GetObjectId
I (3565) wolfssl: wolfSSL Entering GetAlgoId
I (3565) wolfssl: wolfSSL Entering GetObjectId
I (3575) wolfssl: wolfSSL Leaving wolfSSL_CTX_use_PrivateKey_buffer, return 1
I (3575) tls_server: Loaded PrivateKey_buffer server_sm2_priv

I (3585) wolfssl: wolfSSL Entering wolfSSL_CTX_load_verify_buffer_ex
I (3595) wolfssl: Processing CA PEM file
I (3595) wolfssl: wolfSSL Entering PemToDer
I (3605) wolfssl: Adding a CA
I (3605) wolfssl: wolfSSL Entering GetExplicitVersion
I (3615) wolfssl: wolfSSL Entering wc_GetSerialNumber
I (3615) wolfssl: Got Cert Header
I (3625) wolfssl: wolfSSL Entering GetObjectId
I (3625) wolfssl: Got Algo ID
I (3635) wolfssl: Getting Name
I (3635) wolfssl: Getting Cert Name
I (3635) wolfssl: Getting Name
I (3645) wolfssl: Getting Cert Name
I (3645) wolfssl: Got Subject Name
I (3655) wolfssl: wolfSSL Entering GetAlgoId
I (3655) wolfssl: wolfSSL Entering GetObjectId
I (3665) wolfssl: wolfSSL Entering GetObjectId
I (3665) wolfssl: Got Key
I (3665) wolfssl: Parsed Past Key
I (3675) wolfssl: wolfSSL Entering DecodeCertExtensions
I (3675) wolfssl: wolfSSL Entering GetObjectId
I (3685) wolfssl: wolfSSL Entering DecodeSubjKeyId
I (3685) wolfssl: wolfSSL Entering GetObjectId
I (3695) wolfssl: wolfSSL Entering DecodeAuthKeyId
I (3705) wolfssl: wolfSSL Entering GetObjectId
I (3705) wolfssl: wolfSSL Entering DecodeBasicCaConstraint
I (3715) wolfssl: wolfSSL Entering GetObjectId
I (3715) wolfssl: wolfSSL Entering DecodeAltNames
I (3725) wolfssl:       Unsupported name type, skipping
I (3725) wolfssl: wolfSSL Entering GetObjectId
I (3735) wolfssl: wolfSSL Entering DecodeExtKeyUsage
I (3735) wolfssl: wolfSSL Entering GetObjectId
I (3745) wolfssl: wolfSSL Entering GetObjectId
I (3745) wolfssl: wolfSSL Entering GetObjectId
I (3755) wolfssl:       Parsed new CA
I (3755) wolfssl:       No key size check done on CA
I (3765) wolfssl:       Freeing Parsed CA
I (3765) wolfssl:       Freeing der CA
I (3775) wolfssl:               OK Freeing der CA
I (3775) wolfssl: wolfSSL Leaving AddCA, return 0
I (3785) wolfssl:    Processed a CA
I (3785) wolfssl: Processed at least one valid CA. Other stuff OK
I (3795) wolfssl: wolfSSL Leaving wolfSSL_CTX_load_verify_buffer_ex, return 1
I (3795) tls_server: Success: load verify buffer

I (3805) tls_server: Finish SM2

I (3805) tls_server: accept clients...
I (3815) wolfssl: Waiting for a connection...
I (14485) wolfssl: wolfSSL Entering wolfSSL_new
I (14495) wolfssl: wolfSSL Entering ReinitSSL
I (14495) wolfssl: wolfSSL Entering SetSSL_CTX
I (14495) wolfssl: wolfSSL Entering wolfSSL_NewSession
I (14505) wolfssl: wolfSSL Leaving wolfSSL_new, return 0
I (14505) wolfssl: wolfSSL Entering wolfSSL_set_fd
I (14515) wolfssl: wolfSSL Entering wolfSSL_set_read_fd
I (14515) wolfssl: wolfSSL Leaving wolfSSL_set_read_fd, return 1
I (14525) wolfssl: wolfSSL Entering wolfSSL_set_write_fd
I (14535) wolfssl: wolfSSL Leaving wolfSSL_set_write_fd, return 1
I (14535) wolfssl: wolfSSL Entering wolfSSL_accept
I (14545) wolfssl: wolfSSL Entering ReinitSSL
I (14545) wolfssl: growing input buffer
I (14555) wolfssl: received record layer msg
I (14555) wolfssl: got HANDSHAKE
I (14565) wolfssl: wolfSSL Entering wolfSSL_get_options
I (14565) wolfssl: wolfSSL Entering DoTls13HandShakeMsg
I (14575) wolfssl: wolfSSL Entering DoTls13HandShakeMsgType
I (14575) wolfssl: processing client hello
I (14585) wolfssl: wolfSSL Entering DoTls13ClientHello
I (14595) wolfssl: wolfSSL Entering DoClientHello
I (14595) wolfssl:     downgrading to TLSv1.2
I (14605) wolfssl: Matched No Compression
I (14605) wolfssl: Adding signature algorithms extension
I (14615) wolfssl: Signature Algorithms extension received
I (14615) wolfssl: Point Formats extension received
I (14625) wolfssl: Supported Groups extension received
I (14625) wolfssl: Unknown TLS extension type
I (14635) wolfssl: Unknown TLS extension type
I (14635) wolfssl: wolfSSL Entering MatchSuite
I (14645) wolfssl: wolfSSL Entering VerifyServerSuite
I (14645) wolfssl: Requires ECC
I (14655) wolfssl: Verified suite validity
I (14655) wolfssl: wolfSSL Leaving DoClientHello, return 0
I (14665) wolfssl: wolfSSL Leaving DoTls13ClientHello, return 0
I (14675) wolfssl: wolfSSL Leaving DoTls13HandShakeMsgType(), return 0
I (14675) wolfssl: wolfSSL Leaving DoTls13HandShakeMsg, return 0
I (14685) wolfssl: Shrinking input buffer
I (14685) wolfssl: accept state ACCEPT_CLIENT_HELLO_DONE
I (14695) wolfssl: accept state ACCEPT_FIRST_REPLY_DONE
I (14705) wolfssl: wolfSSL Entering SendServerHello
I (14705) wolfssl: growing output buffer
I (14715) internal.c: GrowOutputBuffer ok
I (14715) wolfssl: wolfSSL Entering wolfSSL_get_options
I (14725) wolfssl: Point Formats extension to write
W (14735) wolfio: ssl->wflags = 0
I (14735) wolfio: 16 03 03 00 52 02 00 00 4e 03 03 af 87 e2 58 57
I (14735) wolfio: 73 c3 c1 35 1a 59 39 b2 03 9d 14 03 e0 b8 fb e8
I (14745) wolfio: 9d 5b 9c 44 4f 57 4e 47 52 44 01 20 85 77 75 20
I (14755) wolfio: 95 dd 00 e2 91 f8 42 33 f8 61 3f 1f de 81 15 58
I (14755) wolfio: 23 0c e7 1e 71 e6 10 e5 67 23 e0 40 e0 11 00 00
I (14765) wolfio: 06 00 0b 00 02 01 00
W (14775) wolfio: sz          = 87
I (14775) wolfssl: Shrinking output buffer
I (14775) wolfssl: wolfSSL Leaving SendServerHello, return 0
I (14785) wolfssl: accept state SERVER_HELLO_SENT
I (14795) wolfssl: wolfSSL Entering SendCertificate
I (14795) wolfssl: growing output buffer
I (14805) internal.c: GrowOutputBuffer ok
W (14815) wolfio: ssl->wflags = 0
I (14815) wolfio: 16 03 03 02 e6 0b 00 02 e2 00 02 df 00 02 dc 30
I (14815) wolfio: 82 02 d8 30 82 02 7e a0 03 02 01 02 02 01 01 30
I (14825) wolfio: 0a 06 08 2a 81 1c cf 55 01 83 75 30 81 ac 31 0b
I (14835) wolfio: 30 09 06 03 55 04 06 13 02 55 53 31 10 30 0e 06
I (14835) wolfio: 03 55 04 08 0c 07 4d 6f 6e 74 61 6e 61 31 10 30
I (14845) wolfio: 0e 06 03 55 04 07 0c 07 42 6f 7a 65 6d 61 6e 31
I (14855) wolfio: 14 30 12 06 03 55 04 0a 0c 0b 77 6f 6c 66 53 53
I (14855) wolfio: 4c 5f 73 6d 32 31 0f 30 0d 06 03 55 04 0b 0c 06
I (14865) wolfio: 43 41 2d 73 6d 32 31 18 30 16 06 03 55 04 03 0c
I (14875) wolfio: 0f 77 77 77 2e 77 6f 6c 66 73 73 6c 2e 63 6f 6d
I (14875) wolfio: 31 1f 30 1d 06 09 2a 86 48 86 f7 0d 01 09 01 16
I (14885) wolfio: 10 69 6e 66 6f 40 77 6f 6c 66 73 73 6c 2e 63 6f
I (14895) wolfio: 6d 31 17 30 15 06 0a 09 92 26 89 93 f2 2c 64 01
I (14895) wolfio: 01 0c 07 77 6f 6c 66 53 53 4c 30 1e 17 0d 32 33
I (14905) wolfio: 30 32 31 35 30 36 32 33 30 37 5a 17 0d 32 35 31
I (14915) wolfio: 31 31 31 30 36 32 33 30 37 5a 30 81 b0 31 0b 30
I (14915) wolfio: 09 06 03 55 04 06 13 02 55 53 31 10 30 0e 06 03
I (14925) wolfio: 55 04 08 0c 07 4d 6f 6e 74 61 6e 61 31 10 30 0e
I (14935) wolfio: 06 03 55 04 07 0c 07 42 6f 7a 65 6d 61 6e 31 14
I (14945) wolfio: 30 12 06 03 55 04 0a 0c 0b 77 6f 6c 66 53 53 4c
I (14945) wolfio: 5f 73 6d 32 31 13 30 11 06 03 55 04 0b 0c 0a 53
I (14955) wolfio: 65 72 76 65 72 2d 73 6d 32 31 18 30 16 06 03 55
I (14965) wolfio: 04 03 0c 0f 77 77 77 2e 77 6f 6c 66 73 73 6c 2e
I (14965) wolfio: 63 6f 6d 31 1f 30 1d 06 09 2a 86 48 86 f7 0d 01
I (14975) wolfio: 09 01 16 10 69 6e 66 6f 40 77 6f 6c 66 73 73 6c
I (14985) wolfio: 2e 63 6f 6d 31 17 30 15 06 0a 09 92 26 89 93 f2
I (14985) wolfio: 2c 64 01 01 0c 07 77 6f 6c 66 53 53 4c 30 5a 30
I (14995) wolfio: 14 06 08 2a 81 1c cf 55 01 82 2d 06 08 2a 81 1c
I (15005) wolfio: cf 55 01 82 2d 03 42 00 04 94 70 2b 46 e4 5e 0f
I (15005) wolfio: 41 fb 8f 2d 34 0a 41 40 19 5e fb d4 1d 11 ac fa
I (15015) wolfio: f5 93 37 c6 fa 87 08 f7 16 1f 2c ce 30 40 9d 4f
I (15025) wolfio: a6 2a 0a a1 d6 95 33 c3 a6 03 98 e6 8d 05 34 b0
I (15025) wolfio: 97 0c de a4 c7 cf 53 8f d1 a3 81 89 30 81 86 30
I (15035) wolfio: 1d 06 03 55 1d 0e 04 16 04 14 67 ae 60 ff 7e 1b
I (15045) wolfio: 0f 95 ae 1f 82 59 f2 6c 56 2d 93 ef 17 32 30 1f
I (15045) wolfio: 06 03 55 1d 23 04 18 30 16 80 14 47 0a 48 7e bb
I (15055) wolfio: 02 a8 5a 26 57 2b 19 a9 7b 61 8b 7f 5d 99 6e 30
I (15065) wolfio: 0c 06 03 55 1d 13 01 01 ff 04 02 30 00 30 0e 06
I (15075) wolfio: 03 55 1d 0f 01 01 ff 04 04 03 02 03 a8 30 13 06
I (15075) wolfio: 03 55 1d 25 04 0c 30 0a 06 08 2b 06 01 05 05 07
I (15085) wolfio: 03 01 30 11 06 09 60 86 48 01 86 f8 42 01 01 04
I (15095) wolfio: 04 03 02 06 40 30 0a 06 08 2a 81 1c cf 55 01 83
I (15095) wolfio: 75 03 48 00 30 45 02 20 1b ca 94 28 7f f6 b2 0d
I (15105) wolfio: 31 43 50 e1 d5 34 17 dd af 3a de 81 06 67 9a b3
I (15115) wolfio: 06 22 7e 64 ec fd 0e b9 02 21 00 a1 48 a8 32 d1
I (15115) wolfio: 05 09 6b 1c eb 89 12 66 d8 38 a1 c4 5c 89 09 0f
I (15125) wolfio: fd e9 c0 3b 1d fb cd b5 4c 31 68
W (15135) wolfio: sz          = 747
I (15135) wolfssl: Shrinking output buffer
I (15135) wolfssl: wolfSSL Leaving SendCertificate, return 0
I (15145) wolfssl: accept state CERT_SENT
I (15155) wolfssl: wolfSSL Entering SendCertificateStatus
I (15155) wolfssl: wolfSSL Leaving SendCertificateStatus, return 0
I (15165) wolfssl: accept state CERT_STATUS_SENT
I (15165) wolfssl: wolfSSL Entering SendServerKeyExchange
I (15175) wolfssl: Using ephemeral ECDH
I (15175) wolfssl: wolfSSL Entering EccMakeKey
I (15535) wolfssl: wolfSSL Leaving EccMakeKey, return 0
I (15535) wolfssl: Trying ECC private key, RSA didn't work
I (15535) wolfssl: wolfSSL Entering GetAlgoId
I (15545) wolfssl: wolfSSL Entering GetObjectId
I (15555) wolfssl: Using ECC private key
I (15555) wolfssl: wolfSSL Entering Sm2wSm3Sign
I (15915) wolfssl: wolfSSL Leaving Sm2wSm3Sign, return 0
I (15915) wolfssl: wolfSSL Entering SendHandshakeMsg
I (15925) wolfssl: growing output buffer
I (15925) internal.c: GrowOutputBuffer ok
W (15925) wolfio: ssl->wflags = 0
I (15935) wolfio: 16 03 03 00 95 0c 00 00 91 03 00 29 41 04 fd f5
I (15935) wolfio: 5e 74 15 30 1d f3 84 ae a5 69 96 a9 5b dd 27 b3
I (15945) wolfio: 00 7d 40 3a 59 93 93 6f 4d 1f 62 dc 60 48 34 1f
I (15955) wolfio: a8 1d 34 b8 76 8f 8b 27 4a 1b 77 64 8e 2e d5 27
I (15955) wolfio: 03 95 8b 9d a5 ed a4 a6 b9 40 1b ea aa 10 07 08
I (15965) wolfio: 00 48 30 46 02 21 00 cb 89 61 e9 21 f9 c6 4d ad
I (15975) wolfio: aa e7 f1 3f 6f 27 46 f0 35 ec 45 4e 8a ae f3 ac
I (15985) wolfio: 7c c0 cf 68 11 44 e2 02 21 00 f6 40 5c bc 66 5a
I (15985) wolfio: 74 1e 92 5d 9a 03 75 e7 7f 16 c2 b3 c8 fe 8d 5c
I (15995) wolfio: 63 35 36 da 61 38 76 dc 4e d6
W (15995) wolfio: sz          = 154
I (16005) wolfssl: Shrinking output buffer
I (16005) wolfssl: wolfSSL Leaving SendServerKeyExchange, return 0
I (16015) wolfssl: accept state KEY_EXCHANGE_SENT
I (16025) wolfssl: accept state CERT_REQ_SENT
I (16025) wolfssl: wolfSSL Entering SendServerHelloDone
I (16035) wolfssl: growing output buffer
I (16035) internal.c: GrowOutputBuffer ok
W (16045) wolfio: ssl->wflags = 0
I (16045) wolfio: 16 03 03 00 04 0e 00 00 00
W (16045) wolfio: sz          = 9
I (16055) wolfssl: Embed Send error
I (16055) wolfssl:      Connection reset
I (16065) int: Sent = -3
W (16065) int: WOLFSSL_CBIO_ERR_CONN_RST
E (16075) int: SOCKET_ERROR_E 2
I (16075) wolfssl: wolfSSL Leaving SendServerHelloDone, return -308
I (16085) wolfssl: wolfSSL error occurred, error = -308
I (16085) wolfssl: wolfSSL Entering wolfSSL_get_error
I (16095) wolfssl: wolfSSL Leaving wolfSSL_get_error, return -308
E (16085) tls_server: wolfSSL_accept error -308
I (16105) wolfssl: Client connected successfully
I (16105) wolfssl: wolfSSL Entering wolfSSL_read
I (16115) wolfssl: wolfSSL Entering wolfSSL_read_internal
I (16125) wolfssl: wolfSSL Entering ReceiveData
I (16125) wolfssl: User calling wolfSSL_read in error state, not allowed
I (16135) wolfssl: wolfSSL Leaving wolfSSL_read_internal, return -308
E (16145) tls_server: ERROR: failed to read
I (16145) wolfssl: Client sends:
I (16145) wolfssl:
I (16155) wolfssl: wolfSSL Entering wolfSSL_write
I (16155) wolfssl: handshake not complete, trying to finish
I (16165) wolfssl: wolfSSL Entering wolfSSL_negotiate
I (16165) wolfssl: wolfSSL Entering wolfSSL_accept
I (16175) wolfssl: wolfSSL Entering ReinitSSL
W (16185) wolfio: ssl->wflags = 0
I (16185) wolfio: 16 03 03 00 04 0e 00 00 00
W (16185) wolfio: sz          = 9
I (16195) wolfssl: Embed Send error
I (16195) wolfssl:      General error
I (16205) int: Sent = -1
E (16205) int: SOCKET_ERROR_E
I (16205) wolfssl: wolfSSL error occurred, error = -308
I (16215) wolfssl: wolfSSL Leaving wolfSSL_negotiate, return -1
I (16225) wolfssl: wolfSSL Leaving wolfSSL_write, return -1
E (16225) tls_server: ERROR: failed to write
I (16235) wolfssl: wolfSSL Entering wolfSSL_free
I (16235) wolfssl: Free'ing server ssl
I (16245) wolfssl: Shrinking output buffer
I (16245) wolfssl: wolfSSL Entering ClientSessionToSession
I (16255) wolfssl: wolfSSL Entering wolfSSL_FreeSession
I (16255) wolfssl: wolfSSL_FreeSession full free
I (16265) wolfssl: CTX ref count not 0 yet, no free
I (16265) wolfssl: wolfSSL Leaving wolfSSL_free, return 0
I (16275) wolfssl: Waiting for a connection...
```

### Wireshark:

![wireshark](./wireshark.png)
