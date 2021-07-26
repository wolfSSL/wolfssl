## wolfSSL IoT-Safe Example


### Evaluation Platform

  * ST [P-L496G-CELL02](https://www.st.com/en/evaluation-tools/p-l496g-cell02.html)

including:
    * STM32L496AGI6-based low-power discovery mother board
    * STMiQuectel BG96 modem, plugged into the 'STMod+' connector
    * IoT-Safe capable SIM card

### Description

This example firmware will run an example TLS 1.2 server using wolfSSL, and a 
TLS 1.2 client, on the same host, using an IoT-safe applet supporting the
[IoT.05-v1-IoT standard](https://www.gsma.com/iot/wp-content/uploads/2019/12/IoT.05-v1-IoT-Security-Applet-Interface-Description.pdf).

The client and server routines alternate their execution in a single-threaded,
cooperative loop.

Client and server communicate to each other using memory buffers to establish a 
TLS session without the use of TCP/IP sockets.

### IoT-Safe interface

In this example, the client is the IoT-safe capable endpoint. First, it creates
a wolfSSL context `cli_ctx` normally:

```
   wolfSSL_CTX_iotsafe_enable(cli_ctx);
```

In order to activate IoT-safe support in this context, the following function is
called:

```
    printf("Client: Enabling IoT Safe in CTX\n");
    wolfSSL_CTX_iotsafe_enable(cli_ctx);
```


Additionally, after the SSL session creation, shown below:

```
    printf("Creating new SSL\n");
    cli_ssl = wolfSSL_new(cli_ctx);
```

the client associates the pre-provisioned keys and the available slots in the
IoT safe applet to the current session:


```
    wolfSSL_iotsafe_on(cli_ssl, PRIVKEY_ID, ECDH_KEYPAIR_ID, PEER_PUBKEY_ID,
        PEER_CERT_ID);

```

The applet that has been tested with this demo has the current configuration:

   Key slot | Name | Description 
   -------|--------|------------------
   0x02 | `PRIVKEY_ID` | pre-provisioned with client ECC key
   0x03 | `ECDH_KEYPAIR_ID` | can store a keypair generated in the applet, used for shared key derivation
   0x04 | `PEER_PUBKEY_ID` | used to store the server's public key for key derivation
   0x05 | `PEER_CERT_ID` | used to store the server's public key to authenticate the peer


The following file is used to read the client's certificate:
   
  File Slot | Name | Description
  ----------|------|------------
  0x03 | `CRT_FILE_ID` | pre-provisioned with client certificate


### Compiling and running

From this directory, run 'make', then use your favorite flash programming
software to upload the firmware `image.bin` to the target board.



