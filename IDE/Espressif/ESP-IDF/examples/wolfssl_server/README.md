#wolfSSL Example

The Example contains a wolfSSL simple server.

1. "make menuconfigure" to configure the project

    1-1. Example Configuration ->
           WIFI SSID : your own WIFI, which is connected to the Internet.(default is "myssid")  
           WIFI Password : WIFI password, and default is "mypassword"

When you want to test the wolfSSL simple server demo

1. "make flash" to compile the code and load the firmware
2. "make monitor" to see the context. The assigned IP address can be found in output message.
3. Once the server connects to the wifi, it is waiting for client request.  
    ("Waiting for a connection..." message will be displayed.)
   
4. You can use <wolfssl>/examples/client to test the server  
    e.g ./example/client/client -h xx.xx.xx

See the README.md file in the upper level 'examples' directory for more information about examples.

