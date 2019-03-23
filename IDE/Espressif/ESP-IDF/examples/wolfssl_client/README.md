#wolfSSL Example

The Example contains of wolfSSL tls client demo.

1. "make menuconfig" to config the project  
    1-1. Example Configuration ->

          WIFI SSID: your own WIFI, which is connected to the Internet.(default is "myssid")  
          WIFI Password: WIFI password, and default is "mypassword"  
          Target host ip address : the host that you want to connect to.(default is 127.0.0.1)
    
    Note: the example program uses 11111 port. If you want to use different port  
        , you need to modify DEFAULT_PORT definition in the code.

When you want to test the wolfSSL client

1. "make flash monitor" to load the firmware and see the context  
2. You can use <wolfssl>/examples/server/server program for test.  

         e.g. Launch ./examples/server/server -v 4 -b -i

See the README.md file in the upper level 'examples' directory for more information about examples.
