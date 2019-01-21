

# Deos Port
## Overview
You can enable the wolfSSL support for Deos RTOS available [here](https://www.ddci.com/products_deos_do_178c_arinc_653/) using the `#define WOLFSSL_DEOS`.
Deos is a time & space partitioned, multi-core enabled, DO-178C DAL A certifiable RTOS.
## Usage

You can start with your OpenArbor IDE-based example project for Deos with the network stack (lwip) to integrate wolfSSL source code.

wolfSSL supports a compile-time user configurable options in the `IDE/ECLIPSE/DEOS/user_settings.h` file.

The `tls_wolfssl.c` example application provides a simple function to run the selected examples at compile time through the following four #defines in user_settings.h. You can undefine any of these macro options to run a test.
```
       1. #undef NO_CRYPT_TEST
       2. #undef NO_CRYPT_BENCHMARK
       3. #undef NO_WOLFSSL_CLIENT
       4. #undef NO_WOLFSSL_SERVER
```
Do one of the following steps for building and running wolfSSL with the Deos kernel examples, which are included in the DDS release:
If you want to create a project from scratch, skip the Importing the project section and follow the steps in the other sections.

If you want to use an pre-configured example project, go to the Importing the project section, skip the other sections and follow the Building and Running section.

#### Importing the project
In this section you will import a pre-configured example project.
1. Launch the OpenArbor IDE as an administrator
2. In the Workspace Launcher dialog, in the Workspace field, enter your
workspace
3. Right-click in the Project Explorer view and select Import
4. In the Import dialog, select General > Existing Projects into Workspace, then click Next.
5. In the Import Projects dialog, select Select archive file, then browse to `IDE/ECLIPSE/DEOS/` and double-click `deosWolfssl.zip` file
6. In the Import Projects dialog, click Finish


#### Setting up a Deos project with wolfSSL
 1. Download the wolfSSL source code or a zip file from GitHub. You can remove all of the files except for these folders and its contents. The top folder for this example is wolfsslPort.
```
wolfsslPort
      |-- IDE
          | -- ECLIPSE
               | -- DEOS
      |-- src
      |-- wolfcrypt
          | -- benchmark
          | -- src
          | -- test
      |-- wolfssl
          |-- openssl
          |-- wolfcrypt
              |-- port
```
 2. Remove these two platform specific assembly source files:
    -   wolfsslPort/wolfcrypt/src/aes_asm.asm
    -   wolfsslPort/wolfcrypt/src/aes_asm.S

 3. Launch the OpenArbor IDE as an administrator
 4. Create a DDC-I Deos example project. In the main menu, go to File >DDC-I Deos example project > socket > udp-vs-tcp
 5. Import the `wolfSSLPort` source code into your project.
    -   Right-click the ` udp-vs-tcp` project and choose File -> Import.
    -   Expand the General folder and select File System, then click Next. You should now see the Import File system dialog.
    -   Browse to the location containing the wolfSSL code and choose OK. Select the `wolfsslPort` folder and check the `Create top-level folder` button, then select Finish. You should see the folder hierarchy the same as wolfSSL folder structures.
6. Review the configuration in $(PROJECT_DIR)/wolfsslPort/IDE/ECLIPSE/DEOS/user_setting.h

7.  Review the custom malloc/realloc/free configuration $(PROJECT_DIR)/wolfsslPort/IDE/ECLIPSE/DEOS/deos_malloc.c . Memory allocated with malloc() is never freed.

#### Configuring the Deos Project
 1. Customize your config/udp-vs-tcp.pd.xml with the following changes:
```
<processTemplate
     mutexQuota = "5"
   >

   <logicalMemoryPools>
           pagesNeeded = "500"
      ></pool>
   </logicalMemoryPools>

   <threadTemplate
      stackSizeInPages = "20"
    ></threadTemplate>

   <mutexTemplates>
      <mutexTemplate
           name = "protectWolfSSLTemp"
           lockTimeInUsec = "40"
           priority = "fastest"
      ></mutexTemplate>
   </mutexTemplates>

</processTemplate>
```
Depending on your configuration, wolfSSL uses upto four mutexes. You also need to configure enough memory for the stack of each threads and the process logical memory pool.


 2. Right click on the `udp-vs-tcp` project, select properties and add the following macros in the DDC-I Options > C Compile > Preprocessor
      -   DEOS_ALLOW_OBSOLETE_DEFINITIONS
      -   WOLFSSL_USER_SETTINGS
 3.  Add the following directory paths in the DDC-I Options > C Compile > Directories and in the DDC-I Options > C++ Compile > Directories
      -   $(PROJECT_DIR)/wolfsslPort
      -   $(PROJECT_DIR)/wolfsslPort/wolfssl
      -   $(PROJECT_DIR)/wolfsslPort/IDE/ECLIPSE/DEOS
      -   $(PROJECT_DIR.printx)/code
 4.  Change the optimization level in the DDC-I Options > C Compile > Code Generation > Optimization level:g
      -   g
 5.  Add the following library dependencies in the DDC-I Options > Deos > Dependencies
      -   math
      -   dart
      -   ansi
      -   printx
          - You must add printx into your workspace, File >DDC-I Deos example project > training > printx
 6.  Edit $(PROJECT_DIR)/wolfsslPort/IDE/ECLIPSE/DEOS/user_setting.h to customize your configuration. For example, you can undef or define these tests.
      -   #undef NO_CRYPT_TEST
      -   #undef NO_CRYPT_BENCHMARK
      -   #undef NO_WOLFSSL_CLIENT
      -   #undef NO_WOLFSSL_SERVER
 7.  Edit your application source file where main() thread is defined and add the following:
      -   #include "printx.h"
      -   #include "tls_wolfssl.h"
      -   and a call to `wolfsslRunTests()`
Here's an example:
```
#include <deos.h>
#include <printx.h>
#include <tls_wolfssl.h>
#include <user_settings.h>

int main(void)
{
  initPrintx("");
  printf("TLS wolfssl example!\n");

  (void) waitUntilNextPeriod();
   wolfsslRunTests();

  deleteThread(currentThreadHandle());
}

```
 8.  Review $(PROJECT_DIR)/udp-vs-tcp/mailbox-transport.config configuration.
```
transportConfigurationId
2                              # Client thread quota - for client and server TCP
2                              # Client connection quota - one for client and one for server
0                              # Server startup quota
0                              # Server connection quota
transportMemoryObject          # Name of memory object used for managing connections
/

connectionId1                  # TCP client connection
Network                        # Server process name
defaultMailbox                 # Server connection request mailbox name
0                              # Server connection mailbox queue size (unused by Network process)
userServiceThread              # Server thread template name
*                              # Error timeout
1                              # Client connection mailbox queue size
/

connectionId2                  # TCP connection
Network                        # Server process name
defaultMailbox                 # Server connection request mailbox name
0                              # Server connection mailbox queue size (unused by Network process)
userServiceThread              # Server thread template name
*                              # Error timeout
1                              # Client connection mailbox queue size
/
```

   #### Building and Running
 1.  Build your project, then load and run your image on a target platform. Review the test results on the console output.


### `wolfcrypt_test()`
wolfcrypt_test() prints a message on the target console similar to the following output:
```
error    test passed!
base64   test passed!
asn      test passed!
...
```
This example doesn't show the whole output.

### `benchmark_test()`
benchmark_test() prints a message on the target console similar to the following output.

```
------------------------------------------------------------------------------
 wolfSSL version 3.15.5
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG               225 KB tooks 1.026 seconds,  219.313 KB/s
AES-128-CBC-enc    250 KB toks 1.105 seconds  226.210 KB/s
AES-128-CBC-dec    225 KB tooks 1.005 seconds,  223.922 KB/s
...
```
This example doesn't show the whole output.

### `wolfssl_client_test()`

You can modify the `TCP_SERVER_IP_ADDR` and `TCP_SERVER_PORT` macros in the `tls_wolfssl.c` file to configure the host address and port. You will also need to define the server certificate. The example client uses the GET request to get a web resource from the server at https://google.com.

### `wolfssl_server_test()`

You can modify the `TLS_SERVER_PORT` in the `tls_wolfssl.c` file to configure the port number to listen on a local-host.
Once you start the TLS server and `Listening for client connection` displays on the serial console, the server is ready to accept client connections.

You can connect to the server using the wolfssl TLS client example from your Linux or Windows host as follows:
```
$ ./examples/client/client.exe -h TLS_SERVER_IP_ADDRESS

The client outputs messages similar to the following:

SSL version is TLSv1.2
SSL cipher suite is TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
SSL curve name is SECP256R1
I hear ya fa shizzle!
```

## References

The test results were collected from the qemu-x86 reference platform target with the following software and tool chains:
- OpenArbor, eclipse based IDE, toolVersion = "3.31.0"
- wolfssl [latest version](https://github.com/wolfSSL/wolfssl)

For more information or questions, please email [support@wolfssl.com](mailto:support@wolfssl.com)
