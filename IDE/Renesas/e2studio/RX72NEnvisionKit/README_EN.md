README_EN.md

# About this document


This document will show you how to build and run test applications for your target board. A Japanese version of this document is also provided in the same location of this file.


# 1. Structure of the project

The folder that contains this README file has:
  1. smc      --- the folder where the smart configurator project is stored.
  2. test     --- the folder where the test application project is stored
  3. wolfssl  --- the folder where the project for the wolfssl library used by the test application is stored.
  4. common   --- the folder where the configuration files etc. are stored
  


# 2. Import projects


After starting e2studio, display the project explorer pane,
select "File" menu> "Open project from file system...",
Display the project import dialog.

Press the directory button and import those three projects to show in the project-explore pane.


# 3. Generate source files in smc project


The smc.scfg file is already prepared in the smc project.
Double-clicking on this file will open the Smart Configurator perspective,
displaying a configuration pane with multiple tabs.
The components currently selected in the Overview tab are listed along with their version.
These are already set up to run the test application.
Board information and clock settings are already set according to RX72N EnvisionKit.

The points that need to be set are
Display the r_t4_rx component settings in the component tab. Where the value of the following property
#IP address for ch0,when DHCP disable.

Then, set the IPv4 address set in RX72N EnvisionKit to a value that suits your environment.
This is the only place that needs to be set.

Save the settings and press the source file generation button at the top right of the screen to generate the source file.

# 4. Copy the source files generated to the test project


When you expand the test project folder on the e2studio Project Explorer pane, you will see "src/smc_gen" folder. Copy the "smc_gen" folder to "test/src" folder to make "test/src/smc_gen". 

After copying the folder, you do not need to touch the smc project unless you attempt to change any configuration such as ip address, stack size, heap size and so on. However, if you change any configuration through Smart configurator, you have to generate source files and then copy them to test/src folder again. 


# 5. Select the behavior of the test project


Test project outputs a executable(application) of name "test". Your can choose the vehavior(type) of the application from encryption test, benchmark, TLS client and TLS server. 

This is done by activating one of following macro definitions in test/src/wolfssl_demo.h:

  1. CRYPT_TEST -- this macro makes the test application as a cryptography algorithm test-bench. Alogithms supported by the wolfSSL are tested and the result are showen in the "Renesas Debug Virtual Console".

  2. BENCHMARK  -- this macro makes the test application perform benchmarking and show the result. Cryptographic algorithms are performed and mesured its processing speed. Some are processed with H/W accelelator.The results are showen in the "Renesas Debug Virtual Console".

  3. TLS_CLIENT -- this macro makes the test application perform TLS handshake with TLS server application to exchange short messages in encrypted format.
  Prior to this test, you need to run a TLS server application and let it listen to the clients. You can use "server" application provided in wolfSSL/examples/Server as TLS server. How to get the server application is explained in later chapter.

  4. TSL_SERVER -- this macro makes the test application perform TLS handshake this TLS client application to exchange short mesages in encypted format. As is the caes of TLS_CLIENT, a TLS client application is required for testing.

# 6. Build the wolfssl project and the test project

Make sure that the above settings are completed before building.
Build in order of "wolfssl" and "test". When you change those settings, we recommend to rebuid those two projects to make sure the settings reflect.  


# 7. Run the test application using the emulator

After connecting the emulator, target board and PC with a cable, test HardwareDebug.launch is already prepared.
Select "Run"> "Debug" in e2 studio to start debugging.

When the debug perspective is displayed, select the e2 studio menu "Renesas Views"> "Debug"> "Renesas Debug Virtual Console"
to display the debug console pane. The progress and results of the test application execution are output to this console.

# 8. Prepare applications for communication

 When you enables ether TLS_CLIENT or TLS_SERVER macro in test/src/wolfssl_demo.h, you need to prepare communication partner applications for your test application. wolfSSL package provides those partner applications as its example programs. 

 When we say "build a wolfSSL package", it means making a wolfssl library and some examples applications. So let us build a wolfSSL package.
 

 ## 8.1 Build a wolfSSL with Visual Studio on Windows 

 You must be working in Windows environment. Let us introduce you the easiest way to build a wolfSSL. wolfSSL package has wolfssl.sln and wolfssl64.sln in the base folder. If you already have VisualStudio installed in your PC, your double-click ether one of those solution files leads you to ready to build wolfSSL.

 In your solution explore pane, you will see seven projects. In them,
 "client" and "server" projects will provide you the communication partner apps. Let us forcus only on "client" and "server" projects now. Expand either project, you will see user_settings.h. You need to customise those apps by adding some macros in the file.

Macros need to add are based on the cryptographical feature limitations of your target device or wolfSSL itself. As of now, wolfSSL supports RSA key exchange and AES-CBC mode encryption for TLS handshake with  Rnesas RX72N and TSIP.

Open user_settings.h to add following four macros around line #70.

```
#define WOLFSSL_STATIC_RSA 
#define HAVE_AESGCM
#define HAVE_AES_CBC
#define WOLFSSL_DH_CONST
```

like as:

```
  #else
    /* The servers and clients */
    #define OPENSSL_EXTRA
    #define NO_PSK
    
    /* add following four macros */
    #define WOLFSSL_STATIC_RSA 
    #define HAVE_AESGCM
    #define HAVE_AES_CBC
    #define WOLFSSL_DH_CONST

  #endif
#endif /* HAVE_FIPS */
```

Please note that the user_settings.h is shared among seven projects.
Onece you add macros they give affect to other example projects.

After editing of the user_settings.h, you can build the solution to make all those seven example applications be built. 


## 8.2 Build a wolfSSL on Linux or its variant

The communication partner apps are not limited to build on Windows. If you have Linux or variant OS and gcc/autoconf tools, you can build a wolfSSL package along the instruction below:

https://www.wolfssl.com/docs/wolfssl-manual/ch2/


# 9. Running the test application

## 9.1 CRYPT_TEST  or BENCHMARK
In the section 7, you have your test application ready to run on E2Studio.
If your choice of the test application operation shown in the section 5 is 
ether CRYPT_TEST or BENCHMARK, just run the test executable on your board.
The test result will appear in the "Renesas Debug Virtual Console". 
You can stop debugging after the result was printed out.

## 9.2 TLS_CLINET

If your test application is built as TLS_Client, you have to run the partner app built in the section 8 and make it listen to the connection from the test app. The partner app is "server.exe". Open a console and type as following:

```
> server.exe -b -d -i
```
server.exe starts listening forever on port 11111 of any ip addresses.
Windows firewall might block the server.exe and ask your approval.  
Then you can run the test app in your target board from the emulator.  
Shortly, you can see following messages on the "Renesas Debug Virtual Console" in the E2Studio.  

```
--Renesas Degug Virtual Console--

cipher : AES128-SHA
Received: I hear you fa shizzle!

cipher : AES128-SHA256
Received: I hear you fa shizzle!

cipher : AES256-SHA
Received: I hear you fa shizzle!

cipher : AES256-SHA256
Received: I hear you fa shizzle!
```

In the command prompt, where you started server.exe, also will show similar messages. -i option passed to the server.exe makes it keep listenning until you type Control-C.

## 9.2 TLS_SERVER

Before you try this case, remember the ip address you assigned the board in the section 3. Your target board will start listening on port 11111. This time, you need to run the target prior to the partner app(i.e. client.exe).
After the test app start running on the target board, you can start client.exe with option "-h target-board-ip-address"

```
> client.exe -h XXX.XXX.XXX.XXX
```

# 10. Disable usage of H/W accelelation

You may want to compare performance of cryptographic features with and without TSIP. For that case, you can disable the use of TSIP by commenting out the macro "WOLFSSL_RENESAS_TSIP" in wolf-base/IDE/Renesas/e2studio/RX72NEnvisionKit/common/user_settings.h.  

```
-- user_settings.h --
  ... 
/* #define WOLFSSL_RENESAS_TSIP */
#define WOLFSSL_RENESAS_TSIP_VER  109
  ...
```

After rebuilding the test application, it performs all the cryptographic operations by software only.