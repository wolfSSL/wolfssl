## Wind River Workbench using VxWorks with wolfSSL
####1 Necessary Files if Using VxWorks Simulator
The following files are required to replicate this build:
* vxsim\_linux\_1\_0\_2\_2 (directory)
* Includes
    * compilers/gnu-4.8.1.5/include/c++/4.8
    * compilers/gnu-4.8.1.5/include/c++/4.8/i586-wrs-vxworks
    * compilers/gnu-4.8.1.5/lib/gcc/i586-wrs-vxworks/4.8.1/include
    * compilers/gnu-4.8.1.5/lib/gcc/i586-wrs-vxworks/4.8.1/include-fixed
    * vsb\_vxsim\_linux/share/h
    * vsb\_vxsim\_linux/krnl/h/system
    * vsb\_vxsim\_linux/krnl/h/public
    * vsb\_vxsim\_linux/krnl/configlette
    * vsb\_vxsim\_linux/h
* usrAppInit.c (should be created when with new VxWorks image)
    * Include this at the top:
        #include <wolfssl/wolfcrypt/settings.h>
        #include <wolfcrypt/test/test.h>
        #include <wolfssl/ssl.h> /* name change portability layer */
        #include <wolfssl/test.h>
        extern int benchmark_test(void* args);
        extern THREAD\_RETURN WOLFSSL\_THREAD client\_test(void* args);
        extern THREAD\_RETURN WOLFSSL\_THREAD server\_test(void* args);
    * Inside main function UsrAppInit (void):
        func\_args args = { 0 };
        tcp\_ready ready;
        InitTcpReady(&ready);
        args.signal = &ready;
        benchmark\_test(NULL);
        wolfcrypt\_test(NULL);
        /* client\_test(NULL); */
        /*server\_test(&args);*/
* usrRtpAppInit.c (should be created when with new VxWorks image)
    Leave unchanged
* This project was tested with a pre-built image in the VxWorks distribution
called vsb\_vxsim\_linux.

####2 Steps
1. Start by creating a new VxWorks image in Workbench by going to File > New >
Project and then selecting VxWorks Image Project.

2. Right click on the project and go to Import > Filesystem. Choose the path
to the wolfSSL library here. Uncheck everything except the examples, src and 
wolfcrypt directories.
In the wolfcrypt/src folder, uncheck aes\_asm.asm and aes\_asm.s.

3. Include the path to the wolfSSL header files, wolfssl/wolfssl:
To do this, right click the project and go to Properties > Build Properties > Paths.
Choose Browse and select the wolfssl directory. Click ok.

4. In wolfssl/wolfssl/wolfcrypt/settings.h, uncomment #define WOLFSSL_VXWORKS

5. If not using a filesystem, right click on project, go to Properties > 
Build Properties > Variables.
Highlight EXTRA\_DEFINE. Click Edit and add the following to this line:
    
        -DUSE_CERT_BUFFERS_2048 -DNO_FILESYSTEM

6. If using a filesystem, copy the certs folder in wolfssl to the Wind River
Workbench workspace folder. This is where the simulator looks for the filesystem. 

7. If NO\_\_DEV\_RANDOM remains defined in wolfssl/wolfcrypt/settings.h under
\#ifdef WOLFSSL\_VXWORKS, a new GenerateSeed() function will need to be defined
in wolfcrypt/src/random.c.

####3 Testing wolfSSL with VxWorks:
#####3.1 wolfCrypt Test and Benchmark Applications
The wolfCrypt test application will test each of the cryptographic algorithms
and output the status for each as a success or failure. The benchmark application will output the runtime of
the cryptographic algorithms in milliseconds.

1. Include these header files in usrAppInit.c:
       
        #include <wolfcrypt/test/test.h>
        #include <wolfssl/ssl.h>
        #include <wolfssl/wolfcrypt/settings.h>
        #include <wolfssl/test.h>

2. In usrAppInit.c, make a call to the wolfCrypt test and benchmark applications 
by adding the following to the usrAppInit() function:

        typedef struct func_args {
            int    argc;
            char** argv;
            int    return_code;
        } func_args;

        func_args args;

        wolfcrypt_test(&args);
        wolfcrypt_benchmark(&args);

3. Start the simulator and check that all wolfCrypt tests pass.

#####3.2 Example Client
The wolfSSL example client.c file can be found in wolfssl/examples/client.

1. In usrAppInit.c, inlucde the func\_args as described in the Test Application
section, and add a call to the client function:

        client_test(&args);

2. Add the /examples/client/client.h header file to the includes at the top of usrAppInit.c.

3. The wolfSSLIP will need to be changed to the IP address to connect to. If using the VxWorks Simulator, localhost will not work. NAT should be selected in the Simulator Connection Advanced setup. To do this, click the dropdown button next to VxWorks Simulator at the top of Workbench and select Open Connection Details. Make sure the correct image file is selected for you project: <Project\_Dir>/default/VxWorks. Then click Advanced and select NAT as the Network Config. Click OK and Apply.

4. If using the example server from within the wolfSSL directory on the host
machine to connect the client to, configure and make wolfSSL and then run:

        ./examples/server/server -d -b
    
    The -d option disables peer checks, -b allows for binding to any interface.

5. Start the example client in Workbench.

#####3.3 Example Server
The example server requires more configuration than the client if using the
VxWorks simulator.

1. Add the server.h header file to the includes at the top of usrAppInit.c.

2. In usrAppInit.c, add:
    
        func_args args = { 0 };
        tcp_ready ready;
        InitTcpReady(&ready);
        args.signal = &ready;
        server_test(&args);

3. Start the server and complete the following:
    Go to "Open Connection Details" under VxWorks Simulator which is in the connections
    dropdown. Choose the corresponding kernel image, typically called
    project/default/VxWorks. Select simnetd from the dropdown and enter
    192.168.200.1 as the IP address. To connect to the server running on the VxWorks Simulator, enter these commands
    into the host terminal any directory (for Ubuntu 14.04):

        sudo openvpn --mktun --dev tap0
    
    In Wind River directory:

        sudo vxworks-7/host/x86-linux2/bin/vxsimnetd
    
    This will start the vxsimnetd application. Leave it open. The IP address to
    connect to the server is the same as above.

4. Start the client on the host machine:

        ./examples/client/client -d
    
    The -d option disables peer checks.
