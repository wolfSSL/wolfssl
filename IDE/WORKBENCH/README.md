## Wind River Workbench using VxWorks with wolfSSL
###SETUP:
####Steps (There are many ways to set this up, this is one example)
1. Open WorkBench and go to File > Import > Existing Projects Into Workspace
2. Make sure the correct path to wolfSSL header files(wolfssl/wolfssl) is 
selected by right clicking the project and going to Properties > Build 
Properties > Paths. If you need to change this to a different path, do so now.
3. Right click on the project and go to Import > Filesystem. Choose your path
to the wolfSSL library here. Uncheck everything except the src and wolfcrypt 
directories. Only keep wolfcrypt/test/test.h, not test.c. Also uncheck test 
and benchmark directories and aes\_asm.asm and aes\_asm.s files from wolfcrypt/src. 
4. In wolfSSL/test.h, make sure certs are in the proper directory, or move.
5. The wolfcrypt source files, namely misc.c, may need to be moved directly under
a wolfcrypt folder within the project. It will be \<name\_of\_project\>/wolfcrypt/src/misc.c.
Alnternatively, add wolfssl to the include path, #include 
\<wolfssl/wolfcrypt/src/misc.c\>.
6. Make sure TFM\_X86 is undefined. 

####Necessary Files
You will need the following files to replicate this build:
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
* usrAppInit.c (should be created when you create a new VxWorks image)
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
* usrRtpAppInit.c (should be created when you create a new VxWorks image)
    Leave unchanged
* This project was tested with a pre-built image in the VxWorks distribution
called vsb\_vxsim\_linux. \<BEGIN\> $(VSB\_DIR) line in the .wpj file may need to be 
changed according to the VxWorks package being used. 

###VXWORKS SIMULATOR:
In "Open Connection Details" under VxWorks Simulator which is in the connections
dropdown. After the project has been build, choose the corresponding kernel image, typically called project/default/VxWorks. Select simnetd from the dropdown and enter 192.168.200.1 as the IP address.

To connect to a server running on the VxWorks Simulator, enter these commands
into the host terminal (for Ubuntu 14.04):
    sudo openvpn --mktun --dev tap0
In Wind River directory:
    vxworks-7/host/x86-linux2/bin/vxsimnetd
This will start the vxsimnetd application. Leave it open. The IP address to 
connect to the server is the same as above. 
