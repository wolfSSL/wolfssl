# wolfSSL CSharp Wrappers

This directory contains the CSharp wrapper for the wolfSSL TLS layer with examples.

* `wolfSSL_CSharp`: wolfSSL TLS layer wrappers (library).
* `wolfCrypt-Test`: wolfCrypt layer wrapper testing.
* `user_settings.h`: wolfCrypt wrapper user settings.

Examples:
* `wolfSSL-DTLS-PSK-Server`
* `wolfSSL-DTLS-Server`
* `wolfSSL-Example-IOCallbacks`
* `wolfSSL-TLS-Client`
* `wolfSSL-TLS-PSK-Client`
* `wolfSSL-TLS-PSK-Server`
* `wolfSSL-TLS-Server`
* `wolfSSL-TLS-ServerThreaded`

## Windows

A Visual Studio solution `wolfSSL_CSharp.sln` is provided. This will allow you
to build the wrapper library and examples. It includes the wolfSSL Visual Studio
project directly.

To successfully run and build the solution on Windows Visual Studio you will
need to open a new solution `wolfSSL_CSharp.sln` located in `wrapper\CSharp\wolfSSL_CSharp.sln`.

The default `user_settings.h` is part of the Additional Include Directories, typically in `[WOLFSSL_ROOT]/wrapper/CSharp`

```
AdditionalIncludeDirectories="./;./wrapper/CSharp"
```


See also the alternative sample Windows `user_settings.h` in `[WOLFSSL_ROOT]/IDE/WIN`:

```
AdditionalIncludeDirectories="./;./IDE/WIN"
```


Select the CPU type, configuration, and target file.
select `Build` and either `Rebuild Solution` or `Build Solution`.

The `wolfssl` project will typically need the `DLL_Debug` or `DLL_Release` configuration with `x64` platform.


Check that the proper preprocessor definitions are included: `BUILDING_WOLFSSL;WOLFSSL_DLL;WOLFSSL_USER_SETTINGS`

Syntax for project file:
```
PreprocessorDefinitions="BUILDING_WOLFSSL;WOLFSSL_DLL;WOLFSSL_USER_SETTINGS"
```
Some older versions of Visual Studio will require manually setting the Configure Type to create a DLL file:

```
Configuration Properties - General

- Configuration Type: change from Static Library (.lib) - Dynamic Library (.dll)
```

For errors such as these:

```
error LNK2019: unresolved external symbol __imp__inet_pton@12 ...
error LNK2019: unresolved external symbol __imp__htons@4 ...
error LNK2019: unresolved external symbol __imp__recv@16 ...
```

Add `Ws2_32.lib` to Configuration Properties - Linker - ( Input || Additional Dependency)

Note the `AnyCPU` Platform may not work with C libraries compiled to a specific architecture.
An error like this will likely be encountered:

```
System.DllNotFoundException
  HResult=0x80131524
  Message=Unable to load DLL 'wolfssl.dll': The specified module could not be found. (Exception from HRESULT: 0x8007007E)
  Source=wolfSSL_CSharp
  StackTrace:
   at wolfSSL.CSharp.wolfssl.wolfSSL_SetLoggingCb(loggingCb vc)
   at wolfSSL.CSharp.wolfssl.SetLogging(loggingCb input) in C:\workspace\wolfssl\wrapper\CSharp\wolfSSL_CSharp\wolfSSL.cs:line 2716
   at wolfSSL_TLS_Client.Main(String[] args) in C:\workspace\wolfssl\wrapper\CSharp\wolfSSL-TLS-Client\wolfSSL-TLS-Client.cs:line 151
```

There's a separate `wolfSSL_CSharp-Clients.sln` solution file to allow concurrent client
applications in Visual Studio, with server running in `wolfSSL_CSharp.sln`.

Be sure to right-click and "Set as Startup Project" for whichever sample is being used.

If you see this error:

```
  'pwsh.exe' is not recognized as an internal or external command,
  operable program or batch file.
```

Run PowerShell manually from Windows Start Icon. Output should look something like this:

```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

Loading personal and system profiles took 1026ms.
```
## WindowsCE and Other Pocket PC Configurations

The `WindowsCE` should be defined in each project pre-processor declarations as needed.

Also can be manually defined in the `user_settings.h` when building the native C `wolfssl.dll`.

## Linux (Ubuntu) using mono

Prerequisites for linux:

```
apt-get update
apt-get upgrade
apt-get install mono-complete
```

### Build wolfSSL and install

```
./autogen.sh
./configure --enable-keygen --enable-eccencrypt --enable-ed25519 --enable-curve25519 --enable-aesgcm
make
make check
sudo make install
```

### Build and run the wolfCrypt test wrapper

From the `wrapper/CSharp` directory (`cd wrapper/CSharp`):

Compile wolfCrypt test:

```
mcs wolfCrypt-Test/wolfCrypt-Test.cs wolfSSL_CSharp/wolfCrypt.cs -OUT:wolfcrypttest.exe
mono wolfcrypttest.exe
```

### Build and run the wolfSSL client/server test

From the `wrapper/CSharp` directory (`cd wrapper/CSharp`):

Compile server:

```
mcs wolfSSL_CSharp/wolfSSL.cs wolfSSL_CSharp/X509.cs wolfSSL-TLS-Server/wolfSSL-TLS-Server.cs -OUT:server.exe
```

Compile client:

```
mcs wolfSSL_CSharp/wolfSSL.cs wolfSSL_CSharp/X509.cs wolfSSL-TLS-Client/wolfSSL-TLS-Client.cs -OUT:client.exe
```

#### Run the example

In one terminal instance run the server:

```
mono server.exe
```

And in another terminal instance run the client:

```
mono client.exe
```

#### Enabling SNI

To enable SNI, just pass the `-S` argument with the specified hostname to the client:

```
mono client.exe -S hostname
```

And run the server with the `-S` flag:

```
mono server.exe -S
```
