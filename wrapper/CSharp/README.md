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

Select the CPU type, configuration, and target file.
select `Build` and either `Rebuild Solution` or `Build Solution`.

### Visual Studio Build Configurations

In addition to the Configuration and Platform build options, Visual Studio has a `Platform Toolset` option in the (C not C#) `wolfssl` project file.
This can be found in the (Right-click on wolfssl project) `Property pages - General`.

A missing Platform Toolset is assumed to be Visual Studio 2010. Click the drop-down to see options available.

```text
  <PropertyGroup Condition ...
    <PlatformToolset>v143</PlatformToolset>
```

| Visual Studio Version | Internal Version | Platform Toolset |
|-----------------------|------------------|------------------|
| Visual Studio 2010    | 10.0             | v100             |
| Visual Studio 2012    | 11.0             | v110             |
| Visual Studio 2013    | 12.0             | v120             |
| Visual Studio 2015    | 14.0             | v140             |
| Visual Studio 2017    | 15.0             | v141             |
| Visual Studio 2019    | 16.0             | v142             |
| Visual Studio 2022    | 17.0             | v143             |

The `wolfssl` C project can also have the Toolset modified by right-clicking on the project and selecting "Retarget Projects".

Retargeting typically only offers to upgrade to the latest Platform Toolset, so the `wolfssl.vcxproj` file
will need to be manually edited if older versions are required.

### Debugging Native Code

Right-click on the `wolfSSL_CSharp` project, select `Properties` and
navigate to the `Debug` panel.

Be sure to check the box under `Debugger engines`: [x] `Enable native code debugging`.

This will allow single-step debugging into the native wolfSSL C library.

Do this also for the startup project being debugged.

If the error `Interop debugging is not supported` is encountered,
check which version of the .NET framework is being used.
Only 4.x or later supports native code debugging from a C# app.

See also:

https://learn.microsoft.com/en-us/visualstudio/debugger/debugging-native-code

### Calling Convention

The wolfSSL functions are wrapped like this:

```
[DllImport(wolfssl_dll, CallingConvention = CallingConvention.Cdecl)]
private extern static int wolfSSL_Init();
```

Where `wolfssl_dll` is a constant compile-time string that points to the `wolfssl.dll` file.

### Troubleshooting Windows DLL

The `wolfssl.dll` file is created with the `DLL Debug` and `DLL Release` configurations
and is typically compiled to:

```
C:\workspace\wolfssl-%USERNAME$\wrapper\CSharp\Debug\x64\wolfssl.dll
```

From a developer command prompt:

```
dumpbin /EXPORTS C:\workspace\wolfssl-$USER\wrapper\CSharp\Debug\x64\wolfssl.dll
```

There should be a long list of functions. If not, be sure to build with `WOLFSSL_DLL` (should be automatically included with DLL Debug/Release configurations).

See the project file `PreprocessorDefinitions` section:

```
<PreprocessorDefinitions>BUILDING_WOLFSSL;WOLFSSL_DLL;WOLFSSL_USER_SETTINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
```

If wolfSSL was _not_ compiled with `WOLFSSL_DLL` the `Unable to find an entry point` will be encountered:

```
wolfssl init error System.EntryPointNotFoundException: Unable to find an entry point named 'wolfSSL_Init' in DLL 'wolfssl.dll'.
   at wolfSSL.CSharp.wolfssl.wolfSSL_Init()
   at wolfSSL.CSharp.wolfssl.Init() in C:\workspace\wolfssl-%USERNAME%\wrapper\CSharp\wolfSSL_CSharp\wolfSSL.cs:line nnn
Calling ctx Init from wolfSSL
```

Note the `WOLFSSL_DLL` is used in the wolfssl `wolfssl/wolfssl/wolfcrypt/visibility.h` and defines the `WOLFSSL_API` like this:

```
#define WOLFSSL_API __declspec(dllexport)
```

Only the wolfSSL function declarations decorated with this tag will be visible ion the DLL.

#### Finding the wolfssl.dll

The most common problem encountered on Windows is the DLL location.

If not developing wolfSSL for Windows, one option is to copy the `wolfssl.dll` to `C:\Windows\System32\`.

Another option is to add to the system environment path or your user environment path:

```
set PATH=%PATH%;C:\path\to\your\wolfssl.dll
```

#### Check Architecture (x86 vs x64)

Your C# application must match the architecture of wolfssl.dll:

- If your C# app is x64, wolfssl.dll must be 64-bit.
- If your C# app is x86, wolfssl.dll must be 32-bit.

#### Ensure wolfssl.dll is Unblocked

If you downloaded wolfssl.dll from the Internet, Windows may block it.

Right-click wolfssl.dll, go to Properties, and check Unblock under Security.


## Linux (Ubuntu) using WSL

The Microsoft Windows Subsystem for Linux cam be used for wolfSSL.

```bash
sudo
sudo apt-get update
sudo apt-get upgrade
sudo apt install -y build-essential autoconf automake libtool pkg-config

export WORKSPACE="/mnt/c/workspace"
export WOLFSSL_ROOT="$WORKSPACE/wolfssl-$USER"

cd "WOLFSSL_ROOT"
```

When using a git repository, run `autogen.sh`:

```
cd "$WOLFSSL_ROOT"
./autogen.sh
```

###  Build wolfSSL and install it system-wide

To have a single instance of wolfSSL:

```
./configure
make
make check   # (optional, but highly recommended)
sudo make install
```

### Build wolfSSL and install to arbitrary directory

To have an isolated instance of wolfSSL, in this case `$HOME/wolfssl-install-psk`:

```bash
make clean
make distclean

rm -rf "$HOME/wolfssl-install-psk"

./configure --enable-all --disable-crypttests \
            --disable-examples \
            --enable-opensslall --enable-opensslextra \
            --enable-tls13 --enable-dtls13 --enable-dtls --enable-psk \
            CFLAGS="-DWOLFSSL_STATIC_PSK" --enable-shared \
            --prefix="$HOME/wolfssl-install-psk"

make -j$(nproc)
make install
```



### Compile specific example in WSL

```bash
# Optionally fetch additional examples
git clone https://github.com/wolfSSL/wolfssl-examples.git "$WORKSPACE/wolfssl-examples-$USER"
cd "$WORKSPACE/wolfssl-examples-$USER"

THIS_EXAMPLE="client-dtls-psk"

export WOLFSSL_DIR="$HOME/wolfssl-install-psk"
export CFLAGS="-I$WOLFSSL_DIR/include"
export LDFLAGS="-L$WOLFSSL_DIR/lib"

export LD_LIBRARY_PATH="$HOME/wolfssl-install-psk/lib:$LD_LIBRARY_PATH"

gcc -o "$THIS_EXAMPLE" "$THIS_EXAMPLE".c \
    -I$HOME/wolfssl-install-psk/include  \
    -L$HOME/wolfssl-install-psk/lib -Wl,-rpath=$HOME/wolfssl-install-psk/lib -lwolfssl -lm
```

## Linux (Ubuntu) using mono

Prerequisites for linux:

```bash
apt-get update
apt-get upgrade
apt-get install mono-complete
```

### Build wolfSSL and install system-wide

```bash
./autogen.sh
./configure --enable-keygen --enable-eccencrypt --enable-ed25519 --enable-curve25519 --enable-aesgcm
make
make check
sudo make install
```

### Build and run the wolfCrypt test wrapper

From the `wrapper/CSharp` directory (`cd wrapper/CSharp`):

Compile wolfCrypt test with mono:

```bash
mcs wolfCrypt-Test/wolfCrypt-Test.cs wolfSSL_CSharp/wolfCrypt.cs -OUT:wolfcrypttest.exe
mono wolfcrypttest.exe
```

### Build and run the wolfSSL client/server test

From the `wrapper/CSharp` directory (`cd wrapper/CSharp`):

Compile server with mono:

```bash
mcs wolfSSL_CSharp/wolfSSL.cs wolfSSL_CSharp/X509.cs wolfSSL-TLS-Server/wolfSSL-TLS-Server.cs -OUT:server.exe
```

Compile client with mono:

```bash
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
