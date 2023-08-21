# wolfSSL CMake notes

The root of the wolfSSL repo contains a [CMakeLists.txt](./CMakeLists.txt) that can be used to compile the
[examples](examples/README.md).

In the simplest form:

```bash
# create a root directory for wolfssl repo
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-all
```

See the [documentation](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html) for more details
on the various `./configure` options.

## Build CMake Examples for Linux


```bash
# From the root of the wolfSSL repo:

mkdir -p out
pushd out
cmake ..
cmake --build .

# View the available ciphers with:
./examples/client/client -e
popd
```

## Build CMake Examples for Windows

```bash
# From the root of the wolfSSL repo:


mkdir -p out
pushd out
cmake ..
cmake --build .

# View the available ciphers with:
./examples/client/client -e
popd
```

## ARIA cipher suite

The ARIA cipher needs a 3rd party source binary, typically called `MagicCrypto.tar.gz`.

When debugging, these environment variables may be helpful:

#### Enable ARIA Cipher for Linux Examples

```bash
# From the root of the wolfSSL repo:

# set to your path
export ARIA_DIR=/mnt/c/workspace/MagicCrypto

mkdir -p out
pushd out
cmake ..
cmake --build .

# View the available ciphers with:
./examples/client/client -e
popd
```

#### Enable ARIA Cipher for Windows Examples

Unzip your `MagicCrypto.tar.gz`, shown here for `C:\workspace\MagicCrypto`

```bash
# set to your path
export ARIA_DIR=c:\\workspace\\MagicCrypto

mkdir -p out
pushd out
cmake ..
cmake --build .

# View the available ciphers with:
./examples/client/client -e
popd
```

