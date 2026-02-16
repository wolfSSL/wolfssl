# CMake consumer test

This is a minimal CMake project that consumes the installed wolfSSL
package config.

## Build

```
cmake -S . -B build -DCMAKE_PREFIX_PATH=/path/to/wolfssl/install
cmake --build build
./build/wolfssl_consumer
```
