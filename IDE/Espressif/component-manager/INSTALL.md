# Install for ESP Component Manager

See the `wolfssl_component_publish.sh` bash script.

Examples are copied into the local [./examples/](./examples/README.md) directory.

Each example project needs to have a `main/idf_component.yml` file,
as well as a file called `init_demo.sh`.

The example `idf_component.yml` file should be edited as needed. Typical contents:

```
## IDF Component Manager Manifest File
dependencies:
  wolfssl/wolfssl: "^5.6.0-stable"
  ## Required IDF version
  idf:
    version: ">=4.1.0"
```

# ESP Component Examples

Note that when the ESP Component manager installs wolfSSL, then the source code for wolfSSL
will be *in the local component directory*. Normally there's only a cmake file that points
to where the wolfSSL library is located.

## Test build of examples

Set `WOLFSSL_ROOT` to the location of the to-be-published wolfSSL directory:

```
 export WOLFSSL_ROOT=/mnt/c/workspace/wolfssl-gojimmypi-PR/IDE/Espressif/component-manager/
```

The component files in [./lib/components/wolfssl](./lib/components/wolfssl/README.md) will
be copied to each respective example project to confirm they will build.
