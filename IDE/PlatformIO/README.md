# PlatformIO

Follow the [instructions](https://docs.platformio.org/en/latest/core/installation/methods/index.html) to install PlatformIO.

Note there are two options:

- [Core CLI](https://docs.platformio.org/en/latest/core/index.html)
- [VSCode IDE](https://docs.platformio.org/en/latest/integration/ide/vscode.html#ide-vscode)


## Publishing

The PlatformIO Core CLI is needed to publish wolfSSL:

See also the [Arduino](../ARDUINO/README.md) publishing notes.


### Publish PlatformIO Arduino Library with Windows

The wolfSSL publishing is done from the `scripts`. Here are somple examples:

Setup the PlatformIO CLI:

```dos
set PATH=%PATH%;C:\Users\%USERNAME%\.platformio\penv\Scripts\
pio --help
pio account show
```

Publish

```dos
pio pkg publish --owner wolfSSL C:\workspace\Arduino-wolfSSL
```

### Publish with Linux

```bash
set PATH=%PATH%;C:\Users\%USERNAME%\.platformio\penv\Scripts\
pio --help
pio account show
```

```bash
pio pkg publish --owner wolfSSL ~\workspace\Arduino-wolfSSL
```

### Create a staging / preview wolfssl org

See 

```
pio org create wolfssl-staging --email support@wolfssl.com --displayname "testing preview wolfssl"
```

### Add user to org

The creator of an org is automatically added as user / owner at org creation time. Others can be added:

```
pio org add wolfssl-staging gojimmypi
```

### Publish Arduino wolfSSL to staging / preview site:

```
pio pkg publish --owner wolfssl-staging C:\workspace\Arduino-wolfSSL
```

### Publish Regular wolfSSL to staging / preview site:

```
pio pkg publish --owner wolfssl-staging C:\workspace\wolfssl-gojimmypi\IDE\PlatformIO\PlatformIO_wolfSSL
```

### Remove published version from staging site:

`pio pkg unpublish [<organization>/]<pkgname>[@<version>] [OPTIONS]`

```
pio pkg unpublish wolfssl-staging/wolfssl@5.6.6-test1
```
