# Infineon Modus Toolbox

Steps for building wolfSSL/wolfTPM with the Infineon Modus Toolbox examples:

1) Add Dependency:

In "deps" folder add wolfssl.mtb containing:

```
https://github.com/wolfssl/wolfssl#v5.7.0-stable#$$ASSET_REPO$$/wolfssl/wolfssl-stable
```

For wolfTPM add wolftpm.mtb containing:

```
https://github.com/wolfssl/wolftpm#master#$$ASSET_REPO$$/wolftpm/wolftpm-stable
```

2) Add components:
In `Makefile` under `COMPONENTS` add `WOLFSSL` and `WOLFTPM`.

3) Add defines:

Add `DEFINES+=WOLFSSL_USER_SETTINGS WOLFTPM_USER_SETTINGS` in Makefile.

4) Build settings:

Add a `user_settings.h` file for wolfSSL/wolfTPM build settings into `config` directory.
A template is provided here in `IDE/Infineon/user_settings.h`.

5) Ignores:

The required library ignores are found in the `.cyignore` file in the wolfSSL and wolfTPM root.
