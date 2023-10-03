This is the Espressif Component Version of wolfSSL v5.6.3-Staging01-237d10a.3, Staging Release #11 (version ^5.6.3-Staging01-237d10a.3)

For questions or beta test of this library, please send a message to support@wolfssl.com

For details on how wolfSSL is published to the ESP Component Registry, see the
[INSTALL.md](https://github.com/wolfssl/wolfssl/tree/master/IDE/Espressif/component-manager/INSTALL.md) file.

See the [wolfSSL Manual](https://www.wolfssl.com/documentation/manuals/wolfssl/index.html).

The [wolfSSL embedded TLS library](https://www.wolfssl.com/products/wolfssl/) is a lightweight, portable, 
C-language-based SSL/TLS library targeted at IoT, embedded, and RTOS environments primarily because of its size, 
speed, and feature set. It works seamlessly in desktop, enterprise, and cloud environments as well. 
wolfSSL supports industry standards up to the current [TLS 1.3](https://www.wolfssl.com/tls13) and DTLS 1.3, 
is up to 20 times smaller than OpenSSL, offers a simple API, an OpenSSL compatibility layer,
OCSP and CRL support, is backed by the robust [wolfCrypt cryptography library](https://github.com/wolfssl/wolfssl/tree/master/wolfcrypt), 
and much more.

The CMVP has issued FIPS 140-2 Certificates #3389 and #2425 for the wolfCrypt Module developed by wolfSSL Inc.  
For more information, see our [FIPS FAQ](https://www.wolfssl.com/license/fips/) or contact fips@wolfssl.com.

# Getting Started

Check out the Examples on the right pane of the [wolfssl component page](https://components.espressif.com/components/wolfssl/wolfssl/).

Typically you need only 4 lines to run an example from scratch in the EDP-IDF environment:

```
. ~/esp/esp-idf/export.sh
idf.py create-project-from-example "wolfssl/wolfssl^5.6.0-stable:wolfssl_benchmark"
cd wolfssl_benchmark
idf.py -b 115200 flash monitor
```

or for VisualGDB:

```
. /mnt/c/SysGCC/esp32/esp-idf/v5.0/export.sh
```


### Espressif Component Notes

Here are some ESP Registry-specific details of the wolfssl component.

#### Component Name

The naming convention of the build-system name of a dependency installed by the component manager
is always `namespace__component`. The namespace for wolfSSL is `wolfssl`. The build-system name
is thus `wolfssl__wolfssl`. We'll soon be publishing `wolfssl__wolfssh`, `wolfssl__wolfmqtt` and more.

A project `cmakelists.txt` doesn't need to mention it at all when using wolfSSL as a managed component.


#### Component Manager

To check which version of the [Component Manager](https://docs.espressif.com/projects/idf-component-manager/en/latest/getting_started/index.html#checking-the-idf-component-manager-version) 
is currently available, use the command:

```
python -m idf_component_manager -h
```

The Component Manager should have been installed during the [installation of the ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/#installation). 
If your version of ESP-IDF doesn't come with the IDF Component Manager, 
you can [install it](https://docs.espressif.com/projects/idf-component-manager/en/latest/guides/updating_component_manager.html#installing-and-updating-the-idf-component-manager):

```
python -m pip install --upgrade idf-component-manager
```

For further details on the Espressif Component Manager, see the [idf-component-manager repo](https://github.com/espressif/idf-component-manager/).

#### Contact

Have a specific request or questions? We'd love to hear from you! Please contact us at 
[support@wolfssl.com](mailto:support@wolfssl.com?subject=Espressif%20Component%20Question) or 
[open an issue on GitHub](https://github.com/wolfSSL/wolfssl/issues/new/choose).

# Licensing and Support

wolfSSL (formerly known as CyaSSL) and wolfCrypt are either licensed for use
under the GPLv2 (or at your option any later version) or a standard commercial
license. For our users who cannot use wolfSSL under GPLv2
(or any later version), a commercial license to wolfSSL and wolfCrypt is
available. 

See the [LICENSE.txt](./LICENSE.txt), visit [wolfssl.com/license](https://www.wolfssl.com/license/),
contact us at [licensing@wolfssl.com](mailto:licensing@wolfssl.com?subject=Espressif%20Component%20License%20Question) 
or call +1 425 245 8247

View Commercial Support Options: [wolfssl.com/products/support-and-maintenance](https://www.wolfssl.com/products/support-and-maintenance/)
