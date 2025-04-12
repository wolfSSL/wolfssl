# Arduino Basic TLS Listening Client

Open the `wolfssl_client.ino` file in the Arduino IDE.

NOTE: Moving; See https://github.com/wolfSSL/wolfssl-examples/pull/499

If using WiFi, be sure to set `ssid` and `password` values.

May need "Ethernet by Various" library to be installed. Tested with v2.0.2 and v2.8.1.

See the `#define WOLFSSL_TLS_SERVER_HOST` to set your own server address.

Other IDE products are also supported, such as:

- [PlatformIO in VS Code](https://docs.platformio.org/en/latest/frameworks/arduino.html)
- [VisualGDB](https://visualgdb.com/tutorials/arduino/)
- [VisualMicro](https://www.visualmicro.com/)

For examples on other platforms, see the [IDE directory](https://github.com/wolfssl/wolfssl/tree/master/IDE).
Additional examples can be found on [wolfSSL/wolfssl-examples](https://github.com/wolfSSL/wolfssl-examples/).


### Troubleshooting

When encountering odd errors such as `undefined reference to ``_impure_ptr'`, try cleaning the Arduino
cache directories. For Windows, that's typically in:

```text
C:\Users\%USERNAME%\AppData\Local\Temp\arduino\sketches
```
