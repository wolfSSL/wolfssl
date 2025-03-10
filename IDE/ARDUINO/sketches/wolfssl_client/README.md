# Arduino Basic TLS Listening Client

Open the [wolfssl_client.ino](./wolfssl_client.ino) file in the Arduino IDE.

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
