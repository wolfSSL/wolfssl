# Arduino AES CTR Example

Open the [wolfssl_AES_CTR.ino](./wolfssl_AES_CTR.ino) file in the Arduino IDE.

Other IDE products are also supported, such as:

- [PlatformIO in VS Code](https://docs.platformio.org/en/latest/frameworks/arduino.html)
- [VisualGDB](https://visualgdb.com/tutorials/arduino/)
- [VisualMicro](https://www.visualmicro.com/)

For examples on other platforms, see the [IDE directory](https://github.com/wolfssl/wolfssl/tree/master/IDE).
Additional examples can be found on [wolfSSL/wolfssl-examples](https://github.com/wolfSSL/wolfssl-examples/).


### Troubleshooting

When encountering odd errors such as `undefined reference to ``_impure_ptr'`, such as this:

```text
c:/users/gojimmypi/appdata/local/arduino15/packages/esp32/tools/xtensa-esp32-elf-gcc/esp-2021r2-patch5-8.4.0/bin/../lib/gcc/xtensa-esp32-elf/8.4.0/../../../../xtensa-esp32-elf/bin/ld.exe: C:\Users\gojimmypi\AppData\Local\Temp\arduino\sketches\EAB8D79A02D1ECF107884802D893914E\libraries\wolfSSL\wolfcrypt\src\logging.c.o:(.literal.wolfssl_log+0x8): undefined reference to `_impure_ptr'
collect2.exe: error: ld returned 1 exit status

exit status 1

Compilation error: exit status 1
```

Try cleaning the Arduino cache directories. For Windows, that's typically in:

```text
C:\Users\%USERNAME%\AppData\Local\Temp\arduino\sketches
```

Remove all other boards from other serial ports, leaving one the one being programmed.
