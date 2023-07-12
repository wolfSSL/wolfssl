# Ada Binding Example

Download and install the GNAT community edition compiler and studio:
https://www.adacore.com/download

Linux Install:

```sh
chmod +x gnat-2021-20210519-x86_64-linux-bin
./gnat-2021-20210519-x86_64-linux-bin
```

```sh
export PATH="/opt/GNAT/2021/bin:$PATH"
gprclean
gprbuild default.gpr


./c_tls_server_main
./tls_server_main &
./c_tls_client_main 127.0.0.1
```
