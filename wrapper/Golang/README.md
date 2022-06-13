# wolfSSL Golang Wrapper

This directory contains a very light wrapper around wolfSSL for GO and a server/client example. 

## Building the Server/Client example

The example `.go` files are located in the `wolfSSL-TLS-Server-Client` directory. Switch to that directory and follow the instructions below. 

To build the server, run :
```
go build server.go ssl.go
```

To build the client, run :
```
go build client.go ssl.go
```

Make sure to run both the server and client from within the `wolfSSL-TLS-Server-Client` directory or change the certificate and key paths in the code so that the files are found.

**NOTE**: If you have wolfSSL installed in a non-standard location, edit the `CFLAGS` and `LDFLAGS` specifications in `ssl.go` to correspond to your custom installation path.
