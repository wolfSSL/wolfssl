# Create/Update Signed CA
This document describes how to create/update Signed CA data that is used at an example program.

## Signed CA Creation
### Generate RSA Key pair
```
2048 bit RSA key pair
$ openssl genrsa 2048 2> /dev/null > rsa_private.pem
$ openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem 2> /dev/null
```

### Sign to CA certificate
```
Signed by 2048-bit RSA
$ openssl dgst -sha256 -sign rsa_private.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1-out <signed-CA>.sign <CA-file-for-Signed>

For an example program, it assumes that wolfSSL example CA cert is to be signed.
e.g.
$ openssl dgst -sha256 -sign rsa_private.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1-out Signed-CA.sign /path/for/wolfssl/certs/ca-cert.der
```

### Convert Signed CA to C source
It is able to use `dertoc.pl` to generate c-source data from signed-ca binary data.

```
$ /path/to/wolfssl/scripts/dertoc.pl ./ca-cert.der.sign ca_cert_der_sig example.c
```


## Appendix
### Example Keys
There are multiple example keys for testing in the `example_keys` folder.
```
<example_keys>
|
+----+ rsa_private.pem  an example 2048-bit rsa private key for signing CA cert
     + rsa_public.pem   an example 2048-bit rsa public key for verifying CA cert
     + generate_signCA.sh an example script to generate signed-certificate data for the example program
```
