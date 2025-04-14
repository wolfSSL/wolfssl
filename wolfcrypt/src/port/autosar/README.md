## 1.0 Intro To Using wolfSSL with AutoSAR

This readme covers building and using wolfSSL for AutoSAR applications. Currently AES-CBC and RNG are supported. The version of AutoSAR used for reference was 4.4. Currently there is no asynchronous support.


## 2.0 Building wolfSSL

### 2.1 wolfSSL Library
To enable the use of AutoSAR with wolfSSL use the enable option --enable-autosar. In example “./configure --eanble-autosar”. If building without autotools then the macro WOLFSSL_AUTOSAR should be defined. This is usually defined in a user_settings.h file which gets included to the wolfSSL build when the macro WOLFSSL_USER_SETTINGS is defined.


### 2.2 Key Redirection
By default the next available key with the same key type desired is used. When specific keys are to be used then key input redirection is needed. This is done at compile time with setting specific macros. An example of key redirection would be as follows :

/* set redirection of primary and secondary */
#define REDIRECTION_CONFIG 0x03

/* set primary key to keyId of 1 and element type CRYPTO_KE_CIPHER_KEY */
#define REDIRECTION_IN1_KEYID 1
#define REDIRECTION_IN1_KEYELMID 0x01


/* set secondary key to keyId of 4 and element type CRYPTO_KE_CIPHER_IV */
#define REDIRECTION_IN2_KEYID 4
#define REDIRECTION_IN2_KEYELMID 0x05


## 3.0 example

There is an example test case located at wolfcrypt/src/port/autsar/example.c. After compiling with autotools (./configure --enable-autsar && make) the example can be ran by running the command ./wolfcrypt/src/port/autsar/example.test

## 4.0 API Implemented

- Std_ReturnType Csm_Decrypt(uint32 jobId,
         Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
         uint8* resultPtr, uint32* resultLengthPtr);
- Std_ReturnType Csm_Encrypt(uint32 jobId,
         Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
         uint8* resultPtr, uint32* resultLengthPtr);
- Std_ReturnType Csm_KeyElementSet(uint32 keyId, uint32 keyElementId,
         const uint8* keyPtr, uint32 keyLength);
- Std_ReturnType Csm_RandomGenerate( uint32 jobId, uint8* resultPtr,
         uint32* resultLengthPtr);

Along with the structures necessary for these API.
