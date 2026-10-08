## 1.0 Intro To Using wolfSSL with AutoSAR

This readme covers building and using wolfSSL for AutoSAR applications. The
version of AutoSAR used for reference was 4.4. wolfCrypt is plugged in
underneath the standard Csm -> CryIf -> Crypto driver chain, so an application
SW-C calls the standardized Csm_* API.

Currently supported:

- AES-CBC encrypt and decrypt (CRYPTO_ENCRYPT, CRYPTO_DECRYPT)
- Random generation (CRYPTO_RANDOMGENERATE)
- AES-CMAC generate and verify (CRYPTO_MACGENERATE, CRYPTO_MACVERIFY), when
  built with --enable-autosar-cmac. See section 2.4.

Not yet supported. Csm.h declares the full set of AutoSAR service and algorithm
enums, but everything outside the services above sits behind
CSM_UNSUPPORTED_ALGS with no driver implementation:

- hash, AEAD, signature, key derivation and certificate services
- MAC algorithms other than AES-CMAC
- cipher modes other than CBC
- asynchronous jobs. CRYPTO_PROCESSING_SYNC is the only processing type
  accepted. Csm_CancelJob/CryIf_CancelJob do work -- they release the slot a
  job holds -- but there is nothing queued for them to withdraw.
- padding. CRYPTO_ALGOFAM_PADDING_PKCS7 exists as an enum value only, so every
  buffer passed to Csm_Encrypt or Csm_Decrypt must be a whole number of 16 byte
  blocks. Pad in the application.

Two deviations worth noting:

- resultLengthPtr is in/out in the AutoSAR specification, but this port never
  writes back through it for encrypt or decrypt. For CBC the output length
  equals the input length. Csm_RandomGenerate reads it as the number of bytes
  wanted and likewise does not update it. Csm_MacGenerate does update it.
- MAC lengths: Csm_MacVerify's macLength is in BITS, as the specification
  defines it, and Csm_MacGenerate's macLengthPtr is in BYTES. The asymmetry is
  the specification's, not this port's invention, but it is a footgun: passing
  the byte length Csm_MacGenerate returned straight into Csm_MacVerify asks
  for eight times less than intended, and 16 (bytes) becomes 16 bits, which is
  below the floor and refused. Multiply by 8.

  The driver converts a bit length to ceil(macLength / 8) bytes, compares the
  whole bytes and then the trailing partial byte under a mask, so a length
  that is not a multiple of 8 works -- SecOC profile 1's 24 bits happen to
  land on a byte boundary, but nothing requires that. A length longer than
  the 128 bit tag is rejected, which is also what a byte count passed by
  mistake runs into.

  The unit of Csm_MacGenerate's macLengthPtr is UNVERIFIED against the
  specification here: treat it as bytes and confirm before a conformance run.
  A wrong unit there cannot over-read anything, it only reports a length the
  caller may misread.

  wolfSSL_Csm_MacVerifyWithKey is byte-based throughout, being a wolfSSL
  extension, and takes the buffer size beside the length so neither can be
  misread.

The keystore and the job table each have their own mutex, so key provisioning
and a streaming job do not serialize against one another. Within a single job,
AutoSAR assumes one owner: two threads driving the same jobId concurrently is
not supported.


## 2.0 Building wolfSSL

### 2.1 wolfSSL Library
To enable the use of AutoSAR with wolfSSL use the enable option
--enable-autosar. For example "./configure --enable-autosar". With CMake the
equivalent is -DWOLFSSL_AUTOSAR=yes. If building without either then the macro
WOLFSSL_AUTOSAR should be defined. This is usually defined in a user_settings.h
file which gets included to the wolfSSL build when the macro
WOLFSSL_USER_SETTINGS is defined; in that case also add csm.c, cryif.c and
crypto.c from this directory to the build.


### 2.2 Key Redirection
By default the next available key with the same key type desired is used. When
specific keys are to be used then key input redirection is needed. This is done
at compile time with setting specific macros. An example of key redirection
would be as follows :

/* set redirection of primary and secondary */
#define REDIRECTION_CONFIG 0x03

/* set primary key to keyId of 1 and element type CRYPTO_KE_CIPHER_KEY */
#define REDIRECTION_IN1_KEYID 1
#define REDIRECTION_IN1_KEYELMID 0x01


/* set secondary key to keyId of 4 and element type CRYPTO_KE_CIPHER_IV */
#define REDIRECTION_IN2_KEYID 4
#define REDIRECTION_IN2_KEYELMID 0x05

These macros are compiled into csm.c and crypto.c, which makes redirection a
property of the wolfSSL library rather than of the application. With autotools
that means passing them to configure:

./configure --enable-autosar CPPFLAGS="-DREDIRECTION_CONFIG=0x03 \
    -DREDIRECTION_IN1_KEYID=1 -DREDIRECTION_IN1_KEYELMID=0x01 \
    -DREDIRECTION_IN2_KEYID=4 -DREDIRECTION_IN2_KEYELMID=0x05"

Three things to be aware of:

- REDIRECTION_CONFIG is only tested for being defined. The bitmask value (0x03
  above, primary and secondary input redirected) is not interpreted, so any
  non-zero value behaves the same.
- Redirection applies to the whole build. Although Crypto_JobType carries a
  jobRedirectionInfoRef, the CSM points every job at one file-scope struct, so
  there is no per-job redirection at runtime.
- The redirection path does not filter on key length at all, where the default
  scan honours a non-zero algorithm.keyLength. Either way the driver rejects a
  stored key that is not a valid AES key length when it builds the job.


### 2.3 Sizing
Two compile time limits, both overridable:

- MAX_KEYSTORE (default 15) key slots. Csm_KeyElementSet returns E_NOT_OK for a
  keyId at or above this.
- MAX_JOBS (default 10) concurrent streaming jobs. A job's context is allocated
  on CRYPTO_OPERATIONMODE_START and released on CRYPTO_OPERATIONMODE_FINISH, so
  a job abandoned without FINISH holds its slot.


### 2.4 MAC services
The MAC generate and verify services are an add-on to --enable-autosar:

./configure --enable-autosar --enable-autosar-cmac

They are AES-CMAC only. The option turns on wolfCrypt's CMAC for you
(WOLFSSL_CMAC and WOLFSSL_AES_DIRECT), so --enable-cmac is not needed
separately. With CMake the equivalent is -DWOLFSSL_AUTOSAR_CMAC=yes, which
likewise implies -DWOLFSSL_CMAC=yes. Enabling it without --enable-autosar is an
error rather than a silent no-op.

Notes:

- The key is read from key element CRYPTO_KE_MAC_KEY. The specification scopes
  key element IDs per key, so MAC_KEY and CIPHER_KEY share the value 0x01, and
  this port's keystore is flat -- one slot holds one element. The element ID
  therefore cannot tell a cipher key from a MAC key, and a job that lets the
  driver resolve its own key takes the first slot holding 0x01, whichever
  service provisioned it.

  A build using both cipher and MAC services must name the slot it means:

```
  Csm_KeyElementSet(0, CRYPTO_KE_CIPHER_KEY, cipherKey, 16);
  Csm_KeyElementSet(1, CRYPTO_KE_CIPHER_IV,  iv,        16);
  Csm_KeyElementSet(2, CRYPTO_KE_MAC_KEY,    macKey,    16);

  wolfSSL_Csm_EncryptWithKey(jobId, 0, mode, in, inSz, out, &outSz);
  wolfSSL_Csm_MacGenerateWithKey(jobId, 2, mode, in, inSz, mac, &macSz);
```

  These are wolfSSL extensions, not AUTOSAR 4.4 API, hence the prefix. keyId
  names the slot holding the KEY element only; the cipher IV is still resolved
  by the driver, element 0x05 being unambiguous. WOLFSSL_CSM_KEY_ID_ANY is the
  resolve-it-yourself behaviour the plain Csm_* services use.

  Key input redirection (section 2.2) does NOT separate the two: it maps an
  element ID to one slot for every service, so a cipher job and a MAC job both
  resolve to the same slot. keysep_test in the port test covers this.

  A build with the MAC services does not guess. When more than one populated
  slot holds element 0x01, a job that did not name its slot is refused rather
  than resolved to the first match -- otherwise a SW-C written against the
  standard Csm API would quietly compute a CMAC under the AES-CBC key, and the
  verifying side, set up the same way, would accept it. One such slot is
  unambiguous whichever service provisioned it, so a single-key ECU is
  unaffected; an ECU holding several keys must use the *WithKey calls. A build
  without --enable-autosar-cmac has only one user of 0x01 and keeps the plain
  first-match scan.

  Key input redirection and the MAC services cannot both be configured. A
  redirected build maps element 0x01 to ONE slot for every service, so cipher
  and MAC jobs resolve to the same key and the scan's "more than one candidate"
  test has nothing to work with. crypto.c refuses that combination at build
  time rather than per job: refusing per job would mean no unnamed job could
  resolve 0x01 at all, leaving Csm_Encrypt() and Csm_MacGenerate() unusable and
  only the wolfSSL extensions working, which is not something an AUTOSAR port
  should quietly become. Drop redirection and name the slot per job, drop
  --enable-autosar-cmac, or declare with
  WOLFSSL_AUTOSAR_ALLOW_AMBIGUOUS_KEY_ELEMENT that only one of the two services
  is used.

  WOLFSSL_AUTOSAR_ALLOW_AMBIGUOUS_KEY_ELEMENT restores first-match in a build
  that has the MAC services. It is for the ECU that uses only ONE of the two
  services and keeps several of its keys in different slots: 0x01 then has a
  single meaning and first-match is what the port always did. An ECU using
  both services should name the slot instead, which works either way.
- Csm_MacGenerate writes the full 16 byte tag and updates *macLengthPtr.
- Csm_MacVerify accepts a macLength shorter than the full tag, in which case
  the leading bytes are compared, down to WOLFSSL_AUTOSAR_MAC_MIN_SZ bytes.
  That floor defaults to 3, the 24 bit authenticator AUTOSAR SecOC profile 1
  truncates to; shorter is refused, because a 1 or 2 byte tag is forged by
  guessing. The default is below wolfCrypt's own WC_CMAC_TAG_MIN_SZ (4 bytes,
  8 under FIPS), deliberately, so that an AUTOSAR port is not refusing its own
  standard's profile -- raise it to WC_CMAC_TAG_MIN_SZ, or to 16 to refuse
  truncation outright, on an ECU that does not need profile 1. Its return value only says whether the job
  ran: the comparison result is written to verifyPtr as CRYPTO_E_VER_OK or
  CRYPTO_E_VER_NOT_OK. A mismatch is not an E_NOT_OK.
- Streaming works the same as for the cipher services, except that the tag only
  exists once CRYPTO_OPERATIONMODE_FINISH has been processed.


### 2.5 Heap and hardware offload
Csm_ConfigType carries two fields, and Csm_Init() passes both down through
CryIf to the Crypto driver, which applies them to every wolfCrypt context it
creates -- the AES contexts, the CMAC contexts and the DRBG:

    Csm_ConfigType config = WOLFSSL_CSM_CONFIG_DEFAULT;

    config.heap  = NULL;        /* or a WOLFSSL_STATIC_MEMORY hint */
    config.devId = myDeviceId;  /* or INVALID_DEVID for software */
    Csm_Init(&config);

Initialize with WOLFSSL_CSM_CONFIG_DEFAULT rather than zeroing the struct. A
config is taken at face value: devId is copied as given, so a zero-initialized
Csm_ConfigType asks for crypto callback device 0, which is a valid device, not
software. Code written against the older one-field struct that set only heap
needs this.

devId is a wolfCrypt crypto callback device ID. Setting it is what makes the
Crypto driver a front end for an HSM, SHE block or accelerator rather than a
software implementation -- which is the arrangement the CryIf/Crypto split
exists for. The application registers the device first:

    wolfCrypt_Init();
    wc_CryptoCb_RegisterDevice(myDeviceId, myCallback, myCtx);
    Csm_Init(&config);

wolfCrypt_Init() is not optional there: free slots in the crypto callback
device table are marked with INVALID_DEVID, and nothing sets that up until it
runs. Registration fails with BUFFER_E ("out of devices") if it is skipped.
Building wolfSSL with --enable-cryptocb is what provides the callback machinery.

Csm_Init(NULL) selects the default allocator and WOLFSSL_AUTOSAR_DEVID, which
defaults to INVALID_DEVID -- software, exactly as the port behaved before these
fields did anything. A build with no runtime configuration to plumb, such as a
user_settings.h ECU build, can point the whole port at a device by defining
WOLFSSL_AUTOSAR_DEVID instead of passing a config.

Two things to be aware of:

- Calling Csm_Init() again re-reads the configuration, but only while no job
  owns a slot and none is starting. Quiesce the SW-Cs first: FINISH every open
  job, or Csm_CancelJob() the ones that will never be finished. A call made
  while a job is open does nothing at all -- the previous heap, devId, keystore
  and DRBG stay in force -- and since the service returns void, as the
  specification defines it, that refusal is reported to the DET as
  CSM_E_INIT_FAILED (a log line under -DDEBUG_WOLFSSL) rather than to the
  caller. The alternative was worse: a job runs its wolfCrypt context outside
  the driver's locks, so freeing one from under a live job is a use-after-free,
  and the job could still report success having encrypted under zeroed state.

  Once quiescent, the re-init frees the DRBG -- so a later
  Csm_RandomGenerate() builds a fresh one with the new heap and devId -- clears
  the keystore and the job table, and publishes the new configuration while
  holding every lock its readers use. The driver mutexes themselves are created
  once and kept, since re-initializing a live mutex is undefined for pthreads
  and leaks the previous object where wc_InitMutex() allocates one.
- Csm_ConfigType, CryIf_ConfigType and Crypto_ConfigType each gained a field.
  They are only ever passed by pointer and allocated by the caller, but an
  application compiled against the older headers must be rebuilt.


### 2.6 Keys the driver never sees
A keystore slot normally holds the key material. With WOLF_PRIVATE_KEY_ID it
can instead hold a NAME for a key that lives in the device, so the key never
enters RAM at all:

    wolfSSL_Csm_KeyElementSetId(0U, CRYPTO_KE_CIPHER_KEY, id, idLen);
    wolfSSL_Csm_KeyElementSetLabel(0U, CRYPTO_KE_CIPHER_KEY, "ecu-comm-key");

These two are wolfSSL extensions, not AUTOSAR 4.4 Csm API, which is why they
carry the prefix. A cipher job whose key slot names a device key is built with
wc_AesInit_Id() or wc_AesInit_Label() rather than wc_AesSetKey(): the software
key schedule is left empty on purpose, the context reaches the crypto callback,
and a fall-through to a software path fails instead of encrypting under an
all-zero key. Only the IV is still material, because an IV is not secret.

The empty key schedule is what makes this safe, so the port refuses a job it
cannot make that guarantee for, rather than running and hoping:

- A named key with no devId configured (section 2.5) is refused. A name with no
  device behind it names nothing, and the job would otherwise go straight to
  the software path it was supposed to be protected from.
- A build where wolfCrypt's key-is-set check is not enforced refuses named
  CIPHER keys altogether. The check is what turns "no key schedule" into an
  error, and it is absent in two different ways:

  - WOLFSSL_AES_REQUIRE_KEY_SET is not defined, because
    WOLFSSL_NO_AES_KEY_SET_CHECK turned it off.
  - The back end is one of those listed under
    WC_AES_KEY_SET_CHECK_UNSUPPORTED in aes.h -- STM32, Freescale LTC/MMCAU,
    CryptoCell, SCE, SiLabs SE, TI, CAAM, PSA, Xilinx, which are exactly the
    ECU targets this feature is for. These replace wc_AesCbcEncrypt() and
    wc_AesCbcDecrypt() with their own implementations, and those never consult
    WC_AES_KEY_IS_SET: once the crypto callback declines, the call goes to the
    hardware with whatever key state the context holds. Forcing
    WOLFSSL_AES_REQUIRE_KEY_SET on only makes the macro true, so the port
    refuses named cipher keys on such a target regardless of it.

  Without the check, a device that declines the operation falls through and
  encrypts under an all-zero key, reporting success. Where the refusal applies,
  the keystore must hold the key material for cipher jobs; MAC jobs can still
  use a named key, CMAC initialization having its own NULL-key refusal.

Limits worth knowing:

- The MAC services can use a named key too. wolfCrypt stores the name on the
  Cmac, offers the job to the crypto callback, and only rejects a NULL key once
  the callback has declined -- so a MAC job on such a slot either runs in the
  device or fails, and needs no equivalent of the key-is-set condition above.
  machandle_test in the port test checks the tag against a known answer, which
  is what proves the device's key was used.
- MAX_KEY_ID_LEN (32) and MAX_KEY_LABEL_LEN (31) bound what a slot can hold.
  The label limit is one short of wolfCrypt's AES_MAX_LABEL_LEN on purpose:
  wc_AesInit_Label() takes a 32 character label, but wolfCrypt's CMAC keeps one
  only below that length and silently stores nothing at 32, so a 32 character
  label would work for cipher jobs and reach a MAC device with no label.
- Whether an identifier or a label is the right choice is a property of the
  device driver, not of this port: both are passed through untouched.


### 2.7 Module identity and error reporting
Csm.h declares what AUTOSAR expects a module header to declare, so a dependent
module can check it was built against the same release:

    WOLFSSL_CSM_MODULE_ID                   110, per the AUTOSAR module list
    WOLFSSL_CSM_VENDOR_ID                   0, see below
    WOLFSSL_CSM_AR_RELEASE_MAJOR_VERSION    4
    WOLFSSL_CSM_AR_RELEASE_MINOR_VERSION    4
    WOLFSSL_CSM_AR_RELEASE_REVISION_VERSION 0

The vendor ID is assigned by AUTOSAR and wolfSSL has none, so it is 0. Define
WOLFSSL_CSM_VENDOR_ID to the integrator's assigned ID if a conformance run
needs a real one. Csm_GetVersionInfo() reports these two IDs and the wolfSSL
version as the software version, the shim having none of its own.

Development errors go through ReportToDET(), which takes the same arguments as
the AUTOSAR DET entry point:

    void ReportToDET(uint16 moduleId, uint8 instanceId, uint8 apiId,
                     uint8 errorId);

Build with WOLFSSL_AUTOSAR_DET and it forwards straight to

    Std_ReturnType Det_ReportError(uint16 ModuleId, uint8 InstanceId,
                                   uint8 ApiId, uint8 ErrorId);

which the application or the stack supplies -- the port deliberately does not
include Det.h, so it has no dependency on an AUTOSAR include tree. A shared
library build then carries an undefined symbol until the application provides
it; link statically, or allow it, depending on the toolchain. Without
WOLFSSL_AUTOSAR_DET the report goes to the wolfSSL log instead, which needs
--enable-debug and wolfSSL_Debugging_ON() to be visible.

The error IDs are the ones the CSM specification assigns, declared in Csm.h:

    WOLFSSL_CSM_E_PARAM_POINTER    0x01
    WOLFSSL_CSM_E_SMALL_BUFFER     0x03
    WOLFSSL_CSM_E_PARAM_HANDLE     0x04
    WOLFSSL_CSM_E_UNINIT           0x05
    WOLFSSL_CSM_E_INIT_FAILED      0x07
    WOLFSSL_CSM_E_PROCESSING_MODE  0x08

Service IDs (WOLFSSL_CSM_API_ID_*) are a different matter: unlike the module
and error IDs, those values have NOT been checked against the specification's
service ID table. They are only passed through to the DET, so a wrong one
mislabels a report rather than breaking anything, but confirm them before a
conformance run. WOLFSSL_CSM_API_ID_UNKNOWN is available for a call site whose
ID is not known.

Reported so far: CSM_E_PARAM_POINTER from both MAC services,
CSM_E_SMALL_BUFFER from wolfSSL_Csm_MacVerifyWithKey when the MAC length does
not fit the buffer, and CSM_E_INIT_FAILED from Csm_Init when it is refused
because a job is still open -- that one being a failure the caller has no other
way to see, the service returning void. The rest return E_NOT_OK without
reporting, where the specification wants CSM_E_PARAM_POINTER on a NULL pointer
from every service, so WOLFSSL_CSM_E_PARAM_HANDLE, _UNINIT and
_PROCESSING_MODE are declared but not yet reached.

CSM_E_UNINIT in particular: the specification wants every service other than
Csm_GetVersionInfo to report it when called before Csm_Init(). This port does
not track whether it has been initialized, so such a call fails in the driver
without a DET report.

What this port still does not do, if conformance is the goal: the five AUTOSAR
type names aliased with #define rather than typedef (Crypto_JobType and four
others in Csm.h), most of the Csm API (see section 1.0), and no
Csm_MainFunction, which asynchronous processing would need.


## 3.0 example

There is an example test case located at wolfcrypt/src/port/autosar/test.c.
After compiling with autotools (./configure --enable-autosar && make) the
example can be run with the command ./wolfcrypt/src/port/autosar/test.test
It is built unless --disable-examples is used.

The test covers single-shot and streamed AES-CBC, random generation and
keystore exhaustion. Three further cases are compiled in only when their feature
is configured, so the build decides what runs: key redirection needs
REDIRECTION_CONFIG (section 2.2), the AES-CMAC known-answer case needs
--enable-autosar-cmac (section 2.4), and a case that checks a configured devId
really reaches a crypto callback needs --enable-cryptocb (section 2.5). A fourth
needs WOLF_PRIVATE_KEY_ID with it and checks that a key named rather than stored
produces the same ciphertext as the key itself (section 2.6). A fifth needs
WOLFSSL_AUTOSAR_DET, supplies a Det_ReportError() of its own, and checks a
development error arrives with the module and error IDs the specification
assigns (section 2.7).

For standalone example applications that link against an installed wolfSSL, see
the autosar directory of https://github.com/wolfSSL/wolfssl-examples

## 4.0 API Implemented

- void Csm_Init(const Csm_ConfigType* config);
- void Csm_GetVersionInfo(Std_VersionInfoType* version);
- Std_ReturnType Csm_CancelJob(uint32 jobId, Crypto_OperationModeType mode);
- Std_ReturnType Csm_Decrypt(uint32 jobId,
         Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
         uint8* resultPtr, uint32* resultLengthPtr);
- Std_ReturnType Csm_Encrypt(uint32 jobId,
         Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
         uint8* resultPtr, uint32* resultLengthPtr);
- Std_ReturnType Csm_KeyElementSet(uint32 keyId, uint32 keyElementId,
         const uint8* keyPtr, uint32 keyLength);

With WOLF_PRIVATE_KEY_ID, additionally (wolfSSL extensions, see section 2.6):

- Std_ReturnType wolfSSL_Csm_KeyElementSetId(uint32 keyId,
         uint32 keyElementId, const uint8* idPtr, uint32 idLength);
- Std_ReturnType wolfSSL_Csm_KeyElementSetLabel(uint32 keyId,
         uint32 keyElementId, const char* label);
- Std_ReturnType Csm_RandomGenerate( uint32 jobId, uint8* resultPtr,
         uint32* resultLengthPtr);

With --enable-autosar-cmac, additionally:

- Std_ReturnType Csm_MacGenerate(uint32 jobId,
         Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
         uint8* macPtr, uint32* macLengthPtr);
- Std_ReturnType Csm_MacVerify(uint32 jobId,
         Crypto_OperationModeType mode, const uint8* dataPtr, uint32 dataLength,
         const uint8* macPtr, uint32 macLength,
         Crypto_VerifyResultType* verifyPtr);

Along with the structures necessary for these API.

Csm_Init must be called before any other call; it brings up CryIf and the
Crypto driver, including the keystore, the job table and the driver mutexes.
The config argument carries the heap hint and the device ID (section 2.5);
NULL selects the default allocator and WOLFSSL_AUTOSAR_DEVID, which is software
unless the build overrides it. Every Std_ReturnType above
returns E_OK on success and E_NOT_OK on failure; build with --enable-debug and
call wolfSSL_Debugging_ON() to see the reason reported to the DET.
