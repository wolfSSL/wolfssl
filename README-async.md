# wolfSSL / wolfCrypt Asynchronous Support

The asynchronous code was previously maintained at https://github.com/wolfSSL/wolfAsyncCrypt but was integrated into wolfSSL proper starting with release v5.8.4.

This feature is enabled using:
`./configure --enable-asynccrypt` or `#define WOLFSSL_ASYNC_CRYPT`.

If async crypto is enabled but no hardware backend is enabled or if `WOLFSSL_ASYNC_CRYPT_SW` is defined, a software backend using wolfCrypt is used instead. This software backend can simulate periodic hardware delays using the macro `WOLF_ASYNC_SW_SKIP_MOD`, which is on by default if `DEBUG_WOLFSSL` is defined.

## Design

Each crypto algorithm has its own `WC_ASYNC_DEV` structure, which contains a `WOLF_EVENT`, local crypto context and local hardware context.

For SSL/TLS the `WOLF_EVENT` context is the `WOLFSSL*` and the type is `WOLF_EVENT_TYPE_ASYNC_WOLFSSL`. For wolfCrypt operations the `WOLF_EVENT` context is the `WC_ASYNC_DEV*` and the type is `WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT`.

A generic event system has been created using a `WOLF_EVENT` structure when `HAVE_WOLF_EVENT` is defined. The event structure resides in the `WC_ASYNC_DEV`.

The asynchronous crypto system is modeled after epoll. The implementation uses `wolfSSL_AsyncPoll` or `wolfSSL_CTX_AsyncPoll` to check if any async operations are complete.

## Hardware Backends

Supported hardware backends:

* Intel QuickAssist with QAT 1.6 or QAT 1.7 driver. See README.md in `wolfcrypt/src/port/intel/README.md`.
* Cavium Nitrox III and V. See README.md in `wolfcrypt/src/port/cavium/README.md`.

## wolfCrypt Backend

The wolfCrypt backend uses the same API as the hardware backends do. Once an asynchronous operation is initiated with the software backend, subsequent calls to `wolfSSL_AsyncPoll` will call into wolfCrypt to complete the operation. If non-blocking is enabled, for example, for ECC (via `WC_ECC_NONBLOCK`), each `wolfSSL_AsyncPoll` will do a chunk of work for the operation and return, to minimize blocking time.

## API's

### ```wolfSSL_AsyncPoll```
```
int wolfSSL_AsyncPoll(WOLFSSL* ssl, WOLF_EVENT_FLAG flags);
```

Polls the provided WOLFSSL object's reference to the WOLFSSL_CTX's event queue to see if any operations outstanding for the WOLFSSL object are done. Return the completed event count on success.

### ```wolfSSL_CTX_AsyncPoll```
```
int wolfSSL_CTX_AsyncPoll(WOLFSSL_CTX* ctx, WOLF_EVENT** events, int maxEvents, WOLF_EVENT_FLAG flags, int* eventCount)
```

Polls the provided WOLFSSL_CTX context event queue to see if any pending events are done. If the `events` argument is provided then a pointer to the `WOLF_EVENT` will be returned up to `maxEvents`. If `eventCount` is provided then the number of events populated will be returned. The `flags` allows for `WOLF_POLL_FLAG_CHECK_HW` to indicate if the crypto backend (i.e. hardware or wolfCrypt, if the software implementation is being used) should be polled again or just return more events.

### ```wolfAsync_DevOpen```
```
int wolfAsync_DevOpen(int *devId);
```

Open the async device and returns an `int` device id for it.

### ```wolfAsync_DevOpenThread```
```
int wolfAsync_DevOpenThread(int *devId, void* threadId);
```
Opens the async device for a specific thread. A crypto instance is assigned and thread affinity set.

### ```wolfAsync_DevClose```
```
void wolfAsync_DevClose(int *devId)
```

Closes the async device.

### ```wolfAsync_DevCopy```
```
int wolfAsync_DevCopy(WC_ASYNC_DEV* src, WC_ASYNC_DEV* dst);
```

Copy async device memory safe (not pointers to old device).

### ```wolfAsync_DevCtxInit```
```
int wolfAsync_DevCtxInit(WC_ASYNC_DEV* asyncDev, word32 marker, void* heap, int devId);
```

Initialize the device context and open the device hardware using the provided `WC_ASYNC_DEV ` pointer, marker and device id (from wolfAsync_DevOpen).

### ```wolfAsync_DevCtxFree```
```
void wolfAsync_DevCtxFree(WC_ASYNC_DEV* asyncDev);
```

Closes and free's the device context.


### ```wolfAsync_EventInit```
```
int wolfAsync_EventInit(WOLF_EVENT* event, enum WOLF_EVENT_TYPE type, void* context, word32 flags);
```

Initialize an event structure with provided type and context. Sets the pending flag and the status code to `WC_PENDING_E`. Current flag options are `WC_ASYNC_FLAG_NONE` and `WC_ASYNC_FLAG_CALL_AGAIN` (indicates crypto needs called again after WC_PENDING_E).

### ```wolfAsync_EventWait ```
```
int wolfAsync_EventWait(WOLF_EVENT* event);
```

Waits for the provided event to complete.

### ```wolfAsync_EventPoll```
```
int wolfAsync_EventPoll(WOLF_EVENT* event, WOLF_EVENT_FLAG event_flags);
```

Polls the provided event to determine if its done.

### ```wolfAsync_EventPop ```

```
int wolfAsync_EventPop(WOLF_EVENT* event, enum WOLF_EVENT_TYPE event_type);
```

This will check the event to see if the event type matches and the event is complete. If it is then the async return code is returned. If not then `WC_NOT_PENDING_E` is returned.


### ```wolfAsync_EventQueuePush```
```
int wolfAsync_EventQueuePush(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event);
```

Pushes an event to the provided event queue and assigns the provided event.

### ```wolfAsync_EventQueuePoll```
```
int wolfAsync_EventQueuePoll(WOLF_EVENT_QUEUE* queue, void* context_filter,
    WOLF_EVENT** events, int maxEvents, WOLF_EVENT_FLAG event_flags, int* eventCount);
```

Polls all events in the provided event queue. Optionally filters by context. Will return pointers to the done events.

### ```wc_AsyncHandle```
```
int wc_AsyncHandle(WC_ASYNC_DEV* asyncDev, WOLF_EVENT_QUEUE* queue, word32 flags);
```

This will push the event inside asyncDev into the provided queue.

### ```wc_AsyncWait```
```
int wc_AsyncWait(int ret, WC_ASYNC_DEV* asyncDev, word32 flags);
```

This will wait until the provided asyncDev is done (or error).

### ```wolfAsync_HardwareStart```
```
int wolfAsync_HardwareStart(void);
```

If using multiple threads this allows a way to start the hardware before using `wolfAsync_DevOpen` to ensure the memory system is setup. Ensure that `wolfAsync_HardwareStop` is called on exit. Internally there is a start/stop counter, so this can be called multiple times, but stop must also be called the same number of times to shutdown the hardware.

### ```wolfAsync_HardwareStop```
```
void wolfAsync_HardwareStop(void);
```

Stops hardware if internal `--start_count == 0`.

## Examples

### TLS Server Example

```c
int devId = INVALID_DEVID;

ret = wolfAsync_DevOpen(&devId);
if (ret != 0) {
    err_sys("Async device open failed");
}
wolfSSL_CTX_SetDevId(ctx, devId);

do {
    err = 0; /* reset error */
    ret = wolfSSL_accept(ssl, msg, msgSz, &msgSz);
    if (ret <= 0) {
        err = wolfSSL_get_error(ssl, 0);
        if (err == WC_PENDING_E) {
            ret = wolfSSL_AsyncPoll(ssl, WOLF_POLL_FLAG_CHECK_HW);
            if (ret < 0) break;
        }
    }
} while (err == WC_PENDING_E);
if (ret != WOLFSSL_SUCCESS) {
    err_sys("SSL_connect failed");
}

wolfAsync_DevClose(&devId);
```

### wolfCrypt RSA Example

```c
static int devId = INVALID_DEVID;
RsaKey key;

ret = wolfAsync_DevOpen(&devId);
if (ret != 0)
    err_sys("Async device open failed");

wc_InitRsaKey_ex(&key, HEAP_HINT, devId);
if (ret == 0) {
    ret = wc_RsaPrivateKeyDecode(tmp, &idx, &key, (word32)bytes);
    do {
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
        if (ret >= 0)
            ret = wc_RsaPublicEncrypt(in, inLen, out, outSz, &key, &rng);
    } while (ret == WC_PENDING_E);
    wc_FreeRsaKey(&key);
}

wolfAsync_DevClose(&devId);
```

## Build Options

1. Async multi-threading can be disabled by defining `WC_NO_ASYNC_THREADING`. This only disables internal async threading functions. You are free to use other threading APIs or paradigms in your application.
2. Software benchmarks can be disabled by defining `NO_SW_BENCH`.
3. The `WC_ASYNC_THRESH_NONE` define can be used to disable the cipher thresholds, which are tunable values to determine at what size hardware should be used vs. software.
4. Use `WOLFSSL_DEBUG_MEMORY` and `WOLFSSL_TRACK_MEMORY` to help debug memory issues. QAT also supports `WOLFSSL_DEBUG_MEMORY_PRINT`.


## References

### TLS Client/Server Async Example

We have a full TLS client/server async examples here:

* [https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/server-tls-epoll-perf.c](https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/server-tls-epoll-perf.c)

* [https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/client-tls-perf.c](https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/client-tls-perf.c)

#### TLS Threaded epoll Example Building

```sh
git clone git@github.com:wolfSSL/wolfssl-examples.git
cd wolfssl-examples
cd tls
# For QuickAssist: Uncomment QAT lines at top of Makefile
make
```

#### TLS Threaded epoll Example Usage

```sh
$ ./client-tls-perf -?
perf 4.5.0 (NOTE: All files relative to wolfSSL home dir)
-?          Help, print this usage
-p <num>    Port to listen on, not 0, default 11111
-v <num>    SSL version [0-3], SSLv3(0) - TLS1.2(3)), default 3
-l <str>    Cipher suite list (: delimited)
-c <file>   Certificate file,           default ../certs/client-cert.pem
-k <file>   Key file,                   default ../certs/client-key.pem
-A <file>   Certificate Authority file, default ../certs/ca-cert.pem
-r          Resume session
-n <num>    Benchmark <num> connections
-N <num>    <num> concurrent connections
-R <num>    <num> bytes read from client
-W <num>    <num> bytes written to client
-B <num>    Benchmark <num> written bytes
```

#### TLS Threaded epoll Example Output

```sh
$ sudo ./server-tls-epoll-threaded -n 10000
$ sudo ./client-tls-perf -n 10000

wolfSSL Server Benchmark 16384 bytes
    Num Conns         :     10000
    Total             : 18575.800 ms
    Total Avg         :     1.858 ms
    t/s               :   538.335
    Accept            : 35848.428 ms
    Accept Avg        :     3.585 ms
    Total Read bytes  : 163840000 bytes
    Total Write bytes : 163840000 bytes
    Read              :   402.212 ms (  388.476 MBps)
    Write             :   591.469 ms (  264.173 MBps)
```

## Change Log

### wolfSSL Async Release v5.8.0 (May 01, 2025)
* Includes all wolfSSL v5.8.0 fixes. See ChangeLog.md here: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md#wolfssl-release-580-apr-24-2025
* Update for libwolfssl_sources.h refactor. (https://github.com/wolfSSL/wolfAsyncCrypt/pull/77)

### wolfSSL Async Release v5.7.4 (Oct 29, 2024)
* Includes all wolfSSL v5.7.4 fixes. See ChangeLog.md here: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md#wolfssl-release-574-oct-24-2024
 - Plus fixes for asynchronous release - SHA3/HMAC devId (https://github.com/wolfSSL/wolfssl/pull/8119)
* Fix for Intel QuickAssist RSA Key generation exponent result. (https://github.com/wolfSSL/wolfAsyncCrypt/pull/75)

### wolfSSL Async Release v5.7.0 (Mar 21, 2023)
* Includes all wolfSSL v5.7.0 fixes. See ChangeLog.md here: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md#wolfssl-release-570-mar-20-2024

### wolfSSL Async Release v5.6.6 (Dec 20, 2023)
* Includes all wolfSSL v5.6.6 fixes. See ChangeLog.md here: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md#wolfssl-release-566-dec-19-2023
 - Plus wolfSSL PR 7085 fix for invalid `dh_ffdhe_test` for even P when using Intel QuickAssist. https://github.com/wolfSSL/wolfssl/pull/7085
* Fix for missing `IntelQaFreeFlatBuffer` with DH enabled and no keygen. (broken in PR #71)
* Add return code checking for wc_AsyncThreadCreate_ex in exit_fail section for pthread_attr_destroy. (PR #72)

### wolfSSL Async Release v5.6.4 (Oct 30, 2023)
* Fixes for support async with crypto or pk callbacks.
* Rename `WC_NOT_PENDING_E` -> `WC_NO_PENDING_E`

### wolfSSL Async Release v5.6.3 (June 16, 2023)
* Includes all wolfSSL v5.6.3 fixes. See ChangeLog.md here: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md#wolfssl-release-563-jun-16-2023
* Add sanity check of index devId before accessing array
* Use the blocking call from the async test

### wolfSSL Async Release v5.6.0 (Mar 29, 2023)
* Includes all wolfSSL v5.6.0 fixes. See ChangeLog.md here: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md#wolfssl-release-560-mar-24-2023
* wolfAsyncCrypt github repository became public.

### wolfSSL Async Release v5.5.4 (Dec 22, 2022)

* Includes all wolfSSL v5.5.4 fixes. See ChangeLog.md here: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md#wolfssl-release-554-dec-21-2022
* Use the `wc_ecc_shared_secret_ex` version for async test. Requires https://github.com/wolfSSL/wolfssl/pull/5868

### wolfSSL Async Release v5.5.3 (Nov 8, 2022)

* Includes all wolfSSL v5.5.1-v5.5.3 fixes. See ChangeLog.md here: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md#wolfssl-release-553-nov-2-2022
* Fix for Intel QAT handling of sign R when cofactor is not 1. https://github.com/wolfSSL/wolfssl/pull/5737 and https://github.com/wolfSSL/wolfAsyncCrypt/pull/54
* Fix check scalar bits for ECC cofactor. https://github.com/wolfSSL/wolfssl/pull/5737
* Fixes for async sniffer: https://github.com/wolfSSL/wolfssl/pull/5734
  - Handling of packets with multiple TLS messages.
  - Multiple back to back sessions.
  - Ensure all pending queued packets are finished before ending pcap processing.
* Fix for various tests that do not properly handle `WC_PENDING_E`. https://github.com/wolfSSL/wolfssl/pull/5773
* Revert "Fix for sniffer to decode out of order packets". https://github.com/wolfSSL/wolfssl/pull/5771

### wolfSSL Async Release v5.5.0 (Sep 2, 2022)

* Includes all wolfSSL v5.5.0 fixes. See ChangeLog.md here: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md#wolfssl-release-550-aug-30-2022
* Fix for handling return codes from `pthread_attr_destroy`.
* Fix for async session tickets. https://github.com/wolfSSL/wolfssl/pull/5534
* Fix for async with OCSP non-blocking in ProcessPeerCerts. https://github.com/wolfSSL/wolfssl/pull/5539

### wolfSSL Async Release v5.4.0 (July 11, 2022)
* Fix for DH trim of leading zeros to use memmove.
* Fix to print errors to stderr.
* Fix to consistently return the status of failed pthreads funcs.
* Move async device pointer (https://github.com/wolfSSL/wolfssl/pull/5149)

### wolfSSL Async Release v5.3.0 (May 5, 2022)

* Added Intel QuickAssist ECC Key Generation acceleration. Specifically point multiplication similar to our `wc_ecc_mulmod_ex2`.
* Fix for building Intel QAT with SP math all
* Fix for `error: unused function 'IntelQaFreeFlatBuffer'`.
* Fix for handling the Koblitz curve param "a", which is all zeros.
* Fixes for scan-build warnings.
* Includes wolfSSL PR https://github.com/wolfSSL/wolfssl/pull/5101

### wolfSSL Async Release v5.2.0 (Feb 21, 2022)

* Adds `WC_NO_ASYNC_SLEEP` option to hide wc_AsyncSleep for platforms that do not need it.
* Fix for async test anonymous union on some platforms (`#pragma anon_unions` and `HAVE_ANONYMOUS_INLINE_AGGREGATES`)
* Fixes for invalidPrintfArgType_sint (cppcheck) and readability-redundant-preprocessor (clang-tidy).

### wolfSSL Async Release v5.1.0 (Jan 3rd, 2022)


### wolfSSL Async Release v5.0.0 (11/01/2021)

* Fix for issue with QAT AES GCM input buffer already NUMA and not aligned.

### wolfSSL Async Release v4.8.0 (07/14/2021)

* Fix for new QAT 1.7 hash types warning.
* Updated Intel QAT 1.7 build instructions.
* Includes possible HAVE_WOLF_BIGINT leaks in PR https://github.com/wolfSSL/wolfssl/pull/4208

### wolfSSL Async Release v4.7.0 (02/20/2021)

* Fix for ARC4 macro typo

### wolfSSL Async Release v4.6.0 (12/21/2020)

* Documentation updates.
* Fixes for Cavium Nitrox and Intel Quick Assist (wolfSSL/wolfssl#3577) with TLS v1.3

### wolfSSL Async Release v4.4.0 (04/24/2020)

* Fix for uninitialized `supSha3` warning.
* Fix for use of incorrect devId for wolfSSL_SHA3_256_Init.
* Fix for QAT with Shake256.
* Fix for QAT example `./build.sh`.

### wolfSSL Async Release v4.3.0 (12/20/2019)

* Fix for async date override callback issue.
* Updates to Octeon README.

### wolfSSL Async Release v4.2.0 (10/22/2019)

* Fix for QuickAssist DH Agree issue with leading zero bytes.
* Fix for QuickAssist AES CBC issue with previous IV on back-to-back operations.
* Updates to QuickAssist README.md for latest QAT v1.7 driver.
* Instructions for Octeon III (CN7300) use.

### wolfSSL Async Release v4.0.0 (03/25/2019)

* Fix for building with QuickAssist v1.7 driver (4.4.0-00023) (was missing usdm_drv during configure with check).
* Fix for building async with file system disabled.
* Fix for SHA-3 runtime detection for not supported in hardware.

### wolfSSL Async Release v3.15.8 (03/01/2019) - Intermediate release

* Performance improvements for QuickAssist.
* Added new build option `QAT_POLL_RESP_QUOTA` to indicate maximum number of callbacks to service per poll. The default is 0 (all), was previously 8.
* Added useful QAT_DEBUG logging for ECC and DH operations.
* Cleanup whitespace in quickassist.c.
* Enhanced the Cavium macros for `CAVIUM_MAX_PENDING` and `CAVIUM_MAX_POLL` over-ridable.
* Added build-time override for benchmark thread count `WC_ASYNC_BENCH_THREAD_COUNT`.
* Fixes for wolfCrypt test with asynchronous support enabled and `--enable-nginx`.
* Fix to use QAT for ECC sign and verify when SP is enabled and key was initialized with devId.
* Fixes issues with wolfCrypt test and QAT not properly calling "again" for the ECC sign, verify and shared secret.
* Correct the output for multi-threaded benchmark using `-base10` option.
* Fixes to QAT HMAC enables in benchmark tool.
* Adds new `NO_HW_BENCH` to support using multi-threaded software only benchmarks.

### wolfSSL Async Release v3.15.7 (12/27/2018)

* Fixes for various analysis warnings (https://github.com/wolfSSL/wolfssl/pull/2003).
* Added QAT v1.7 driver support.
* Added QAT SHA-3 support.
* Added QAT RSA Key Generation support.
* Added support for new usdm memory driver.
* Added support for detecting QAT version and features.
* Added `QAT_ENABLE_RNG` option to disable QAT TRNG/DRBG.
* Added alternate hashing method to cache all updates (avoids using partial updates).

### wolfSSL Async Release v3.15.5 (11/09/2018)

* Fixes for various analysis warnings (https://github.com/wolfSSL/wolfssl/pull/1918).
* Fix for QAT possible double free case where `ctx->symCtx` is not trapped.
* Improved QAT debug messages when using `QAT_DEBUG`.
* Fix for QAT RNG to allow zero length. This resolves PSS case where `wc_RNG_GenerateBlock` is called for saltLen == 0.


### wolfSSL Async Release v3.15.3 (06/20/2018)

* Fixes for fsantize tests with Cavium Nitrox V.
* Removed typedef for `CspHandle`, since its already defined.
* Fixes for a couple of fsanitize warnings.
* Fix for possible leak with large request to `IntelQaDrbg`.

### wolfSSL Async Release v3.14.4 (04/13/2018)

* Added Nitrox V ECC.
* Added Nitrox V SHA-224 and SHA-3
* Added Nitrox V AES GCM
* Added Nitrox III SHA2 384/512 support for HMAC.
* Added error code handling for signature check failure.
* Added error translate for `ERR_PKCS_DECRYPT_INCORRECT`
* Added useful `WOLFSSL_NITROX_DEBUG` and show count for pending checks.
* Cleanup of Nitrox symmetric processing to use single while loops.
* Cleanup to only include some headers in cavium_nitrox.c port.
* Fixes for building against Nitrox III and V SDK.
* Updates to README.md with required CFLAGS/LDFLAGS when building without ./configure.
* Fix for Intel QuickAssist HMAC to use software for unsupported hash algorithms.


### wolfSSL Async Release v3.12.2 (10/22/2017)

* Fix for HMAC QAT when block size aligned. The QAT HMAC final without any buffers will fail incorrectly (bug in QAT 1.6).
* Nitrox fix for rename of `ContextType` to `context_type_t`. Updates to Nitrox README.md.
* Workaround for `USE_QAE_THREAD_LS` issue with realloc from a different thread.
* Fix for hashing to allow zero length. This resolves issue with new empty hash tests.
* Fix bug with blocking async where operation was being free'd before completion. Set freeFunc prior to performing operation and check ret code in poll.
* Fix leak with cipher symmetric context close.
* Fix QAT_DEBUG partialState offset.
* Fixes for symmetric context caching.
* Refactored async event initialization so its done prior to making possible async calls.
* Fix to resolve issue with QAT callbacks and multi-threading.
* The cleanup is now handled in polling function and the event is only marked done from the polling thread that matches the originating thread.
* Fix possible mem leak with multiple threads `g_qatEcdhY` and `g_qatEcdhCofactor1`.
* Fix the block polling to use `ret` instead of `status`.
* Change order of `IntelQaDevClear` and setting `event->ret`.
* Fixes to better handle threading with async.
* Refactor of async event state.
* Refactor to initialize event prior to operation (in case it finishes before adding to queue).
* Fixes issues with AES GCM decrypt that can corrupt up to authTag bytes at end of output buffer provided.
* Optimize the Hmac struct to replace keyRaw with ipad.
* Enhancement to allow reuse of the symmetric context for ciphers.
* Fixes for QuickAssist (QAT) multi-threading. Fix to not set return code until after callback cleanup.
* Disable thread binding to specific CPU by default (enabled now with `WC_ASYNC_THREAD_BIND`).
* Added optional define `QAT_USE_POLLING_CHECK ` to have only one thread polling at a time (not required and doesn't improve performance).
* Reduced default QAT_MAX_PENDING for benchmark to 15 (120/num_threads).
* Fix for IntelQaDrbg to handle buffer over 0xFFFF in length.
* Added working DRBG and TRNG implementations for QAT.
* Fix to set callback status after ret and output have been set. Cleanup of the symmetric context.
* Updates to support refactored dynamic types.
* Fix for QAT symmetric to allow NULL authTag.
* Fix GCC 7 build warning with braces.
* Cleanup formatting.

### wolfSSL Async Release v3.11.0 (05/05/2017)

* Fixes for Cavium Nitrox III/V.
    - Fix with possible crash when using a request Id that is already complete, due to partial submissions not marking event done.
    - Improvements to max buffer lengths.
    - Fixes to handle various return code patterns with CNN55XX-SDK.
    - All Nitrox V tests and benchmarks pass. Bench: RSA 2048-bit public 336,674 ops/sec and private (CRT) 66,524 ops/sec.

* Intel QuickAssist support and various async fixes/improvements:
    - Added support for Intel QuickAssist v1.6 driver with QuickAssist 8950 hardware
    - Added QAE memory option to use static memory list instead of dynamic list using `USE_QAE_STATIC_MEM`.
    - Added tracking of deallocs and made the values signed long.
    - Improved code for wolf header check and expanded to 16-byte alignment for performance improvement with TLS.
    - Added ability to override limit dev access parameters and all configurable QAT fields.
    - Added async simulator tests for DH, DES3 CBC and AES CBC/GCM.
    - Rename AsyncCryptDev to WC_ASYNC_DEV.
    - Refactor to move WOLF_EVENT into WC_ASYNC_DEV.
    - Refactor the async struct/enum names to use WC_ naming.
    - Refactor of the async event->context to use WOLF_EVENT_TYPE_ASYNC_WOLFSSL or WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT to indicate the type of context pointer.
    - Added flag to WOLF_EVENT which is used to determine if the async complete should call into operation again or goto next `WC_ASYNC_FLAG_CALL_AGAIN`.
    - Cleanup of the "wolfAsync_DevCtxInit" calls to make sure asyncDev is always cleared if invalid device id is used.
    - Eliminated WOLFSSL_ASYNC_CRYPT_STATE.
    - Removed async event type WOLF_EVENT_TYPE_ASYNC_ANY.
    - Enable the random extra delay option by default for simulator as it helps catch bugs.
    - Cleanup for async free to also check marker.
    - Refactor of the async wait and handle to reduce duplicate code.
    - Added async simulator test for RSA make key.
    - Added WC_ASYNC_THRESH_NONE to allow bypass of threshold for testing
    - Added static numbers for the async sim test types, for easier debugging of the “testDev->type” value.
    - Populate heap hint into asyncDev struct.
    - Enhancement to cache the asyncDev to improve poll performance.
    - Added async threading helpers and new wolfAsync_DevOpenThread.
    - Added WC_NO_ASYNC_THREADING to prevent async threading.
    - Added new API “wc_AsyncGetNumberOfCpus” for getting number of CPU’s.
    - Added new “wc_AsyncThreadYield” API.
    - Added WOLF_ASYNC_MAX_THREADS.
    - Added new API for wolfAsync_DevCopy.
    - Fix to make sure an async init failure sets the deviceId to INVALID_DEVID.
    - Fix for building with async threading support on Mac.
    - Fix for using simulator so it supports multiple threads.

* Moved Intel QuickAssist and Cavium Nitrox III/V code into async repo.
* Added new WC_ASYNC_NO_* options to allow disabling of individual async algorithms.
    - New defines are: WC_ASYNC_NO_CRYPT, WC_ASYNC_NO_PKI and WC_ASYNC_NO_HASH.
    - Additionally each algorithm has a WC_ASYNC_NO_[ALGO] define.


### wolfSSL Async Release v3.9.8 (07/25/2016)

* Asynchronous wolfCrypt and Cavium Nitrox V support.

### wolfSSL Async Release v3.9.0 (03/04/2016)

* Initial version with async simulator and README.md.


## Support

For questions email wolfSSL support at support@wolfssl.com
