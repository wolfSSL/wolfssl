/* user_settings_embedded.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Embedded configuration with CPU, assembly and math selection.
 *
 * Everything is driven by the WC_CFG_* switches in sections 1 to 8 below.
 * Set those; the "derived settings" half of the file turns them into the
 * wolfSSL defines and does not normally need editing.
 *
 * See doc/ASM_AND_MATH_DEFINES.md for what each generated define does and
 * which CPUs support which kind of assembly.
 *
 * Build and test:
 *   cp ./examples/configs/user_settings_embedded.h user_settings.h
 *   ./configure --enable-usersettings --disable-examples
 *   make
 *   ./wolfcrypt/test/testwolfcrypt
 *
 * The defaults are portable C, so the recipe above works on a host as-is.
 * Set one WC_CFG_CPU_* switch in section 1 for a real target.
 *
 * Testing an assembly configuration with autotools needs two extra things,
 * because --enable-usersettings deliberately adds no CFLAGS of its own:
 *   - the matching --enable-* option, so the assembly files are added to the
 *     build at all (--enable-sp-asm, --enable-intelasm, --enable-armasm,
 *     --enable-riscv-asm, --enable-ppc32-asm, --enable-ppc64-asm);
 *   - the instruction set flags for the compiler, since some accelerated code
 *     is written as intrinsics rather than assembly.
 * For example:
 *   x86_64  ./configure --enable-usersettings --disable-examples \
 *               --enable-intelasm --enable-sp-asm
 *           make CFLAGS="-O2 -maes -msse4 -mpclmul"
 *   Aarch64 ./configure --host=aarch64-linux-gnu --enable-usersettings \
 *               --disable-examples --enable-armasm --enable-sp-asm \
 *               CFLAGS="-O2 -march=armv8-a+crypto -mstrict-align"
 * Autotools picks the ARM-mode port files for a generic "arm" host, so a
 * Cortex-M or Thumb profile is best built from the project's own makefile or
 * IDE with the file list below rather than through ./configure.
 *
 * Source files to add to a hand-built project, by CPU (in addition to the
 * usual wolfcrypt sources):
 *   all targets     wolfcrypt/src/sp_int.c
 *   portable 32-bit wolfcrypt/src/sp_c32.c
 *   portable 64-bit wolfcrypt/src/sp_c64.c
 *   Cortex-M        wolfcrypt/src/sp_cortexm.c
 *   ARM Thumb       wolfcrypt/src/sp_armthumb.c
 *   ARM32           wolfcrypt/src/sp_arm32.c
 *   Aarch64         wolfcrypt/src/sp_arm64.c
 *   x86_64          wolfcrypt/src/sp_x86_64.c, sp_x86_64_asm.S
 * The ARM SP files hold their assembly inline in C, so no .S file is needed
 * for them. For the per-algorithm assembly add the matching files from
 * wolfcrypt/src/port/arm/, port/riscv64/, port/ppc32/ or port/ppc64/ - the
 * ".S" variants, or the "_asm_c.c" variants when WC_CFG_ASM_INLINE is set.
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* 1. TARGET CPU - set exactly one to 1                                      */
/* ========================================================================= */
/* PORTABLE is plain C for any CPU. It ignores section 2 entirely. */
#define WC_CFG_CPU_PORTABLE        1
#define WC_CFG_CPU_CORTEX_M        0   /* Cortex-M3/M4/M7/M33 (Thumb-2) */
#define WC_CFG_CPU_ARM_THUMB       0   /* Thumb: Cortex-M0/M0+/M1/M23 */
#define WC_CFG_CPU_ARM32           0   /* ARMv4/v6/v7-A, ARM mode */
#define WC_CFG_CPU_AARCH64         0   /* ARMv8-A 64-bit */
#define WC_CFG_CPU_RISCV32         0
#define WC_CFG_CPU_RISCV64         0
#define WC_CFG_CPU_PPC32           0
#define WC_CFG_CPU_PPC64           0
#define WC_CFG_CPU_X86_64          0   /* host builds / simulators */

/* ARM architecture level: 4, 6 or 7. Ignored for Aarch64. Set 6 for a
 * Thumb-1 core (ARMv6-M / ARMv8-M baseline), which has no Thumb-2 assembly;
 * 7 for Thumb-2 (ARMv7-M and later, ARMv7-A, Cortex-R). See
 * doc/ASM_AND_MATH_DEFINES.md section 6 for the full per-architecture table. */
#define WC_CFG_ARM_ARCH            7

/* ========================================================================= */
/* 2. ASSEMBLY                                                               */
/* ========================================================================= */
/* Master switch. 0 gives pure C everywhere (WOLFSSL_NO_ASM). */
#define WC_CFG_ASM                 1

/* Big-number assembly - speeds up RSA, DH and ECC. */
#define WC_CFG_ASM_SP              1

/* Per-algorithm assembly - AES, SHA-2, SHA-3, ChaCha20, Poly1305. */
#define WC_CFG_ASM_CRYPTO          1

/* Set when the toolchain cannot assemble .S files. Uses the inline
 * assembly-in-C variants (*_asm_c.c) instead. ARM, RISC-V and PowerPC only.
 * This define only tells the sources which form to compile - the project must
 * also build the *_asm_c.c files in place of the .S ones. Under autotools
 * that means the matching --enable-armasm=inline (or --enable-riscv-asm,
 * --enable-ppc32-asm=inline, ...); setting this alone leaves the inline
 * bodies compiled out and the .S symbols undefined at link time. */
#define WC_CFG_ASM_INLINE          0

/* --- ARM ---------------------------------------------------------------- */
/* ARMv8 Crypto Extensions (AES/SHA instructions). Aarch64 and some ARMv8
 * 32-bit cores only. Cortex-M and ARMv7-A and earlier must leave this 0. */
#define WC_CFG_ARM_HW_CRYPTO       0
/* NEON. Not present on Cortex-M. */
#define WC_CFG_ARM_NEON            0
/* Aarch64 only: use the ARMv8.2 SHA-512 and SHA-3 instructions. */
#define WC_CFG_ARM_SHA512_CRYPTO   0
/* Cortex-M (Thumb-2) only: the core has no UMAAL instruction, so use the
 * code paths that avoid it. Cortex-M3 is detected automatically; set this by
 * hand for any other Thumb-2 core that lacks the instruction. Thumb-1 cores
 * (Cortex-M0/M0+/M1, Cortex-M23) are unaffected - their SP implementation
 * never emits UMAAL, so this switch does nothing there. */
#define WC_CFG_ARM_NO_UMAAL        0
/* The core has a UDIV instruction in the mode being built for, so use the
 * word-divide assembly that needs it. Applies to both the ARM32 and Cortex-M
 * selections, which share one block in sp_int.c.
 *   Cortex-M  ARMv7-M and later have UDIV, so this is safe on M3 and above.
 *   ARM mode  needs the integer divide extension (ARMv7VE, or
 *             -march=armv7-a+idiv); a plain ARMv7-A build will not assemble.
 * Leave 0 if unsure - the C fallback is used instead. */
#define WC_CFG_ARM_UDIV            0

/* --- RISC-V (64-bit) ---------------------------------------------------- */
#define WC_CFG_RISCV_BITMANIP      0   /* Zbb / Zbkb */
#define WC_CFG_RISCV_SCALAR_CRYPTO 0   /* Zkned  - AES, SHA-2 */
#define WC_CFG_RISCV_VECTOR        0   /* V */
#define WC_CFG_RISCV_VECTOR_CRYPTO 0   /* Zvkned - vector AES, SHA-2 */
/* No switches for Zbc/Zbkc or Zvkg: WOLFSSL_RISCV_CARRYLESS and
 * WOLFSSL_RISCV_VECTOR_GCM select no code - the CLMUL and VGMUL/VGHSH
 * instructions come with the vector-crypto assembly itself, and those two
 * defines only add text to the build capability string in wolfmath.c. */

/* --- PowerPC ------------------------------------------------------------ */
#define WC_CFG_PPC_SMALL           0   /* smaller PowerPC assembly */
#define WC_CFG_PPC64_POWER8        0   /* POWER8 SHA-256 / SHA-3 */

/* --- hardware offload --------------------------------------------------- */
/* Route operations to a crypto engine or secure element through the crypto
 * callback layer (wolfcrypt/src/cryptocb.c). This is the third option beside
 * plain C and assembly, and is independent of both: register a device with
 * wc_CryptoCb_RegisterDevice() and anything it declines falls back to the
 * software path built by the switches above. */
#define WC_CFG_CRYPTO_CB           0

/* ========================================================================= */
/* 3. MEMORY                                                                 */
/* ========================================================================= */
/* 0 = no malloc anywhere. Everything comes off the stack or a static pool,
 *     so keep the enabled key sizes small and check the worst-case frame. */
#define WC_CFG_HEAP                1

/* Move large variables off the stack and onto the heap. Requires a heap. */
#define WC_CFG_SMALL_STACK         1

/* Serve allocations from a caller-provided static buffer. Verified here only
 * alongside WC_CFG_HEAP 0: with the C heap still present and no pool loaded,
 * the wolfCrypt RNG self-test fails (DRBG_CONT_FIPS_E), because nothing has
 * given the allocator a pool to work from. */
#define WC_CFG_STATIC_MEMORY       0

/* Compiler or coding standard forbids C99 variable-length arrays. */
#define WC_CFG_NO_VLA              0

/* ========================================================================= */
/* 4. SIZE VERSUS SPEED                                                      */
/* ========================================================================= */
/* Smaller code, smaller stack frames, slower. Applies to the math and to the
 * individual algorithms: small AES tables with no loop unrolling, the small
 * GCM multiply instead of the 4-bit table, the compact SHA implementations,
 * and RSA without CRT. */
#define WC_CFG_SMALL               1

/* 1 = math for any key size or curve (WOLFSSL_SP_MATH_ALL).
 * 0 = only the sizes selected in section 5 (WOLFSSL_SP_MATH). Smaller, but
 *     anything not compiled in fails at run time - including certificates
 *     signed with a key size that is not enabled. */
#define WC_CFG_MATH_ALL_SIZES      1

/* Largest number, in bits, an sp_int has to hold. 0 lets sp_int.h derive it
 * from the algorithms enabled below, which is right unless something outside
 * this file (a large FFDHE group, a big certificate key) needs more. Every
 * sp_int is sized from this, so it sets the memory floor for the math. */
#define WC_CFG_SP_INT_BITS         0

/* ========================================================================= */
/* 5. PUBLIC KEY                                                             */
/* ========================================================================= */
#define WC_CFG_ECC                 1
#define WC_CFG_ECC_P256            1
#define WC_CFG_ECC_P384            0
#define WC_CFG_ECC_P521            0

#define WC_CFG_RSA                 0
#define WC_CFG_RSA_2048            1   /* only used when WC_CFG_RSA is 1 */
#define WC_CFG_RSA_3072            0
#define WC_CFG_RSA_4096            0

#define WC_CFG_DH                  0
/* Finite-field groups to offer. TLS 1.3 will not build with DH enabled and
 * none of these selected. Separate from the RSA sizes above: a build can want
 * RSA-2048 certificates and FFDHE-3072 key exchange. */
#define WC_CFG_DH_2048             1
#define WC_CFG_DH_3072             0
#define WC_CFG_DH_4096             0
#define WC_CFG_CURVE25519          0
#define WC_CFG_ED25519             0

/* Small, slow X25519/Ed25519 implementations. Off by default: the normal C
 * implementation gets scalar blinding automatically (settings.h enables
 * WOLFSSL_CURVE25519_BLINDING for the C non-small build), and the small one
 * cannot have it - curve25519.c rejects the combination outright. Turn this
 * on only if the code size matters more than that protection. */
#define WC_CFG_25519_SMALL         0

/* Verify only - no signing, no ECDH, no key export. Suits a bootloader or a
 * device that only checks signatures. Note that key generation is not gated
 * by these: ecc.c has no keygen switch, so wc_ecc_make_key stays in the
 * build. */
#define WC_CFG_ECC_VERIFY_ONLY     0

/* Shamir's trick for ECC verify: roughly twice as fast, at the cost of a
 * larger table on the stack or heap during the operation. */
#define WC_CFG_ECC_SHAMIR          1

/* Fixed-point ECC cache. Faster repeated operations on the same key, but it
 * holds a large table for the life of the process - rarely worth it on a
 * microcontroller. Sizes are FP_ENTRIES and FP_LUT (see ecc.c). */
#define WC_CFG_ECC_FP_CACHE        0

/* Size ecc_point from the curve rather than from the RSA/DH key size. Saves
 * a large amount of memory whenever RSA or DH is also enabled, since the
 * math is otherwise dimensioned for the biggest of them. Requires a heap -
 * ecc.h rejects it outright when WOLFSSL_NO_MALLOC is set. */
#define WC_CFG_ALT_ECC_SIZE        0

/* --- post-quantum ------------------------------------------------------- */
/* ML-KEM (FIPS 203) key encapsulation, and ML-DSA (FIPS 204) signatures.
 * Neither uses the big-number math, so the SP switches in sections 2 and 4
 * do not apply to them - they are polynomial arithmetic with their own
 * assembly, reached through the same WC_CFG_ASM_CRYPTO switch. Both pull in
 * SHA-3 and SHAKE regardless of WC_CFG_SHA3. Expect a few kB of extra code
 * and noticeably larger keys and signatures than ECC.
 *
 * Enable one parameter set unless interoperating with something specific.
 * 768 and ML-DSA-44 are the widely deployed tiers. */
#define WC_CFG_MLKEM               0
#define WC_CFG_MLKEM_512           0
#define WC_CFG_MLKEM_768           1
#define WC_CFG_MLKEM_1024          0

#define WC_CFG_MLDSA               0
#define WC_CFG_MLDSA_44            1
#define WC_CFG_MLDSA_65            0
#define WC_CFG_MLDSA_87            0

/* Verify only - no key generation and no signing. The natural choice for a
 * device that authenticates a peer or checks a firmware image but never
 * issues a signature itself. */
#define WC_CFG_MLDSA_VERIFY_ONLY   0

/* ========================================================================= */
/* 6. SYMMETRIC AND HASH                                                     */
/* ========================================================================= */
/* AES itself. 0 removes aes.c entirely, for a ChaCha20-Poly1305-only
 * profile; the mode switches below then have nothing to apply to. */
#define WC_CFG_AES                 1
#define WC_CFG_AES_GCM             1
#define WC_CFG_AES_CBC             0
#define WC_CFG_AES_CCM             0
#define WC_CFG_CHACHA_POLY         0

#define WC_CFG_SHA256              1
#define WC_CFG_SHA224              0   /* shares the SHA-256 core */
#define WC_CFG_SHA384              0
#define WC_CFG_SHA512              0
#define WC_CFG_SHA3                0
#define WC_CFG_SHA1                0   /* legacy, off by default */

/* ========================================================================= */
/* 7. TLS                                                                    */
/* ========================================================================= */
/* Protocol versions. The TLS layer is built when at least one of these is
 * selected; with both off there is no TLS at all and the build is wolfCrypt
 * only (WOLFCRYPT_ONLY plus NO_TLS), which is what a device using the crypto
 * API directly wants. Everything else in this section then has no effect.
 * There is deliberately no separate on/off switch for the layer, so that
 * "TLS enabled with no version" - which wolfSSL rejects with "No TLS version
 * enabled!" - cannot be expressed. */
#define WC_CFG_TLS13               1
#define WC_CFG_TLS12               0
#define WC_CFG_DTLS                0
#define WC_CFG_CLIENT_ONLY         1
#define WC_CFG_SERVER_ONLY         0

/* X.509 certificates. 0 drops ASN.1, certificate handling and base64/base16
 * entirely - the smallest TLS build there is, but then authentication has to
 * come from a pre-shared key, so WC_CFG_PSK must be on. Note that
 * wolfcrypt/test/test.c calls the ASN.1 API unconditionally, so the library
 * builds but that test program does not; build src/libwolfssl.la alone. */
#define WC_CFG_CERTS               1

/* Pre-shared keys. Required when WC_CFG_CERTS is 0; also how TLS 1.3
 * resumption works. */
#define WC_CFG_PSK                 0

/* Negotiate a smaller record size with the peer. This is the switch that
 * most directly cuts RAM, since the I/O buffers are sized from it. */
#define WC_CFG_MAX_FRAGMENT        0

/* Server Name Indication. Needed to reach a virtual host, so in practice
 * most clients talking to the public internet want it. */
#define WC_CFG_SNI                 0

/* Application-Layer Protocol Negotiation, e.g. to select HTTP/2 or MQTT. */
#define WC_CFG_ALPN                0

/* Session tickets - resume without holding session state on the device.
 * Needs WC_CFG_RTC: a ticket carries a validity time, and settings.h drops
 * ticket support outright when NO_ASN_TIME is set. */
#define WC_CFG_SESSION_TICKET      0

/* Session cache size. Needs WC_CFG_RTC for the same reason as tickets -
 * settings.h forces NO_SESSION_CACHE when NO_ASN_TIME is set, so without a
 * clock this switch has no effect. The cache is pure RAM, so on a target that
 * does have a clock it is one of the larger levers:
 *   0  none (NO_SESSION_CACHE)
 *   1  MICRO_SESSION_CACHE  - 1 session,  about 400 bytes + 576 bytes
 *   2  SMALL_SESSION_CACHE  - 6 sessions, about 2 kB + 3 kB
 * The library default, used by neither of these, holds 33 sessions and costs
 * roughly 13 kB + 17 kB. A client that only ever talks to one server needs
 * no more than 1. */
#define WC_CFG_SESSION_CACHE       0

/* TLS record buffer size in bytes, 128 to 16384. 0 leaves the library
 * default, which is already small (128 for TLS, the MTU for DTLS) and grows
 * the buffer from the heap when a peer sends a larger record. Set a value
 * only to pin the buffer, and pair it with WC_CFG_MAX_FRAGMENT so the peer
 * agrees not to exceed it. */
#define WC_CFG_RECORD_SIZE         0

/* Never grow the output buffer beyond the record size, even for a large
 * write. Needed if the build has no heap to grow into. */
#define WC_CFG_STATIC_CHUNKS_ONLY  0

/* Longest peer certificate chain accepted. Each link costs parsing time and
 * memory; the library default is 9. A device that talks to one known service
 * usually needs 2 or 3. 0 leaves the default. */
#define WC_CFG_MAX_CHAIN_DEPTH     0

/* Verify certificates with less memory, at some cost in speed. */
#define WC_CFG_SMALL_CERT_VERIFY   0

/* Trust a specific peer certificate directly instead of building a chain to
 * a CA. Suits a device pinned to one known server, and avoids carrying and
 * parsing CA certificates at all. */
#define WC_CFG_TRUST_PEER_CERT     0

/* TLS 1.3 0-RTT early data: one fewer round trip on resumption, which matters
 * on a battery-powered or high-latency link. Replayable by design - only use
 * it for idempotent requests. Requires resumption to be possible at all:
 * either session tickets, which need WC_CFG_RTC, or WC_CFG_PSK. */
#define WC_CFG_EARLY_DATA          0

/* OCSP stapling: the server supplies its own revocation proof, so the device
 * never opens a second connection to a responder. It still needs the OCSP
 * parsing code, which this pulls in, and certificate support. Currently also
 * needs WC_CFG_TLS12 - see the validation note below. */
#define WC_CFG_OCSP_STAPLING       0

/* --- DTLS ---------------------------------------------------------------- */
/* Connection ID (RFC 9146). The session survives the peer's address changing,
 * which on a NATed or roaming IoT link saves a full handshake. */
#define WC_CFG_DTLS_CID            0

/* Fix the DTLS MTU rather than using the default of 1400 bytes. Set to the
 * link MTU on a constrained network; 0 leaves the default. */
#define WC_CFG_DTLS_MTU            0

/* ========================================================================= */
/* 8. PLATFORM                                                               */
/* ========================================================================= */
#define WC_CFG_SINGLE_THREADED     1
#define WC_CFG_FILESYSTEM          0
#define WC_CFG_USER_IO             1   /* provide send/recv callbacks */
#define WC_CFG_BIG_ENDIAN          0
#define WC_CFG_NO_HW_DIVIDE        0   /* no hardware 64/32 divide */

/* There is deliberately no "no 64-bit type" switch. NO_64BIT drops sp_int.h
 * to 16-bit words, and no sp_*.c provides the specialised RSA/ECC code at
 * that width, so the build fails to link as soon as a public key algorithm
 * is enabled. On a 64-bit host it does not even compile: the ULONG_MAX chain
 * in sp_int.h has no branch for a 64-bit long with NO_64BIT set. */

/* Build the BSD socket I/O layer. Off for a target with no sockets, which is
 * the usual case when WC_CFG_USER_IO supplies the transport instead. */
#define WC_CFG_SOCKETS             0

/* /dev/random is present and readable. Left at 1 so the file builds and runs
 * on a host out of the box. A bare metal target has no such device: set this
 * to 0 and supply entropy another way, either WC_CFG_HW_RNG or a
 * wc_GenerateSeed() in the port. Setting it to 0 with no replacement is a
 * compile error from random.c, by design. */
#define WC_CFG_DEV_RANDOM          1

/* Inline the small helpers in misc.c into each caller. On for speed; turn it
 * off to compile misc.c once, which shrinks code and makes the helpers
 * visible to a debugger. Turning it off means the project must also build
 * wolfcrypt/src/misc.c as its own translation unit, otherwise min(),
 * ForceZero(), xorbuf() and rotrFixed() are left undefined at link time.
 * With autotools that is ./configure --disable-inline. */
#define WC_CFG_INLINE              1

/* wolfSSL's memory abstraction, which is what makes XMALLOC/XFREE routable
 * and lets wolfSSL_SetAllocators() and the static memory pool work. Turning
 * it off calls the C library directly. Ignored when WC_CFG_STATIC_MEMORY is
 * set, since the pool is built on the wrapper. */
#define WC_CFG_MEMORY_WRAPPER      1

/* Runtime logging through wolfSSL_Debugging_ON(). Costs code and const data,
 * but is the first thing to reach for when a handshake fails on a board. */
#define WC_CFG_DEBUG               0

/* Building with the Arm Compiler / Keil MDK. The inline assembly in sp_int.c
 * has a Keil-specific form that is not selected automatically, so this must be
 * set by hand for that toolchain. IAR and MSVC are detected on their own and
 * need nothing here. */
#define WC_CFG_KEIL                0

/* Real time clock available for certificate validity checking. Without it,
 * date checks are compiled out. */
#define WC_CFG_RTC                 1

/* Hardware RNG. When 1, implement my_rng_gen_block() below.
 * When 0 the hash DRBG is used and you must still provide entropy: either
 * implement wc_GenerateSeed() for the port, or set CUSTOM_RAND_GENERATE_SEED
 * in the derived section. */
#define WC_CFG_HW_RNG              0

/* Error strings cost several kB of const data. */
#define WC_CFG_ERROR_STRINGS       0

/* ========================================================================= */
/* ========================================================================= */
/* DERIVED SETTINGS - not normally edited                                    */
/* ========================================================================= */
/* ========================================================================= */

/* The TLS layer follows the protocol versions selected in section 7. */
#define WC_CFG_TLS (WC_CFG_TLS13 || WC_CFG_TLS12)

/* --- validation --------------------------------------------------------- */
#if (WC_CFG_CPU_PORTABLE + WC_CFG_CPU_CORTEX_M + WC_CFG_CPU_ARM_THUMB +      \
     WC_CFG_CPU_ARM32 + WC_CFG_CPU_AARCH64 + WC_CFG_CPU_RISCV32 +            \
     WC_CFG_CPU_RISCV64 + WC_CFG_CPU_PPC32 + WC_CFG_CPU_PPC64 +              \
     WC_CFG_CPU_X86_64) != 1
    #error "Set exactly one WC_CFG_CPU_* switch to 1 in section 1."
#endif

#if !WC_CFG_HEAP && WC_CFG_SMALL_STACK
    #error "WC_CFG_SMALL_STACK moves data to the heap - needs WC_CFG_HEAP."
#endif

#if WC_CFG_TLS && WC_CFG_CERTS && !WC_CFG_ECC && !WC_CFG_RSA
    #error "Certificate-based TLS needs one of WC_CFG_ECC or WC_CFG_RSA."
#endif

#if WC_CFG_TLS && !WC_CFG_CERTS && !WC_CFG_PSK
    #error "TLS without certificates needs WC_CFG_PSK for authentication."
#endif

#if WC_CFG_CLIENT_ONLY && WC_CFG_SERVER_ONLY
    #error "WC_CFG_CLIENT_ONLY and WC_CFG_SERVER_ONLY are exclusive."
#endif

/* internal.c calls wc_ecc_sign_hash unconditionally once HAVE_ECC is in, so
 * a verify-only ECC build does not link against the TLS layer at all - not
 * even a PSK one. Turn WC_CFG_ECC off instead if TLS needs no ECC. */
#if WC_CFG_ECC_VERIFY_ONLY && WC_CFG_TLS && WC_CFG_ECC
    #error "WC_CFG_ECC_VERIFY_ONLY cannot be combined with TLS and ECC."
#endif

#if WC_CFG_RECORD_SIZE && \
    (WC_CFG_RECORD_SIZE < 128 || WC_CFG_RECORD_SIZE > 16384)
    #error "WC_CFG_RECORD_SIZE must be between 128 and 16384."
#endif

#if WC_CFG_SESSION_CACHE && !WC_CFG_TLS
    #error "WC_CFG_SESSION_CACHE only applies to a TLS build."
#endif

#if (WC_CFG_DTLS_CID || WC_CFG_DTLS_MTU) && !WC_CFG_DTLS
    #error "The DTLS switches need WC_CFG_DTLS."
#endif

#if WC_CFG_TRUST_PEER_CERT && !WC_CFG_CERTS
    #error "WC_CFG_TRUST_PEER_CERT needs certificate support."
#endif

#if WC_CFG_OCSP_STAPLING && !WC_CFG_CERTS
    #error "WC_CFG_OCSP_STAPLING needs certificate support."
#endif

/* Stapling in a TLS 1.3-only build does not currently compile: internal.c
 * guards ProcessCSR_ex() on !WOLFSSL_NO_TLS12 while the TLS 1.3 code path
 * calls it, so the call is built and the definition is not. Enable TLS 1.2
 * alongside until that is resolved upstream. */
#if WC_CFG_OCSP_STAPLING && WC_CFG_TLS13 && !WC_CFG_TLS12
    #error "WC_CFG_OCSP_STAPLING needs WC_CFG_TLS12 - see comment above."
#endif

/* Session resumption of any kind carries a validity time, so settings.h
 * disables the cache and tickets when NO_ASN_TIME is set. Catch that here
 * rather than let the switches silently do nothing. */
#if (WC_CFG_SESSION_CACHE || WC_CFG_SESSION_TICKET) && !WC_CFG_RTC
    #error "Session cache and tickets need a clock - set WC_CFG_RTC."
#endif

#if WC_CFG_EARLY_DATA && !WC_CFG_SESSION_TICKET && !WC_CFG_PSK
    #error "WC_CFG_EARLY_DATA needs WC_CFG_SESSION_TICKET or WC_CFG_PSK."
#endif

#if WC_CFG_EARLY_DATA && !WC_CFG_TLS13
    #error "WC_CFG_EARLY_DATA is a TLS 1.3 feature."
#endif

#if WC_CFG_ALT_ECC_SIZE && !WC_CFG_HEAP
    #error "WC_CFG_ALT_ECC_SIZE needs a heap - ecc.h rejects it with no malloc."
#endif

#if WC_CFG_MLKEM && !WC_CFG_MLKEM_512 && !WC_CFG_MLKEM_768 && !WC_CFG_MLKEM_1024
    #error "WC_CFG_MLKEM is set but no parameter set is enabled."
#endif

#if WC_CFG_MLDSA && !WC_CFG_MLDSA_44 && !WC_CFG_MLDSA_65 && !WC_CFG_MLDSA_87
    #error "WC_CFG_MLDSA is set but no parameter set is enabled."
#endif

#if WC_CFG_ECC && !WC_CFG_ECC_P256 && !WC_CFG_ECC_P384 && !WC_CFG_ECC_P521
    #error "WC_CFG_ECC is set but no curve is enabled."
#endif

#if WC_CFG_RSA && !WC_CFG_RSA_2048 && !WC_CFG_RSA_3072 && !WC_CFG_RSA_4096
    #error "WC_CFG_RSA is set but no key size is enabled."
#endif

#if WC_CFG_TLS && WC_CFG_TLS13 && !WC_CFG_SHA256
    #error "TLS 1.3 requires SHA-256."
#endif

/* Every TLS 1.3 cipher suite is AEAD, so a build with none has no suite to
 * negotiate. internal.h derives HAVE_AEAD from these. */
#if WC_CFG_TLS13 && !(WC_CFG_AES && (WC_CFG_AES_GCM || WC_CFG_AES_CCM)) && \
    !WC_CFG_CHACHA_POLY
    #error "TLS 1.3 needs an AEAD cipher: AES-GCM, AES-CCM or ChaCha-Poly."
#endif

#if WC_CFG_SHA224 && !WC_CFG_SHA256
    #error "SHA-224 shares the SHA-256 core - enable WC_CFG_SHA256."
#endif

#if WC_CFG_ARM_HW_CRYPTO && WC_CFG_CPU_CORTEX_M
    #error "Cortex-M has no ARMv8 Crypto Extensions."
#endif

/* The Thumb-1 cores have no ARMv8 crypto extensions either, and asking for
 * them pulls in AArch32 AES entry points that are never compiled. */
#if WC_CFG_ARM_HW_CRYPTO && WC_CFG_CPU_ARM_THUMB
    #error "Thumb-1 cores have no ARMv8 Crypto Extensions."
#endif

/* Cortex-M uses the Thumb-2 assembly, which needs ARMv7-M or later. */
#if WC_CFG_CPU_CORTEX_M && WC_CFG_ASM_CRYPTO && (WC_CFG_ARM_ARCH < 7)
    #error "Cortex-M assembly is Thumb-2 - set WC_CFG_ARM_ARCH 7 or later."
#endif

#if WC_CFG_STATIC_MEMORY && WC_CFG_HEAP
    #error "WC_CFG_STATIC_MEMORY needs WC_CFG_HEAP 0 - see its comment."
#endif

#if WC_CFG_DH && !WC_CFG_DH_2048 && !WC_CFG_DH_3072 && !WC_CFG_DH_4096
    #error "WC_CFG_DH needs at least one FFDHE group."
#endif

/* --- platform ----------------------------------------------------------- */
/* Alignment, in bytes, applied to generated data buffers - it is what
 * XGEN_ALIGN expands to. Hardware crypto engines and some assembly need their
 * input aligned, and the TLS record header otherwise leaves payloads on an odd
 * boundary. 4 suits a 32-bit embedded target; raise it if your port's engine
 * needs more, or set 0 to emit no alignment attribute at all.
 *
 * Not set for x86_64, because settings.h makes a better choice there on its
 * own: 16 when AES-NI is in use, which the SSE loads in aes.c require, and 0
 * otherwise. Overriding it with 4 would quietly weaken the AES-NI build. */
#if !WC_CFG_CPU_X86_64
    #define WOLFSSL_GENERAL_ALIGNMENT 4
#endif

/* Size of "long long" on this target, in bytes. Without autoconf there is no
 * config.h to supply it, so state it here: types.h uses it to pick the 64-bit
 * word type, and only guesses from limits.h or a list of known targets when it
 * is absent. sp_int.h also sizes its own word types from it, so it is stated
 * unconditionally. */
#ifndef SIZEOF_LONG_LONG
    #define SIZEOF_LONG_LONG 8
#endif

#if WC_CFG_SINGLE_THREADED
    #define SINGLE_THREADED
#endif

#if !WC_CFG_FILESYSTEM
    #define NO_FILESYSTEM
    #define NO_WOLFSSL_DIR
    #define NO_WRITEV
    #define WOLFSSL_IGNORE_FILE_WARN
#endif

#if WC_CFG_USER_IO
    /* set with wolfSSL_CTX_SetIORecv() / wolfSSL_CTX_SetIOSend() */
    #define WOLFSSL_USER_IO
#endif

#if WC_CFG_BIG_ENDIAN
    #define BIG_ENDIAN_ORDER
#endif

#if !WC_CFG_ERROR_STRINGS
    #define NO_ERROR_STRINGS
#endif

#if !WC_CFG_SOCKETS
    #define WOLFSSL_NO_SOCK
#endif

#if !WC_CFG_DEV_RANDOM
    #define NO_DEV_RANDOM
#endif

#if !WC_CFG_INLINE
    #define NO_INLINE
#endif

#if WC_CFG_DEBUG
    #define DEBUG_WOLFSSL
#endif

#if WC_CFG_KEIL
    #define WOLFSSL_KEIL
#endif

#if WC_CFG_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif

/* Make wolfcrypt/benchmark/benchmark.c use small buffers and short run times
 * so it fits, and finishes, on a microcontroller. No effect on the library. */
#define BENCH_EMBEDDED

/* Do not declare the legacy "RNG" alias for WC_RNG. The short name collides
 * with symbols in many embedded SDKs and RTOS headers. */
#define NO_OLD_RNGNAME

/* Use the table-driven ASN.1 parser rather than the original hand-written one.
 * Smaller and the maintained path - see wolfcrypt/src/ASN_TEMPLATE.md. */
#define WOLFSSL_ASN_TEMPLATE

/* --- memory ------------------------------------------------------------- */
#if WC_CFG_SMALL_STACK
    #define WOLFSSL_SMALL_STACK
#endif

#if !WC_CFG_HEAP
    #define WOLFSSL_NO_MALLOC
    #define WOLFSSL_SP_NO_MALLOC
#endif

#if WC_CFG_STATIC_MEMORY
    #define WOLFSSL_STATIC_MEMORY
    #define WOLFSSL_MALLOC_CHECK
#endif

#if !WC_CFG_MEMORY_WRAPPER && !WC_CFG_STATIC_MEMORY
    /* The static memory pool is implemented on top of the wrapper, so the
     * wrapper can only be dropped when that is off too. */
    #define NO_WOLFSSL_MEMORY
#endif

#if WC_CFG_NO_VLA
    #define WOLFSSL_SP_NO_DYN_STACK
#endif

/* --- math back end ------------------------------------------------------ */
#if WC_CFG_MATH_ALL_SIZES
    #define WOLFSSL_SP_MATH_ALL
#else
    #define WOLFSSL_SP_MATH
#endif

#if WC_CFG_SMALL
    #define WOLFSSL_SP_SMALL
#endif

#if WC_CFG_NO_HW_DIVIDE
    #define WOLFSSL_SP_DIV_32
#endif

#if WC_CFG_SP_INT_BITS
    #define SP_INT_BITS WC_CFG_SP_INT_BITS
#endif

/* Timing-attack hardening. All three are on by default in wolfSSL and are
 * repeated here so they survive a hand-written build, where nothing else
 * turns them on. They cost speed; leave them alone unless the threat model
 * genuinely excludes an attacker who can observe timing.
 *
 * TFM_TIMING_RESISTANT applies to the fastmath back end (tfm.c) and to
 * wolfmath.c, so it only bites if this configuration is later switched away
 * from SP math. ECC_TIMING_RESISTANT makes ECC scalar multiplication
 * constant time. WC_RSA_BLINDING blinds RSA private key operations, which
 * needs an RNG to be available. */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* --- CPU: assembly and word size ---------------------------------------- */
#if !WC_CFG_ASM || WC_CFG_CPU_PORTABLE
    /* Portable C. WOLFSSL_NO_ASM also keeps the legacy math back ends from
     * pulling in their own assembly. */
    #define WOLFSSL_NO_ASM
    #define TFM_NO_ASM

#elif WC_CFG_CPU_CORTEX_M
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_ARM_CORTEX_M
    #endif
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_ARM_CORTEX_M_ASM
    #endif
    #if WC_CFG_ARM_NO_UMAAL
        #define WOLFSSL_SP_NO_UMAAL
    #endif
    #if WC_CFG_ARM_UDIV
        #define WOLFSSL_SP_ARM32_UDIV
    #endif
    #if WC_CFG_ASM_CRYPTO
        #define WOLFSSL_ARMASM
        #define WOLFSSL_ARMASM_THUMB2
        #define WOLFSSL_ARMASM_NO_NEON
        #define WOLFSSL_ARMASM_NO_HW_CRYPTO
    #endif

#elif WC_CFG_CPU_ARM_THUMB
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_ARM_THUMB
    #endif
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_ARM_THUMB_ASM
    #endif
    /* The per-algorithm ARM assembly is Thumb-2, which needs ARMv7 or later.
     * On a Thumb-1 core (ARMv6-M: Cortex-M0/M0+/M1, or ARMv8-M baseline:
     * Cortex-M23) there is no assembly to use - wolfSSL ships none for
     * Thumb-1 - so only the SP acceleration above applies and the algorithms
     * use their C implementations. */
    #if WC_CFG_ASM_CRYPTO && (WC_CFG_ARM_ARCH >= 7)
        #define WOLFSSL_ARMASM
        #define WOLFSSL_ARMASM_THUMB2
        #if !WC_CFG_ARM_NEON
            #define WOLFSSL_ARMASM_NO_NEON
        #endif
        #if !WC_CFG_ARM_HW_CRYPTO
            #define WOLFSSL_ARMASM_NO_HW_CRYPTO
        #endif
    #endif

#elif WC_CFG_CPU_ARM32
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_ARM32
    #endif
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_ARM32_ASM
    #endif
    #if WC_CFG_ARM_UDIV
        #define WOLFSSL_SP_ARM32_UDIV
    #endif
    #if WC_CFG_ASM_CRYPTO
        #define WOLFSSL_ARMASM
        #if !WC_CFG_ARM_NEON
            #define WOLFSSL_ARMASM_NO_NEON
        #endif
        #if !WC_CFG_ARM_HW_CRYPTO
            #define WOLFSSL_ARMASM_NO_HW_CRYPTO
        #endif
    #endif

#elif WC_CFG_CPU_AARCH64
    #define WOLFSSL_AARCH64_BUILD
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_ARM64
    #endif
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_ARM64_ASM
    #endif
    #if WC_CFG_ASM_CRYPTO
        #define WOLFSSL_ARMASM
        #if !WC_CFG_ARM_NEON
            #define WOLFSSL_ARMASM_NO_NEON
        #endif
        #if !WC_CFG_ARM_HW_CRYPTO
            #define WOLFSSL_ARMASM_NO_HW_CRYPTO
        #endif
        #if WC_CFG_ARM_SHA512_CRYPTO
            /* needs -march=armv8.2-a+crypto+sha3 */
            #define WOLFSSL_ARMASM_CRYPTO_SHA512
            #define WOLFSSL_ARMASM_CRYPTO_SHA3
        #endif
    #endif

#elif WC_CFG_CPU_RISCV32
    /* No specialised SP assembly and no algorithm port for 32-bit RISC-V.
     * The inline SP assembly in sp_int.c is all that is available. */
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_RISCV32
    #endif

#elif WC_CFG_CPU_RISCV64
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_RISCV64
    #endif
    /* Specialised SP assembly, inline in sp_riscv64.c. Needs only the base
     * integer ISA plus M, so it is selected by WC_CFG_ASM_SP alone and is
     * independent of the extensions WC_CFG_ASM_CRYPTO switches on below. */
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_RISCV64_ASM
    #endif
    #if WC_CFG_ASM_CRYPTO
        #define WOLFSSL_RISCV_ASM
        #if WC_CFG_RISCV_BITMANIP
            #define WOLFSSL_RISCV_BASE_BIT_MANIPULATION
            #define WOLFSSL_RISCV_BIT_MANIPULATION
        #endif
        #if WC_CFG_RISCV_SCALAR_CRYPTO
            #define WOLFSSL_RISCV_SCALAR_CRYPTO_ASM
        #endif
        #if WC_CFG_RISCV_VECTOR
            #define WOLFSSL_RISCV_VECTOR
        #endif
        #if WC_CFG_RISCV_VECTOR_CRYPTO
            #define WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
        #endif
    #endif

#elif WC_CFG_CPU_PPC32
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_PPC
    #endif
    #if WC_CFG_ASM_CRYPTO
        #define WOLFSSL_PPC32_ASM
        #if WC_CFG_PPC_SMALL
            #define WOLFSSL_PPC32_ASM_SMALL
        #endif
    #endif

#elif WC_CFG_CPU_PPC64
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_PPC64
    #endif
    #if WC_CFG_ASM_CRYPTO
        #define WOLFSSL_PPC64_ASM
        #if WC_CFG_PPC_SMALL
            #define WOLFSSL_PPC64_ASM_SMALL
        #endif
        #if WC_CFG_PPC64_POWER8
            #define WOLFSSL_PPC64_ASM_CRYPTO
            #define WOLFSSL_PPC64_ASM_POWER8
        #endif
    #endif

#elif WC_CFG_CPU_X86_64
    #define WOLFSSL_X86_64_BUILD
    #if WC_CFG_ASM_SP
        #define WOLFSSL_SP_X86_64
    #endif
    #if WC_CFG_ASM_SP
        /* not supported for MinGW/Cygwin hosts - use the C code there */
        #define WOLFSSL_SP_X86_64_ASM
    #endif
    #if WC_CFG_ASM_CRYPTO
        #define WOLFSSL_AESNI
        #define USE_INTEL_SPEEDUP
    #endif
#endif

/* Architecture level for the 32-bit ARM targets. Set outside the assembly
 * blocks above because sp_int.c consults WOLFSSL_ARM_ARCH for its own inline
 * assembly, so it must be right even when the per-algorithm assembly is off. */
#if WC_CFG_CPU_CORTEX_M || WC_CFG_CPU_ARM_THUMB || WC_CFG_CPU_ARM32
    #define WOLFSSL_ARM_ARCH WC_CFG_ARM_ARCH
#endif

/* Inline assembly-in-C variants, for toolchains that cannot assemble .S. */
#if WC_CFG_ASM && WC_CFG_ASM_INLINE
    #define WOLFSSL_ARMASM_INLINE
    #define WOLFSSL_RISCV_ASM_INLINE
    #define WOLFSSL_PPC32_ASM_INLINE
    #define WOLFSSL_PPC64_ASM_INLINE
#endif

/* --- SP: which algorithms and sizes ------------------------------------- */
#if WC_CFG_RSA
    #define WOLFSSL_HAVE_SP_RSA
#endif
#if WC_CFG_DH
    #define WOLFSSL_HAVE_SP_DH
#endif
#if WC_CFG_ECC
    #define WOLFSSL_HAVE_SP_ECC
#endif

#if WC_CFG_RSA || WC_CFG_DH
    #if !WC_CFG_RSA_2048
        #define WOLFSSL_SP_NO_2048
    #endif
    #if !WC_CFG_RSA_3072
        #define WOLFSSL_SP_NO_3072
    #endif
    #if WC_CFG_RSA_4096
        #define WOLFSSL_SP_4096
    #endif
#endif

#if WC_CFG_ECC
    #if !WC_CFG_ECC_P256
        #define WOLFSSL_SP_NO_256
    #endif
    #if WC_CFG_ECC_P384
        #define WOLFSSL_SP_384
        #define HAVE_ECC384
    #endif
    #if WC_CFG_ECC_P521
        #define WOLFSSL_SP_521
        #define HAVE_ECC521
    #endif
#endif

/* --- public key --------------------------------------------------------- */
#if WC_CFG_ECC
    #define HAVE_ECC
    #define ECC_USER_CURVES         /* only the curves selected above */
    #if !WC_CFG_ECC_P256
        #define NO_ECC256
    #endif
    #if WC_CFG_ECC_VERIFY_ONLY
        /* settings.h turns each of these into the matching HAVE_ECC_* */
        #define NO_ECC_SIGN
        #define NO_ECC_DHE
        #define NO_ECC_KEY_EXPORT
    #endif
    #if WC_CFG_ECC_SHAMIR
        #define ECC_SHAMIR
    #endif
    #if WC_CFG_ECC_FP_CACHE
        #define FP_ECC
    #endif
    #if WC_CFG_ALT_ECC_SIZE
        #define ALT_ECC_SIZE
    #endif
#endif
/* There is no NO_ECC: ECC is absent whenever HAVE_ECC is not defined. */

#if !WC_CFG_RSA
    #define NO_RSA
#else
    #define WC_RSA_PSS
    #if WC_CFG_SMALL
        /* Private key operations without CRT: much less memory, several
         * times slower. Also forces WOLFSSL_SP_SMALL in the sp_*.c files. */
        #define RSA_LOW_MEM
    #endif
#endif

#if WC_CFG_DH
    #if WC_CFG_DH_2048
        #define HAVE_FFDHE_2048
    #endif
    #if WC_CFG_DH_3072
        #define HAVE_FFDHE_3072
    #endif
    #if WC_CFG_DH_4096
        #define HAVE_FFDHE_4096
    #endif
#else
    #define NO_DH
#endif

#if WC_CFG_CURVE25519
    #define HAVE_CURVE25519
    #if WC_CFG_25519_SMALL
        #define CURVE25519_SMALL
    #endif
#endif
#if WC_CFG_ED25519
    #define HAVE_ED25519
    #if WC_CFG_25519_SMALL
        #define ED25519_SMALL
    #endif
#endif

/* DSA is not offered as a switch: it has no role in TLS 1.2 or 1.3 as
 * deployed, and ECDSA covers the same ground. */
/* --- post-quantum ------------------------------------------------------- */
/* Parameter sets are opt-out here: defining WOLFSSL_HAVE_MLKEM alone builds
 * all three, so each one not selected has to be turned off by name. */
#if WC_CFG_MLKEM
    #define WOLFSSL_HAVE_MLKEM
    #if !WC_CFG_MLKEM_512
        #define WOLFSSL_NO_ML_KEM_512
    #endif
    #if !WC_CFG_MLKEM_768
        #define WOLFSSL_NO_ML_KEM_768
    #endif
    #if !WC_CFG_MLKEM_1024
        #define WOLFSSL_NO_ML_KEM_1024
    #endif
    #if WC_CFG_SMALL
        /* Loop the polynomial arithmetic instead of unrolling it. */
        #define WOLFSSL_MLKEM_SMALL
        #define WOLFSSL_MLKEM_NO_LARGE_CODE
    #endif
    #if WC_CFG_HEAP && !WC_CFG_STATIC_MEMORY
        /* Allocate the key buffers rather than carrying them in the key
         * struct. Rejected by wc_mlkem.c when there is no malloc. */
        #define WOLFSSL_MLKEM_DYNAMIC_KEYS
    #endif
#endif

#if WC_CFG_MLDSA
    #define WOLFSSL_HAVE_MLDSA
    #if !WC_CFG_MLDSA_44
        #define WOLFSSL_NO_ML_DSA_44
    #endif
    #if !WC_CFG_MLDSA_65
        #define WOLFSSL_NO_ML_DSA_65
    #endif
    #if !WC_CFG_MLDSA_87
        #define WOLFSSL_NO_ML_DSA_87
    #endif
    #if WC_CFG_MLDSA_VERIFY_ONLY
        #define WOLFSSL_MLDSA_VERIFY_ONLY
        /* Stream the verify rather than expanding the whole key at once. */
        #define WOLFSSL_MLDSA_VERIFY_SMALL_MEM
    #endif
    #if WC_CFG_SMALL
        #define WOLFSSL_MLDSA_SMALL
    #endif
    #if !WC_CFG_CERTS
        /* Nothing decodes an ML-DSA certificate in a no-X.509 build. */
        #define WOLFSSL_MLDSA_NO_ASN1
    #endif
#endif

#if WC_CFG_MLKEM || WC_CFG_MLDSA
    /* Both are built on SHAKE, so SHA-3 comes in whether or not it was asked
     * for in section 6. sha3.h hides the wc_Shake* API behind these. */
    #ifndef WOLFSSL_SHA3
        #define WOLFSSL_SHA3
    #endif
    #define WOLFSSL_SHAKE128
    #define WOLFSSL_SHAKE256
#endif

#define NO_DSA

/* --- symmetric and hash ------------------------------------------------- */
#if !WC_CFG_AES
    #define NO_AES
#endif

#if WC_CFG_AES && WC_CFG_AES_GCM
    #define HAVE_AESGCM
    #if WC_CFG_SMALL
        /* GHASH without a precomputed table - smallest, slowest. */
        #define GCM_SMALL
    #else
        /* 4-bit table: the usual speed/size compromise for GHASH. */
        #define GCM_TABLE_4BIT
    #endif
#endif

#if WC_CFG_SMALL && WC_CFG_AES
    /* Compact AES: 256-byte tables instead of 4 x 1kB, and no unrolling of
     * the round loop. */
    #define WOLFSSL_AES_SMALL_TABLES
    #define WOLFSSL_AES_NO_UNROLL
#endif
#if WC_CFG_AES && !WC_CFG_AES_CBC
    #define NO_AES_CBC
#endif
#if WC_CFG_AES && WC_CFG_AES_CCM
    #define HAVE_AESCCM
#endif

#if WC_CFG_CHACHA_POLY
    #define HAVE_CHACHA
    #define HAVE_POLY1305
    #define HAVE_ONE_TIME_AUTH
#endif

#if !WC_CFG_SHA256
    #define NO_SHA256
#endif
#if WC_CFG_SHA224
    /* Truncated SHA-256 with a different IV - it is compiled into sha256.c,
     * so it costs almost nothing once SHA-256 is already in. */
    #define WOLFSSL_SHA224
#endif

/* The larger SHA-2 sizes are also pulled in by what depends on them, not only
 * by the switches in section 6: P-384 is signed with SHA-384 and P-521 with
 * SHA-512 (the wolfCrypt test vectors do exactly this, and fail with
 * BAD_LENGTH_E if the digest is missing), and Ed25519 is defined in terms of
 * SHA-512 - settings.h refuses to build it otherwise. */
#if WC_CFG_SHA384 || (WC_CFG_ECC && WC_CFG_ECC_P384)
    #define WOLFSSL_SHA384
#endif
#if WC_CFG_SHA512 || (WC_CFG_ECC && WC_CFG_ECC_P521) || WC_CFG_ED25519
    #define WOLFSSL_SHA512
#endif
/* SHA-384 and SHA-512 are both absent simply by not defining WOLFSSL_SHA384
 * or WOLFSSL_SHA512 - sha512.h gates on those two. There is no NO_SHA512 to
 * emit: the library never reads that macro. */
#if WC_CFG_SHA3
    #define WOLFSSL_SHA3
#endif

/* Compact hash cores - loop rather than unroll the compression rounds. Placed
 * after the digests are selected so each only lands when its digest is built.
 */
#if WC_CFG_SMALL
    #if WC_CFG_SHA1
        #define USE_SLOW_SHA
    #endif
    #if WC_CFG_SHA256
        #define USE_SLOW_SHA256
    #endif
    #if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
        #define USE_SLOW_SHA512
    #endif
#endif
#if !WC_CFG_SHA1
    #define NO_SHA
#endif

/* Never wanted on a new embedded design, so these are compiled out rather
 * than offered as switches. Drop the relevant line if an existing protocol
 * or file format forces one of them on you.
 *
 * MD4, MD5 and RC4 are broken. 3DES is obsolete and slow, and
 * NO_DES3_TLS_SUITES additionally removes the 3DES TLS cipher suites from
 * the suite tables in internal.h even if 3DES itself were built. PWDBASED is
 * the PBKDF family, PKCS#8 and PKCS#12 are encrypted key container formats -
 * all three are only needed to read password-protected key files, which an
 * embedded target normally does not do. NO_SIG_WRAPPER drops the generic
 * wc_Signature* layer in signature.c; call the RSA or ECC API directly. */
#define NO_MD4
#define NO_MD5
#define NO_RC4
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_PWDBASED
#define NO_PKCS8
#define NO_PKCS12
#define NO_SIG_WRAPPER

/* --- RNG ---------------------------------------------------------------- */
#if WC_CFG_HW_RNG
    #define WC_NO_HASHDRBG
    extern int my_rng_gen_block(unsigned char* output, unsigned int sz);
    #define CUSTOM_RAND_GENERATE_BLOCK my_rng_gen_block
#else
    #define HAVE_HASHDRBG
    /* Entropy source. Implement wc_GenerateSeed() in a port file, or supply
     * a seed function here:
     * extern int my_rng_seed(unsigned char* output, unsigned int sz);
     * #define CUSTOM_RAND_GENERATE_SEED my_rng_seed
     *
     * WOLFSSL_GENSEED_FORTEST provides a non-random stub. Bring-up only -
     * it is not safe for anything that leaves the bench. */
#endif

/* --- time --------------------------------------------------------------- */
#if !WC_CFG_RTC
    /* No clock: certificate validity dates cannot be checked. */
    #define NO_ASN_TIME
#else
    /* Provide the platform clock:
     * #define USER_TIME
     * extern unsigned long my_time(unsigned long* timer);
     * #define XTIME my_time
     */
#endif

/* --- TLS ---------------------------------------------------------------- */
#if WC_CFG_TLS
    #define HAVE_TLS_EXTENSIONS
    /* Supported groups. This is a TLS extension, not an ECC feature: it
     * carries whichever key exchange groups the build offers - ECC curves,
     * X25519, ML-KEM hybrids - so it belongs to the TLS layer and is needed
     * even by a build that does key exchange without ECC. TLS 1.3 cannot
     * offer a key share without it. */
    #define HAVE_SUPPORTED_CURVES
    #define HAVE_EXTENDED_MASTER
    #if WC_CFG_SESSION_CACHE == 0
        #define NO_SESSION_CACHE
    #elif WC_CFG_SESSION_CACHE == 1
        #define MICRO_SESSION_CACHE
    #else
        #define SMALL_SESSION_CACHE
    #endif

    #if WC_CFG_TLS13
        #define WOLFSSL_TLS13
        #define HAVE_HKDF
        /* HAVE_AEAD is deliberately not defined here: internal.h derives it
         * from whether an AEAD cipher is actually built (AES-GCM, AES-CCM,
         * ChaCha20-Poly1305, ...). Forcing it would claim AEAD support a
         * cipher-less configuration does not have. */
    #endif
    #if !WC_CFG_TLS12
        #define WOLFSSL_NO_TLS12
    #endif
    #define NO_OLD_TLS

    #if WC_CFG_DTLS
        #define WOLFSSL_DTLS
        #if WC_CFG_TLS13
            #define WOLFSSL_DTLS13
        #endif
    #endif

    #if WC_CFG_CLIENT_ONLY
        #define NO_WOLFSSL_SERVER
    #endif
    #if WC_CFG_SERVER_ONLY
        #define NO_WOLFSSL_CLIENT
    #endif

    #if !WC_CFG_PSK
        #define NO_PSK
    #endif
    #if WC_CFG_EARLY_DATA
        #define WOLFSSL_EARLY_DATA
    #endif
    #if WC_CFG_OCSP_STAPLING
        /* Stapling is an OCSP consumer, so the OCSP code has to be present;
         * internal.h refuses to build the extension without it. The device
         * still never fetches a response itself - the server supplies it. */
        #define HAVE_OCSP
        #define HAVE_CERTIFICATE_STATUS_REQUEST
    #endif
    #if WC_CFG_TRUST_PEER_CERT
        #define WOLFSSL_TRUST_PEER_CERT
    #endif
    #if WC_CFG_SMALL_CERT_VERIFY
        #define WOLFSSL_SMALL_CERT_VERIFY
    #endif
    #if WC_CFG_RECORD_SIZE
        #define RECORD_SIZE WC_CFG_RECORD_SIZE
    #endif
    #if WC_CFG_STATIC_CHUNKS_ONLY
        #define STATIC_CHUNKS_ONLY
    #endif
    #if WC_CFG_MAX_CHAIN_DEPTH
        #define MAX_CHAIN_DEPTH WC_CFG_MAX_CHAIN_DEPTH
    #endif
    #if WC_CFG_DTLS && WC_CFG_DTLS_CID
        #define WOLFSSL_DTLS_CID
    #endif
    #if WC_CFG_DTLS && WC_CFG_DTLS_MTU
        #define WOLFSSL_DTLS_MTU
        #define WOLFSSL_MAX_MTU WC_CFG_DTLS_MTU
    #endif
    #if WC_CFG_MAX_FRAGMENT
        #define HAVE_MAX_FRAGMENT
    #endif
    #if WC_CFG_SNI
        #define HAVE_SNI
    #endif
    #if WC_CFG_ALPN
        #define HAVE_ALPN
    #endif
    #if WC_CFG_SESSION_TICKET
        #define HAVE_SESSION_TICKET
    #endif
#else
    #define WOLFCRYPT_ONLY
    #define NO_TLS
    #define NO_PSK
#endif

#if !WC_CFG_CERTS
    /* No X.509 at all: no DER/PEM parsing, no certificate store, and no
     * base64/base16 since nothing is left that needs to decode them. */
    #define NO_ASN
    #define NO_CERTS
    #define NO_CODING
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
