# wolfCrypt CUDA AES Port

## Status

The CUDA AES port is experimental. It has been tested for functional
correctness only and is intended for evaluation and performance
experimentation. Read the security considerations below before using it to
protect real data.

## Building

You will need to have the CUDA libraries and toolchains installed to be able to use this. For the simplest
setup, I used the 'nvidia/cuda:12.3.2-devel-ubuntu22.04' container with the '--gpus=all' flag. Note that
Docker must be set up to allow passing through the CUDA instructions to the host. The container only needs
'automake' and 'libtool' installed: `apt update && apt install -y automake libtool`.

This code was tested for functional correctness with the following:
    ./configure --enable-all --disable-shared --disable-crl-monitor --enable-cuda CC=nvcc && make check

There are still things that can be done to optimize, but the basic functionality is there.

## Security considerations

### Threat models the table-based kernel is designed for

The default build (large T-tables, `WOLFSSL_AES_SMALL_TABLES` not defined)
looks up each T-table entry with a masked scan: it reads one entry from
every `WC_CACHE_LINE_SZ`-byte region of the table and keeps only the
wanted one. Which region holds the entry is therefore hidden, but the
offset within a region still depends on the key and data.

This only holds if the scan granularity matches the GPU. Caveats:

- `WC_CACHE_LINE_SZ` is chosen from host-architecture macros (64 on
  x86_64, otherwise 32), not detected from the GPU.
- The tables are assumed to be aligned to that size; this is not enforced.
- GPUs may cache or transfer memory at a finer granularity (for example
  32-byte sectors). Offsets within a region can then be observable at that
  granularity. Defining `WC_CACHE_LINE_SZ=32` makes the scan finer at some
  performance cost.

Within those limits, the scan is intended to resist:

- **Remote attackers** who can choose or observe plaintext/ciphertext and
  measure end-to-end operation time over a network.
- **Cache-timing attackers** who share a CPU or GPU cache with the
  encrypting process and observe which cache lines are accessed, at cache
  line granularity.

These protections apply only when every local user and process that can
run code on, or query, the GPU is trusted, for example a dedicated
single-tenant host or appliance.

### Threat models it is NOT designed for

- **Power, energy, or EM analysis**, whether by physical measurement or by
  software-readable device telemetry (power/energy counters). T-table AES
  has data-dependent power use, and the cache-line mitigation does nothing
  about it.
- **Untrusted local users or tenants with GPU access**, including shared
  or multi-tenant GPUs, containers or VMs with the GPU passed through, and
  users who can read device telemetry or change device power/clock
  settings.
- **Fine-grained timing measurements** made on the same system, especially
  under clock or power settings the attacker can influence.
- **Privileged local attackers** (root or driver-level access), who can
  read GPU memory directly.

### `WOLFSSL_AES_SMALL_TABLES`

With small tables, S-box lookups in the CUDA kernel index the table
directly; only a prefetch is applied. This build is not designed to
resist timing or cache attacks on the GPU and should not be used where
any of the threat models above are a concern.

### Other notes

- **Offloaded operations.** Only AES encryption runs on the GPU; all AES
  decryption (for example CBC and ECB decryption) uses the CPU
  implementation. Single-block encryption runs as a one-thread kernel.
  When `HAVE_AES_ECB` is defined, the following are offloaded in parallel,
  many blocks under the same key:
  - AES-ECB encryption.
  - AES-CTR when the input and output buffers differ.
  - AES-GCM encryption and decryption when not operating in place. GCM uses
    AES encryption in both directions.

  In-place AES-CTR and AES-GCM encrypt one block per kernel launch.
- **Key material in device memory.** Round keys are copied to GPU memory
  for each operation and freed without being zeroized.
- **Error handling.** CUDA errors (allocation, copy, launch) are not
  reported to the caller; a failed GPU operation may yield incorrect
  output without an error code.
- **Bitsliced AES is not supported with CUDA.** `WC_AES_BITSLICED` does not
  build with `HAVE_CUDA` and is not a constant-time alternative here.
