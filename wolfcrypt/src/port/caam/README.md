# wolfSSL CAAM Port

See `caam_doc.pdf` for documentation about building and using the driver on
i.MX under INTEGRITY, and `IDE/QNX/README.md` for the QNX build.

## Linux user space (`--enable-caam=linux`)

Runs the same driver core (`caam_driver.c`) from a Linux user space process,
developed against the SEC on a QorIQ T1040. QNX reaches the hardware through a
resource manager; here the driver runs in the calling process and a request is
a direct call.

    ./configure --host=powerpc-linux-gnu CC=powerpc-linux-gnu-gcc \
                --enable-caam=linux
    make

Accelerated: **AES-CBC, AES-CTR, AES-ECB** and the **TRNG**. Everything else
returns `CRYPTOCB_UNAVAILABLE` and runs in software, so an unsupported
operation is a performance question, not a correctness one. Hashing has no
descriptors in this driver (as on QNX), there is no i.MX style secure memory
block on this part so blobs and black keys are out, and public key is not
dispatched yet even though the driver carries the descriptors.

### The engine has to be yours

The in-tree `caam` driver claims all four job rings at boot and, on a part with
more than 4 GB of DDR, sets `MCFGR[PS]` for 64-bit descriptor pointers.
`MCFGR` is global to the block, so sharing it is not an option: this driver
writes 32-bit pointer words. Take the whole engine, then put it back in 32-bit
mode:

    for j in ffe301000.jr ffe302000.jr ffe303000.jr ffe304000.jr; do
        echo $j > /sys/bus/platform/drivers/caam_jr/unbind; done
    echo ffe300000.crypto > /sys/bus/platform/drivers/caam/unbind

Unbinding leaves that driver's interrupt handler registered, and the first job
to complete would otherwise raise an IRQ it services against freed state and
panic the kernel. `CAAM_SET_JOBRING_ADDR()` masks the ring interrupt when it
claims the ring; the driver polls anyway.

### Reserved DMA memory

The engine cannot use ordinary user pages: they are not physically contiguous,
and on a 36-bit part they sit above what a 32-bit descriptor pointer can
address (measured on a T1040: virtual `0x100b4f10` -> physical
`0x1_EF9C2F10`). Boot Linux with `mem=` so it stops managing the top of DDR,
and the port carves engine buffers out of that reserved range instead:

    setenv othbootargs 'ramdisk_size=1000000 mem=2048M'

That leaves physical `[2 GB, 4 GB)` unmanaged, contiguous, and below the
32-bit limit. It also makes `CONFIG_STRICT_DEVMEM` allow the mapping, since
the range is no longer reported as System RAM.

Note CCSR is at the full physical address under Linux (`0xF_FE000000` on a
T1040), not the 32-bit view bare metal sees.

| Macro | Default | Meaning |
|---|---|---|
| `CAAM_LINUX_CCSR_PHYS` | `0xFFE000000ULL` | Physical base of the CCSR window |
| `CAAM_LINUX_SEC_OFFSET` | `0x300000` | SEC block within CCSR |
| `CAAM_LINUX_JR_OFFSET` | `0x1000` | Which job ring to claim |
| `CAAM_LINUX_POOL_PHYS` | `0x80000000ULL` | Base of the reserved DMA pool |
| `CAAM_LINUX_POOL_SZ` | 256 KB | Size of that pool |
| `CAAM_LINUX_AES_MAX` | 16 KB | Largest AES request taken; bigger goes to software |

### Performance: read this before enabling it

On a T1040 at 1.4 GHz the engine is **slower than software AES**, measured
with the same binary over the same buffers:

| Buffer | Software | CAAM | Ratio |
|---:|---:|---:|---:|
| 512 B | 42.69 MiB/s | 21.61 MiB/s | 0.51x |
| 1 KB | 44.61 MiB/s | 24.88 MiB/s | 0.56x |
| 4 KB | 45.67 MiB/s | 27.09 MiB/s | 0.59x |
| 8 KB | 46.30 MiB/s | 27.50 MiB/s | 0.59x |
| 16 KB | 46.31 MiB/s | 27.75 MiB/s | 0.60x |

Hardware throughput is flat at roughly 28 MiB/s because the per-job cost
dominates: two `memcpy`s to stage operands in and results out of the pool, a
descriptor build, and a polled completion. Software rises with buffer size and
the e5500's AES is quick. The gap does narrow with key size, since the engine
barely notices AES-256 while software slows down.

So the reason to enable this is not throughput. It is access to the TRNG as a
real entropy source, and having the crypto happen somewhere other than the
core. Closing the gap means removing the bounce buffers (letting callers
allocate from the pool directly), raising the transfer size toward the SEC's
64 KB per-descriptor limit, and completing on an interrupt rather than a poll.
