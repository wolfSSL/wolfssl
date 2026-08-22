# How the kernel module serves `get_random_bytes()`

Enabled with `--enable-linuxkm-rbgc`.  Needs a kernel carrying one of the
patches in `linuxkm/patches/`, which export
`wolfssl_linuxkm_register_random_bytes_handlers()` and its unregister
counterpart from `drivers/char/random.c`.  Without one of those patches the
module does not build: `linuxkm/module_hooks.c` stops on an `#error` naming
this directory.

## The idea in one paragraph

The Linux kernel has its own random number generator.  When wolfSSL is loaded
as a FIPS module, we take over `get_random_bytes()` so the numbers come from
the validated module instead.  The hard part is not the cryptography, it is
that the kernel asks for random numbers from places where you are not allowed
to wait for anything: inside interrupt handlers, and inside NMIs.  So the
design is arranged so that **no caller ever has to wait, and no caller is ever
turned away**.

## The shape

One "root" generator gathers real entropy.  It never answers a caller.  Its
only job is to feed the leaves.  Each CPU gets its own leaves, so two CPUs
never queue behind each other.

```
                    entropy source (SP 800-90B noise)
                              |
                              |  only the root ever draws from it
                              v
                        +-----------+
                        |   root    |   refreshes on its own timer
                        +-----------+
                          /   |   \
             seeds        /   |    \        seeds
                         v    v     v
   CPU 0                CPU 1              CPU 2      ...
 +---------+          +---------+        +---------+
 | leaf    |          | leaf    |        | leaf    |   <- normal work
 +---------+          +---------+        +---------+      (apps, softirq,
 | nmi A/B |          | nmi A/B |        | nmi A/B |       hardirq)
 +---------+          +---------+        +---------+   <- NMI only
      ^                    ^                  ^
      |                    |                  |
  get_random_bytes()  get_random_bytes()  get_random_bytes()
```

A leaf is a DRBG: give it a seed, it produces an endless stream of random
bytes.  After a while it must be re-seeded, or the stream is no longer
considered fresh.

## Why one leaf per CPU is enough for normal work

A caller turns interrupts off while it uses its leaf.  With interrupts off, a
CPU cannot be pulled away to run something else.  So on CPU 0, an application,
a softirq and a hardirq can never be inside the leaf at the same time - they
have to take turns by construction.  And no other CPU touches CPU 0's leaf.

```
CPU 0 timeline:   [ app uses leaf 0 ]---[ hardirq uses leaf 0 ]---[ app ]
                   ^ interrupts off      ^ interrupts off
                   nothing can interleave here
```

## The re-seed problem, and the fix

Re-seeding rewrites the leaf.  If that happened while a caller was reading the
leaf, the caller would get garbage - so the old design made callers wait, and
if they could not wait, turned them away.

The fix: **do the re-seed on the same CPU that owns the leaf.**  A small
background job is pinned to each CPU.  When it runs, it turns interrupts off,
which means no caller on that CPU can possibly be inside the leaf.  It
re-seeds, turns interrupts back on, and leaves.  Nobody waited.  Nobody was
refused.

```
CPU 0:  [ app ]---[ re-seed job, interrupts off ]---[ app ]---[ softirq ]
                   ^ safe: nothing else on CPU 0 can run right now
```

This is the same pattern the kernel's own generator uses for its per-CPU state.

## NMI is the exception

An NMI - "non-maskable interrupt" - is the one thing that turning interrupts
off does *not* stop.  It can arrive at any instant, even in the middle of the
re-seed job.  So an NMI cannot share the normal leaf.

Each CPU therefore has **two** NMI generators, A and B.  Exactly one is "live"
at a time.  The re-seed job works on the spare, never on the live one, and
then flips a single switch to make the spare live:

```
before:   live -> [ A ]        [ B ] <- job re-seeds this one, off to the side
                     ^
                  NMI reads A

flip:     live -> [ B ]        [ A ] <- becomes the spare, untouched
                     ^                   until the next re-seed cycle
                  NMI reads B
```

Flipping the switch is a single instruction.  An NMI landing at any moment
reads either A or B, and both are complete, working generators.  There is no
in-between state to catch.

That leaves one hole.  An NMI that started reading A can be stalled
mid-handler - on a virtual machine the whole CPU can be taken away for hundreds
of milliseconds - and if the re-seed job came round twice while it was stalled,
the second pass would be rewriting A underneath it.

Two things close it.  First, the re-seed job for a CPU's pair runs on that CPU,
so a stalled NMI stalls the job along with it: the job cannot come round even
once while the NMI is mid-read, let alone twice.  CPU hot-plug is the only
thing that can put that job on a different CPU, and it is turned away when it
lands on one.

Second, as a backstop, each generator carries a version number, bumped before
it is re-seeded.  An NMI notes the version, generates the caller's bytes, and
checks the version again before telling the caller they are good:

```
  NMI:   note version of A  ->  generate the bytes  ->  version still same?
                                                          |            |
                                                         yes           no
                                                          |            |
                                                    tell the      read the other
                                                    caller they   one over the
                                                    are good      top, up to 3x
```

Nothing is generated before it is asked for and nothing is kept afterwards.
The bytes are written where the caller asked for them, and the caller is
stopped inside the call until it returns; a return of anything but success
means the kernel refills the whole buffer itself, so an interrupted read is
simply overwritten rather than needing to be held anywhere.

A changed version is not a reason to give up.  It means that generator was
re-seeded mid-read, and the *other* one is live now and fully working - so the
NMI simply reads that one instead.  Only if three reads in a row are each
interrupted does it give up.

That matters more than it looks.  Giving up does not mean "no bytes"; it means
the kernel answers from its own generator, which is outside the module.  Those
bytes are real randomness, but they are not the validated module's output, so
every refusal is a hole in the claim that the module serves this call.  A
re-seed lands about 7.6 times a second per CPU and a read takes microseconds,
so three interrupted reads in a row is not something the measured rates can
produce.

## Big requests are cut into pieces

While a leaf is producing bytes, interrupts are turned off on that CPU.  That
is what makes the whole scheme safe, but it means the CPU cannot respond to
anything else for as long as it takes.

The catch is that the caller chooses the size.  `ip_rt_init()` asks for 65536
bytes in a single call.  A 256-byte piece takes 4.1 microseconds; 65536 bytes
is 256 such pieces, so producing that much in one go would keep interrupts off
for about 1.05 milliseconds - far too long, and on a real-time kernel it is
simply not allowed.

So a request is served 256 bytes at a time, letting interrupts back in between
pieces:

```
  one 64 KB request

  before:  [============== interrupts off ==============]   ~1.05 ms
                                                                 nothing else
                                                                 can run

  after:   [==] [==] [==] [==] [==] ... [==]                     each piece is
             ^    ^    ^    ^                                     the same small
             interrupts are back on here                          cost, however
                                                                  big the ask
```

The time interrupts are off is now set by the piece size, not by the request
size.  A bigger request takes more pieces, not longer pieces.

Splitting is safe because each piece is a complete, independent request to the
generator.  If something else on that CPU asks for random bytes between two
pieces, it simply gets served and moves the generator on; the next piece
carries on from wherever it now is.  Every byte handed back came from the
validated module either way.

## What this buys

* Every caller is served, in every context.  Nothing waits, and nothing is
  handed back to the kernel's own generator: the one path that could refuse now
  re-reads the other instance instead, three times before giving up, and with
  the on-CPU re-seed rule in place there is no sequence of events left that
  makes even the first re-read necessary.
* Large requests are served in 256-byte pieces, so the time spent with
  interrupts turned off does not grow with the size of the request.  Measured
  over 62,504 requests of 64 KB each, the time interrupts are off is the same
  as for a small request: 4.1 microseconds at the median, 8.2 at the 99th
  percentile.  Served in one go the same request would have blocked interrupts
  for about 1.05 milliseconds.
* Only the root touches the entropy source.  Nothing is generated in advance
  and stored for later use - each seed is produced at the moment it is needed
  and destroyed immediately after.
* Measured: 133 million calls, zero served by the kernel's generator, other
  than the handful that arrive before the module is even loaded.

## What the module does NOT serve

Two things are outside the module, and both belong in the Security Policy.
Measured on `linux-6.16.12`, x86_64 and aarch64 guests.

### 1. Everything before the self-tests finish

The kernel needs random numbers long before the module is allowed to give it
any.  This is not a timing accident that a bigger patch could fix - FIPS 140-3
forbids a module from providing cryptographic services until its power-on
self-tests pass, and those take real time:

```
 0.04s  kernel's own generator ready
 1.74s  libwolfssl.ko starts loading
        |
        |  <-- FIPS integrity check and self-tests: 1.2s to 4.1s
        |
 4.26s  our hook goes live
```

So there is necessarily a window where the kernel asks and the module may not
answer.  Building wolfSSL into the kernel instead of loading it as a module
shortens the window but cannot remove it - the self-tests still have to run.

**Who asks during that window.**  Measured on `linux-6.16.12`: 40 calls on
x86_64, 28 on aarch64.  Nothing in this list is a cryptographic key.

| calls | bytes | caller | what it is | cryptographic? |
|---:|---:|---|---|---|
| 11 | 4 | `key_alloc` | serial number for a kernel keyring key | no, an identifier |
| 10 | 10 | `rc80211_minstrel_init` | wireless rate-control jitter | no, a tie-breaker |
| 5 | 8 | `sys_getrandom` | userspace asked directly | unknown, userspace decides |
| 5 | 16 | `load_elf_binary` | `AT_RANDOM`: stack canary, pointer guard | no, hardening values |
| 4 | 16 | `uuid_gen` | random UUIDs | no, identifiers |
| 1 | 65536 | `ip_rt_init` | IPv4 route cache hash seed | no, anti-collision |
| 1 | 4 | `sysctl_ipv4_init` | IPv4 sysctl setup | no |
| 1 | 4 | `net_ns_init` | network namespace setup | no |
| 1 | 16 | `fill_ptr_key` | key for hashing pointers in log output | no, anti-disclosure |
| 1 | 128 | `kcmp_cookies_init` | `kcmp()` syscall cookies | no, anti-disclosure |

aarch64 is the same without the wireless and IPv4-sysctl rows, and with one
fewer `key_alloc`.

The only two that leave the kernel are `load_elf_binary` and `sys_getrandom`,
which become stack canaries and pointer guards for the few processes that start
before the module is up.

This list is a property of the kernel's configuration - `rc80211_minstrel_init`
appears only because this guest has wireless built in - so re-measure per
target rather than reusing the table.

### 2. `get_random_u8/u16/u32/u64` - never, at any time

These do not go through `get_random_bytes()`.  They call the kernel's internal
generator directly, so the hook is never offered them, before or after the
module loads:

```
  get_random_bytes()  --> hook --> wolfSSL      served
  get_random_u32()    --------------> kernel    never offered
```

Measured on an otherwise idle guest: about 400 such calls in two minutes on
both architectures, continuous rather than a one-time boot window, and growing
with real system activity - TCP sequence numbers, address-space layout
randomisation and slab randomisation all use this family.

**This gap belongs to the experimental test hook, not to the design.**  The
supported kernel patches in `linuxkm/patches/` hook `_get_random_bytes()`,
which the whole `get_random_uN` family calls, and `linuxkm/lkcapi_sha_glue.c`
already registers handlers against it.  The blastmatrix harness uses a simpler
hook on the public `get_random_bytes()` wrapper because four of the six kernel
versions it tests have no supported patch; that wrapper sits one level above
`_get_random_bytes()`, so the batched family flows past it.  Numbers on this
page were taken through the simpler hook and therefore describe
`get_random_bytes()` only.

### What can honestly be claimed

> Every `get_random_bytes()` call after the module's power-on self-tests
> complete is served by the validated module.

Measured over 274.5 million calls across four architectures: zero fell back to
the kernel's generator.  The `get_random_u32()` family and the boot window
above are outside that statement.

## Where the code is

| file | what |
|---|---|
| `wolfcrypt/src/linuxkm_get_entropy.c` | the root, the leaves, the service.  Inside the FIPS boundary. |
| `wolfssl/wolfcrypt/linuxkm_get_entropy.h` | its declarations.  All internal; none of this is public API. |
| `linuxkm/module_hooks.c` | registers the hook and runs the per-CPU re-seed jobs.  Outside the boundary. |

The standards detail - which SP 800-90C rule each step follows - is in the
comment block at the top of `linuxkm_get_entropy.c`.
