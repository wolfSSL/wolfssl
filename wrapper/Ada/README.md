# Ada Binding Example
The source code for the Ada/SPARK binding of the WolfSSL library
is the WolfSSL Ada package in the wolfssl.ads and wolfssl.adb files.

The source code here also demonstrates a (D)TLS v1.3 server and client
using the WolfSSL Ada binding. The implementation is cross-platform
and compiles on Linux, Mac OS X and Windows.

Security: The WolfSSL Ada binding avoids usage of the
Secondary Stack. The GNAT compiler has a number of hardening
features for example Stack Scrubbing; the compiler can generate
code to zero-out stack frames used by subprograms.
Unfortunately this works well for the primary stack but not
for the secondary stack. The GNAT User's Guide recommends
avoiding the secondary stack using the restriction
No_Secondary_Stack (see the GNAT configuration file gnat.adc
which instructs compilation of the WolfSSL Ada binding under
this restriction). Note, however, that the examples do make use of the
secondary stack.

Portability: The WolfSSL Ada binding makes no usage of controlled types
and has no dependency upon the Ada.Finalization package.
Lighter Ada run-times for embedded systems often have
the restriction No_Finalization. The WolfSSL Ada binding has
been developed with maximum portability in mind.

Not only can the WolfSSL Ada binding be used in Ada applications but
also SPARK applications (a subset of the Ada language suitable
formal verification). To formally verify the Ada code in this repository
open the client.gpr with GNAT Studio and then select
SPARK -> Prove All Sources and use Proof Level 2. Or when using the command
line, use `gnatprove -Pclient.gpr --level=4 -j12` (`-j12` is there in
order to instruct the prover to use 12 CPUs if available).

```
Summary of SPARK analysis
=========================

---------------------------------------------------------------------------------------------------------------
SPARK Analysis results        Total        Flow   CodePeer                       Provers   Justified   Unproved
---------------------------------------------------------------------------------------------------------------
Data Dependencies                 2           2          .                             .           .          .
Flow Dependencies                 .           .          .                             .           .          .
Initialization                   15          15          .                             .           .          .
Non-Aliasing                      .           .          .                             .           .          .
Run-time Checks                  58           .          .    58 (CVC4 85%, Trivial 15%)           .          .
Assertions                        6           .          .                      6 (CVC4)           .          .
Functional Contracts             91           .          .                     91 (CVC4)           .          .
LSP Verification                  .           .          .                             .           .          .
Termination                       .           .          .                             .           .          .
Concurrency                       .           .          .                             .           .          .
---------------------------------------------------------------------------------------------------------------
Total                           172    17 (10%)          .                     155 (90%)           .          .
```

## Compiler and Build System installation

### Recommended: [Alire](https://alire.ada.dev)
[Alire](https://alire.ada.dev) is a modern package manager for the Ada
ecosystem.  The latest version is available for Windows, OSX, Linux and FreeBSD
systems.  It can install a complete Ada toolchain if needed, see `alr install`
for more information.

In order to use WolfSSL in a project, just add WolfSSL as a dependency by
running `alr with wolfssl` within your project's directory.

If the project is to be verified with SPARK, just add `gnatprove` as a
dependency by running `alr with gnatprove` and then running `alr gnatprove`,
which will execute the SPARK solver. If you get warnings, it is recommended to
increase the prove level: `alr gnatprove --level=4`.

### GNAT FSF Compiler and GPRBuild manual installation
In May 2022 AdaCore announced the end of the GNAT Community releases.
Pre-built binaries for the GNAT FSF compiler and GPRBuild can be
downloaded and manually installed from here:
https://github.com/alire-project/GNAT-FSF-builds/releases
Make sure the executables for the compiler and GPRBuild are on the PATH
and use gprbuild to build the source code.

#### Manual build of the project

```sh
cd wrapper/Ada
gprclean
gprbuild default.gpr
gprbuild client.gpr

cd obj/
./tls_server_main &
./tls_client_main 127.0.0.1
```

On Windows, build the executables with:
```sh
gprbuild -XOS=Windows default.gpr
gprbuild -XOS=Windows client.gpr
```

## Files
The (D)TLS v1.3 client example in the Ada/SPARK programming language
using the WolfSSL library can be found in the files:
tls_client_main.adb
tls_client.ads
tls_client.adb

The (D)TLS v1.3 server example in the Ada/SPARK programming language
using the WolfSSL library can be found in the files:
tls_server_main.adb
tls_server.ads
tls_server.adb
