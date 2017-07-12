Fuzz Targets
============

The files in this directory are fuzzing targets for wolfSSL. They follow the
LLVM libFuzzer API and have a very specific naming scheme for integration with
[Google's OSS-Fuzz service][oss-fuzz]. For more information about these
qualities, see [the section on making new targets](#new_target) below. To be
run, they must be linked against `libFuzzer.a`. For more information about
compilation, see [the section on compiling](#compiling_target) below.

[The very last section of this README](#future) is meant to document the
foreseeable future of this directory, including suggestions on what fuzz
targets should be written next. It is requested that future editors of this
directory update that section to reflect their work and thoughts.

<a name="compiling_target">Compiling Targets</a>
------------------------------------------------

The first thing to know is that you only need to compile these yourself if you
intend to do testing outside of the OSS-Fuzz environment, which is useful, as
getting OSS-Fuzz up takes some time. After you have finished compiling, you may
move on to [the section on running fuzz targets](#run_targt) below.

For information on how to get a target running inside of OSS-Fuzz, see [the
section on OSS-Fuzz](#with_oss-fuzz) below.

For the entirety of this section, let "`fuzz_target`" be a stand-in for the
name of your target. It will be identical to the file name of the source code,
but with out the ".c" extension.

If you have access to the make utility, everything will be simple: simply
execute `make fuzz_target` to compile it. If necessary, make will automatically
retrieve the libFuzzer library and the most recent version of clang, both of
which are required for compilation. Neither are installed, but kept locally
instead. If you wish to get these dependencies explicitly, call `make deps` or
`make dependencies`. They are synonymous

Furthermore, running `make` or `make all` will compile all files ending in ".c"
as fuzz targets, running `make clean` will delete the compiled fuzz targets but
leave the source files intact, and running `make spotless` will act like `make
clean` but also delete libFuzzer and clang.

If you don't have access to make, you're going to have to do it all by hand.
What follows for the rest of this section are the instructions for doing what
the Makefile describes, but by yourself. If make is available and worked, you
may skip the remainder of this section.

The first thing to know is that the fuzz targets in this directory are written
in C, yet `libFuzzer.a` is a C++ library. As such, the compilation of a target
comes in two fazes: compile, then link. Similarly, because of the nature of
libFuzzer, compilation must be done through clang rather than gcc.

The official libFuzzer documentation can be found [on the LLVM
website][libFuzzer].

The first thing to do is to get libFuzzer. To do this, run these commands from
the shell:

```
$ git clone https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer Fuzzer
$ ./Fuzzer/build.sh
```

The above clones in the libFuzzer git repository then builds it. There should
now be a `libFuzzer.a` in this directory.

Next we need an up-to-date version of clang. To do this, we're going to clone
down some tools. Because of how those tools expect their directory hierarchy,
we're going to put that repository three directories deep. After that, we'll
use those tools to pull down the most up-to-date version of clang then make a
link for our convenience. In all, that looks like this:

```
$ export CLANG_TOOLS=https://chromium.googlesource.com/chromium/src/tools/clang
$ git clone $CLANG_TOOLS new_clang/clang/clang
$ python new_clang/clang/clang/scripts/update.py
$ cp -s -t . new_clang/third_party/llvm-build/Release+Asserts/bin/clang{,++}
```

And with that, you now have a recent version of clang. It has not been
installed, so to use it you'll have to call clang like
```
$ ./clang
```
from this directory. Alternatively, you could call it like
```
$ ./new_clang/third_party/llvm-build/Release+Asserts/bin/clang
```
but that's a huge command. That's why we make links.

To compile, run these commands from the shell:

```
$ ./clang -fsanitize=address -fsanitize-coverage=trace-pc-guard -c fuzz_target.c -o fuzz_target.o
$ ./clang++ -fsanitize=address -fsanitize-coverage=trace-pc-guard fuzz_target.o -L. -lwolfssl -lFuzzer -o fuzz_target
$ rm fuzz_target.o
```

And with that, `fuzz_target` has been compiled. This compile step is the only 

<a name="run_target">Running Targets</a>
----------------------------------------

For the entirety of this section, let "`fuzz_target`" be a stand-in for the
name of your target. It will be identical to the file name of the source code,
but with out the ".c" extention.

After compiling, `fuzz_target` is an executable that can be called like this:

```
$ ./fuzz_target [OPTION ...] [CORPUS ...]
```
or
```
$ ./fuzz_target [OPTION ...] [FILE ...]
```

A corpus is a directory with files containing example input data, good or bad,
for the fuzzer to use as a starting point. If a new file is generated, it will
be placed in the first corpus listed. If files are passed, they will be passed
without being fuzzed. This is useful for testing if a fuzz target modification
worked.

Options come strictly in the form `-flag=value`. Here are some useful options:

* `-runs=N`: run N tests. The default (N = -1) means to run indefinitely.
* `-max_len=N`: cap input data at at most N bytes of data
* `-max_total_time=N`: run tests for at most N seconds. The default (N = 0)
  means to run indefinitely.
* `-help=1`: show help, including calling convention and all options

<a name="new_target">Writing New Targets</a>
--------------------------------------------

There are three different things that you should make every time you make a new
fuzz target: [source code](#target_src), [options](#target_opt), and
[corpus](#target_corp). See their respective subsections below for more
information on each.

All three parts must be placed in the same directory with all the other fuzz
targets. There are no exceptions; failure to comply with this will prevent your
fuzz target from being found by OSS-Fuzz.

The only required part is the source code; options files and corpuses (corpi?)
may be omitted, though it is recommended that you include all three components.

The fourth, extra optional part is the dictionary. You can read more about how
to use or include them in [the OSS-Fuzz documentation][dict]. If you wish to
include one, create a file ending in ".dict" in this directory, then add a line
like this to the options file for the fuzz target that will use it:

```
[libfuzzer]
dict = my_dictionary.dict
```

Furthermore, in this directory is a file named `user_settings.h`. The contents
of this file will be used when compiling wolfSSL in the OSS-Fuzz environment.
It's most important job is to replace the random number generator with a
counter so that wolfSSL will behave deterministically.

### <a name="target_src">Source Code</a>

The source code is more or less what you'd expect: the code describing the
test. It can be named however you like, though must end with ".c". Internally,
the only requirement is that it not implement `main()` and instead implement a
function for this prototype:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t sz);
```

For definitions of `uint8_t` and `size_t`, include `stdint.h` and `stdlib.h`
respectively.

In this function, `data` is a buffer of size `sz` bytes. Within this buffer is
the content of a file. If the target was invoked at the command line with file
names, the content of data will be exactly the content of the file. Otherwise,
it will contain the fuzzed version of files in the corpus.

From here, all you need to do to accomplish the test is to pass `data` and `sz`
to whatever API call you wish to fuzz. For examples, please see the other fuzz
targets contained in this directory.

### <a name="target_opt">Options</a>

An options file will indicate to OSS-Fuzz which flags and values to pass to the
fuzz target when running it. It is not required, but it is recommended that you
at least define `max_len`.

An options file should be named the same as the source code, but with
".options" in place of ".c".

The format seems to be similar to [the ini format][ini], though no explicit
confirmation of this was found. Regardless, a file about like this is suitable:

```
[libfuzzer]
max_len = 1024
```

### <a name="target_corp">Corpus</a>

A corpus is a directory containing "seeds" for the fuzzer. The fuzzer will
intelligently generate fuzzed input from these files to feed into the fuzz
target. Inside, you can include good or bad input. In general, it is
recommended that you include a few examples of good input. If ever fuzzing
finds an example of bad input, it is also recommended that you add this bad
input to make sure the problem that created it is not re-introduced.

The corpus must be a directory named the same as the source code, but with
`_corpus` in place of ".c".

The contents of the corpus do not need to conform to any kind of naming scheme,
though libFuzzer expects the file's name to be the sha1 sum of the file, and so
it is recommended that all corpus files are named accordingly.

<a name="with_oss-fuzz">Running Targets in OSS-Fuzz</a>
-------------------------------------------------------

If you've followed all the conventions described in [the section on writing new
targets](#new_target) above, you can get any target you've written to run in
OSS-Fuzz pretty simply.

Before trying to get a target working with OSS-Fuzz, it is recommended that you
can confirm that it compiles and runs locally, because doing so makes the
turn-around on fixing bugs/mistakes much shorter. For more information on
compiling targets locally, see [the section on compiling](#compiling_target)
above.

The first thing to do is to make sure that Docker is installed and running. To
do this, please consult [Docker's website][docker]. If you are on a Linux
system, it is probable that Docker is already in your distribution's software
repository.

To get the OSS-Fuzz repository down onto your local machine, a git-clone like
this should work:

```
$ git clone https://github.com/google/oss-fuzz
```

Note that if you are going to be modifying the fuzz targets, you'll need to
modify where Docker will get its targets. Open
`./oss-fuzz/projects/wolfssl/Dockerfile` and change the line
```
RUN git clone --depth 1 https://github.com/wolfssl/wolfssl.git wolfssl
```
to something like this:
```
RUN git clone --depth 1 https://github.com/<you>/wolfssl.git -b <work_branch>wolfssl
```

Be sure to replace `<you>` with your github user name and `<work_branch>` with
the branch to which you are pushing your new targets.

From the OSS-Fuzz root directory, we're going to run some Python scripts. Take
notice that these scripts are written in Python 2. Furthermore, you will
probably need to run them with root permissions. Appending `sudo` should do.
Finally, these commands require the Docker daemon to be running. Those commands
should look like this:

```
# python infra/helper.py build_image wolfssl
# python infra/helper.py build_fuzzers --sanitizer address wolfssl
```

You may also choose to use `memory` or `undefined` for the sanitizer option.

To actually run a fuzz target, run this command:

```
# python infra/helper.py run_fuzzer wolfssl <fuzz_target>
```

Where `<fuzz_target>` corresponds with the file name (without the ".c") of the
target you wish to run.

<a name="future">Future Direction</a>
-------------------------------------

Add more tests for various wolfSSL and wolfCrypt APIs. Focus on APIs which
process buffers containing data that plausibly could originate from some
outside source. As examples, in `server.c` the fuzzed data is impersonating a
server, and in `pem2der.c` the fuzzed data is used as a PEM certificate. In
each case, the fuzzed data represents malformed input.

<!-- References -->
[libFuzzer]: http://llvm.org/docs/LibFuzzer.html
[libFuzzer_use]: http://llvm.org/docs/LibFuzzer.html#fuzzer-usage
[oss-fuzz]: https://github.com/google/oss-fuzz
[ini]: https://en.wikipedia.org/wiki/INI_file
[dict]: https://github.com/google/oss-fuzz/blob/master/docs/new_project_guide.md#dictionaries
[docker]: https://www.docker.com/
