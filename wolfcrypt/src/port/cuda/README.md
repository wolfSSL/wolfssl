You will need to have the CUDA libraries and toolchains installed to be able to use this. For the simplest
setup, I used the 'nvidia/cuda:12.3.2-devel-ubuntu22.04' container with the '--gpus=all' flag. Note that
Docker must be set up to allow passing through the CUDA instructions to the host. The container only needs
'automake' and 'libtool' installed: `apt update && apt install -y automake libtool`.

This code was tested with the following:
    ./configure --enable-all --disable-shared --disable-crl-monitor --enable-cuda CC=nvcc && make check

There are still things that can be done to optimize, but the basic functionality is there.
