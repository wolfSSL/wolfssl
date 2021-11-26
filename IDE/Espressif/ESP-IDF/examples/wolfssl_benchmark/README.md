# wolfSSL Benchmark Example

The Example contains of wolfSSL benchmark program.

1. `idf.py menuconfig` to configure the program.  
    1-1. Example Configuration ->

    BENCH_ARG : argument that you want to use. Default is "-lng 0"  
    The list of argument can be find in help.

When you want to run the benchmark program

1. `idf.py -p <PORT> flash` to compile and load the firmware
2. `idf.py monitor` to see the message

See the README.md file in the upper level 'examples' directory for more information about examples.
