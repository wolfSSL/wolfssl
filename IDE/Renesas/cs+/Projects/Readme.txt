
wolfssl_lib:
  Build wolfssl_lib.lib

test:
  Build test wolfCrypt
  To get missing files 
  - create DUMMY project
  - copy all files under DUMMY project except DUMMY.*
  - uncomment "Use SIM I/O" lines in resetprg.c
  - set heap size in sbrk.h
    suggested starting from more than 0x8000
  - set stack size in stacksct.h
    suggested starting from more than 0x4000

