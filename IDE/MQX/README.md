#How to build with MQX
## Overview
This Makefile is for building wolfSSL library and sample programs running with MQX.
It has following tartes.
 - wolfssllib: wolfSSL static library
 - test: crypt test
 - benchmark: cypher benchmark
 - client: TLS client example
 - server: TLS server example

## Prerequisites
- Installed MQX

## Setup
- wolfSSL configuration parameters
  You can add or remove configuration options in <wolfSSL-root>/IDE/MQX/user_settings.h.

- Setup Makefile
  MQX_ROOT: MQX source code installed path
  MQXLIB:   MQX library path to like with
  CC:       compiler
  AR:       archiver
  WOLF_ROOT: change this if you move this Makefile location
