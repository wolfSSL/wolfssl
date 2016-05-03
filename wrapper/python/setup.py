#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

from setuptools import setup, find_packages

os.chdir(os.path.dirname(sys.argv[0]) or ".")

setup(
    name="wolfcrypt",
    version="0.1.0",
    description="A Python wrapper that encapsulates wolfSSL's wolfCrypt API",
    long_description=open("README.rst", "rt").read(),
    url="https://wolfssl.github.io/wolfcrypt-py",
    author="wolfSSL",
    author_email="info@wolfssl.com",
    classifiers=[
        "Development Status :: 0 - Alpha",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: PyPy",
        "License :: GPLv2 License :: Commercial License",
    ],
    packages=find_packages(),
    setup_requires=["cffi>=1.6.0"],
    install_requires=["cffi>=1.6.0"],
    cffi_modules=["./wolfcrypt/build_ffi.py:ffi"]
)
