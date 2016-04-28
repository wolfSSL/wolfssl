#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

from setuptools import setup, find_packages

os.chdir(os.path.dirname(sys.argv[0]) or ".")

setup(
    name="wolfcrypt",
    version="0.1",
    description="A python wrapper for the wolfCrypt API",
    long_description=open("README.rst", "rt").read(),
    url="https://github.com/wolfssl/wolfcrypt-py",
    author="Moisés Guimarães",
    author_email="moises@wolfssl.com",
    classifiers=[
        "Development Status :: 0 - Alpha",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: PyPy",
        "License :: GPLv2 License :: Commercial License",
    ],
    packages=find_packages(),
    setup_requires=["cffi>=1.5.2"],
    install_requires=["cffi>=1.5.2"],
    cffi_modules=["./wolfcrypt/build_ffi.py:ffi"]
)
