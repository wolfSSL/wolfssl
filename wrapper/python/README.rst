wolfcrypt: the wolfSSL Crypto Engine
====================================


A Python wrapper which encapsulates the wolfCrypt API inside wolfSSL library


**REQUIRES** [wolfSSL](https://github.com/wolfSSL/wolfssl)


1. Clone the repository::


    $ git clone git@github.com:wolfssl/wolfcrypt-py.git


2. Make sure that ``cffi``, ``py.test``, and ``tox`` are installed::


    $ pip install -r requirements-testing.txt


3. Run ``python setup.py install`` to build and install wolfcrypt-py::


    $ python setup.py install
    ...
    Finished processing dependencies for wolfcrypt==0.1


4. Test locally with ``tox``::


    $ tox
    ...
    _________________________________ summary _________________________________
    py27: commands succeeded
    congratulations :)