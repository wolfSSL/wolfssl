wolfcrypt: the wolfSSL Crypto Engine
====================================


A Python wrapper which encapsulates the wolfCrypt API from wolfSSL library


1. Clone the repository and install wolfssl::


    $ git clone git@github.com:wolfssl/wolfssl.git
    $ cd wolfssl
    $ ./autogen.sh
    $ ./configure
    $ make
    $ sudo make install


2. Make sure that ``cffi``, ``py.test``, and ``tox`` are installed::


    $ cd wrappers/python
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
