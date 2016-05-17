

wolfcrypt: the wolfSSL Crypto Engine
====================================

**wolfCrypt Python**, a.k.a. ``wolfcrypt`` is a Python library that encapsulates
**wolfSSL's wolfCrypt API**.

**wolfCrypt** is a lightweight, portable, C-language-based crypto library
targeted at IoT, embedded, and RTOS environments primarily because of its size,
speed, and feature set. It works seamlessly in desktop, enterprise, and cloud
environments as well.


Installation
------------

Dependencies
~~~~~~~~~~~~

Before installing ``wolfcrypt``, make sure you have ``wolfssl`` C library
installed in your machine:

.. code-block:: console

    $ git clone git@github.com:wolfssl/wolfssl.git
    $ cd wolfssl
    $ ./autogen.sh
    $ ./configure
    $ make
    $ sudo make install

**Linux ONLY:** Update your dynamic linker:

.. code-block:: console

    $ sudo ldconfig
    # or
    $ export LD_LIBRARY_PATH=/usr/local/lib


**Linux ONLY:** Make sure you have ``python-dev``, ``python3-dev``,
``python-pip`` and ``libffi-dev`` installed:

.. code-block:: console

    $ sudo apt-get update
    $ sudo apt-get install python-dev python3-dev python-pip libffi-dev


Now, you can install ``wolfcrypt`` via ``pip`` or ``source code``:

wolfcrypt pip installation
~~~~~~~~~~~~~~~~~~~~~~~~~~

To install ``wolfcrypt`` with ``pip``:

.. code-block:: console

    $ sudo -H pip install wolfcrypt


wolfcrypt source installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Before** proceeding with installation, you can test ``wolfcrypt`` locally with
``tox``:

1. Make sure that the testing requirements are installed:

.. code-block:: console

    $ sudo -H pip install -r requirements-testing.txt


2. Run ``tox``:

.. code-block:: console

    $ tox
    ...
    _________________________________ summary _________________________________
    py27: commands succeeded
    SKIPPED: py34: InterpreterNotFound: python3.4
    py35: commands succeeded
    congratulations :)

Note that some tests might be skipped if you don't have the proper interpreter.


**Now**, to install ``wolfcrypt`` from sources:

1. Get the sources:

.. code-block:: console

    $ git clone git@github.com:wolfssl/wolfssl.git
    $ cd wolfssl/wrapper/python

2. Build and install ``wolfcrypt``

.. code-block:: console

    $ sudo python setup.py install
    ...
    Finished processing dependencies for wolfcrypt...
