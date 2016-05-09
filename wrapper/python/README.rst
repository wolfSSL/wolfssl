

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

You can install ``wolfcrypt`` via ``pip`` or ``source code``, but before
installing it, make sure you have ``wolfssl`` C library installed in your
machine.

To install wolfssl do:

.. code-block:: console

    $ git clone git@github.com:wolfssl/wolfssl.git
    $ cd wolfssl
    $ ./autogen.sh
    $ ./configure
    $ make
    $ sudo make install


wolfcrypt pip installation
~~~~~~~~~~~~~~~~~~~~~~~~~~

To install ``wolfcrypt`` with ``pip``:

.. code-block:: console

    $ pip install wolfcrypt

or if you need admin privileges to use ``pip``:

.. code-block:: console

    $ sudo -H pip install wolfcrypt


wolfcrypt source installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To install ``wolfcrypt`` from sources:

1. Get the sources:

.. code-block:: console

    $ git clone git@github.com:wolfssl/wolfssl.git
    $ cd wolfssl/wrappers/python

2. Build and install ``wolfcrypt``

.. code-block:: console

    $ python setup.py install
    ...
    Finished processing dependencies for wolfcrypt...

or if you need admin privileges to use the install command:

.. code-block:: console

    $ sudo python setup.py install


Testing
-------

Test ``wolfcrypt`` locally with ``tox``:

1. Make sure that the testing requirements are installed:

.. code-block:: console

    $ pip install -r requirements-testing.txt


2. Call ``tox``:

.. code-block:: console

    $ tox
    ...
    _________________________________ summary _________________________________
    py27: commands succeeded
    py35: commands succeeded
    congratulations :)
