

wolfssl: the wolfSSL Inc. SSL/TLS library
=========================================

**wolfssl Python**, a.k.a. ``wolfssl`` is a Python library that encapsulates
**wolfSSL's C SSL/TLS library**.

`wolfssl <https://wolfssl.com/wolfSSL/Products-wolfssl.html>`_ is a
lightweight, portable, C-language-based crypto library
targeted at IoT, embedded, and RTOS environments primarily because of its size,
speed, and feature set. It works seamlessly in desktop, enterprise, and cloud
environments as well. It is the crypto engine behind `wolfSSl's embedded ssl
library <https://wolfssl.com/wolfSSL/Products-wolfssl.html>`_.


Installation
------------

In order to use ``wolfssl``, first you'll need to install ``wolfssl`` C
embedded SSL/TLS library.

Installing ``wolfssl`` C SSL/TLS library:
~~~~~~~~~~~~~~~~~~~~~~~~

**Mac OSX**

.. code-block:: console

    brew install wolfssl

or

.. code-block:: console

    git clone https://github.com/wolfssl/wolfssl.git
    cd wolfssl/
    ./autogen.sh
    ./configure --enable-sha512
    make
    sudo make install


**Ubuntu**

.. code-block:: console

    sudo apt-get update
    sudo apt-get install -y git autoconf libtool

    git clone https://github.com/wolfssl/wolfssl.git
    cd wolfssl/
    ./autogen.sh
    ./configure --enable-sha512
    make
    sudo make install

    sudo ldconfig

**CentOS**

.. code-block:: console

    sudo rpm -ivh http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-6.noarch.rpm
    sudo yum update
    sudo yum install -y git autoconf libtool

    git clone git@github.com:wolfssl/wolfssl.git
    cd wolfssl
    ./autogen.sh
    ./configure --enable-sha512
    make
    sudo make install

    echo /usr/local/lib > wolfssl.conf
    sudo mv wolfssl.conf /etc/ld.so.conf
    sudo ldconfig


Installing ``wolfssl`` python module:
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Mac OSX**

.. code-block:: console

    sudo -H pip install wolfssl


**Ubuntu**

.. code-block:: console

    sudo apt-get install -y python-dev python3-dev python-pip libffi-dev
    sudo -H pip install wolfssl


**CentOS**

.. code-block:: console

    sudo yum install -y python-devel python3-devel python-pip libffi-devel
    sudo -H pip install wolfssl


Testing ``wolfssl`` python module:
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

    python -c "from wolfssl.hashes import Sha; print Sha().hexdigest()"

expected output: **da39a3ee5e6b4b0d3255bfef95601890afd80709**


Testing ``wolfssl``'s source code with ``tox`` :
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To run the unit tests in the source code, you'll need ``tox`` and a few other
requirements. The source code relies at 'WOLFSSL_DIR/wrapper/python/wolfssl'
where WOLFSSL_DIR is the path of ``wolfssl``'s source code.

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

Note: the test is performed using multiple versions of python. If you are
missing a version the test will be skipped with an **InterpreterNotFound
error**.
