AsyncSSH Overview
=================

AsyncSSH is a Python package which provides an asynchronous client and
server implementation of the SSHv2 protocol on top of the Python asyncio
framework. It requires Python 3.4 or later and either the PyCA library or
the PyCrypto library for some cryptographic functions.

This package is released under the following terms:

    Copyright (c) 2013-2014 by Ron Frederick <ronf@timeheart.net>.
    All rights reserved.

    This program and the accompanying materials are made available under
    the terms of the Eclipse Public License v1.0 which accompanies this
    distribution and is available at:

        http://www.eclipse.org/legal/epl-v10.html

    Contributors:
        Ron Frederick - initial implementation, API, and documentation

Notable features include:

* Written from the ground up to be based on Python 3
* Support for a number of key exchange methods
    - Diffie Hellman group1 and group14 with SHA1
    - Diffie Hellman group exchange with SHA1 and SHA256
    - Elliptic Curve Diffie Hellman (nistp256, nistp384, and nistp521)
    - Curve25519 (if curve25519-donna Python wrapper is installed)
* Support for multiple authentication methods
    - Password, public key, and keyboard-interactive
* Support for a variety of public key formats
    - DSA, RSA, and ECDSA keys
    - PKCS#1/PKCS#8 DER and PEM, OpenSSH, and RFC4716 formats
    - Password-based encryption of private keys
* Support for OpenSSH host and user certificates
    - Version 00 certificates for DSA and RSA keys
    - Version 01 certificates for DSA, RSA, and ECDSA keys
    - Support for force-command and source-address critical options
    - Support for permit-pty and permit-port-forwarding extensions
* Support for a variety of ciphers (provided via PyCA or PyCrypto)
    - AES, ARC4, Blowfish, CAST, and Triple DES
* Support for a variety of MAC algorithms
    - HMAC with MD5, SHA1, SHA256, and SHA512
* Support for gzip compression
    - Including OpenSSH variant to delay compression until after auth
* Support for passing environment variables, terminal type, and window size
* Support for multiple simultaneous sessions on a single SSH connection
* Support for handling multiple SSH connections in a single event loop
* Support for direct and forwarded TCP/IP channels
* Support for both byte and string based I/O with settable encoding
* Compatibility with OpenSSH "Encrypt then MAC" option for better security
* Time and byte-count based session key renegotiation
* Designed to be easy to extend to support new forms of key exchange,
  authentication methods, ciphers, and compression algorithms

Prerequisites
=============

To use ``asyncssh``, you need the following:

* Python 3.4 or later
* PyCrypto 2.6 or later and/or PyCA 0.6.1 or later

Installation
============

#. Install Python 3.4 or later from http://www.python.org or your
   favorite packaging system.

#. Optionally install PyCrypto 2.6 or later from http://www.pycrypto.org
   or your favorite packaging system.

#. Optionally install PyCA 0.6.1 or later from https://cryptography.io
   or your favorite packaging system.

#. Optionally install curve25519-donna from
   http://github.com/agl/curve25519-donna if you want support for
   Curve25519 Diffie Hellman key exchange.

#. Install AsyncSSH by running::

   % pip install asyncssh
    
#. Check out the `examples`__ to get started!
     __ http://asyncssh.timeheart.net/#clientexamples

Mailing Lists
=============

Three mailing lists are available for AsyncSSH:

* `asyncssh-announce@googlegroups.com`__: Project announcements
* `asyncssh-dev@googlegroups.com`__: Development discussions
* `asyncssh-users@googlegroups.com`__: End-user discussions
    __ http://groups.google.com/d/forum/asyncssh-announce
    __ http://groups.google.com/d/forum/asyncssh-dev
    __ http://groups.google.com/d/forum/asyncssh-users
