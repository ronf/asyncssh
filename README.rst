AsyncSSH: Asynchronous SSH for Python
=====================================

AsyncSSH is a Python package which provides an asynchronous client and
server implementation of the SSHv2 protocol on top of the Python 3.6+
asyncio framework.

.. code:: python

  import asyncio, asyncssh, sys

  async def run_client():
      async with asyncssh.connect('localhost') as conn:
          result = await conn.run('echo "Hello!"', check=True)
          print(result.stdout, end='')

  try:
      asyncio.get_event_loop().run_until_complete(run_client())
  except (OSError, asyncssh.Error) as exc:
      sys.exit('SSH connection failed: ' + str(exc))

Check out the `examples`__ to get started!

__ http://asyncssh.readthedocs.io/en/stable/#client-examples

Features
--------

* Full support for SSHv2, SFTP, and SCP client and server functions

  * Shell, command, and subsystem channels
  * Environment variables, terminal type, and window size
  * Direct and forwarded TCP/IP channels
  * OpenSSH-compatible direct and forwarded UNIX domain socket channels
  * Local and remote TCP/IP port forwarding
  * Local and remote UNIX domain socket forwarding
  * Dynamic TCP/IP port forwarding via SOCKS
  * X11 forwarding support on both the client and the server
  * SFTP protocol version 3 with OpenSSH extensions

    * Experimental support for SFTP versions 4-6, when requested

  * SCP protocol support, including third-party remote to remote copies

* Multiple simultaneous sessions on a single SSH connection
* Multiple SSH connections in a single event loop
* Byte and string based I/O with settable encoding
* A variety of `key exchange`__, `encryption`__, and `MAC`__ algorithms
* Support for `gzip compression`__

  * Including OpenSSH variant to delay compression until after auth

* User and host-based public key, password, and keyboard-interactive
  authentication methods

* Many types and formats of `public keys and certificates`__

  * Including OpenSSH-compatible support for U2F and FIDO2 security keys
  * Including PKCS#11 support for accessing PIV security tokens
  * Including support for X.509 certificates as defined in RFC 6187

* Support for accessing keys managed by `ssh-agent`__ on UNIX systems

  * Including agent forwarding support on both the client and the server

* Support for accessing keys managed by PuTTY's Pageant agent on Windows
* Support for accessing host keys via OpenSSH's ssh-keysign
* OpenSSH-style `known_hosts file`__ support
* OpenSSH-style `authorized_keys file`__ support
* Partial support for `OpenSSH-style configuration files`__
* Compatibility with OpenSSH "Encrypt then MAC" option for better security
* Time and byte-count based session key renegotiation
* Designed to be easy to extend to support new forms of key exchange,
  authentication, encryption, and compression algorithms

__ http://asyncssh.readthedocs.io/en/stable/api.html#key-exchange-algorithms
__ http://asyncssh.readthedocs.io/en/stable/api.html#encryption-algorithms
__ http://asyncssh.readthedocs.io/en/stable/api.html#mac-algorithms
__ http://asyncssh.readthedocs.io/en/stable/api.html#compression-algorithms
__ http://asyncssh.readthedocs.io/en/stable/api.html#public-key-support
__ http://asyncssh.readthedocs.io/en/stable/api.html#ssh-agent-support
__ http://asyncssh.readthedocs.io/en/stable/api.html#known-hosts
__ http://asyncssh.readthedocs.io/en/stable/api.html#authorized-keys
__ http://asyncssh.readthedocs.io/en/stable/api.html#config-file-support

License
-------

This package is released under the following terms:

  Copyright (c) 2013-2022 by Ron Frederick <ronf@timeheart.net> and others.

  This program and the accompanying materials are made available under
  the terms of the Eclipse Public License v2.0 which accompanies this
  distribution and is available at:

    http://www.eclipse.org/legal/epl-2.0/

  This program may also be made available under the following secondary
  licenses when the conditions for such availability set forth in the
  Eclipse Public License v2.0 are satisfied:

     GNU General Public License, Version 2.0, or any later versions of
     that license

  SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later

For more information about this license, please see the `Eclipse
Public License FAQ <https://www.eclipse.org/legal/epl-2.0/faq.php>`_.

Prerequisites
-------------

To use AsyncSSH 2.0 or later, you need the following:

* Python 3.6 or later
* cryptography (PyCA) 2.8 or later

Installation
------------

Install AsyncSSH by running:

  ::

    pip install asyncssh

Optional Extras
^^^^^^^^^^^^^^^

There are some optional modules you can install to enable additional
functionality:

* Install bcrypt from https://pypi.python.org/pypi/bcrypt
  if you want support for OpenSSH private key encryption.

* Install fido2 from https://pypi.org/project/fido2 if you want support
  for key exchange and authentication with U2F/FIDO2 security keys.

* Install python-pkcs11 from https://pypi.org/project/python-pkcs11 if
  you want support for accessing PIV keys on PKCS#11 security tokens.

* Install gssapi from https://pypi.python.org/pypi/gssapi if you
  want support for GSSAPI key exchange and authentication on UNIX.

* Install libsodium from https://github.com/jedisct1/libsodium
  and libnacl from https://pypi.python.org/pypi/libnacl if you have
  a version of OpenSSL older than 1.1.1b installed and you want
  support for Curve25519 key exchange, Ed25519 keys and certificates,
  or the Chacha20-Poly1305 cipher.

* Install libnettle from http://www.lysator.liu.se/~nisse/nettle/
  if you want support for UMAC cryptographic hashes.

* Install pyOpenSSL from https://pypi.python.org/pypi/pyOpenSSL
  if you want support for X.509 certificate authentication.

* Install pywin32 from https://pypi.python.org/pypi/pywin32 if you
  want support for using the Pageant agent or support for GSSAPI
  key exchange and authentication on Windows.

AsyncSSH defines the following optional PyPI extra packages to make it
easy to install any or all of these dependencies:

  | bcrypt
  | fido2
  | gssapi
  | libnacl
  | pkcs11
  | pyOpenSSL
  | pywin32

For example, to install bcrypt, fido2, gssapi, libnacl, pkcs11, and
pyOpenSSL on UNIX, you can run:

  ::

    pip install 'asyncssh[bcrypt,fido2,gssapi,libnacl,pkcs11,pyOpenSSL]'

To install bcrypt, fido2, libnacl, pkcs11, pyOpenSSL, and pywin32 on
Windows, you can run:

  ::

    pip install 'asyncssh[bcrypt,fido2,libnacl,pkcs11,pyOpenSSL,pywin32]'

Note that you will still need to manually install the libsodium library
listed above for libnacl to work correctly and/or libnettle for UMAC
support. Unfortunately, since libsodium and libnettle are not Python
packages, they cannot be directly installed using pip.

Installing the development branch
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you would like to install the development branch of asyncssh directly
from Github, you can use the following command to do this:

  ::

      pip install git+https://github.com/ronf/asyncssh@develop

Mailing Lists
-------------

Three mailing lists are available for AsyncSSH:

* `asyncssh-announce@googlegroups.com`__: Project announcements
* `asyncssh-dev@googlegroups.com`__: Development discussions
* `asyncssh-users@googlegroups.com`__: End-user discussions

__ http://groups.google.com/d/forum/asyncssh-announce
__ http://groups.google.com/d/forum/asyncssh-dev
__ http://groups.google.com/d/forum/asyncssh-users
