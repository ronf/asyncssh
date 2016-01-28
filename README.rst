AsyncSSH: Asynchronous SSH for Python
=====================================

AsyncSSH is a Python package which provides an asynchronous client and
server implementation of the SSHv2 protocol on top of the Python 3.4+
asyncio framework.

.. code:: python

  import asyncio, asyncssh, sys

  @asyncio.coroutine
  def run_client():
      with (yield from asyncssh.connect('localhost')) as conn:
          stdin, stdout, stderr = yield from conn.open_session('echo "Hello!"')

          output = yield from stdout.read()
          print(output, end='')

          yield from stdout.channel.wait_closed()

          status = stdout.channel.get_exit_status()
          if status:
              print('Program exited with status %d' % status, file=sys.stderr)
          else:
              print('Program exited successfully')

  asyncio.get_event_loop().run_until_complete(run_client())

Check out the `examples`__ to get started!

__ http://asyncssh.readthedocs.org/en/stable/#client-examples

Features
--------

* Full support for SSHv2 and SFTP client and server functions

  * Shell, command, and subsystem channels
  * Environment variables, terminal type, and window size
  * Direct and forwarded TCP/IP channels
  * OpenSSH-compatible direct and forwarded UNIX domain socket channels
  * Local and remote TCP/IP port forwarding
  * Local and remote UNIX domain socket forwarding
  * SFTP protocol version 3 with OpenSSH extensions

* Multiple simultaneous sessions on a single SSH connection
* Multiple SSH connections in a single event loop
* Byte and string based I/O with settable encoding
* A variety of `key exchange`__, `encryption`__, and `MAC`__ algorithms
* Support for `gzip compression`__

  * Including OpenSSH variant to delay compression until after auth

* Password, public key, and keyboard-interactive user authentication methods
* Many types and formats of `public keys and certificates`__
* Support for accessing keys managed by `ssh-agent`__
* OpenSSH-style ssh-agent forwarding support
* OpenSSH-style `known_hosts file`__ support
* OpenSSH-style `authorized_keys file`__ support
* Compatibility with OpenSSH "Encrypt then MAC" option for better security
* Time and byte-count based session key renegotiation
* Designed to be easy to extend to support new forms of key exchange,
  authentication, encryption, and compression algorithms

__ http://asyncssh.readthedocs.org/en/stable/api.html#key-exchange-algorithms
__ http://asyncssh.readthedocs.org/en/stable/api.html#encryption-algorithms
__ http://asyncssh.readthedocs.org/en/stable/api.html#mac-algorithms
__ http://asyncssh.readthedocs.org/en/stable/api.html#compression-algorithms
__ http://asyncssh.readthedocs.org/en/stable/api.html#public-key-support
__ http://asyncssh.readthedocs.org/en/stable/api.html#ssh-agent-support
__ http://asyncssh.readthedocs.org/en/stable/api.html#known-hosts
__ http://asyncssh.readthedocs.org/en/stable/api.html#authorized-keys

License
-------

This package is released under the following terms:

  Copyright (c) 2013-2016 by Ron Frederick <ronf@timeheart.net>.
  All rights reserved.

  This program and the accompanying materials are made available under
  the terms of the **Eclipse Public License v1.0** which accompanies
  this distribution and is available at:

    http://www.eclipse.org/legal/epl-v10.html

For more information about this license, please see the `Eclipse
Public License FAQ <https://eclipse.org/legal/eplfaq.php>`_.

Prerequisites
-------------

To use ``asyncssh``, you need the following:

* Python 3.4 or later
* cryptography (PyCA) 1.1 or later

Installation
------------

Install AsyncSSH by running:

  ::

    pip install asyncssh

Optional Extras
^^^^^^^^^^^^^^^

There are some optional modules you can install to enable additional
functionality:

* Install bcrypt from https://code.google.com/p/py-bcrypt
  if you want support for OpenSSH private key encryption.

* Install libsodium from https://github.com/jedisct1/libsodium
  and libnacl from https://github.com/saltstack/libnacl if you want
  support for curve25519 Diffie Hellman key exchange, ed25519 keys,
  and the chacha20-poly1305 cipher.

AsyncSSH defines the following optional PyPI extra packages to make it
easy to install any or all of these dependencies:

  | bcrypt
  | libnacl

For example, to install all of these, you can run:

  ::

    pip install 'asyncssh[bcrypt,libnacl]'

Note that you will still need to manually install the libsodium library
listed above for libnacl to work correctly. Unfortunately, since
libsodium is not a Python package, it cannot be directly installed using
pip.

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
