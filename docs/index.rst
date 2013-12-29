.. toctree::
   :hidden:

   changes
   api

.. currentmodule:: asyncssh

AsyncSSH Overview
=================

AsyncSSH is a Python package which provides an asynchronous client and
server implementation of the SSHv2 protocol on top of the Python asyncore
framework. It requires Python 3.2 or later and the PyCrypto library for some
cryptographic functions.

This package is released under the following terms:

   .. include:: ../COPYRIGHT

Notable features include:

.. rst-class:: tight-list

   * Written from the ground up to be based on Python 3
   * Support for a number of key exchange methods
      - Diffie Hellman group1 and group14 with SHA1
      - Diffie Hellman group exchange with SHA1 and SHA256
      - Elliptic Curve Diffie Hellman (nistp256, nistp384, and nistp521)
   * Support for multiple authentication methods
      - Password, public key, and keyboard-interactive
   * Support for a variety of public key formats
      - DSA, RSA, and ECDSA keys
      - PKCS#1/PKCS#8 DER and PEM, OpenSSH, and RFC4716 formats
      - Password-based encryption of private keys
   * Support for a variety of ciphers (provided via PyCrypto)
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

    * Python 3.2 or later
    * PyCrypto 2.6 or later

Installation
============

    #. Install Python 3.2 or later from http://www.python.org or your
       favorite packaging system.

    #. Install PyCrypto 2.6 or later from http://www.pycrypto.org or your
       favorite packaging system.

    #. Download, unpack, and install `asyncssh-0.5.0.tar.gz
       <asyncssh-0.5.0.tar.gz>`_ by running the following commands::

       % tar zxf asyncssh-0.5.0.tar.gz
       % cd asyncssh-0.5.0
       % python setup.py install

    #. Check out the examples below to get started!

.. _ClientExamples:

Client Examples
===============

Simple client
-------------

The following code shows an example of a simple SSH client which logs into
localhost and lists files in a directory named 'abc' under the user's home
directory. The username provided is the logged in user, and the user's
default SSH client certificates are presented during authentication. The
server's host key is checked against the user's SSH known_hosts file and
the connection will fail if there's no entry for localhost there or if the
key doesn't match.

   .. include:: ../examples/simple_client.py
      :literal:
      :start-line: 15

To check against a different set of server host keys, they can be read
and provided in the server_host_keys argument when the :class:`SSHClient`
instance is created:

   .. code::

      from asyncssh import read_public_key_list
      host_keys = read_public_key_list('ssh_host_keys.pub')

      client = MySSHClient('localhost', server_host_keys=host_keys)

Server host key checking can be disabled by setting the server_host_keys
argument to ``None``, but that's not recommended as it makes the
connection vulnerable to a man-in-the-middle attack.

To log in as a different remote user, thea username argument can be
provided:

   .. code::

      client = MySSHClient('localhost', username='user123')

To use a different set of client keys for authentication, they can be
read and provided in the client_keys argument:

   .. code::

      from asyncssh import read_private_key
      client_key = read_private_key('my_ssh_key')

      client = MySSHClient('localhost', client_keys=[client_key])

Password authentication can be used by providing a password argument:

   .. code::

      client = MySSHClient('localhost', password='secretpw')

Any of the arguments above can be combined together as needed. If client
keys and a password are both provided, either may be used depending
on what forms of authentication the server supports and whether the
authentication with them is successful.

Handling of stderr
------------------

The above code doesn't distinguish output going to stdout vs. stderr, but
that's easy to do with the following change:

   .. include:: ../examples/stderr_client.py
      :literal:
      :start-line: 15

Simple client with input
------------------------

The following example demonstrates sending input to a remote program.
It executes the calculator program 'bc' and performs some basic math
calculations.

   .. include:: ../examples/math_client.py
      :literal:
      :start-line: 15

When run, this program should produce the following output:

   .. code::

      2+2 = 4
      1*2*3*4 = 24
      2^32 = 4294967296

Note that input is not provided until the :meth:`handle_open()
<SSHClientSession.handle_open>` method is called, and :meth:`send_eof()
<SSHClientSession.send_eof>` is used to signal the end of input,
causing the 'bc' program to exit.

Checking exit status
--------------------

The following example is a variation of the simple client which shows
how to check the remote program's exit status.

   .. include:: ../examples/check_exit_status.py
      :literal:
      :start-line: 15

Setting environment variables
-----------------------------

The following example demonstrates setting environment variables
for the remote session and displaying them by executing the 'env'
command.

   .. include:: ../examples/set_environment.py
      :literal:
      :start-line: 15

Any number of environment variables can be passed in the dictionary
given to :meth:`set_environment() <SSHClientSession.set_environment>`.
Note that SSH servers may restrict which environment variables (if any)
are accepted, so this feature may require setting options on the SSH
server before it will work.

Setting terminal information
----------------------------

The following example demonstrates setting the terminal type and
window size passed to the remote session.

   .. include:: ../examples/set_terminal.py
      :literal:
      :start-line: 15

The :meth:`set_terminal() <SSHClientSession.set_terminal>` method also
takes an optional dictionary for setting :ref:`POSIX terminal modes
<PTYModes>` defined in section 8 of :rfc:`4254#section-8`, and the
:meth:`set_window_size() <SSHClientSession.set_window_size>` method
takes optional arguments for setting the terminal's width and height
in pixels in addition to the width and height in characters.

Port forwarding
---------------

The following example demonstrates the client setting up a local TCP
listener on port 8080 and requesting that connections which arrive on
that port be forwarded across SSH to the server and on to port 80 on
``www.google.com``:

   .. include:: ../examples/local_forwarding_client.py
      :literal:
      :start-line: 15

To listen on a dynamically assigned port, the client can pass in ``0``
as the bind port. If the listener is successfully opened, the selected
port will be available in the ``listen_port`` member variable when the
:meth:`handle_open() <SSHClientLocalPortForwarder.handle_open>` method
is called. If the listen fails, the :meth:`handle_open_error()
<SSHClientLocalPortForwarder.handle_open_error>` method is called
with the exception that was raised.

The client can limit which connections are forwarded by overriding the
:meth:`accept_connection() <SSHClientLocalPortForwarder.accept_connection>`
method. It is passed the address and port of the client attempting the
connection and can return ``True`` or ``False`` to accept or reject the
connection. The following example listens on a random port and rejects
connections from ``localhost``:

   .. include:: ../examples/local_forwarding_client2.py
      :literal:
      :start-line: 15

The client can also request remote port forwarding from the server. The
following example shows the client requesting that the server listen on
port 8080 and that connections arriving there be forwarded across SSH
and on to port 80 on ``localhost``:

   .. include:: ../examples/remote_forwarding_client.py
      :literal:
      :start-line: 15

The client can request that the server listen on a dynamic port by passing
in a listen port value of ``0``, getting back the selected port via the
``listen_port`` member variable when the :meth:`handle_open()
<SSHClientRemotePortForwarder.handle_open>` method is called. If the
listen request to the server fails, the :meth:`handle_open_error()
<SSHClientRemotePortForwarder.handle_open_error>` method is called.

The client can limit which incoming connections are accepted by overriding
:meth:`accept_connection() <SSHClientRemotePortForwarder.accept_connection>`,
return ``True`` to accept connections, ``False`` to reject them with a
"Connection refused" error, or raising a :exc:`ChannelOpenError` exception
to return some other error.

Direct TCP connections
----------------------

The client can also ask the server to open a TCP connection and directly
send and receive data on it. In this example, a connection is attempted
to port 80 on ``www.google.com`` and an HTTP HEAD request is sent for
the document root.

Note that unlike :class:`SSHClientSession`, all the I/O on
:class:`SSHTCPConnection` defaults to sending and receiving bytes rather
than strings to allow arbitrary binary data to be exchanged. However,
this can be changed by setting encoding when the connection is created.

   .. include:: ../examples/direct_client.py
      :literal:
      :start-line: 15

Forwarded TCP connections
-------------------------

The client can also directly process data from incoming TCP connections
received on the server. The following example demonstrates the client
requesting that the server listen on port 8888 and forward any received
connections back to it over SSH. It then has a simple handler which
prints a message and closes the connection.

As in the direct TCP connection example above, the default would be to
send and receive bytes on this connection rather than strings, but
here we set the encoding to UTF-8 to be able to directly send and
receive strings:

   .. include:: ../examples/listening_client.py
      :literal:
      :start-line: 15

.. _ServerExamples:

Server Examples
===============

Simple server
-------------

The following code shows an example of a simple SSH server which listens
for connections on port 8022, does password authentication, and prints
a meessage when users authenticate successfully and start a shell.

   .. include:: ../examples/simple_server.py
      :literal:
      :start-line: 15

To authenticate with client keys, the server would look something like
the following. Client keys need to be copied into a a file named
:samp:`{username}.pub` in a directory called ``authorized_keys``.

   .. include:: ../examples/simple_keyed_server.py
      :literal:
      :start-line: 15

Simple server with input
------------------------

The following example demonstrates reading input in a server session.
It will sum a column of numbers, displaying the total and closing the
connection when it receives EOF. Note that this is not an interactive
application -- you'll need to have the SSH client read from a file or
pipe rather than the terminal for this to work right.

   .. include:: ../examples/math_server.py
      :literal:
      :start-line: 15

Getting environment variables
-----------------------------

The following example demonstrates reading environment variables set
by the client. It will show all of the variables set by the client,
or return an error if none are set. Note that SSH clients may not
restrict which environment variables (if any) are sent by default,
so you may need to set options in the client to get it to do so.

   .. include:: ../examples/show_environment.py
      :literal:
      :start-line: 15

Getting terminal information
----------------------------

The following example demonstrates reading the client's terminal
type and window size, and handling window size changes during a
session.

   .. include:: ../examples/show_terminal.py
      :literal:
      :start-line: 15

Port forwarding
---------------

The following example demonstrates a server accepting port forwarding
requests from clients, but only when they are destined to port 80. When
such a connection is received, a connection is attempted to the requested
host and port and data is bidirectionally forwarded over SSH from the
client to this destination. Requests by the client to connect to any
other port are rejected.

   .. include:: ../examples/local_forwarding_server.py
      :literal:
      :start-line: 15

The server can also support forwarding inbound TCP connections back to
the client. The following example demonstrates a server which will accept
requests like this from clients, but only to listen on port 8080. When
such a connection is received, the client is notified and data is
bidirectionally forwarded from the incoming connection over SSH to the
client.

   .. include:: ../examples/remote_forwarding_server.py
      :literal:
      :start-line: 15

Direct TCP connections
----------------------

The server can also accept direct TCP connection requests from the client
and process the data on them itself. The following example demonstrates a
server which accepts requests to port 7 (the "echo" port) for any host and
echoes the data itself rather than forwarding the connection:

   .. include:: ../examples/direct_server.py
      :literal:
      :start-line: 15
