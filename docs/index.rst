.. toctree::
   :hidden:

   changes
   api

.. currentmodule:: asyncssh

.. include:: ../README.rst

.. _ClientExamples:

Client Examples
===============

Simple client
-------------

The following code shows an example of a simple SSH client which logs into
localhost and lists files in a directory named 'abc' under the user's home
directory. The username provided is the logged in user, and the user's
default SSH client keys or certificates are presented during authentication.
The server's host key is checked against the user's SSH known_hosts file and
the connection will fail if there's no entry for localhost there or if the
key doesn't match.

   .. include:: ../examples/simple_client.py
      :literal:
      :start-line: 15

To check against a different set of server host keys, they can be read
and provided in the server_host_keys argument when the :class:`SSHClient`
instance is created:

   .. code::

     host_keys = asyncssh.read_public_key_list('ssh_host_keys.pub')

     conn, client = yield from asyncssh.create_connection(None, 'localhost',
                                                          server_host_keys=host_keys)


Server host key checking can be disabled by setting the server_host_keys
argument to ``None``, but that's not recommended as it makes the
connection vulnerable to a man-in-the-middle attack.

To log in as a different remote user, the username argument can be
provided:

   .. code::

     conn, client = yield from asyncssh.create_connection(None, 'localhost',
                                                          username='user123')

To use a different set of client keys for authentication, they can be
read and provided in the client_keys argument:

   .. code::

     client_key = asyncssh.read_private_key('my_ssh_key')

     conn, client = yield from asyncssh.create_connection(None, 'localhost',
                                                          client_keys=[client_key])

Password authentication can be used by providing a password argument:

   .. code::

     conn, client = yield from asyncssh.create_connection(None, 'localhost',
                                                          password='secretpw')

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
It executes the calculator program ``bc`` and performs some basic math
calculations.

   .. include:: ../examples/math_client.py
      :literal:
      :start-line: 15

Note that input is not sent on the channel  until the :meth:`session_started()
<SSHClientSession.session_started>` method is called, and :meth:`write_eof()
<SSHClientChannel.write_eof>` is used to signal the end of input, causing the
'bc' program to exit.

This example can be simplified by using the higher-level "streams" API. With
that, callbacks aren't needed. Here's the streams version of the above example,
using :meth:`open_session <SSHClientConnection.open_session>` instead of
:meth:`create_session <SSHClientConnection.create_session>`:

   .. include:: ../examples/stream_math_client.py
      :literal:
      :start-line: 15

When run, this program should produce the following output:

   .. code::

      2+2 = 4
      1*2*3*4 = 24
      2^32 = 4294967296

Checking exit status
--------------------

The following example is a variation of the simple client which shows how to
receive the remote program's exit status using the :meth:`exit_status_received
<SSHClientSession.exit_status_received>` callback.

   .. include:: ../examples/check_exit_status.py
      :literal:
      :start-line: 15

From servers that support it, exit signals can also be received using
:meth:`exit_signal_received <SSHClientSession.exit_signal_received>`.

Exit status can be also queried after the channel has closed by using the
methods :meth:`get_exit_status <SSHClientChannel.get_exit_status>` and
:meth:`get_exit_signal <SSHClientChannel.get_exit_signal>`. This is
how it is done when using the streams API, since callbacks aren't available
there.

Setting environment variables
-----------------------------

The following example demonstrates setting environment variables
for the remote session and displaying them by executing the 'env'
command.

   .. include:: ../examples/set_environment.py
      :literal:
      :start-line: 15

Any number of environment variables can be passed in the dictionary
given to :meth:`create_session() <SSHClientConnection.create_session>`.
Note that SSH servers may restrict which environment variables (if any)
are accepted, so this feature may require setting options on the SSH
server before it will work.

Setting terminal information
----------------------------

The following example demonstrates setting the terminal type and size
passed to the remote session.

   .. include:: ../examples/set_terminal.py
      :literal:
      :start-line: 15

Note that this will cause AsyncSSH to request a pseudo-tty from the
server. When a pseudo-tty is used, the server will no longer send output
going to stderr with a different data type. Instead, it will be mixed
with output going to stdout (unless it is redirected elsewhere by the
remote command).

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
as the listening port. If the listener is successfully opened, the selected
port will be available via the :meth:`get_port() <SSHListener.get_port>`
method on the returned listener object:

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

To limit which connections are accepted or dynamically select where to
forward traffic to, the client can implement their own session factory and
call :meth:`forward_connection() <SSHClientConnection.forward_connection>`
on the connections they wish to forward and raise an error on those they
wish to reject:

   .. include:: ../examples/remote_forwarding_client2.py
      :literal:
      :start-line: 15

Just as with local listeners, the client can request remote port forwarding
from a dynamic port by passing in ``0`` as the listening port and then call
:meth:`get_port() <SSHListener.get_port>` on the returned listener to
determine which port was selected.

Direct TCP connections
----------------------

The client can also ask the server to open a TCP connection and directly
send and receive data on it by using the :meth:`create_connection()
<SSHClientConnection.create_connection>` method on the
:class:`SSHClientConnection` object. In this example, a connection is
attempted to port 80 on ``www.google.com`` and an HTTP HEAD request is
sent for the document root.

Note that unlike sessions created with :meth:`create_session()
<SSHClientConnection.create_session>`, the I/O on these connections defaults
to sending and receiving bytes rather than strings, allowing arbitrary
binary data to be exchanged. However, this can be changed by setting
the encoding to use when the connection is created.

   .. include:: ../examples/direct_client.py
      :literal:
      :start-line: 15

To use the streams API to open a direct connection, you can use
:meth:`open_connection <SSHClientConnection.open_connection>` instead of
:meth:`create_connection <SSHClientConnection.create_connection>`:

   .. include:: ../examples/stream_direct_client.py
      :literal:
      :start-line: 15

Forwarded TCP connections
-------------------------

The client can also directly process data from incoming TCP connections
received on the server. The following example demonstrates the client
requesting that the server listen on port 8888 and forward any received
connections back to it over SSH. It then has a simple handler which
echoes any data it receives back to the sender.

As in the direct TCP connection example above, the default would be to
send and receive bytes on this connection rather than strings, but here
we set the encoding explicitly so all data is sent and received as strings:

   .. include:: ../examples/listening_client.py
      :literal:
      :start-line: 15

To use the streams API to open a listening connection, you can use
:meth:`start_server <SSHClientConnection.start_server>` instead
of :meth:`create_server <SSHClientConnection.create_server>`:

   .. include:: ../examples/stream_listening_client.py
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

To authenticate with SSH client keys, the server would look something
like the following. Client keys need to be placed in a file named
:samp:`{username}.pub` in a directory called ``authorized_keys``.

   .. include:: ../examples/simple_keyed_server.py
      :literal:
      :start-line: 15

To authenticate with SSH certificates, the server would look something
like the following. Public keys to trust as certificate authorities need
to be placed in a file called ``ssh_user_ca_keys``.

   .. include:: ../examples/simple_cert_server.py
      :literal:
      :start-line: 15

Simple server with input
------------------------

The following example demonstrates reading input in a server session.
It will sum a column of numbers, displaying the total and closing the
connection when it receives EOF. Note that this is not an interactive
application, so no echoing of user input is provided. You'll need to
have the SSH client read from a file or pipe rather than the terminal
or tell it not to allocate a pty for this to work right.

   .. include:: ../examples/math_server.py
      :literal:
      :start-line: 15

Here's an example of this server written using the streams API. In this
case, :meth:`session_requested() <SSHServer.session_requested>` returns
a handler coroutine instead of a session object. When a new SSH session is
requested, the handler coroutine is called with AsyncSSH stream objects
representing stdin, stdout, and stderr that it can use to perform I/O.

This example also shows how to catch exceptions thrown when break messages,
signals, or terminal size changes are received.

   .. include:: ../examples/stream_math_server.py
      :literal:
      :start-line: 15

Getting environment variables
-----------------------------

The following example demonstrates reading environment variables set
by the client. It will show all of the variables set by the client,
or return an error if none are set. Note that SSH clients may restrict
which environment variables (if any) are sent by default, so you may
need to set options in the client to get it to do so.

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

Here's an example of this server written using the streams API. In this
case, :meth:`connection_requested() <SSHServer.connection_requested>`
returns a handler coroutine instead of a session object. When a new
direct TCP connection is opened, the handler coroutine is called with
AsyncSSH stream objects which can be used to perform I/O on the tunneled
connection.

   .. include:: ../examples/stream_direct_server.py
      :literal:
      :start-line: 15
