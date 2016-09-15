.. toctree::
   :hidden:

   changes
   contributing
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
      :start-line: 14

This example only uses the output on stdout, but output on stderr is also
collected as another attribute in the returned :class:`SSHCompletedProcess`
object.

To check against a different set of server host keys, they can be read
and provided in the known_hosts argument when the connection is opened:

   .. code::

     async with asyncssh.connect('localhost', known_hosts='my_known_hosts') as conn:


Server host key checking can be disabled by setting the known_hosts
argument to ``None``, but that's not recommended as it makes the
connection vulnerable to a man-in-the-middle attack.

To log in as a different remote user, the username argument can be
provided:

   .. code::

     async with asyncssh.connect('localhost', username='user123') as conn:

To use a different set of client keys for authentication, they can be
read and provided in the client_keys argument:

   .. code::

     async with asyncssh.connect('localhost', client_keys=['my_ssh_key']) as conn:

Password authentication can be used by providing a password argument:

   .. code::

     async with asyncssh.connect('localhost', password='secretpw') as conn:

Any of the arguments above can be combined together as needed. If client
keys and a password are both provided, either may be used depending
on what forms of authentication the server supports and whether the
authentication with them is successful.

Callback example
----------------

AsyncSSH also provides APIs that use callbacks rather than "await" and "async
with". Here's the example above written using custom :class:`SSHClient` and
:class:`SSHClientSession` subclasses:

   .. include:: ../examples/callback_client.py
      :literal:
      :start-line: 14

In cases where you don't need to customize callbacks on the SSHClient class,
this code can be simplified somewhat to:

   .. include:: ../examples/callback_client2.py
      :literal:
      :start-line: 14

If you need to distinguish output going to stdout vs. stderr, that's easy to
do with the following change:

   .. include:: ../examples/callback_client3.py
      :literal:
      :start-line: 14

Interactive input
-----------------

The following example demonstrates sending interactive input to a remote
process. It executes the calculator program ``bc`` and performs some basic
math calculations. Note that it uses the :meth:`create_process
<SSHClientConnection.create_process>` method rather than the :meth:`run
<SSHClientConnection.run>` method. This starts the process but doesn't wait
for it to exit, allowing interaction with it.

   .. include:: ../examples/math_client.py
      :literal:
      :start-line: 14

When run, this program should produce the following output:

   .. code::

      2+2 = 4
      1*2*3*4 = 24
      2^32 = 4294967296

I/O redirection
---------------

The following example shows how to pass a fixed input string to a remote
process and redirect the resulting output to the local file '/tmp/stdout'.
Input lines containing 1, 2, and 3 are passed into the 'tail -r' command
and the output written to '/tmp/stdout' should contain the reversed lines
3, 2, and 1:

   .. include:: ../examples/redirect_input.py
      :literal:
      :start-line: 14

The ``stdin``, ``stdout``, and ``stderr`` arguments support redirecting
to a variety of locations include local files, pipes, and sockets as
well as an :class:`SSHReader` or :class:`SSHWriter` objects associated
with other remote SSH processes. Here's an example of piping stdout from
a local process to a remote process:

   .. include:: ../examples/redirect_local_pipe.py
      :literal:
      :start-line: 14

Here's an example of piping one remote process to another:

   .. include:: ../examples/redirect_remote_pipe.py
      :literal:
      :start-line: 14

In this example both remote processes are running on the same SSH
connection, but this redirection can just as easily be used between
SSH sessions associated with connections going to different servers.

Checking exit status
--------------------

The following example shows how to test the exit status of a remote process:

   .. include:: ../examples/check_exit_status.py
      :literal:
      :start-line: 14

If an exit signal is received, the exit status will be set to -1 and exit
signal information is provided in the ``exit_signal`` attribute of the
returned :class:`SSHCompletedProcess`.

If the ``check`` argument in :meth:`run <SSHClientConnection.run>` is set
to ``True``, any abnormal exit will raise a :exc:`ProcessError` exception
instead of returning an :class:`SSHCompletedProcess`.

Running multiple clients
------------------------

The following example shows how to run multiple clients in parallel and
process the results when all of them have completed:

   .. include:: ../examples/gather_results.py
      :literal:
      :start-line: 14

Results could be processed as they became available by setting up a
loop which repeatedly called :func:`asyncio.wait` instead of calling
:func:`asyncio.gather`.

Setting environment variables
-----------------------------

The following example demonstrates setting environment variables
for the remote session and displaying them by executing the 'env'
command.

   .. include:: ../examples/set_environment.py
      :literal:
      :start-line: 14

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
      :start-line: 14

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
      :start-line: 14

To listen on a dynamically assigned port, the client can pass in ``0``
as the listening port. If the listener is successfully opened, the selected
port will be available via the :meth:`get_port() <SSHListener.get_port>`
method on the returned listener object:

   .. include:: ../examples/local_forwarding_client2.py
      :literal:
      :start-line: 14

The client can also request remote port forwarding from the server. The
following example shows the client requesting that the server listen on
port 8080 and that connections arriving there be forwarded across SSH
and on to port 80 on ``localhost``:

   .. include:: ../examples/remote_forwarding_client.py
      :literal:
      :start-line: 14

To limit which connections are accepted or dynamically select where to
forward traffic to, the client can implement their own session factory and
call :meth:`forward_connection() <SSHClientConnection.forward_connection>`
on the connections they wish to forward and raise an error on those they
wish to reject:

   .. include:: ../examples/remote_forwarding_client2.py
      :literal:
      :start-line: 14

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
      :start-line: 14

To use the streams API to open a direct connection, you can use
:meth:`open_connection <SSHClientConnection.open_connection>` instead of
:meth:`create_connection <SSHClientConnection.create_connection>`:

   .. include:: ../examples/stream_direct_client.py
      :literal:
      :start-line: 14

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
      :start-line: 14

To use the streams API to open a listening connection, you can use
:meth:`start_server <SSHClientConnection.start_server>` instead
of :meth:`create_server <SSHClientConnection.create_server>`:

   .. include:: ../examples/stream_listening_client.py
      :literal:
      :start-line: 14

SFTP client
-----------

AsyncSSH also provides SFTP support. The following code shows an example
of starting an SFTP client and requesting the download of a file:

   .. include:: ../examples/sftp_client.py
      :literal:
      :start-line: 14

To recursively download a directory, preserving access and modification
times and permissions on the files, the preserve and recurse arguments
can be included:

   .. code::

      await sftp.get('example_dir', preserve=True, recurse=True)

Wild card pattern matching is supported by the :meth:`mget <SFTPClient.mget>`,
:meth:`mput <SFTPClient.mput>`, and :meth:`mcopy <SFTPClient.mcopy>` methods.
The following downloads all files with extension "txt":

   .. code::

      await sftp.mget('*.txt')

See the :class:`SFTPClient` documentation for the full list of available
actions.

.. _ServerExamples:

Server Examples
===============

Simple server
-------------

The following code shows an example of a simple SSH server which listens
for connections on port 8022, does password authentication, and prints
a message when users authenticate successfully and start a shell.

   .. include:: ../examples/simple_server.py
      :literal:
      :start-line: 14

To authenticate with SSH client keys or certificates, the server would
look something like the following. Client and certificate authority
keys for each user need to be placed in a file matching the username in
a directory called ``authorized_keys``.

   .. include:: ../examples/simple_keyed_server.py
      :literal:
      :start-line: 22

It is also possible to use a single authorized_keys file for all users.
This is common when using certificates, as AsyncSSH can automatically
enforce that the certificates presented have a principal in them which
matches the username. In this case, a custom :class:`SSHServer` subclass
is no longer required, and so the :func:`listen` function can be used in
place of :func:`create_server`.

   .. include:: ../examples/simple_cert_server.py
      :literal:
      :start-line: 21

Simple server with input
------------------------

The following example demonstrates reading input in a server session.
It adds a column of numbers, displaying the total when it receives EOF.

   .. include:: ../examples/math_server.py
      :literal:
      :start-line: 21

Callback example
----------------

Here's an example of the server above written using callbacks in
custom :class:`SSHServer` and :class:`SSHServerSession` subclasses.

   .. include:: ../examples/callback_math_server.py
      :literal:
      :start-line: 21

Serving multiple clients
------------------------

The following is a slightly more complicated example showing how a
server can manage multiple simultaneous clients. It implements a
basic chat service, where clients can send messages to one other.

   .. include:: ../examples/chat_server.py
      :literal:
      :start-line: 21

Line editing
------------

When SSH clients request a pseudo-terminal, they generally default to
sending input a character at a time and expect the remote system to
provide character echo and line editing. To better support interactive
applications like the one above, AsyncSSH defaults to providing basic
line editing for server sessions which request a pseudo-terminal.

When thise line editor is enabled, it defaults to delivering input to
the application a line at a time. Applications can switch between line
and character at a time input using the :meth:`set_line_mode()
<SSHLineEditorChannel.set_line_mode>` method. Also, when in line
mode, applications can enable or disable echoing of input using the
:meth:`set_echo() <SSHLineEditorChannel.set_echo>` method. The
following code provides an example of this.

   .. include:: ../examples/editor.py
      :literal:
      :start-line: 21

Getting environment variables
-----------------------------

The following example demonstrates reading environment variables set
by the client. It will show all of the variables set by the client,
or return an error if none are set. Note that SSH clients may restrict
which environment variables (if any) are sent by default, so you may
need to set options in the client to get it to do so.

   .. include:: ../examples/show_environment.py
      :literal:
      :start-line: 21

Getting terminal information
----------------------------

The following example demonstrates reading the client's terminal
type and window size, and handling window size changes during a
session.

   .. include:: ../examples/show_terminal.py
      :literal:
      :start-line: 21

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
      :start-line: 21

The server can also support forwarding inbound TCP connections back to
the client. The following example demonstrates a server which will accept
requests like this from clients, but only to listen on port 8080. When
such a connection is received, the client is notified and data is
bidirectionally forwarded from the incoming connection over SSH to the
client.

   .. include:: ../examples/remote_forwarding_server.py
      :literal:
      :start-line: 21

Direct TCP connections
----------------------

The server can also accept direct TCP connection requests from the client
and process the data on them itself. The following example demonstrates a
server which accepts requests to port 7 (the "echo" port) for any host and
echoes the data itself rather than forwarding the connection:

   .. include:: ../examples/direct_server.py
      :literal:
      :start-line: 21

Here's an example of this server written using the streams API. In this
case, :meth:`connection_requested() <SSHServer.connection_requested>`
returns a handler coroutine instead of a session object. When a new
direct TCP connection is opened, the handler coroutine is called with
AsyncSSH stream objects which can be used to perform I/O on the tunneled
connection.

   .. include:: ../examples/stream_direct_server.py
      :literal:
      :start-line: 21

SFTP server
-----------

The following example shows how to start an SFTP server with default
behavior:

   .. include:: ../examples/simple_sftp_server.py
      :literal:
      :start-line: 21

A subclass of :class:`SFTPServer` can be provided as the value of the SFTP
factory to override specific behavior. For example, the following code
remaps path names so that each user gets access to only their own individual
directory under ``/tmp/sftp``:

   .. include:: ../examples/chroot_sftp_server.py
      :literal:
      :start-line: 21

More complex path remapping can be performed by implementing the
:meth:`map_path <SFTPServer.map_path>` and
:meth:`reverse_map_path <SFTPServer.reverse_map_path>` methods. Individual
SFTP actions can also be overridden as needed. See the :class:`SFTPServer`
documentation for the full list of methods to override.
