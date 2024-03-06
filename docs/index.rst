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
      :start-line: 22

This example shows using the :class:`SSHClientConnection` returned by
:func:`connect()` as a context manager, so that the connection is
automatically closed when the end of the code block which opened it is
reached. However, if you need the connection object to live longer, you
can use "await" instead of "async with":

   .. code::

     conn = await asyncssh.connect('localhost')

In this case, the application will need to close the connection explicitly
when done with it, and it is best to also wait for the close to complete.
This can be done with the following code from inside an async function:

   .. code::

     conn.close()
     await conn.wait_closed()

Only stdout is referenced this example, but output on stderr is also
collected as another attribute in the returned :class:`SSHCompletedProcess`
object.

Shell and exec sessions default to an encoding of 'utf-8', so read and
write calls operate on strings by default. If you want to send and
receive binary data, you can set the encoding to `None` when the
session is opened to make read and write operate on bytes instead.
Alternate encodings can also be selected to change how strings are
converted to and from bytes.

To check against a different set of server host keys, they can be provided
in the known_hosts argument when the connection is opened:

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
provided in the client_keys argument:

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
      :start-line: 22

In cases where you don't need to customize callbacks on the SSHClient class,
this code can be simplified somewhat to:

   .. include:: ../examples/callback_client2.py
      :literal:
      :start-line: 22

If you need to distinguish output going to stdout vs. stderr, that's easy to
do with the following change:

   .. include:: ../examples/callback_client3.py
      :literal:
      :start-line: 22

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
      :start-line: 22

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
      :start-line: 22

The ``stdin``, ``stdout``, and ``stderr`` arguments support redirecting
to a variety of locations include local files, pipes, and sockets as
well as :class:`SSHReader` or :class:`SSHWriter` objects associated with
other remote SSH processes. Here's an example of piping stdout from a
local process to a remote process:

   .. include:: ../examples/redirect_local_pipe.py
      :literal:
      :start-line: 22

Here's an example of piping one remote process to another:

   .. include:: ../examples/redirect_remote_pipe.py
      :literal:
      :start-line: 22

In this example both remote processes are running on the same SSH
connection, but this redirection can just as easily be used between
SSH sessions associated with connections going to different servers.

Checking exit status
--------------------

The following example shows how to test the exit status of a remote process:

   .. include:: ../examples/check_exit_status.py
      :literal:
      :start-line: 22

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
      :start-line: 22

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
      :start-line: 22

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
      :start-line: 22

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
      :start-line: 22

To listen on a dynamically assigned port, the client can pass in ``0``
as the listening port. If the listener is successfully opened, the selected
port will be available via the :meth:`get_port() <SSHListener.get_port>`
method on the returned listener object:

   .. include:: ../examples/local_forwarding_client2.py
      :literal:
      :start-line: 22

The client can also request remote port forwarding from the server. The
following example shows the client requesting that the server listen on
port 8080 and that connections arriving there be forwarded across SSH
and on to port 80 on ``localhost``:

   .. include:: ../examples/remote_forwarding_client.py
      :literal:
      :start-line: 22

To limit which connections are accepted or dynamically select where to
forward traffic to, the client can implement their own session factory and
call :meth:`forward_connection() <SSHClientConnection.forward_connection>`
on the connections they wish to forward and raise an error on those they
wish to reject:

   .. include:: ../examples/remote_forwarding_client2.py
      :literal:
      :start-line: 22

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
      :start-line: 22

To use the streams API to open a direct connection, you can use
:meth:`open_connection <SSHClientConnection.open_connection>` instead of
:meth:`create_connection <SSHClientConnection.create_connection>`:

   .. include:: ../examples/stream_direct_client.py
      :literal:
      :start-line: 22

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
      :start-line: 22

To use the streams API to open a listening connection, you can use
:meth:`start_server <SSHClientConnection.start_server>` instead
of :meth:`create_server <SSHClientConnection.create_server>`:

   .. include:: ../examples/stream_listening_client.py
      :literal:
      :start-line: 22

SFTP client
-----------

AsyncSSH also provides SFTP support. The following code shows an example
of starting an SFTP client and requesting the download of a file:

   .. include:: ../examples/sftp_client.py
      :literal:
      :start-line: 22

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

SCP client
----------

AsyncSSH also supports SCP. The following code shows an example of
downloading a file via SCP:

   .. include:: ../examples/scp_client.py
      :literal:
      :start-line: 22

To upload a file to a remote system, host information can be specified for
the destination instead of the source:

   .. code::

      await asyncssh.scp('example.txt', 'localhost:')

If the destination path includes a file name, that name will be used instead
of the original file name when performing the copy. For instance:

   .. code::

      await asyncssh.scp('example.txt', 'localhost:example2.txt')

If the destination path refers to a directory, the origin file name
will be preserved, but it will be copied into the requested directory.

Wild card patterns are also supported on local source paths. For instance,
the following copies all files with extension "txt":

   .. code::

      await asyncssh.scp('*.txt', 'localhost:')

When copying files from a remote system, any wild card expansion is the
responsibility of the remote SCP program or the shell which starts it.

Similar to SFTP, SCP also supports options for recursively copying a
directory and preserving modification times and permissions on files
using the preserve and recurse arguments:

   .. code::

      await asyncssh.scp('example_dir', 'localhost:', preserve=True, recurse=True)

In addition to the ``'host:path'`` syntax for source and destination paths,
a tuple of the form ``(host, path)`` is also supported. A non-default port
can be specified by replacing ``host`` with ``(host, port)``, resulting in
something like:

   .. code::

      await asyncssh.scp((('localhost', 8022), 'example.txt'), '.')

An already open :class:`SSHClientConnection` can also be passed as the host:

   .. code::

      async with asyncssh.connect('localhost') as conn:
          await asyncssh.scp((conn, 'example.txt'), '.')

Multiple file patterns can be copied to the same destination by making the
source path argument a list.  Source paths in this list can be a mixture
of local and remote file references and the destination path can be
local or remote, but one or both of source and destination must be remote.
Local to local copies are not supported.

See the :func:`scp` function documentation for the complete list of
available options.

.. _ServerExamples:

Server Examples
===============

Simple server
-------------

The following code shows an example of a simple SSH server which listens
for connections on port 8022, does password authentication, and prints
a message when users authenticate successfully and start a shell.

Shell and exec sessions default to an encoding of 'utf-8', so read and
write calls operate on strings by default. If you want to send and
receive binary data, you can set the encoding to `None` when the
session is opened to make read and write operate on bytes instead.
Alternate encodings can also be selected to change how strings are
converted to and from bytes.

   .. include:: ../examples/simple_server.py
      :literal:
      :start-line: 22

To authenticate with SSH client keys or certificates, the server would
look something like the following. Client and certificate authority
keys for each user need to be placed in a file matching the username in
a directory called ``authorized_keys``.

   .. include:: ../examples/simple_keyed_server.py
      :literal:
      :start-line: 30

It is also possible to use a single authorized_keys file for all users.
This is common when using certificates, as AsyncSSH can automatically
enforce that the certificates presented have a principal in them which
matches the username. In this case, a custom :class:`SSHServer` subclass
is no longer required, and so the :func:`listen` function can be used in
place of :func:`create_server`.

   .. include:: ../examples/simple_cert_server.py
      :literal:
      :start-line: 29

Simple server with input
------------------------

The following example demonstrates reading input in a server session.
It adds a column of numbers, displaying the total when it receives EOF.

   .. include:: ../examples/math_server.py
      :literal:
      :start-line: 29

Callback example
----------------

Here's an example of the server above written using callbacks in
custom :class:`SSHServer` and :class:`SSHServerSession` subclasses.

   .. include:: ../examples/callback_math_server.py
      :literal:
      :start-line: 29

I/O redirection
---------------

The following shows an example of I/O redirection on the server side,
executing a process on the server with input and output redirected
back to the SSH client:

   .. include:: ../examples/redirect_server.py
      :literal:
      :start-line: 29

Serving multiple clients
------------------------

The following is a slightly more complicated example showing how a
server can manage multiple simultaneous clients. It implements a
basic chat service, where clients can send messages to one other.

   .. include:: ../examples/chat_server.py
      :literal:
      :start-line: 29

Line editing
------------

When SSH clients request a pseudo-terminal, they generally default to
sending input a character at a time and expect the remote system to
provide character echo and line editing. To better support interactive
applications like the one above, AsyncSSH defaults to providing basic
line editing for server sessions which request a pseudo-terminal.

When this line editor is enabled, it defaults to delivering input to
the application a line at a time. Applications can switch between line
and character at a time input using the :meth:`set_line_mode()
<SSHLineEditorChannel.set_line_mode>` method. Also, when in line
mode, applications can enable or disable echoing of input using the
:meth:`set_echo() <SSHLineEditorChannel.set_echo>` method. The
following code provides an example of this.

   .. include:: ../examples/editor.py
      :literal:
      :start-line: 29

Getting environment variables
-----------------------------

The following example demonstrates reading environment variables set
by the client. It will show all of the variables set by the client,
or return an error if none are set. Note that SSH clients may restrict
which environment variables (if any) are sent by default, so you may
need to set options in the client to get it to do so.

   .. include:: ../examples/show_environment.py
      :literal:
      :start-line: 29

Getting terminal information
----------------------------

The following example demonstrates reading the client's terminal
type and window size, and handling window size changes during a
session.

   .. include:: ../examples/show_terminal.py
      :literal:
      :start-line: 29

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
      :start-line: 29

The server can also support forwarding inbound TCP connections back to
the client. The following example demonstrates a server which will accept
requests like this from clients, but only to listen on port 8080. When
such a connection is received, the client is notified and data is
bidirectionally forwarded from the incoming connection over SSH to the
client.

   .. include:: ../examples/remote_forwarding_server.py
      :literal:
      :start-line: 29

Direct TCP connections
----------------------

The server can also accept direct TCP connection requests from the client
and process the data on them itself. The following example demonstrates a
server which accepts requests to port 7 (the "echo" port) for any host and
echoes the data itself rather than forwarding the connection:

   .. include:: ../examples/direct_server.py
      :literal:
      :start-line: 29

Here's an example of this server written using the streams API. In this
case, :meth:`connection_requested() <SSHServer.connection_requested>`
returns a handler coroutine instead of a session object. When a new
direct TCP connection is opened, the handler coroutine is called with
AsyncSSH stream objects which can be used to perform I/O on the tunneled
connection.

   .. include:: ../examples/stream_direct_server.py
      :literal:
      :start-line: 29

SFTP server
-----------

The following example shows how to start an SFTP server with default
behavior:

   .. include:: ../examples/simple_sftp_server.py
      :literal:
      :start-line: 29

A subclass of :class:`SFTPServer` can be provided as the value of the SFTP
factory to override specific behavior. For example, the following code
remaps path names so that each user gets access to only their own individual
directory under ``/tmp/sftp``:

   .. include:: ../examples/chroot_sftp_server.py
      :literal:
      :start-line: 29

More complex path remapping can be performed by implementing the
:meth:`map_path <SFTPServer.map_path>` and
:meth:`reverse_map_path <SFTPServer.reverse_map_path>` methods. Individual
SFTP actions can also be overridden as needed. See the :class:`SFTPServer`
documentation for the full list of methods to override.

SCP server
----------

The above server examples can be modified to also support SCP by simply
adding ``allow_scp=True`` alongside the specification of the ``sftp_factory``
in the :func:`listen` call. This will use the same :class:`SFTPServer`
instance when performing file I/O for both SFTP and SCP requests. For
instance:

   .. include:: ../examples/simple_scp_server.py
      :literal:
      :start-line: 29

Reverse Direction Example
=========================

One of the unique capabilities of AsyncSSH is its ability to support
"reverse direction" SSH connections, using the functions
:func:`connect_reverse` and :func:`listen_reverse`. This can be
helpful when implementing protocols such as "NETCONF Call Home",
described in :rfc:`8071`. When using this capability, the SSH protocol
doesn't change, but the roles at the TCP level about which side acts
as a TCP client and server are reversed, with the TCP client taking
on the role of the SSH server and the TCP server taking on the role of
the SSH client once the connection is established.

For these examples to run, the following files must be created:

  * The file ``client_host_key`` must exist on the client and contain an
    SSH private key for the client to use to authenticate itself as a
    host to the server. An SSH certificate can optionally be provided
    in ``client_host_key-cert.pub``.
  * The file ``trusted_server_keys`` must exist on the client and contain
    a list of trusted server keys or a ``cert-authority`` entry with a
    public key trusted to sign server keys if certificates are used. This
    file should be in "authorized_keys" format.
  * The file ``server_key`` must exist on the server and contain an SSH
    private key for the server to use to authenticate itself to the
    client. An SSH certificate can optionally be provided in
    ``server_key-cert.pub``.
  * The file ``trusted_client_host_keys`` must exist on the server and
    contain a list of trusted client host keys or a ``@cert-authority``
    entry with a public key trusted to sign client host keys if
    certificates are used. This file should be in "known_hosts" format.

Reverse Direction Client
------------------------

The following example shows a reverse-direction SSH client which will run
arbitrary shell commands given to it by the server it connects to:

   .. include:: ../examples/reverse_client.py
      :literal:
      :start-line: 32

Reverse Direction Server
------------------------

Here is the corresponding server which makes requests to run the commands:

   .. include:: ../examples/reverse_server.py
      :literal:
      :start-line: 32
