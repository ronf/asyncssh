.. module:: asyncssh

.. _API:

API Documentation
*****************

Overview
========

The AsyncSSH API is modeled after the new Python ``asyncio`` framework, with
a :func:`create_connection` coroutine to create an SSH client and a
:func:`create_server` coroutine to create an SSH server. Like the
``asyncio`` framework, these calls take a parameter of a factory which
creates protocol objects to manage the connections once they are open.
For AsyncSSH, :func:`create_connection` should be passed a ``client_factory``
which returns objects derived from :class:`SSHClient` and :func:`create_server`
should be passed a ``server_factory`` which returns objects derived from
:class:`SSHServer`. In addition, each connection will have an associated
:class:`SSHClientConnection` or :class:`SSHServerConnection` object passed
to the protocol objects which can be used to perform actions on the connection.

For client connections, authentication can be performed by passing in a
username and password or SSH keys as arguments to :func:`create_connection`
or by implementing handler methods on the :class:`SSHClient` object which
return credentials when the server requests them. If no credentials are
provided, AsyncSSH automatically attempts to send the username of the
local user and the keys found in their :file:`.ssh` subdirectory. A list of
expected server host keys can also be specified, with AsyncSSH defaulting
to looking for matching lines in the user's :file:`.ssh/known_hosts` file.

For server connections, handlers can be implemented on the :class:`SSHServer`
object to return which authentication methods are supported and to validate
credentials provided by clients.

Once an SSH client connection is established and authentication is successful,
multiple simultaneous channels can be opened on it.  This is accomplished
calling methods such as :meth:`create_session()
<SSHClientConnection.create_session>`, :meth:`create_connection()
<SSHClientConnection.create_connection>`, :meth:`create_unix_connection()
<SSHClientConnection.create_unix_connection>`, :meth:`create_tun()
<SSHClientConnection.create_tun>`, and :meth:`create_tap()
<SSHClientConnection.create_tap>` on the :class:`SSHClientConnection` object.
The client can also set up listeners on remote TCP ports and UNIX domain
sockets by calling :meth:`create_server() <SSHClientConnection.create_server>`
and :meth:`create_unix_server() <SSHClientConnection.create_unix_server>`.
All of these methods take ``session_factory`` arguments that return
:class:`SSHClientSession`, :class:`SSHTCPSession`, or :class:`SSHUNIXSession`
objects used to manage the channels once they are open. Alternately, channels
can be opened using :meth:`open_session() <SSHClientConnection.open_session>`,
:meth:`open_connection() <SSHClientConnection.open_connection>`,
:meth:`open_unix_connection() <SSHClientConnection.open_unix_connection>`,
:meth:`open_tun() <SSHClientConnection.open_tun>`, or
:meth:`open_tap() <SSHClientConnection.open_tap>`, which return
:class:`SSHReader` and :class:`SSHWriter` objects that can be used to
perform I/O on the channel. The methods :meth:`start_server()
<SSHClientConnection.start_server>` and :meth:`start_unix_server()
<SSHClientConnection.start_unix_server>` can be used to set up listeners on
remote TCP ports or UNIX domain sockets and get back these :class:`SSHReader`
and :class:`SSHWriter` objects in a callback when new connections are opened.

SSH client sessions can also be opened by calling :meth:`create_process()
<SSHClientConnection.create_process>`. This returns a :class:`SSHClientProcess`
object which has members ``stdin``, ``stdout``, and ``stderr`` which are
:class:`SSHReader` and :class:`SSHWriter` objects. This API also makes
it very easy to redirect input and output from the remote process to local
files, pipes, sockets, or other :class:`SSHReader` and :class:`SSHWriter`
objects. In cases where you just want to run a remote process to completion
and get back an object containing captured output and exit status, the
:meth:`run() <SSHClientConnection.run>` method can be used. It returns an
:class:`SSHCompletedProcess` with the results of the run, or can be set up
to raise :class:`ProcessError` if the process exits with a non-zero exit
status. It can also raise :class:`TimeoutError` if a specified timeout
expires before the process exits.

The client can also set up TCP port forwarding by calling
:meth:`forward_local_port() <SSHClientConnection.forward_local_port>` or
:meth:`forward_remote_port() <SSHClientConnection.forward_remote_port>` and
UNIX domain socket forwarding by calling :meth:`forward_local_path()
<SSHClientConnection.forward_local_path>` or :meth:`forward_remote_path()
<SSHClientConnection.forward_remote_path>`. Mixed forwarding from a TCP port
to a UNIX domain socket or vice-versa can be set up using the functions
:meth:`forward_local_port_to_path()
<SSHClientConnection.forward_local_port_to_path>`,
:meth:`forward_local_path_to_port()
<SSHClientConnection.forward_local_path_to_port>`,
:meth:`forward_remote_port_to_path()
<SSHClientConnection.forward_remote_port_to_path>`, and
:meth:`forward_remote_path_to_port()
<SSHClientConnection.forward_remote_path_to_port>`. In these cases, data
transfer on the channels is managed automatically by AsyncSSH whenever new
connections are opened, so custom session objects are not required.

Dynamic TCP port forwarding can be set up by calling :meth:`forward_socks()
<SSHClientConnection.forward_socks>`. The SOCKS listener set up by
AsyncSSH on the requested port accepts SOCKS connect requests and is
compatible with SOCKS versions 4, 4a, and 5.

Bidirectional packet forwarding at layer 2 or 3 is also supported using
the functions :meth:`forward_tun() <SSHClientConnection.forward_tun>` and
:meth:`forward_tap() <SSHClientConnection.forward_tap>` to set up tunnels
between local and remote TUN or TAP interfaces. Once a tunnel is established,
packets arriving on TUN/TAP interfaces on either side are sent over the
tunnel and automatically sent out the TUN/TAP interface on the other side.

When an SSH server receives a new connection and authentication is successful,
handlers such as :meth:`session_requested() <SSHServer.session_requested>`,
:meth:`connection_requested() <SSHServer.connection_requested>`,
:meth:`unix_connection_requested() <SSHServer.unix_connection_requested>`,
:meth:`server_requested() <SSHServer.server_requested>`, and
:meth:`unix_server_requested() <SSHServer.unix_server_requested>` on the
associated :class:`SSHServer` object will be called when clients attempt to
open channels or set up listeners. These methods return coroutines which can
set up the requested sessions or connections, returning
:class:`SSHServerSession` or :class:`SSHTCPSession` objects or handler
functions that accept :class:`SSHReader` and :class:`SSHWriter` objects
as arguments which manage the channels once they are open.

To better support interactive server applications, AsyncSSH defaults to
providing echoing of input and basic line editing capabilities when an
inbound SSH session requests a pseudo-terminal. This behavior can be
disabled by setting the ``line_editor`` argument to ``False`` when
starting up an SSH server. When this feature is enabled, server sessions
can enable or disable line mode using the :meth:`set_line_mode()
<SSHLineEditorChannel.set_line_mode>` method of :class:`SSHLineEditorChannel`.
They can also enable or disable input echoing using the :meth:`set_echo()
<SSHLineEditorChannel.set_echo>` method. Handling of specific keys during
line editing can be customized using the :meth:`register_key()
<SSHLineEditorChannel.register_key>` and :meth:`unregister_key()
<SSHLineEditorChannel.unregister_key>` methods.

Each session object also has an associated :class:`SSHClientChannel`,
:class:`SSHServerChannel`, or :class:`SSHTCPChannel` object passed to it
which can be used to perform actions on the channel. These channel objects
provide a superset of the functionality found in ``asyncio`` transport
objects.

In addition to the above functions and classes, helper functions for importing
public and private keys can be found below under :ref:`PublicKeySupport`,
exceptions can be found under :ref:`Exceptions`, supported algorithms can
be found under :ref:`SupportedAlgorithms`, and some useful constants can be
found under :ref:`Constants`.

Main Functions
==============

.. autofunction:: connect
.. autofunction:: connect_reverse
.. autofunction:: listen
.. autofunction:: listen_reverse
.. autofunction:: run_client
.. autofunction:: run_server
.. autofunction:: create_connection
.. autofunction:: create_server
.. autofunction:: get_server_host_key
.. autofunction:: get_server_auth_methods
.. autofunction:: scp

Main Classes
============

.. autoclass:: SSHClient

   ================================== =
   General connection handlers
   ================================== =
   .. automethod:: connection_made
   .. automethod:: connection_lost
   .. automethod:: debug_msg_received
   ================================== =

   ======================================== =
   Host key validation handlers
   ======================================== =
   .. automethod:: validate_host_public_key
   .. automethod:: validate_host_ca_key
   ======================================== =

   ==================================== =
   General authentication handlers
   ==================================== =
   .. automethod:: auth_banner_received
   .. automethod:: auth_completed
   ==================================== =

   ========================================= =
   Public key authentication handlers
   ========================================= =
   .. automethod:: public_key_auth_requested
   ========================================= =

   ========================================= =
   Password authentication handlers
   ========================================= =
   .. automethod:: password_auth_requested
   .. automethod:: password_change_requested
   .. automethod:: password_changed
   .. automethod:: password_change_failed
   ========================================= =

   ============================================ =
   Keyboard-interactive authentication handlers
   ============================================ =
   .. automethod:: kbdint_auth_requested
   .. automethod:: kbdint_challenge_received
   ============================================ =

.. autoclass:: SSHServer

   ================================== =
   General connection handlers
   ================================== =
   .. automethod:: connection_made
   .. automethod:: connection_lost
   .. automethod:: debug_msg_received
   ================================== =

   =============================== =
   General authentication handlers
   =============================== =
   .. automethod:: begin_auth
   .. automethod:: auth_completed
   =============================== =

   ====================================== =
   GSSAPI authentication handlers
   ====================================== =
   .. automethod:: validate_gss_principal
   ====================================== =

   ========================================= =
   Host-based authentication handlers
   ========================================= =
   .. automethod:: host_based_auth_supported
   .. automethod:: validate_host_public_key
   .. automethod:: validate_host_ca_key
   .. automethod:: validate_host_based_user
   ========================================= =

   ========================================= =
   Public key authentication handlers
   ========================================= =
   .. automethod:: public_key_auth_supported
   .. automethod:: validate_public_key
   .. automethod:: validate_ca_key
   ========================================= =

   ======================================= =
   Password authentication handlers
   ======================================= =
   .. automethod:: password_auth_supported
   .. automethod:: validate_password
   .. automethod:: change_password
   ======================================= =

   ============================================ =
   Keyboard-interactive authentication handlers
   ============================================ =
   .. automethod:: kbdint_auth_supported
   .. automethod:: get_kbdint_challenge
   .. automethod:: validate_kbdint_response
   ============================================ =

   ========================================= =
   Channel session open handlers
   ========================================= =
   .. automethod:: session_requested
   .. automethod:: connection_requested
   .. automethod:: unix_connection_requested
   .. automethod:: server_requested
   .. automethod:: unix_server_requested
   .. automethod:: tun_requested
   .. automethod:: tap_requested
   ========================================= =

Connection Classes
==================

.. autoclass:: SSHClientConnection()

   ======================================================================= =
   Connection attributes
   ======================================================================= =
   .. autoattribute:: logger
   ======================================================================= =

   =================================== =
   General connection methods
   =================================== =
   .. automethod:: get_extra_info
   .. automethod:: set_extra_info
   .. automethod:: set_keepalive
   .. automethod:: get_server_host_key
   .. automethod:: send_debug
   .. automethod:: is_closed
   =================================== =

   ====================================================================================================================================================== =
   Client session open methods
   ====================================================================================================================================================== =
   .. automethod:: create_session
   .. automethod:: open_session
   .. automethod:: create_process(*args, bufsize=io.DEFAULT_BUFFER_SIZE, input=None, stdin=PIPE, stdout=PIPE, stderr=PIPE, **kwargs)
   .. automethod:: create_subprocess(protocol_factory, *args, bufsize=io.DEFAULT_BUFFER_SIZE, input=None, stdin=PIPE, stdout=PIPE, stderr=PIPE, **kwargs)
   .. automethod:: run(*args, check=False, timeout=None, **kwargs)
   .. automethod:: start_sftp_client
   .. automethod:: create_ssh_connection
   .. automethod:: connect_ssh
   .. automethod:: connect_reverse_ssh
   .. automethod:: listen_ssh
   .. automethod:: listen_reverse_ssh
   ====================================================================================================================================================== =

   ====================================== =
   Client connection open methods
   ====================================== =
   .. automethod:: create_connection
   .. automethod:: open_connection
   .. automethod:: create_server
   .. automethod:: start_server
   .. automethod:: create_unix_connection
   .. automethod:: open_unix_connection
   .. automethod:: create_unix_server
   .. automethod:: start_unix_server
   .. automethod:: create_tun
   .. automethod:: create_tap
   .. automethod:: open_tun
   .. automethod:: open_tap
   ====================================== =

   =========================================== =
   Client forwarding methods
   =========================================== =
   .. automethod:: forward_local_port
   .. automethod:: forward_local_path
   .. automethod:: forward_local_port_to_path
   .. automethod:: forward_local_path_to_port
   .. automethod:: forward_remote_port
   .. automethod:: forward_remote_path
   .. automethod:: forward_remote_port_to_path
   .. automethod:: forward_remote_path_to_port
   .. automethod:: forward_socks
   .. automethod:: forward_tun
   .. automethod:: forward_tap
   =========================================== =

   =========================== =
   Connection close methods
   =========================== =
   .. automethod:: abort
   .. automethod:: close
   .. automethod:: disconnect
   .. automethod:: wait_closed
   =========================== =

.. autoclass:: SSHServerConnection()

   ======================================================================= =
   Connection attributes
   ======================================================================= =
   .. autoattribute:: logger
   ======================================================================= =

   ============================== =
   General connection methods
   ============================== =
   .. automethod:: get_extra_info
   .. automethod:: set_extra_info
   .. automethod:: set_keepalive
   .. automethod:: send_debug
   .. automethod:: is_closed
   ============================== =

   ============================================ =
   Server authentication methods
   ============================================ =
   .. automethod:: send_auth_banner
   .. automethod:: set_authorized_keys
   .. automethod:: get_key_option
   .. automethod:: check_key_permission
   .. automethod:: get_certificate_option
   .. automethod:: check_certificate_permission
   ============================================ =

   ====================================== =
   Server connection open methods
   ====================================== =
   .. automethod:: create_connection
   .. automethod:: open_connection
   .. automethod:: create_unix_connection
   .. automethod:: open_unix_connection
   ====================================== =

   ===================================== =
   Server channel creation methods
   ===================================== =
   .. automethod:: create_server_channel
   .. automethod:: create_tcp_channel
   .. automethod:: create_unix_channel
   .. automethod:: create_tuntap_channel
   ===================================== =

   =========================== =
   Connection close methods
   =========================== =
   .. automethod:: abort
   .. automethod:: close
   .. automethod:: disconnect
   .. automethod:: wait_closed
   =========================== =

.. autoclass:: SSHClientConnectionOptions()

.. autoclass:: SSHServerConnectionOptions()

Process Classes
===============

.. autoclass:: SSHClientProcess

   ======================================================================= =
   Client process attributes
   ======================================================================= =
   .. autoattribute:: channel
   .. autoattribute:: logger
   .. autoattribute:: env
   .. autoattribute:: command
   .. autoattribute:: subsystem
   .. autoattribute:: stdin
   .. autoattribute:: stdout
   .. autoattribute:: stderr
   .. autoattribute:: exit_status
   .. autoattribute:: exit_signal
   .. autoattribute:: returncode
   ======================================================================= =

   ==================================== =
   Other client process methods
   ==================================== =
   .. automethod:: get_extra_info
   .. automethod:: redirect
   .. automethod:: collect_output
   .. automethod:: communicate
   .. automethod:: wait
   .. automethod:: change_terminal_size
   .. automethod:: send_break
   .. automethod:: send_signal
   ==================================== =

   ======================================================================= =
   Client process close methods
   ======================================================================= =
   .. automethod:: terminate
   .. automethod:: kill
   .. automethod:: close
   .. automethod:: is_closing
   .. automethod:: wait_closed
   ======================================================================= =

.. autoclass:: SSHServerProcess

   ============================== =
   Server process attributes
   ============================== =
   .. autoattribute:: channel
   .. autoattribute:: logger
   .. autoattribute:: command
   .. autoattribute:: subsystem
   .. autoattribute:: env
   .. autoattribute:: term_type
   .. autoattribute:: term_size
   .. autoattribute:: term_modes
   .. autoattribute:: stdin
   .. autoattribute:: stdout
   .. autoattribute:: stderr
   ============================== =

   ============================== =
   Other server process methods
   ============================== =
   .. automethod:: get_extra_info
   .. automethod:: redirect
   ============================== =

   ================================ =
   Server process close methods
   ================================ =
   .. automethod:: exit
   .. automethod:: exit_with_signal
   .. automethod:: close
   .. automethod:: is_closing
   .. automethod:: wait_closed
   ================================ =

.. autoclass:: SSHCompletedProcess()

.. autoclass:: SSHSubprocessReadPipe()

   ==================================== =
   General subprocess pipe info methods
   ==================================== =
   .. automethod:: get_extra_info
   ==================================== =

   ======================================================================= =
   Subprocess pipe read methods
   ======================================================================= =
   .. automethod:: pause_reading
   .. automethod:: resume_reading
   ======================================================================= =

   ======================================================================= =
   General subprocess pipe close methods
   ======================================================================= =
   .. automethod:: close
   ======================================================================= =

.. autoclass:: SSHSubprocessWritePipe()

   ==================================== =
   General subprocess pipe info methods
   ==================================== =
   .. automethod:: get_extra_info
   ==================================== =

   ======================================================================= =
   Subprocess pipe write methods
   ======================================================================= =
   .. automethod:: can_write_eof
   .. automethod:: get_write_buffer_size
   .. automethod:: set_write_buffer_limits
   .. automethod:: write
   .. automethod:: writelines
   .. automethod:: write_eof
   ======================================================================= =

   ======================================================================= =
   General subprocess pipe close methods
   ======================================================================= =
   .. automethod:: abort
   .. automethod:: close
   ======================================================================= =

.. autoclass:: SSHSubprocessProtocol

   ==================================== =
   General subprocess protocol handlers
   ==================================== =
   .. automethod:: connection_made
   .. automethod:: pipe_connection_lost
   ==================================== =

   ================================== =
   Subprocess protocol read handlers
   ================================== =
   .. automethod:: pipe_data_received
   ================================== =

   ================================== =
   Other subprocess protocol handlers
   ================================== =
   .. automethod:: process_exited
   ================================== =

.. autoclass:: SSHSubprocessTransport

   ==================================== =
   General subprocess transport methods
   ==================================== =
   .. automethod:: get_extra_info
   .. automethod:: get_pid
   .. automethod:: get_pipe_transport
   .. automethod:: get_returncode
   .. automethod:: change_terminal_size
   .. automethod:: send_break
   .. automethod:: send_signal
   ==================================== =

   ======================================================================= =
   Subprocess transport close methods
   ======================================================================= =
   .. automethod:: terminate
   .. automethod:: kill
   .. automethod:: close
   .. automethod:: is_closing
   .. automethod:: wait_closed
   ======================================================================= =

Session Classes
===============

.. autoclass:: SSHClientSession

   =============================== =
   General session handlers
   =============================== =
   .. automethod:: connection_made
   .. automethod:: connection_lost
   .. automethod:: session_started
   =============================== =

   ============================= =
   General session read handlers
   ============================= =
   .. automethod:: data_received
   .. automethod:: eof_received
   ============================= =

   ============================== =
   General session write handlers
   ============================== =
   .. automethod:: pause_writing
   .. automethod:: resume_writing
   ============================== =

   ==================================== =
   Other client session handlers
   ==================================== =
   .. automethod:: xon_xoff_requested
   .. automethod:: exit_status_received
   .. automethod:: exit_signal_received
   ==================================== =

.. autoclass:: SSHServerSession

   =============================== =
   General session handlers
   =============================== =
   .. automethod:: connection_made
   .. automethod:: connection_lost
   .. automethod:: session_started
   =============================== =

   =================================== =
   Server session open handlers
   =================================== =
   .. automethod:: pty_requested
   .. automethod:: shell_requested
   .. automethod:: exec_requested
   .. automethod:: subsystem_requested
   =================================== =

   ============================= =
   General session read handlers
   ============================= =
   .. automethod:: data_received
   .. automethod:: eof_received
   ============================= =

   ============================== =
   General session write handlers
   ============================== =
   .. automethod:: pause_writing
   .. automethod:: resume_writing
   ============================== =

   ===================================== =
   Other server session handlers
   ===================================== =
   .. automethod:: break_received
   .. automethod:: signal_received
   .. automethod:: terminal_size_changed
   ===================================== =

.. autoclass:: SSHTCPSession

   =============================== =
   General session handlers
   =============================== =
   .. automethod:: connection_made
   .. automethod:: connection_lost
   .. automethod:: session_started
   =============================== =

   ============================= =
   General session read handlers
   ============================= =
   .. automethod:: data_received
   .. automethod:: eof_received
   ============================= =

   ============================== =
   General session write handlers
   ============================== =
   .. automethod:: pause_writing
   .. automethod:: resume_writing
   ============================== =

.. autoclass:: SSHUNIXSession

   =============================== =
   General session handlers
   =============================== =
   .. automethod:: connection_made
   .. automethod:: connection_lost
   .. automethod:: session_started
   =============================== =

   ============================= =
   General session read handlers
   ============================= =
   .. automethod:: data_received
   .. automethod:: eof_received
   ============================= =

   ============================== =
   General session write handlers
   ============================== =
   .. automethod:: pause_writing
   .. automethod:: resume_writing
   ============================== =

.. autoclass:: SSHTunTapSession

   =============================== =
   General session handlers
   =============================== =
   .. automethod:: connection_made
   .. automethod:: connection_lost
   .. automethod:: session_started
   =============================== =

   ============================= =
   General session read handlers
   ============================= =
   .. automethod:: data_received
   .. automethod:: eof_received
   ============================= =

   ============================== =
   General session write handlers
   ============================== =
   .. automethod:: pause_writing
   .. automethod:: resume_writing
   ============================== =

Channel Classes
===============

.. autoclass:: SSHClientChannel()

   ========================= =
   Channel attributes
   ========================= =
   .. autoattribute:: logger
   ========================= =

   =============================== =
   General channel info methods
   =============================== =
   .. automethod:: get_extra_info
   .. automethod:: set_extra_info
   .. automethod:: get_environment
   .. automethod:: get_command
   .. automethod:: get_subsystem
   =============================== =

   ============================== =
   Client channel read methods
   ============================== =
   .. automethod:: pause_reading
   .. automethod:: resume_reading
   ============================== =

   ======================================= =
   Client channel write methods
   ======================================= =
   .. automethod:: can_write_eof
   .. automethod:: get_write_buffer_size
   .. automethod:: set_write_buffer_limits
   .. automethod:: write
   .. automethod:: writelines
   .. automethod:: write_eof
   ======================================= =

   ===================================== =
   Other client channel methods
   ===================================== =
   .. automethod:: get_exit_status
   .. automethod:: get_exit_signal
   .. automethod:: get_returncode
   .. automethod:: change_terminal_size
   .. automethod:: send_break
   .. automethod:: send_signal
   .. automethod:: kill
   .. automethod:: terminate
   ===================================== =

   ============================= =
   General channel close methods
   ============================= =
   .. automethod:: abort
   .. automethod:: close
   .. automethod:: is_closing
   .. automethod:: wait_closed
   ============================= =

.. autoclass:: SSHServerChannel()

   ======================================================================= =
   Channel attributes
   ======================================================================= =
   .. autoattribute:: logger
   ======================================================================= =

   =============================== =
   General channel info methods
   =============================== =
   .. automethod:: get_extra_info
   .. automethod:: set_extra_info
   .. automethod:: get_environment
   .. automethod:: get_command
   .. automethod:: get_subsystem
   =============================== =

   ================================== =
   Server channel info methods
   ================================== =
   .. automethod:: get_terminal_type
   .. automethod:: get_terminal_size
   .. automethod:: get_terminal_mode
   .. automethod:: get_terminal_modes
   .. automethod:: get_x11_display
   .. automethod:: get_agent_path
   ================================== =

   ============================== =
   Server channel read methods
   ============================== =
   .. automethod:: pause_reading
   .. automethod:: resume_reading
   ============================== =

   ======================================= =
   Server channel write methods
   ======================================= =
   .. automethod:: can_write_eof
   .. automethod:: get_write_buffer_size
   .. automethod:: set_write_buffer_limits
   .. automethod:: write
   .. automethod:: writelines
   .. automethod:: write_stderr
   .. automethod:: writelines_stderr
   .. automethod:: write_eof
   ======================================= =

   ================================= =
   Other server channel methods
   ================================= =
   .. automethod:: set_xon_xoff
   .. automethod:: exit
   .. automethod:: exit_with_signal
   ================================= =

   ============================= =
   General channel close methods
   ============================= =
   .. automethod:: abort
   .. automethod:: close
   .. automethod:: is_closing
   .. automethod:: wait_closed
   ============================= =

.. autoclass:: SSHLineEditorChannel()

   ============================== =
   Line editor methods
   ============================== =
   .. automethod:: register_key
   .. automethod:: unregister_key
   .. automethod:: set_line_mode
   .. automethod:: set_echo
   ============================== =

.. autoclass:: SSHTCPChannel()

   ======================================================================= =
   Channel attributes
   ======================================================================= =
   .. autoattribute:: logger
   ======================================================================= =

   ============================== =
   General channel info methods
   ============================== =
   .. automethod:: get_extra_info
   .. automethod:: set_extra_info
   ============================== =

   ============================== =
   General channel read methods
   ============================== =
   .. automethod:: pause_reading
   .. automethod:: resume_reading
   ============================== =

   ======================================= =
   General channel write methods
   ======================================= =
   .. automethod:: can_write_eof
   .. automethod:: get_write_buffer_size
   .. automethod:: set_write_buffer_limits
   .. automethod:: write
   .. automethod:: writelines
   .. automethod:: write_eof
   ======================================= =

   ============================= =
   General channel close methods
   ============================= =
   .. automethod:: abort
   .. automethod:: close
   .. automethod:: is_closing
   .. automethod:: wait_closed
   ============================= =

.. autoclass:: SSHUNIXChannel()

   ======================================================================= =
   Channel attributes
   ======================================================================= =
   .. autoattribute:: logger
   ======================================================================= =

   ============================== =
   General channel info methods
   ============================== =
   .. automethod:: get_extra_info
   .. automethod:: set_extra_info
   ============================== =

   ============================== =
   General channel read methods
   ============================== =
   .. automethod:: pause_reading
   .. automethod:: resume_reading
   ============================== =

   ======================================= =
   General channel write methods
   ======================================= =
   .. automethod:: can_write_eof
   .. automethod:: get_write_buffer_size
   .. automethod:: set_write_buffer_limits
   .. automethod:: write
   .. automethod:: writelines
   .. automethod:: write_eof
   ======================================= =

   ============================= =
   General channel close methods
   ============================= =
   .. automethod:: abort
   .. automethod:: close
   .. automethod:: is_closing
   .. automethod:: wait_closed
   ============================= =

.. autoclass:: SSHTunTapChannel()

   ======================================================================= =
   Channel attributes
   ======================================================================= =
   .. autoattribute:: logger
   ======================================================================= =

   ============================== =
   General channel info methods
   ============================== =
   .. automethod:: get_extra_info
   .. automethod:: set_extra_info
   ============================== =

   ============================== =
   General channel read methods
   ============================== =
   .. automethod:: pause_reading
   .. automethod:: resume_reading
   ============================== =

   ======================================= =
   General channel write methods
   ======================================= =
   .. automethod:: can_write_eof
   .. automethod:: get_write_buffer_size
   .. automethod:: set_write_buffer_limits
   .. automethod:: write
   .. automethod:: writelines
   .. automethod:: write_eof
   ======================================= =

   ============================= =
   General channel close methods
   ============================= =
   .. automethod:: abort
   .. automethod:: close
   .. automethod:: is_closing
   .. automethod:: wait_closed
   ============================= =

Forwarder Classes
=================

.. autoclass:: SSHForwarder()

   ============================== =
   .. automethod:: get_extra_info
   .. automethod:: close
   ============================== =


Listener Classes
================

.. autoclass:: SSHAcceptor()

   ============================= =
   .. automethod:: get_addresses
   .. automethod:: get_port
   .. automethod:: close
   .. automethod:: wait_closed
   .. automethod:: update
   ============================= =

.. autoclass:: SSHListener()

   =========================== =
   .. automethod:: get_port
   .. automethod:: close
   .. automethod:: wait_closed
   =========================== =

Stream Classes
==============

.. autoclass:: SSHReader()

   ============================== =
   .. autoattribute:: channel
   .. autoattribute:: logger
   .. automethod:: get_extra_info
   .. automethod:: feed_data
   .. automethod:: feed_eof
   .. automethod:: at_eof
   .. automethod:: read
   .. automethod:: readline
   .. automethod:: readuntil
   .. automethod:: readexactly
   ============================== =

.. autoclass:: SSHWriter()

   ============================== =
   .. autoattribute:: channel
   .. autoattribute:: logger
   .. automethod:: get_extra_info
   .. automethod:: can_write_eof
   .. automethod:: drain
   .. automethod:: write
   .. automethod:: writelines
   .. automethod:: write_eof
   .. automethod:: close
   .. automethod:: is_closing
   .. automethod:: wait_closed
   ============================== =

SFTP Support
============

.. autoclass:: SFTPClient()

   ======================================================================= =
   SFTP client attributes
   ======================================================================= =
   .. autoattribute:: logger
   .. autoattribute:: version
   ======================================================================= =

   ===================== =
   File transfer methods
   ===================== =
   .. automethod:: get
   .. automethod:: put
   .. automethod:: copy
   .. automethod:: mget
   .. automethod:: mput
   .. automethod:: mcopy
   ===================== =

   ============================================================================================================================================================================================================================== =
   File access methods
   ============================================================================================================================================================================================================================== =
   .. automethod:: open(path, mode='r', attrs=SFTPAttrs(), encoding='utf-8', errors='strict', block_size=SFTP_BLOCK_SIZE, max_requests=_MAX_SFTP_REQUESTS)
   .. automethod:: open56(path, desired_access=ACE4_READ_DATA | ACE4_READ_ATTRIBUTES, flags=FXF_OPEN_EXISTING, attrs=SFTPAttrs(), encoding='utf-8', errors='strict', block_size=SFTP_BLOCK_SIZE, max_requests=_MAX_SFTP_REQUESTS)
   .. automethod:: truncate
   .. automethod:: rename
   .. automethod:: posix_rename
   .. automethod:: remove
   .. automethod:: unlink
   .. automethod:: readlink
   .. automethod:: symlink
   .. automethod:: link
   .. automethod:: realpath
   ============================================================================================================================================================================================================================== =

   ======================================================= =
   File attribute access methods
   ======================================================= =
   .. automethod:: stat
   .. automethod:: lstat
   .. automethod:: setstat
   .. automethod:: statvfs
   .. automethod:: chown(path, uid or owner, gid or group)
   .. automethod:: chmod
   .. automethod:: utime
   .. automethod:: exists
   .. automethod:: lexists
   .. automethod:: getatime
   .. automethod:: getatime_ns
   .. automethod:: getmtime
   .. automethod:: getcrtime_ns
   .. automethod:: getcrtime
   .. automethod:: getmtime_ns
   .. automethod:: getsize
   .. automethod:: isdir
   .. automethod:: isfile
   .. automethod:: islink
   ======================================================= =

   ================================================= =
   Directory access methods
   ================================================= =
   .. automethod:: chdir
   .. automethod:: getcwd
   .. automethod:: mkdir(path, attrs=SFTPAttrs())
   .. automethod:: makedirs(path, attrs=SFTPAttrs())
   .. automethod:: rmdir
   .. automethod:: rmtree
   .. automethod:: scandir
   .. automethod:: readdir
   .. automethod:: listdir
   .. automethod:: glob
   .. automethod:: glob_sftpname
   ================================================= =

   =========================== =
   Cleanup methods
   =========================== =
   .. automethod:: exit
   .. automethod:: wait_closed
   =========================== =

.. autoclass:: SFTPClientFile()

   ================================================= =
   .. automethod:: read
   .. automethod:: read_parallel
   .. automethod:: write
   .. automethod:: seek(offset, from_what=SEEK_SET)
   .. automethod:: tell
   .. automethod:: stat
   .. automethod:: setstat
   .. automethod:: statvfs
   .. automethod:: truncate
   .. automethod:: chown(uid or owner, gid or group)
   .. automethod:: chmod
   .. automethod:: utime
   .. automethod:: lock
   .. automethod:: unlock
   .. automethod:: fsync
   .. automethod:: close
   ================================================= =

.. autoclass:: SFTPServer

   ============================= =
   SFTP server attributes
   ============================= =
   .. autoattribute:: channel
   .. autoattribute:: connection
   .. autoattribute:: env
   .. autoattribute:: logger
   ============================= =

   ================================== =
   Path remapping and display methods
   ================================== =
   .. automethod:: format_user
   .. automethod:: format_group
   .. automethod:: format_longname
   .. automethod:: map_path
   .. automethod:: reverse_map_path
   ================================== =

   ============================ =
   File access methods
   ============================ =
   .. automethod:: open
   .. automethod:: open56
   .. automethod:: close
   .. automethod:: read
   .. automethod:: write
   .. automethod:: rename
   .. automethod:: posix_rename
   .. automethod:: remove
   .. automethod:: readlink
   .. automethod:: symlink
   .. automethod:: link
   .. automethod:: realpath
   ============================ =

   ============================= =
   File attribute access methods
   ============================= =
   .. automethod:: stat
   .. automethod:: lstat
   .. automethod:: fstat
   .. automethod:: setstat
   .. automethod:: fsetstat
   .. automethod:: statvfs
   .. automethod:: fstatvfs
   .. automethod:: lock
   .. automethod:: unlock
   ============================= =

   ======================== =
   Directory access methods
   ======================== =
   .. automethod:: mkdir
   .. automethod:: rmdir
   .. automethod:: scandir
   ======================== =

   ===================== =
   Cleanup methods
   ===================== =
   .. automethod:: exit
   ===================== =

.. autoclass:: SFTPAttrs()

.. autoclass:: SFTPVFSAttrs()

.. autoclass:: SFTPName()

.. index:: Public key and certificate support
.. _PublicKeySupport:

Public Key Support
==================

AsyncSSH has extensive public key and certificate support.

Supported public key types include DSA, RSA, and ECDSA. In addition, Ed25519
and Ed448 keys are supported if OpenSSL 1.1.1b or later is installed.
Alternately, Ed25519 support is available when the libnacl package and
libsodium library are installed.

Supported certificate types include OpenSSH version 01 certificates for
DSA, RSA, ECDSA, Ed25519, and Ed448 keys and X.509 certificates for DSA,
RSA, and ECDSA keys.

Support is also available for the certificate critical options of
force-command and source-address and the extensions permit-X11-forwarding,
permit-agent-forwarding, permit-port-forwarding, and permit-pty in
OpenSSH certificates.

Several public key and certificate formats are supported including
PKCS#1 and PKCS#8 DER and PEM, OpenSSH, RFC4716, and X.509 DER and
PEM formats.

PEM and PKCS#8 password-based encryption of private keys is supported, as
is OpenSSH private key encryption when the bcrypt package is installed.

.. index:: Specifying private keys
.. _SpecifyingPrivateKeys:

Specifying private keys
-----------------------

Private keys may be passed into AsyncSSH in a variety of forms. The
simplest option is to pass the name of a file to read one or more
private keys from.

An alternate form involves passing in a list of values which can be
either a reference to a private key or a tuple containing a reference
to a private key and a reference to a corresponding certificate or
certificate chain.

Key references can either be the name of a file to load a key from,
a byte string to import as a key, or an already loaded :class:`SSHKey`
private key. See the function :func:`import_private_key` for the list
of supported private key formats.

Certificate references can be the name of a file to load a certificate
from, a byte string to import as a certificate, an already loaded
:class:`SSHCertificate`, or ``None`` if no certificate should be
associated with the key.

Whenever a filename is provided to read the private key from, an attempt
is made to load a corresponding certificate or certificate chain from a
file constructed by appending '-cert.pub' to the end of the name. X.509
certificates may also be provided in the same file as the private key,
when using DER or PEM format.

When using X.509 certificates, a list of certificates can also be
provided. These certificates should form a trust chain from a user or
host certificate up to some self-signed root certificate authority
which is trusted by the remote system.

Instead of passing tuples of keys and certificates or relying on file
naming conventions for certificates, you also have the option of
providing a list of keys and a separate list of certificates. In this
case, AsyncSSH will automatically match up the keys with their
associated certificates when they are present.

New private keys can be generated using the :func:`generate_private_key`
function. The resulting :class:`SSHKey` objects have methods which can
then be used to export the generated keys in several formats for
consumption by other tools, as well as methods for generating new
OpenSSH or X.509 certificates.

.. index:: Specifying public keys
.. _SpecifyingPublicKeys:

Specifying public keys
----------------------

Public keys may be passed into AsyncSSH in a variety of forms. The
simplest option is to pass the name of a file to read one or more
public keys from.

An alternate form involves passing in a list of values each of which
can be either the name of a file to load a key from, a byte string
to import it from, or an already loaded :class:`SSHKey` public key.
See the function :func:`import_public_key` for the list of supported
public key formats.

.. index:: Specifying certificates
.. _SpecifyingCertificates:

Specifying certificates
-----------------------

Certificates may be passed into AsyncSSH in a variety of forms. The
simplest option is to pass the name of a file to read one or more
certificates from.

An alternate form involves passing in a list of values each of which
can be either the name of a file to load a certificate from, a byte string
to import it from, or an already loaded :class:`SSHCertificate` object.
See the function :func:`import_certificate` for the list of supported
certificate formats.

.. index:: Specifying X.509 subject names
.. _SpecifyingX509Subjects:

Specifying X.509 subject names
------------------------------

X.509 certificate subject names may be specified in place of public keys
or certificates in authorized_keys and known_hosts files, allowing any
X.509 certificate which matches that subject name to be considered a
known host or authorized key. The syntax supported for this is compatible
with PKIX-SSH, which adds X.509 certificate support to OpenSSH.

To specify a subject name pattern instead of a specific certificate,
base64-encoded certificate data should be replaced with the string
'Subject:' followed by a comma-separated list of X.509 relative
distinguished name components.

AsyncSSH extends the PKIX-SSH syntax to also support matching on a
prefix of a subject name. To indicate this, a partial subject name
can be specified which ends in ',*'.  Any subject which matches the
relative distinguished names listed before the ",*" will be treated
as a match, even if the certificate provided has additional relative
distinguished names following what was matched.

.. index:: Specifying X.509 purposes
.. _SpecifyingX509Purposes:

Specifying X.509 purposes
-------------------------

When performing X.509 certificate authentication, AsyncSSH can be
passed in an allowed set of ExtendedKeyUsage purposes. Purposes are
matched in X.509 certificates as OID values, but AsyncSSH also allows
the following well-known purpose values to be specified by name:

.. table::
  :align: left

  ================= ==================
  Name              OID
  ================= ==================
  serverAuth        1.3.6.1.5.5.7.3.1
  clientAuth        1.3.6.1.5.5.7.3.2
  secureShellClient 1.3.6.1.5.5.7.3.20
  secureShellServer 1.3.6.1.5.5.7.3.21
  ================= ==================

Values not in the list above can be specified directly by OID as a
dotted numeric string value. Either a single value or a list of values
can be provided.

The check succeeds if any of the specified values are present in the
certificate's ExtendedKeyUsage. It will also succeed if the certificate
does not contain an ExtendedKeyUsage or if the ExtendedKeyUsage contains
the OID 2.5.29.37.0, which indicates the certificate can be used for any
purpose.

This check defaults to requiring a purpose of 'secureShellCient' for
client certificates and 'secureShellServer' for server certificates
and should not normally need to be changed. However, certificates which
contain other purposes can be supported by providing alternate values to
match against, or by passing in the purpose 'any' to disable this checking.

.. index:: Specifying time values
.. _SpecifyingTimeValues:

Specifying time values
----------------------

When generating certificates, an optional validity interval can be
specified using the ``valid_after`` and ``valid_before`` parameters
to the :meth:`generate_user_certificate() <SSHKey.generate_user_certificate>`
and :meth:`generate_host_certificate() <SSHKey.generate_host_certificate>`
methods. These values can be specified in any of the following ways:

    * An int or float UNIX epoch time, such as what is returned by
      :func:`time.time`.
    * A :class:`datetime.datetime` value.
    * A string value of ``now`` to request the current time.
    * A string value in the form ``YYYYMMDD`` to specify an absolute date.
    * A string value in the form ``YYYYMMDDHHMMSS`` to specify an
      absolute date and time.
    * A time interval described in :ref:`SpecifyingTimeIntervals` which is
      interpreted as a relative time from now. This value can be negative
      to refer to times in the past or positive to refer to times in the
      future.

Key and certificate classes/functions
-------------------------------------

.. autoclass:: SSHKey()

   ============================================== =
   .. automethod:: get_algorithm
   .. automethod:: get_comment_bytes
   .. automethod:: get_comment
   .. automethod:: set_comment
   .. automethod:: get_fingerprint
   .. automethod:: convert_to_public
   .. automethod:: generate_user_certificate
   .. automethod:: generate_host_certificate
   .. automethod:: generate_x509_user_certificate
   .. automethod:: generate_x509_host_certificate
   .. automethod:: generate_x509_ca_certificate
   .. automethod:: export_private_key
   .. automethod:: export_public_key
   .. automethod:: write_private_key
   .. automethod:: write_public_key
   .. automethod:: append_private_key
   .. automethod:: append_public_key
   ============================================== =

.. autoclass:: SSHKeyPair()

   ================================= =
   .. automethod:: get_key_type
   .. automethod:: get_algorithm
   .. automethod:: set_certificate
   .. automethod:: get_comment_bytes
   .. automethod:: get_comment
   .. automethod:: set_comment
   ================================= =

.. autoclass:: SSHCertificate()

   ================================== =
   .. automethod:: get_algorithm
   .. automethod:: get_comment_bytes
   .. automethod:: get_comment
   .. automethod:: set_comment
   .. automethod:: export_certificate
   .. automethod:: write_certificate
   .. automethod:: append_certificate
   ================================== =

.. autofunction:: generate_private_key
.. autofunction:: import_private_key
.. autofunction:: import_public_key
.. autofunction:: import_certificate
.. autofunction:: read_private_key
.. autofunction:: read_public_key
.. autofunction:: read_certificate
.. autofunction:: read_private_key_list
.. autofunction:: read_public_key_list
.. autofunction:: read_certificate_list
.. autofunction:: load_keypairs
.. autofunction:: load_public_keys
.. autofunction:: load_certificates
.. autofunction:: load_pkcs11_keys
.. autofunction:: load_resident_keys
.. autofunction:: set_default_skip_rsa_key_validation

.. index:: SSH agent support
.. _SSHAgentSupport:

SSH Agent Support
=================

AsyncSSH supports the ability to use private keys managed by the OpenSSH
ssh-agent on UNIX systems. It can connect via a UNIX domain socket to
the agent and offload all private key operations to it, avoiding the need
to read these keys into AsyncSSH itself. An ssh-agent is automatically
used in :func:`create_connection` when a valid ``SSH_AUTH_SOCK`` is set
in the environment. An alternate path to the agent can be specified via
the ``agent_path`` argument to this function.

An ssh-agent can also be accessed directly from AsyncSSH by calling
:func:`connect_agent`. When successful, this function returns an
:class:`SSHAgentClient` which can be used to get a list of available
keys, add and remove keys, and lock and unlock access to this agent.

SSH agent forwarding may be enabled when making outbound SSH connections
by specifying the ``agent_forwarding`` argument when calling
:func:`create_connection`, allowing processes running on the server
to tunnel requests back over the SSH connection to the client's ssh-agent.

Agent forwarding can be enabled when starting an SSH server by
specifying the ``agent_forwarding`` argument when calling
:func:`create_server`. In this case, the client's ssh-agent can be
accessed from the server by passing the :class:`SSHServerConnection` as
the argument to :func:`connect_agent` instead of a local path. Alternately,
when an :class:`SSHServerChannel` has been opened, the :meth:`get_agent_path()
<SSHServerChannel.get_agent_path>` method may be called on it to get a
path to a UNIX domain socket which can be passed as the ``SSH_AUTH_SOCK``
to local applications which need this access. Any requests sent to this
socket are forwarded over the SSH connection to the client's ssh-agent.

.. autoclass:: SSHAgentClient()

   ===================================== =
   .. automethod:: get_keys
   .. automethod:: add_keys
   .. automethod:: add_smartcard_keys
   .. automethod:: remove_keys
   .. automethod:: remove_smartcard_keys
   .. automethod:: remove_all
   .. automethod:: lock
   .. automethod:: unlock
   .. automethod:: query_extensions
   .. automethod:: close
   .. automethod:: wait_closed
   ===================================== =

.. autoclass:: SSHAgentKeyPair()

   ================================= =
   .. automethod:: get_key_type
   .. automethod:: get_algorithm
   .. automethod:: get_comment_bytes
   .. automethod:: get_comment
   .. automethod:: set_comment
   .. automethod:: remove
   ================================= =

.. autofunction:: connect_agent

.. index:: Config file support
.. _ConfigFileSupport:

Config File Support
===================

AsyncSSH has partial support for parsing OpenSSH client and server
configuration files (documented in the "ssh_config" and "sshd_config"
UNIX man pages, respectively). Not all OpenSSH configuration options
are applicable, so unsupported options are simply ignored. See below
for the OpenSSH config options that AsyncSSH supports.

AsyncSSH also supports "Host" and "Match" conditional blocks. As with
the config options themselves, not all match criteria  are supported,
but the supported criteria should function similar to OpenSSH.

AsyncSSH also supports the "Include" directive, to allow one config
file trigger the loading of others.

.. index:: Supported client config options
.. _SupportedClientConfigOptions:

Supported client config options
-------------------------------

The following OpenSSH client config options are currently supported:

  | AddressFamily
  | BindAddress
  | CASignatureAlgorithms
  | CertificateFile
  | ChallengeResponseAuthentication
  | Ciphers
  | Compression
  | ConnectTimeout
  | EnableSSHKeySign
  | ForwardAgent
  | ForwardX11Trusted
  | GlobalKnownHostsFile
  | GSSAPIAuthentication
  | GSSAPIDelegateCredentials
  | GSSAPIKeyExchange
  | HostbasedAuthentication
  | HostKeyAlgorithms
  | HostKeyAlias
  | Hostname
  | IdentityAgent
  | IdentityFile
  | KbdInteractiveAuthentication
  | KexAlgorithms
  | MACs
  | PasswordAuthentication
  | PreferredAuthentications
  | Port
  | ProxyCommand
  | ProxyJump
  | PubkeyAuthentication
  | RekeyLimit
  | RemoteCommand
  | RequestTTY
  | SendEnv
  | ServerAliveCountMax
  | ServerAliveInterval
  | SetEnv
  | TCPKeepAlive
  | User
  | UserKnownHostsFile

For the "Match" conditional, the following criteria are currently supported:

  | All
  | Exec
  | Host
  | LocalUser
  | OriginalHost
  | User

  .. warning:: When instantiating :class:`SSHClientConnectionOptions`
               objects manually within an asyncio task, you may block
               the event loop if the options refer to a config file with
               "Match Exec" directives which don't return immediate
               results. In such cases, the asyncio `run_in_executor()`
               function should be used. This is taken care of automatically
               when options objects are created by AsyncSSH APIs such as
               :func:`connect` and :func:`listen`.

The following client config token expansions are currently supported:

.. table::
  :align: left

  ===== ============================================================
  Token Expansion
  ===== ============================================================
  %%    Literal '%'
  %C    SHA-1 Hash of connection info (local host, host, port, user)
  %d    Local user's home directory
  %h    Remote host
  %i    Local uid (UNIX-only)
  %L    Short local hostname (without the domain)
  %l    Local hostname (including the domain)
  %n    Original remote host
  %p    Remote port
  %r    Remote username
  %u    Local username
  ===== ============================================================

These expansions are available in the values of the following config options:

  | CertificateFile
  | IdentityAgent
  | IdentityFile
  | RemoteCommand

.. index:: Supported server config options
.. _SupportedServerConfigOptions:

Supported server config options
-------------------------------

The following OpenSSH server config options are currently supported:

  | AddressFamily
  | AuthorizedKeysFile
  | AllowAgentForwarding
  | BindAddress
  | CASignatureAlgorithms
  | ChallengeResponseAuthentication
  | Ciphers
  | ClientAliveCountMax
  | ClientAliveInterval
  | Compression
  | GSSAPIAuthentication
  | GSSAPIKeyExchange
  | HostbasedAuthentication
  | HostCertificate
  | HostKey
  | KbdInteractiveAuthentication
  | KexAlgorithms
  | LoginGraceTime
  | MACs
  | PasswordAuthentication
  | PermitTTY
  | Port
  | ProxyCommand
  | PubkeyAuthentication
  | RekeyLimit
  | TCPKeepAlive
  | UseDNS

For the "Match" conditional, the following criteria are currently supported:

  | All
  | Exec
  | Address
  | Host
  | LocalAddress
  | LocalPort
  | User

  .. warning:: When instantiating :class:`SSHServerConnectionOptions`
               objects manually within an asyncio task, you may block
               the event loop if the options refer to a config file with
               "Match Exec" directives which don't return immediate
               results. In such cases, the asyncio `run_in_executor()`
               function should be used. This is taken care of automatically
               when options objects are created by AsyncSSH APIs such as
               :func:`connect` and :func:`listen`.

The following server config token expansions are currently supported:

.. table::
  :align: left

  ===== ===========
  Token Expansion
  ===== ===========
  %%    Literal '%'
  %u    Username
  ===== ===========

These expansions are available in the values of the following config options:

  | AuthorizedKeysFile

.. index:: Specifying byte counts
.. _SpecifyingByteCounts:

Specifying byte counts
----------------------

A byte count may be passed into AsyncSSH as an integer value, or as a
string made up of a mix of numbers followed by an optional letter of
'k', 'm', or 'g', indicating kilobytes, megabytes, or gigabytes,
respectively. Multiple of these values can be included. For instance,
'2.5m' means 2.5 megabytes. This could also be expressed as '2m512k'
or '2560k'.

.. index:: Specifying time intervals
.. _SpecifyingTimeIntervals:

Specifying time intervals
-------------------------

A time interval may be passed into AsyncSSH as an integer or float value,
or as a string made up of a mix of positive or negative numbers and the
letters 'w', 'd', 'h', 'm', and 's', indicating weeks, days, hours,
minutes, or seconds, respectively. Multiple of these values can be
included. For instance, '1w2d3h' means 1 week, 2 days, and 3 hours.

.. index:: Known hosts
.. _KnownHosts:

Known Hosts
===========

AsyncSSH supports OpenSSH-style known_hosts files, including both
plain and hashed host entries. Regular and negated host patterns are
supported in plain entries. AsyncSSH also supports the ``@cert_authority``
marker to indicate keys and certificates which should be trusted as
certificate authorities and the ``@revoked`` marker to indicate keys and
certificates which should be explicitly reported as no longer trusted.

.. index:: Specifying known hosts
.. _SpecifyingKnownHosts:

Specifying known hosts
----------------------

Known hosts may be passed into AsyncSSH via the ``known_hosts`` argument
to :func:`create_connection`. This can be the name of a file or list of files
containing known hosts, a byte string containing data in known hosts format,
or an :class:`SSHKnownHosts` object which was previously imported from a
string by calling :func:`import_known_hosts` or read from files by calling
:func:`read_known_hosts`. In all of these cases, the host patterns in the
list will be compared against the target host, address, and port being
connected to and the matching trusted host keys, trusted CA keys, revoked
keys, trusted X.509 certificates, revoked X.509 certificates, trusted
X.509 subject names, and revoked X.509 subject names will be returned.

Alternately, a function can be passed in as the ``known_hosts`` argument
that accepts a target host, address, and port and returns lists containing
trusted host keys, trusted CA keys, revoked keys, trusted X.509 certificates,
revoked X.509 certificates, trusted X.509 subject names, and revoked X.509
subject names.

If no matching is required and the caller already knows exactly what the
above values should be, these seven lists can also be provided directly in
the ``known_hosts`` argument.

See :ref:`SpecifyingPublicKeys` for the allowed form of public key values
which can be provided, :ref:`SpecifyingCertificates` for the allowed form
of certificates, and :ref:`SpecifyingX509Subjects` for the allowed form
of X.509 subject names.

Known hosts classes/functions
-----------------------------

.. autoclass:: SSHKnownHosts()

   ===================== =
   .. automethod:: match
   ===================== =

.. autofunction:: import_known_hosts
.. autofunction:: read_known_hosts
.. autofunction:: match_known_hosts

.. index:: Authorized keys
.. _AuthorizedKeys:

Authorized Keys
===============

AsyncSSH supports OpenSSH-style authorized_keys files, including the
cert-authority option to validate user certificates, enforcement of
from and principals options to restrict key matching, enforcement
of no-X11-forwarding, no-agent-forwarding, no-pty, no-port-forwarding,
and permitopen options, and support for command and environment options.

.. index:: Specifying authorized keys
.. _SpecifyingAuthorizedKeys:

Specifying authorized keys
--------------------------

Authorized keys may be passed into AsyncSSH via the
``authorized_client_keys`` argument to :func:`create_server` or by calling
:meth:`set_authorized_keys() <SSHServerConnection.set_authorized_keys>`
on the :class:`SSHServerConnection` from within the :meth:`begin_auth()
<SSHServer.begin_auth>` method in :class:`SSHServer`.

Authorized keys can be provided as either the name of a file or list of
files to read authorized keys from or an :class:`SSHAuthorizedKeys` object
which was previously imported from a string by calling
:func:`import_authorized_keys` or read from files by calling
:func:`read_authorized_keys`.

An authorized keys file may contain public keys or X.509 certificates
in OpenSSH format or X.509 certificate subject names. See
:ref:`SpecifyingX509Subjects` for more information on using subject names
in place of specific X.509 certificates.

Authorized keys classes/functions
---------------------------------

.. autoclass:: SSHAuthorizedKeys()

.. autofunction:: import_authorized_keys
.. autofunction:: read_authorized_keys

.. index:: Logging
.. _Logging:

Logging
=======

AsyncSSH supports logging through the standard Python `logging` package.
Logging is done under the logger named `'asyncssh'` as well as a child
logger named `'asyncssh.sftp'` to allow different log levels to be set
for SFTP related log messages.

The base AsyncSSH log level can be set using the :func:`set_log_level`
function and the SFTP log level can be set using the :func:`set_sftp_log_level`
function. In addition, when either of these loggers is set to level DEBUG,
AsyncSSH provides fine-grained control over the level of debug logging
via the :func:`set_debug_level` function.

AsyncSSH also provides logger objects as members of connection, channel,
stream, and process objects that automatically log additional context about
the connection or channel the logger is a member of. These objects can
be used by application code to output custom log information associated
with a particular connection or channel. Logger objects are also provided
as members of SFTP client and server objects.

.. autofunction:: set_log_level
.. autofunction:: set_sftp_log_level
.. autofunction:: set_debug_level

.. index:: Exceptions
.. _Exceptions:

Exceptions
==========

.. autoexception:: PasswordChangeRequired
.. autoexception:: BreakReceived
.. autoexception:: SignalReceived
.. autoexception:: TerminalSizeChanged
.. autoexception:: DisconnectError
.. autoexception:: CompressionError
.. autoexception:: ConnectionLost
.. autoexception:: HostKeyNotVerifiable
.. autoexception:: IllegalUserName
.. autoexception:: KeyExchangeFailed
.. autoexception:: MACError
.. autoexception:: PermissionDenied
.. autoexception:: ProtocolError
.. autoexception:: ProtocolNotSupported
.. autoexception:: ServiceNotAvailable
.. autoexception:: ChannelOpenError
.. autoexception:: ChannelListenError
.. autoexception:: ProcessError
.. autoexception:: TimeoutError
.. autoexception:: SFTPError
.. autoexception:: SFTPEOFError
.. autoexception:: SFTPNoSuchFile
.. autoexception:: SFTPPermissionDenied
.. autoexception:: SFTPFailure
.. autoexception:: SFTPBadMessage
.. autoexception:: SFTPNoConnection
.. autoexception:: SFTPConnectionLost
.. autoexception:: SFTPOpUnsupported
.. autoexception:: SFTPInvalidHandle
.. autoexception:: SFTPNoSuchPath
.. autoexception:: SFTPFileAlreadyExists
.. autoexception:: SFTPWriteProtect
.. autoexception:: SFTPNoMedia
.. autoexception:: SFTPNoSpaceOnFilesystem
.. autoexception:: SFTPQuotaExceeded
.. autoexception:: SFTPUnknownPrincipal
.. autoexception:: SFTPLockConflict
.. autoexception:: SFTPDirNotEmpty
.. autoexception:: SFTPNotADirectory
.. autoexception:: SFTPInvalidFilename
.. autoexception:: SFTPLinkLoop
.. autoexception:: SFTPCannotDelete
.. autoexception:: SFTPInvalidParameter
.. autoexception:: SFTPFileIsADirectory
.. autoexception:: SFTPByteRangeLockConflict
.. autoexception:: SFTPByteRangeLockRefused
.. autoexception:: SFTPDeletePending
.. autoexception:: SFTPFileCorrupt
.. autoexception:: SFTPOwnerInvalid
.. autoexception:: SFTPGroupInvalid
.. autoexception:: SFTPNoMatchingByteRangeLock
.. autoexception:: KeyImportError
.. autoexception:: KeyExportError
.. autoexception:: KeyEncryptionError
.. autoexception:: KeyGenerationError
.. autoexception:: ConfigParseError

.. index:: Supported algorithms
.. _SupportedAlgorithms:

Supported Algorithms
====================

Algorithms can be specified as either a list of exact algorithm names
or as a string of comma-separated algorithm names that may optionally
include wildcards. An '*' in a name matches zero or more characters and
a '?' matches exactly one character.

When specifying algorithms as a string, it can also be prefixed with '^'
to insert the matching algorithms in front of the default algorithms of
that type, a '+' to insert the matching algorithms after the default
algorithms, or a '-' to return the default algorithms with the matching
algorithms removed.

.. index:: Key exchange algorithms
.. _KexAlgs:

Key exchange algorithms
-----------------------

The following are the default key exchange algorithms currently supported
by AsyncSSH:

  | gss-curve25519-sha256
  | gss-curve448-sha512
  | gss-nistp521-sha512
  | gss-nistp384-sha256
  | gss-nistp256-sha256
  | gss-1.3.132.0.10-sha256
  | gss-gex-sha256
  | gss-group14-sha256
  | gss-group15-sha512
  | gss-group16-sha512
  | gss-group17-sha512
  | gss-group18-sha512
  | gss-group14-sha1
  | sntrup761x25519-sha512\@openssh.com
  | curve25519-sha256
  | curve25519-sha256\@libssh.org
  | curve448-sha512
  | ecdh-sha2-nistp521
  | ecdh-sha2-nistp384
  | ecdh-sha2-nistp256
  | ecdh-sha2-1.3.132.0.10
  | diffie-hellman-group-exchange-sha256
  | diffie-hellman-group14-sha256
  | diffie-hellman-group15-sha512
  | diffie-hellman-group16-sha512
  | diffie-hellman-group17-sha512
  | diffie-hellman-group18-sha512
  | diffie-hellman-group14-sha256\@ssh.com
  | diffie-hellman-group14-sha1
  | rsa2048-sha256

The following key exchange algorithms are supported by AsyncSSH, but
disabled by default:

  | gss-gex-sha1
  | gss-group1-sha1
  | diffie-hellman-group-exchange-sha224\@ssh.com
  | diffie-hellman-group-exchange-sha384\@ssh.com
  | diffie-hellman-group-exchange-sha512\@ssh.com
  | diffie-hellman-group-exchange-sha1
  | diffie-hellman-group14-sha224\@ssh.com
  | diffie-hellman-group15-sha256\@ssh.com
  | diffie-hellman-group15-sha384\@ssh.com
  | diffie-hellman-group16-sha384\@ssh.com
  | diffie-hellman-group16-sha512\@ssh.com
  | diffie-hellman-group18-sha512\@ssh.com
  | diffie-hellman-group1-sha1
  | rsa1024-sha1

GSS authentication support is only available when the gssapi package is
installed on UNIX or the pywin32 package is installed on Windows.

Curve25519 and Curve448 support is available when OpenSSL 1.1.1 or
later is installed. Alternately, Curve25519 is available when the
libnacl package and libsodium library are installed.

SNTRUP support is available when the Open Quantum Safe (liboqs)
dynamic library is installed.

.. index:: Encryption algorithms
.. _EncryptionAlgs:

Encryption algorithms
---------------------

The following are the default encryption algorithms currently supported
by AsyncSSH:

  | chacha20-poly1305\@openssh.com
  | aes256-gcm\@openssh.com
  | aes128-gcm\@openssh.com
  | aes256-ctr
  | aes192-ctr
  | aes128-ctr

The following encryption algorithms are supported by AsyncSSH, but
disabled by default:

  | aes256-cbc
  | aes192-cbc
  | aes128-cbc
  | 3des-cbc
  | blowfish-cbc
  | cast128-cbc
  | seed-cbc\@ssh.com
  | arcfour256
  | arcfour128
  | arcfour

Chacha20-Poly1305 support is available when either OpenSSL 1.1.1b or later
or the libnacl package and libsodium library are installed.

.. index:: MAC algorithms
.. _MACAlgs:

MAC algorithms
--------------

The following are the default MAC algorithms currently supported by AsyncSSH:

  | umac-64-etm\@openssh.com
  | umac-128-etm\@openssh.com
  | hmac-sha2-256-etm\@openssh.com
  | hmac-sha2-512-etm\@openssh.com
  | hmac-sha1-etm\@openssh.com
  | umac-64\@openssh.com
  | umac-128\@openssh.com
  | hmac-sha2-256
  | hmac-sha2-512
  | hmac-sha1
  | hmac-sha256-2\@ssh.com
  | hmac-sha224\@ssh.com
  | hmac-sha256\@ssh.com
  | hmac-sha384\@ssh.com
  | hmac-sha512\@ssh.com

The following MAC algorithms are supported by AsyncSSH, but disabled
by default:

  | hmac-md5-etm\@openssh.com
  | hmac-sha2-256-96-etm\@openssh.com
  | hmac-sha2-512-96-etm\@openssh.com
  | hmac-sha1-96-etm\@openssh.com
  | hmac-md5-96-etm\@openssh.com
  | hmac-md5
  | hmac-sha2-256-96
  | hmac-sha2-512-96
  | hmac-sha1-96
  | hmac-md5-96

UMAC support is only available when the nettle library is installed.

.. index:: Compression algorithms
.. _CompressionAlgs:

Compression algorithms
----------------------

The following are the default compression algorithms currently supported
by AsyncSSH:

  | zlib\@openssh.com
  | none

The following compression algorithms are supported by AsyncSSH, but disabled
by default:

  | zlib

.. index:: Signature algorithms
.. _SignatureAlgs:

Signature algorithms
--------------------

The following are the default public key signature algorithms currently
supported by AsyncSSH:

  | x509v3-ssh-ed25519
  | x509v3-ssh-ed448
  | x509v3-ecdsa-sha2-nistp521
  | x509v3-ecdsa-sha2-nistp384
  | x509v3-ecdsa-sha2-nistp256
  | x509v3-ecdsa-sha2-1.3.132.0.10
  | x509v3-rsa2048-sha256
  | x509v3-ssh-rsa
  | sk-ssh-ed25519\@openssh.com
  | sk-ecdsa-sha2-nistp256\@openssh.com
  | ssh-ed25519
  | ssh-ed448
  | ecdsa-sha2-nistp521
  | ecdsa-sha2-nistp384
  | ecdsa-sha2-nistp256
  | ecdsa-sha2-1.3.132.0.10
  | rsa-sha2-256
  | rsa-sha2-512
  | ssh-rsa-sha224\@ssh.com
  | ssh-rsa-sha256\@ssh.com
  | ssh-rsa-sha384\@ssh.com
  | ssh-rsa-sha512\@ssh.com
  | ssh-rsa

The following public key signature algorithms are supported by AsyncSSH,
but disabled by default:

  | x509v3-ssh-dss
  | ssh-dss

.. index:: Public key & certificate algorithms
.. _PublicKeyAlgs:

Public key & certificate algorithms
-----------------------------------

The following are the default public key and certificate algorithms
currently supported by AsyncSSH:

  | x509v3-ssh-ed25519
  | x509v3-ssh-ed448
  | x509v3-ecdsa-sha2-nistp521
  | x509v3-ecdsa-sha2-nistp384
  | x509v3-ecdsa-sha2-nistp256
  | x509v3-ecdsa-sha2-1.3.132.0.10
  | x509v3-rsa2048-sha256
  | x509v3-ssh-rsa
  | sk-ssh-ed25519-cert-v01\@openssh.com
  | sk-ecdsa-sha2-nistp256-cert-v01\@openssh.com
  | ssh-ed25519-cert-v01\@openssh.com
  | ssh-ed448-cert-v01\@openssh.com
  | ecdsa-sha2-nistp521-cert-v01\@openssh.com
  | ecdsa-sha2-nistp384-cert-v01\@openssh.com
  | ecdsa-sha2-nistp256-cert-v01\@openssh.com
  | ecdsa-sha2-1.3.132.0.10-cert-v01\@openssh.com
  | rsa-sha2-256-cert-v01\@openssh.com
  | rsa-sha2-512-cert-v01\@openssh.com
  | ssh-rsa-cert-v01\@openssh.com
  | sk-ssh-ed25519\@openssh.com
  | sk-ecdsa-sha2-nistp256\@openssh.com
  | ssh-ed25519
  | ssh-ed448
  | ecdsa-sha2-nistp521
  | ecdsa-sha2-nistp384
  | ecdsa-sha2-nistp256
  | ecdsa-sha2-1.3.132.0.10
  | rsa-sha2-256
  | rsa-sha2-512
  | ssh-rsa-sha224\@ssh.com
  | ssh-rsa-sha256\@ssh.com
  | ssh-rsa-sha384\@ssh.com
  | ssh-rsa-sha512\@ssh.com
  | ssh-rsa

The following public key and certificate algorithms are supported by
AsyncSSH, but disabled by default:

  | x509v3-ssh-dss
  | ssh-dss-cert-v01\@openssh.com
  | ssh-dss

Ed25519 and Ed448 support is available when OpenSSL 1.1.1b or later is
installed. Alternately, Ed25519 is available when the libnacl package
and libsodium library are installed.

.. index:: Constants
.. _Constants:

Constants
=========

.. index:: Disconnect reasons
.. _DisconnectReasons:

Disconnect reasons
------------------

The following values defined in section 11.1 of :rfc:`4253#section-11.1`
can be specified as disconnect reason codes:

  | DISC_HOST_NOT_ALLOWED_TO_CONNECT
  | DISC_PROTOCOL_ERROR
  | DISC_KEY_EXCHANGE_FAILED
  | DISC_RESERVED
  | DISC_MAC_ERROR
  | DISC_COMPRESSION_ERROR
  | DISC_SERVICE_NOT_AVAILABLE
  | DISC_PROTOCOL_VERSION_NOT_SUPPORTED
  | DISC_HOST_KEY_NOT_VERIFIABLE
  | DISC_CONNECTION_LOST
  | DISC_BY_APPLICATION
  | DISC_TOO_MANY_CONNECTIONS
  | DISC_AUTH_CANCELLED_BY_USER
  | DISC_NO_MORE_AUTH_METHODS_AVAILABLE
  | DISC_ILLEGAL_USER_NAME

.. index:: Channel open failure reasons
.. _ChannelOpenFailureReasons:

Channel open failure reasons
----------------------------

The following values defined in section 5.1 of :rfc:`4254#section-5.1` can
be specified as channel open failure reason codes:

  | OPEN_ADMINISTRATIVELY_PROHIBITED
  | OPEN_CONNECT_FAILED
  | OPEN_UNKNOWN_CHANNEL_TYPE
  | OPEN_RESOURCE_SHORTAGE

In addition, AsyncSSH defines the following channel open failure reason codes:

  | OPEN_REQUEST_X11_FORWARDING_FAILED
  | OPEN_REQUEST_PTY_FAILED
  | OPEN_REQUEST_SESSION_FAILED

.. index:: SFTP error codes
.. _SFTPErrorCodes:

SFTP error codes
----------------

The following values defined in section 9.1 of the `SSH File Transfer Protocol
Internet Draft <https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-9.1>`_ can be specified as SFTP error codes:

.. table::
  :align: left

  =============================== ====================
  Error code                      Minimum SFTP version
  =============================== ====================
  FX_OK                           3
  FX_EOF                          3
  FX_NO_SUCH_FILE                 3
  FX_PERMISSION_DENIED            3
  FX_FAILURE                      3
  FX_BAD_MESSAGE                  3
  FX_NO_CONNECTION                3
  FX_CONNECTION_LOST              3
  FX_OP_UNSUPPORTED               3
  FX_INVALID_HANDLE               4
  FX_NO_SUCH_PATH                 4
  FX_FILE_ALREADY_EXISTS          4
  FX_WRITE_PROTECT                4
  FX_NO_MEDIA                     4
  FX_NO_SPACE_ON_FILESYSTEM       5
  FX_QUOTA_EXCEEDED               5
  FX_UNKNOWN_PRINCIPAL            5
  FX_LOCK_CONFLICT                5
  FX_DIR_NOT_EMPTY                6
  FX_NOT_A_DIRECTORY              6
  FX_INVALID_FILENAME             6
  FX_LINK_LOOP                    6
  FX_CANNOT_DELETE                6
  FX_INVALID_PARAMETER            6
  FX_FILE_IS_A_DIRECTORY          6
  FX_BYTE_RANGE_LOCK_CONFLICT     6
  FX_BYTE_RANGE_LOCK_REFUSED      6
  FX_DELETE_PENDING               6
  FX_FILE_CORRUPT                 6
  FX_OWNER_INVALID                6
  FX_GROUP_INVALID                6
  FX_NO_MATCHING_BYTE_RANGE_LOCK  6
  =============================== ====================

.. index:: Extended data types
.. _ExtendedDataTypes:

Extended data types
-------------------

The following values defined in section 5.2 of :rfc:`4254#section-5.2` can
be specified as SSH extended channel data types:

  | EXTENDED_DATA_STDERR

.. index:: POSIX terminal modes
.. _PTYModes:

POSIX terminal modes
--------------------

The following values defined in section 8 of :rfc:`4254#section-8` can be
specified as PTY mode opcodes:

  | PTY_OP_END
  | PTY_VINTR
  | PTY_VQUIT
  | PTY_VERASE
  | PTY_VKILL
  | PTY_VEOF
  | PTY_VEOL
  | PTY_VEOL2
  | PTY_VSTART
  | PTY_VSTOP
  | PTY_VSUSP
  | PTY_VDSUSP
  | PTY_VREPRINT
  | PTY_WERASE
  | PTY_VLNEXT
  | PTY_VFLUSH
  | PTY_VSWTCH
  | PTY_VSTATUS
  | PTY_VDISCARD
  | PTY_IGNPAR
  | PTY_PARMRK
  | PTY_INPCK
  | PTY_ISTRIP
  | PTY_INLCR
  | PTY_IGNCR
  | PTY_ICRNL
  | PTY_IUCLC
  | PTY_IXON
  | PTY_IXANY
  | PTY_IXOFF
  | PTY_IMAXBEL
  | PTY_ISIG
  | PTY_ICANON
  | PTY_XCASE
  | PTY_ECHO
  | PTY_ECHOE
  | PTY_ECHOK
  | PTY_ECHONL
  | PTY_NOFLSH
  | PTY_TOSTOP
  | PTY_IEXTEN
  | PTY_ECHOCTL
  | PTY_ECHOKE
  | PTY_PENDIN
  | PTY_OPOST
  | PTY_OLCUC
  | PTY_ONLCR
  | PTY_OCRNL
  | PTY_ONOCR
  | PTY_ONLRET
  | PTY_CS7
  | PTY_CS8
  | PTY_PARENB
  | PTY_PARODD
  | PTY_OP_ISPEED
  | PTY_OP_OSPEED
