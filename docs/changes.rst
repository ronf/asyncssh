.. currentmodule:: asyncssh

Change Log
==========

Release 0.8.4 (12 Sep 2014)
---------------------------

* Fixed an error in the encode/decode functions for PKCS#1 DSA public keys

* Fixed a bug in the unit test code for import/export of RFC4716 public keys

Release 0.8.3 (16 Aug 2014)
--------------------------

* Added a missing import in the curve25519 implementation.

Release 0.8.2 (16 Aug 2014)
---------------------------

* Provided a better long description for PyPI.

* Added link to PyPI in documentation sidebar.

Release 0.8.1 (15 Aug 2014)
---------------------------

* Added a note in the :meth:`validate_public_key()
  <SSHServer.validate_public_key>` documentation clarifying that AsyncSSH
  will verify that the client possesses the corresponding private key before
  authentication is allowed to succeed.

* Switched from setuptools to distutils and added an initial set of unit
  tests.

* Prepared the package to be uploaded to PyPI.

Release 0.8.0 (15 Jul 2014)
---------------------------

* Added support for Curve25519 Diffie Hellman key exchange on systems with
  the curve25519-donna Python package installed.

* Updated the examples to more clearly show what values are returned even
  when not all of the return values are used.

Release 0.7.0 (7 Jun 2014)
--------------------------

* This release adds support for the "high-level" ``asyncio`` streams API,
  in the form of the :class:`SSHReader` and :class:`SSHWriter` classes
  and wrapper methods such as :meth:`open_session()
  <SSHClientConnection.open_session>`, :meth:`open_connection()
  <SSHClientConnection.open_connection>`, and :meth:`start_server()
  <SSHClientConnection.start_server>`. It also allows the callback
  methods on :class:`SSHServer` to return either SSH session objects or
  handler functions that take :class:`SSHReader` and :class:`SSHWriter`
  objects as arguments. See :meth:`session_requested()
  <SSHServer.session_requested>`, :meth:`connection_requested()
  <SSHServer.connection_requested>`, and :meth:`server_requested()
  <SSHServer.server_requested>` for more information.

* Added new exceptions :exc:`BreakReceived`, :exc:`SignalReceived`, and
  :exc:`TerminalSizeChanged` to report when these messages are received
  while trying to read from an :class:`SSHServerChannel` using the new
  streams API.

* Changed :meth:`create_server() <SSHClientConnection.create_server>` to
  accept either a callable or a coroutine for its ``session_factory``
  argument, to allow asynchronous operations to be used when deciding
  whether to accept a forwarded TCP connection.

* Renamed ``accept_connection()`` to :meth:`create_connection()
  <SSHServerConnection.create_connection>` in the :class:`SSHServerConnection`
  class for consistency with :class:`SSHClientConnection`, and added a
  corresponding :meth:`open_connection() <SSHServerConnection.open_connection>`
  method as part of the streams API.

* Added :meth:`get_exit_status() <SSHClientChannel.get_exit_status>` and
  :meth:`get_exit_signal() <SSHClientChannel.get_exit_signal>` methods
  to the :class:`SSHClientChannel` class.

* Added :meth:`get_command() <SSHServerChannel.get_command>` and
  :meth:`get_subsystem() <SSHServerChannel.get_subsystem>` methods to
  the :class:`SSHServerChannel` class.

* Fixed the name of the :meth:`write_stderr() <SSHServerChannel.write_stderr>`
  method and added the missing :meth:`writelines_stderr()
  <SSHServerChannel.writelines_stderr>` method to the :class:`SSHServerChannel`
  class for outputting data to the stderr channel.

* Added support for a return value in the :meth:`eof_received()
  <SSHClientSession.eof_received>` of :class:`SSHClientSession`,
  :class:`SSHServerSession`, and :class:`SSHTCPSession` to support
  half-open channels. By default, the channel is automatically closed
  after :meth:`eof_received() <SSHClientSession.eof_received>` returns,
  but returning ``True`` will now keep the channel open, allowing output
  to still be sent on the half-open channel. This is done automatically
  when the new streams API is used.

* Added values ``'local_peername'`` and ``'remote_peername'`` to the set
  of information available from the :meth:`get_extra_info()
  <SSHTCPChannel.get_extra_info>` method in the :class:`SSHTCPChannel` class.

* Updated functions returning :exc:`IOError` or :exc:`socket.error` to
  return the new :exc:`OSError` exception introduced in Python 3.3.

* Cleaned up some errors in the documentation.

* The :ref:`API`, :ref:`ClientExamples`, and :ref:`ServerExamples` have
  all been updated to reflect these changes, and new examples showing the
  streams API have been added.

Release 0.6.0 (11 May 2014)
---------------------------

* This release is a major revamp of the code to migrate from the
  ``asyncore`` framework to the new ``asyncio`` framework in Python
  3.4. All the APIs have been adapted to fit the new ``asyncio``
  paradigm, using coroutines wherever possible to avoid the need
  for callbacks when performing asynchronous operations.

  So far, this release only supports the "low-level" ``asyncio`` API.

* The :ref:`API`, :ref:`ClientExamples`, and :ref:`ServerExamples` have
  all been updated to reflect these changes.


Release 0.5.0 (11 Oct 2013)
---------------------------

* Added the following new classes to support fully asynchronous
  connection forwarding, replacing the methods previously added in
  release 0.2.0:

    * :class:`SSHClientListener`
    * :class:`SSHServerListener`
    * :class:`SSHClientLocalPortForwarder`
    * :class:`SSHClientRemotePortForwarder`
    * :class:`SSHServerPortForwarder`

  These new classes allow for DNS lookups and other operations to be
  performed fully asynchronously when new listeners are set up. As with
  the asynchronous connect changes below, methods are now available
  to report when the listener is opened or when an error occurs during
  the open rather than requiring the listener to be fully set up in a
  single call.

* Updated examples in :ref:`ClientExamples` and :ref:`ServerExamples`
  to reflect the above changes.

Release 0.4.0 (28 Sep 2013)
---------------------------

* Added support in :class:`SSHTCPConnection` for the following methods
  to allow asynchronous operations to be used when accepting inbound
  connection requests:

    * :meth:`handle_open_request() <SSHTCPConnection.handle_open_request>`
    * :meth:`report_open() <SSHTCPConnection.report_open>`
    * :meth:`report_open_error() <SSHTCPConnection.report_open_error>`

  These new methods are used to implement asynchronous connect
  support for local and remote port forwarding, and to support
  trying multiple destination addresses when connection failures
  occur.

* Cleaned up a few minor documentation errors.

Release 0.3.0 (26 Sep 2013)
---------------------------

* Added support in :class:`SSHClient` and :class:`SSHServer` for setting
  the key exchange, encryption, MAC, and compression algorithms allowed
  in the SSH handshake.

* Refactored the algorithm selection code to pull a common matching
  function back into ``_SSHConnection`` and simplify other modules.

* Extended the listener class to open multiple listening sockets when
  necessary, fixing a bug where sockets opened to listen on ``localhost``
  were not properly accepting both IPv4 and IPv6 connections.

  Now, any listen request which resolves to multiple addresses will open
  listening sockets for each address.

* Fixed a bug related to tracking of listeners opened on dynamic ports.

Release 0.2.0 (21 Sep 2013)
---------------------------

* Added support in :class:`SSHClient` for the following methods related
  to performing standard SSH port forwarding:

    * :meth:`forward_local_port() <SSHClient.forward_local_port>`
    * :meth:`cancel_local_port_forwarding() <SSHClient.cancel_local_port_forwarding>`
    * :meth:`forward_remote_port() <SSHClient.forward_remote_port>`
    * :meth:`cancel_remote_port_forwarding() <SSHClient.cancel_remote_port_forwarding>`
    * :meth:`handle_remote_port_forwarding() <SSHClient.handle_remote_port_forwarding>`
    * :meth:`handle_remote_port_forwarding_error() <SSHClient.handle_remote_port_forwarding_error>`

* Added support in :class:`SSHServer` for new return values in
  :meth:`handle_direct_connection() <SSHServer.handle_direct_connection>`
  and :meth:`handle_listen() <SSHServer.handle_listen>` to activate
  standard SSH server-side port forwarding.

* Added a client_addr argument and member variable to :class:`SSHServer`
  to hold the client's address information.

* Added and updated examples related to port forwarding and using
  :class:`SSHTCPConnection` to open direct and forwarded TCP
  connections in :ref:`ClientExamples` and :ref:`ServerExamples`.

* Cleaned up some of the other documentation.

* Removed a debug print statement accidentally left in related to
  SSH rekeying.

Release 0.1.0 (14 Sep 2013)
---------------------------

* Initial release
