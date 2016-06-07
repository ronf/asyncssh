.. currentmodule:: asyncssh

Change Log
==========

Release 1.5.4 (6 Jun 2016)
--------------------------

* Added support for setting custom SSH client and server version strings.

* Added unit tests for the sftp module, bringing AsyncSSH up to 100%
  code coverage under test on all modules.

* Added new wait_closed() method in SFTPClient class to wait for an
  SFTP client session to be fully closed.

* Fixed an issue with error handling in new parallel SFTP file copy code.

* Fixed some other minor issues in SFTP found during unit tests.

* Fixed some minor documentation issues.

Release 1.5.3 (2 Apr 2016)
--------------------------

* Added support for opening tunneled SSH connections, where an SSH
  connection is opened over another SSH connection's direct TCP/IP
  channel.

* Improve performance of SFTP over high latency connections by having
  the internal copy method issue multiple read requests in parallel.

* Reworked SFTP to mark all coroutine functions explicitly, to provide
  better compatibility with the new Python 3.5 "await" syntax.

* Reworked create_connection() and create_server() functions to do
  argument checking immediately rather than in the SSHConnection
  constructors, improving error reporting and avoiding a bug in
  asyncio which can leak socket objects.

* Fixed a hang which could occur when attempting to close an SSH
  connection with a listener still active.

* Fixed an error related to passing keys in via public_key_auth_requested().

* Fixed a potential leak of an SSHAgentClient object when an error occurs
  while opening a client connection.

* Fixed some race conditions related to channel and connection closes.

* Fixed some minor documentation issues.

* Continued to expand unit test coverage, completing coverage of the
  connection module.

Release 1.5.2 (25 Feb 2016)
---------------------------

* Fixed a bug in UNIX domain socket forwarding introduced in 1.5.1 by the
  TCP_NODELAY change.

* Fixed channel code to report when a channel is closed with incomplete
  Unicode data in the receive buffer. This was previously reported
  correctly when EOF was received on a channel, but not when it was
  closed without sending EOF.

* Added unit tests for channel, forward, and stream modules, partial
  unit tests for the connection module, and a placeholder for unit
  tests for the sftp module.

Release 1.5.1 (23 Feb 2016)
---------------------------

* Added basic support for running AsyncSSH on Windows. Some functionality
  such as UNIX domain sockets will not work there, and the test suite will
  not run there yet, but basic functionality has been tested and seems
  to work. This includes features like bcrypt and support for newer
  ciphers provided by libnacl when these optional packages are installed.

* Greatly improved the performance of known_hosts matching on exact
  hostnames and addresses. Full wildcard pattern matching is still
  supported, but entries involving exact hostnames or addresses are
  now matched thousands of times faster.

* Split known_hosts parsing and matching into separate calls so that a
  known_hosts file can be parsed once and used to make connections to
  several different hosts. Thanks go to Josh Yudaken for suggesting
  this and providing a sample implementation.

* Updated AsyncSSH to allow SSH agent forwarding when it is requested
  even when local client keys are used to perform SSH authentication.

* Updaded channel state machine to better handle close being received
  while the channel is paused for reading. Previously, some data would
  not be delivered in this case.

* Set TCP_NODELAY on sockets to avoid latency problems caused by TCP
  delayed ACK.

* Fixed a bug where exceptions were not always returned properly when
  attempting to drain writes on a stream.

* Fixed a bug which could leak a socket object after an error opening
  a local TCP listening socket.

* Fixed a number of race conditions uncovered during unit testing.

Release 1.5.0 (27 Jan 2016)
---------------------------

* Added support for OpenSSH-compatible direct and forwarded UNIX domain
  socket channels and local and remote UNIX domain socket forwarding.

* Added support for client and server side ssh-agent forwarding.

* Fixed the open_connection() method on SSHServerConnection to not include
  a handler_factory argument. This should only have been present on the
  start_server() method.

* Fixed wait_closed() on SSHForwardListener to work properly when a
  close is in progress at the time of the call.

Release 1.4.1 (23 Jan 2016)
---------------------------

* Fixed a bug in SFTP introduced in 1.4.0 related to handling of
  responses to non-blocking file closes.

* Updated code to avoid calling asyncio.async(), deprecated in
  Python 3.4.4.

* Updated unit tests to avoid errors on systems with an older version
  of OpenSSL installed.

Release 1.4.0 (17 Jan 2016)
---------------------------

* Added ssh-agent client support, automatically using it when SSH_AUTH_SOCK
  is set and client private keys aren't explicitly provided.

* Added new wait_closed() API on SSHConnection to allow applications to wait
  for a connection to be fully closed and updated examples to use it.

* Added a new login_timeout argument when create an SSH server.

* Added a missing acknowledgement response when canceling port forwarding
  and fixed a few other issues related to cleaning up port forwarding
  listeners.

* Added handlers to improve the catching and reporting of exceptions that
  are raised in asynchronous tasks.

* Reworked channel state machine to perform clean up on a channel only
  after a close is both sent and received.

* Fixed SSHChannel to run the connection_lost() handler on the SSHSession
  before unblocking callers of wait_closed().

* Fixed wait_closed() on SSHListener to wait for the acknowledgement from
  the SSH server before returning.

* Fixed a race condition in port forwarding code.

* Fixed a bug related to sending a close on a channel which got a failure
  when being opened.

* Fixed a bug related to handling term_type being set without term_size.

* Fixed some issues related to the automatic conversion of client
  keyboard-interactive auth to password auth. With this change, automatic
  conversion will only occur if the application doesn't override the
  kbdint_challenge_received() method and it will only attempt to
  authenticate once with the password provided.

Release 1.3.2 (26 Nov 2015)
---------------------------

* Added server-side support for handling password changes during password
  authentication, and fixed a few other auth-related bugs.

* Added the ability to override the automatic support for keyboard-interactive
  authentication when password authentication is supported.

* Fixed a race condition in unblocking streams.

* Removed support for OpenSSH v00 certificates now that OpenSSH no longer
  supports them.

* Added unit tests for auth module.

Release 1.3.1 (6 Nov 2015)
--------------------------

* Updated AsyncSSH to depend on version 1.1 or later of PyCA and added
  support for using its new Elliptic Curve Diffie Hellman (ECDH)
  implementation, replacing the the previous AsyncSSH native Python
  version.

* Added support for specifying a passphrase in the create_connection,
  create_server, connect, and listen functions to allow file names
  or byte strings containing encrypted client and server host keys
  to be specified in those calls.

* Fixed handling of cancellation in a few AsyncSSH calls, so it is
  now possible to make calls to things like stream read or drain which
  time out.

* Fixed a bug in keyboard-interactive fallback to password auth which
  was introduced when support was added for auth functions optionally
  being coroutines.

* Move bcrypt check in encrypted key handling until it is needed so
  better errors can be returned if a passphrase is not specified or the
  key derivation function used in a key is unknown.

* Added unit tests for the auth_keys module.

* Updated unit tests to better handle bcrypt or libnacl not being
  installed.

Release 1.3.0 (10 Oct 2015)
---------------------------

* Updated AsyncSSH dependencies to make PyCA version 1.0.0 or later
  mandatory and remove the older PyCrypto support. This change also
  adds support for the PyCA implementation of ECDSA and removes support
  for RC2-based private key encryption that was only supported by
  PyCrypto.

* Refactored ECDH and Curve25519 key exchange code so they can share an
  implementation, and prepared the code for adding a PyCA shim for this
  as soon as support for that is released.

* Hardened the DSA and RSA implementations to do stricter checking of the
  key exchange response, and sped up the RSA implementation by taking
  advantage of optional RSA private key parameters when they are present.

* Added support for asynchronous client and server authentication,
  allowing auth-related callbacks in SSHClient and SSHServer to optionally
  be defined as coroutines.

* Added support for asynchronous SFTP server processing, allowing callbacks
  in SFTPServer to optionally be defined as coroutines.

* Added support for a broader set of open mode flags in the SFTP server.
  Note that this change is not completely backward compatible with previous
  releases. If you have application code which expects a Python mode
  string as an argument to SFTPServer open method, it will need to be
  changed to expect a pflags value instead.

* Fixed handling of eof_received() when it returns false to close the
  half-open connection but still allow sending or receiving of exit status
  and exit signals.

* Added unit tests for the asn1, cipher, compression, ec, kex, known_hosts,
  mac, and saslprep modules and expended the set of pbe and public_key
  unit tests.

* Fixed a set of issues uncovered by ASN.1 unit tests:

    * Removed extra 0xff byte when encoding integers of the form -128*256^n
    * Fixed decoding error for OIDs beginning with 2.n where n >= 40
    * Fixed range check for second component of ObjectIdentifier
    * Added check for extraneous 0x80 bytes in ObjectIdentifier components
    * Added check for negative component values in ObjectIdentifier
    * Added error handling for ObjectIdentifier components being non-integer
    * Added handling for missing length byte after extended tag
    * Raised ASN1EncodeError instead of TypeError on unsupported types

* Added validation on asn1_class argument, and equality and hash methods
  to BitString, RawDERObject, and TaggedDERObject. Also, reordered
  RawDERObject arguments to be consistent with TaggedDERObject and added
  str method to ObjectIdentifier.

* Fixed a set of issues uncovered by additional pbe unit tests:

    * Encoding and decoding of PBES2-encrypted keys with a PRF other than
      SHA1 is now handled correctly.
    * Some exception messages were made more specific.
    * Additional checks were put in for empty salt or zero iteration count
      in encryption parameters.

* Fixed a set of issues uncovered by additional public key unit tests:

    * Properly handle PKCS#8 keys with invalid ASN.1 data
    * Properly handle PKCS#8 DSA & RSA keys with non-sequence for arg_params
    * Properly handle attempts to import empty string as a public key
    * Properly handle encrypted PEM keys with missing DEK-Info header
    * Report check byte mismatches for encrypted OpenSSH keys as bad passphrase
    * Return KeyImportError instead of KeyEncryptionError when passphrase
      is needed but not provided

* Added information about branches to CONTRIBUTING guide.

* Performed a bunch of code cleanup suggested by pylint.

Release 1.2.1 (26 Aug 2015)
---------------------------

* Fixed a problem with passing in client_keys=None to disable public
  key authentication in the SSH client.

* Updated Unicode handling to allow multi-byte Unicode characters to be
  split across successive SSH data messages.

* Added a note to the documentation for AsyncSSH create_connection()
  explaining how to perform the equivalent of a connect with a timeout.

Release 1.2.0 (6 Jun 2015)
--------------------------

* Fixed a problem with the SSHConnection context manager on Python versions
  older than 3.4.2.

* Updated the documentation for get_extra_info() in the SSHConnection,
  SSHChannel, SSHReader, and SSHWriter classes to contain pointers
  to get_extra_info() in their parent transports to make it easier to
  see all of the attributes which can be queried.

* Clarified the legal return values for the session_requested(),
  connection_requested(), and server_requested() methods in
  SSHServer.

* Eliminated calls to the deprecated importlib.find_loader() method.

* Made improvements to README suggested by Nicholas Chammas.

* Fixed a number of issues identified by pylint.

Release 1.1.1 (25 May 2015)
---------------------------

* Added new start_sftp_server method on SSHChannel to allow applications
  using the non-streams API to start an SFTP server.

* Enhanced the default format_longname() method in SFTPServer to properly
  handle the case where not all of the file attributes are returned by
  stat().

* Fixed a bug related to the new allow_pty parameter in create_server.

* Fixed a bug in the hashed known_hosts support introduced in some recent
  refactoring of the host pattern matching code.

Release 1.1.0 (22 May 2015)
---------------------------

* SFTP is now supported!

  * Both client and server support is available.
  * SFTP version 3 is supported, with OpenSSH extensions.
  * Recursive transfers and glob matching are supported in the client.
  * File I/O APIs allow files to be accessed without downloading them.

* New simplified connect and listen APIs have been added.

* SSHConnection can now be used as a context manager.

* New arguments to create_server now allow the specification of a
  session_factory and encoding or sftp_factory as well as controls
  over whether a pty is allowed and the window and max packet size,
  avoiding the need to create custom SSHServer subclasses or custom
  SSHServerChannel instances.

* New examples have been added for SFTP and to show the use of the new
  connect and listen APIs.

* Copyrights in changed files have all been updated to 2015.

Release 1.0.1 (13 Apr 2015)
---------------------------

* Fixed a bug in OpenSSH private key encryption introduced in some
  recent cipher refactoring.

* Added bcrypt and libnacl as optional dependencies in setup.py.

* Changed test_keys test to work properly when bcrypt or libnacl aren't
  installed.

Release 1.0.0 (11 Apr 2015)
---------------------------

* This release finishes adding a number of major features, finally making
  it worthy of being called a "1.0" release.

* Host and user certificates are now supported!

  * Enforcement is done on principals in certificates.
  * Enforcement is done on force-command and source-address critical options.
  * Enforcement is done on permit-pty and permit-port-forwarding extensions.

* OpenSSH-style known hosts files are now supported!

  * Positive and negative wildcard and CIDR-style patterns are supported.
  * HMAC-SHA1 hashed host entries are supported.
  * The @cert-authority and @revoked markers are supported.

* OpenSSH-style authorized keys files are now supported!

  * Both client keys and certificate authorities are supported.
  * Enforcement is done on from and principals options during key matching.
  * Enforcement is done on no-pty, no-port-forwarding, and permitopen.
  * The command and environment options are supported.
  * Applications can query for their own non-standard options.

* Support has been added for OpenSSH format private keys.

  * DSA, RSA, and ECDSA keys in this format are now supported.
  * Ed25519 keys are supported when libnacl and libsodium are installed.
  * OpenSSH private key encryption is supported when bcrypt is installed.

* Curve25519 Diffie-Hellman key exchange is now available via either the
  curve25519-donna or libnacl and libsodium packages.

* ECDSA key support has been enhanced.

  * Support is now available for PKCS#8 ECDSA v2 keys.
  * Support is now available for both NamedCurve and explicit ECParameter
    versions of keys, as long as the parameters match one of the supported
    curves (nistp256, nistp384, or nistp521).

* Support is now available for the OpenSSH chacha20-poly1305 cipher when
  libnacl and libsodium are installed.

* Cipher names specified in private key encryption have been changed to be
  consistent with OpenSSH cipher naming, and all SSH ciphers can now be
  used for encryption of keys in OpenSSH private key format.

* A couple of race conditions in SSHChannel have been fixed and channel
  cleanup is now delayed to allow outstanding message handling to finish.

* Channel exceptions are now properly delivered in the streams API.

* A bug in SSHStream read() where it could sometimes return more data than
  requested has been fixed. Also, read() has been changed to properly block
  and return all data until EOF or a signal is received when it is called
  with no length.

* A bug in the default implementation of keyboard-interactive authentication
  has been fixed, and the matching of a password prompt has been loosened
  to allow it to be used for password authentication on more devices.

* Missing code to resume reading after a stream is paused has been added.

* Improvements have been made in the handling of canceled requests.

* The test code has been updated to test Ed25519 and OpenSSH format
  private keys.

* Examples have been updated to reflect some of the new capabilities.

Release 0.9.2 (26 Jan 2015)
---------------------------

* Fixed a bug in PyCrypto CipherFactory introduced during PyCA refactoring.

Release 0.9.1 (3 Dec 2014)
--------------------------

* Added some missing items in setup.py and MANIFEST.in.

* Fixed the install to work even when cryptographic dependencies aren't
  yet installed.

* Fixed an issue where get_extra_info calls could fail if called when
  a connection or session was shutting down.

Release 0.9.0 (14 Nov 2014)
---------------------------

* Added support to use PyCA (0.6.1 or later) for cryptography. AsyncSSH
  will automatically detect and use either PyCA, PyCrypto, or both depending
  on which is installed and which algorithms are requested.

* Added support for AES-GCM ciphers when PyCA is installed.

Release 0.8.4 (12 Sep 2014)
---------------------------

* Fixed an error in the encode/decode functions for PKCS#1 DSA public keys.

* Fixed a bug in the unit test code for import/export of RFC4716 public keys.

Release 0.8.3 (16 Aug 2014)
---------------------------

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
