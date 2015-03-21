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
<SSHClientConnection.create_session>` or :meth:`create_connection()
<SSHClientConnection.create_connection>` on the :class:`SSHClientConnection`
object. The client can also set up listeners on remote TCP ports by calling
:meth:`create_server() <SSHClientConnection.create_server>`. All of these
methods take ``session_factory`` arguments that return
:class:`SSHClientSession` or :class:`SSHTCPSession` objects used to manage
the channels once they are open. Alternately, channels can be opened using
:meth:`open_session() <SSHClientConnection.open_session>` or
:meth:`open_connection() <SSHClientConnection.open_connection>`, which
return :class:`SSHReader` and :class:`SSHWriter` objects which can be used
to perform I/O on the channel. The method :meth:`start_server()
<SSHClientConnection.start_server>` can be used to set up listeners on
remote TCP ports and get back these :class:`SSHReader` and :class:`SSHWriter`
objects in a callback when new connections are opened.

The client can also set up TCP port forwarding by calling
:meth:`forward_local_port() <SSHClientConnection.forward_local_port>` or
:meth:`forward_remote_port() <SSHClientConnection.forward_remote_port>`. In
these cases, data transfer on the channels is managed automatically by
AsyncSSH whenever new connections are opened, so custom session objects are
not required.

When an SSH server receives a new connection and authentication is successful,
handlers such as :meth:`session_requested() <SSHServer.session_requested>`,
:meth:`connection_requested() <SSHServer.connection_requested>`, and
:meth:`server_requested() <SSHServer.server_requested>` on the associated
:class:`SSHServer` object will be called when clients attempt to open
channels or set up listeners. These methods return coroutines which can
set up the requested sessions or connections, returning
:class:`SSHServerSession` or :class:`SSHTCPSession` objects or handler
functions that accept :class:`SSHReader` and :class:`SSHWriter` objects
as arguments which manage the channels once they are open.

Each session object also has an associated :class:`SSHClientChannel`,
:class:`SSHServerChannel`, or :class:`SSHTCPChannel` object passed to it
which can be used to perform actions on the channel. These channel objects
provide a superset of the functionality found in ``asyncio`` transport
objects.

In addition to the above functions and classes, helper functions for importing
public and private keys can be found below under :ref:`PublicKeyFunctions`,
exceptions can be found under :ref:`Exceptions`, supported algorithms can
be found under :ref:`SupportedAlgorithms`, and some useful constants can be
found under :ref:`Constants`.

Main Functions
==============

create_connection
-----------------

.. autofunction:: create_connection

create_server
-------------

.. autofunction:: create_server

Main Classes
============

SSHClient
---------

.. autoclass:: SSHClient

   +------------------------------------+
   | General connection handlers        |
   +====================================+
   | .. automethod:: connection_made    |
   | .. automethod:: connection_lost    |
   | .. automethod:: debug_msg_received |
   +------------------------------------+

   +--------------------------------------+
   | General authentication handlers      |
   +======================================+
   | .. automethod:: auth_banner_received |
   | .. automethod:: auth_completed       |
   +--------------------------------------+

   +-------------------------------------------+
   | Public key authentication handlers        |
   +===========================================+
   | .. automethod:: public_key_auth_requested |
   +-------------------------------------------+

   +-------------------------------------------+
   | Password authentication handlers          |
   +===========================================+
   | .. automethod:: password_auth_requested   |
   | .. automethod:: password_change_requested |
   | .. automethod:: password_changed          |
   | .. automethod:: password_change_failed    |
   +-------------------------------------------+

   +----------------------------------------------+
   | Keyboard-interactive authentication handlers |
   +==============================================+
   | .. automethod:: kbdint_auth_requested        |
   | .. automethod:: kbdint_challenge_received    |
   +----------------------------------------------+

SSHServer
---------

.. autoclass:: SSHServer

   +------------------------------------+
   | General connection handlers        |
   +====================================+
   | .. automethod:: connection_made    |
   | .. automethod:: connection_lost    |
   | .. automethod:: debug_msg_received |
   +------------------------------------+

   +---------------------------------+
   | General authentication handlers |
   +=================================+
   | .. automethod:: begin_auth      |
   +---------------------------------+

   +-------------------------------------------+
   | Public key authentication handlers        |
   +===========================================+
   | .. automethod:: public_key_auth_supported |
   | .. automethod:: validate_public_key       |
   | .. automethod:: validate_ca_key           |
   +-------------------------------------------+

   +-----------------------------------------+
   | Password authentication handlers        |
   +=========================================+
   | .. automethod:: password_auth_supported |
   | .. automethod:: validate_password       |
   +-----------------------------------------+

   +----------------------------------------------+
   | Keyboard-interactive authentication handlers |
   +==============================================+
   | .. automethod:: kbdint_auth_supported        |
   | .. automethod:: get_kbdint_challenge         |
   | .. automethod:: validate_kbdint_response     |
   +----------------------------------------------+

   +--------------------------------------+
   | Channel session open handlers        |
   +======================================+
   | .. automethod:: session_requested    |
   | .. automethod:: connection_requested |
   | .. automethod:: server_requested     |
   +--------------------------------------+

Connection Classes
==================

SSHClientConnection
-------------------

.. autoclass:: SSHClientConnection()

   +--------------------------------+
   | General connection methods     |
   +================================+
   | .. automethod:: get_extra_info |
   | .. automethod:: send_debug     |
   +--------------------------------+

   +-----------------------------------+
   | Client session open methods       |
   +===================================+
   | .. automethod:: create_session    |
   | .. automethod:: open_session      |
   | .. automethod:: create_connection |
   | .. automethod:: open_connection   |
   | .. automethod:: create_server     |
   | .. automethod:: start_server      |
   +-----------------------------------+

   +-------------------------------------+
   | Client forwarding methods           |
   +=====================================+
   | .. automethod:: forward_connection  |
   | .. automethod:: forward_local_port  |
   | .. automethod:: forward_remote_port |
   +-------------------------------------+

   +----------------------------+
   | Connection close methods   |
   +============================+
   | .. automethod:: abort      |
   | .. automethod:: close      |
   | .. automethod:: disconnect |
   +----------------------------+

SSHServerConnection
-------------------

.. autoclass:: SSHServerConnection()

   +--------------------------------+
   | General connection methods     |
   +================================+
   | .. automethod:: get_extra_info |
   | .. automethod:: send_debug     |
   +--------------------------------+

   +----------------------------------------------+
   | Server authentication methods                |
   +==============================================+
   | .. automethod:: send_auth_banner             |
   | .. automethod:: get_certificate_option       |
   | .. automethod:: check_certificate_permission |
   +----------------------------------------------+

   +------------------------------------+
   | Server connection open methods     |
   +====================================+
   | .. automethod:: create_connection  |
   | .. automethod:: open_connection    |
   +------------------------------------+

   +------------------------------------+
   | Server forwarding methods          |
   +====================================+
   | .. automethod:: forward_connection |
   +------------------------------------+

   +---------------------------------------+
   | Server channel creation methods       |
   +=======================================+
   | .. automethod:: create_server_channel |
   | .. automethod:: create_tcp_channel    |
   +---------------------------------------+

   +----------------------------+
   | Connection close methods   |
   +============================+
   | .. automethod:: abort      |
   | .. automethod:: close      |
   | .. automethod:: disconnect |
   +----------------------------+

Session Classes
===============

SSHClientSession
----------------

.. autoclass:: SSHClientSession

   +---------------------------------+
   | General session handlers        |
   +=================================+
   | .. automethod:: connection_made |
   | .. automethod:: connection_lost |
   | .. automethod:: session_started |
   +---------------------------------+

   +-------------------------------+
   | General session read handlers |
   +===============================+
   | .. automethod:: data_received |
   | .. automethod:: eof_received  |
   +-------------------------------+

   +--------------------------------+
   | General session write handlers |
   +================================+
   | .. automethod:: pause_writing  |
   | .. automethod:: resume_writing |
   +--------------------------------+

   +--------------------------------------+
   | Other client session handlers        |
   +======================================+
   | .. automethod:: xon_xoff_requested   |
   | .. automethod:: exit_status_received |
   | .. automethod:: exit_signal_received |
   +--------------------------------------+

SSHServerSession
----------------

.. autoclass:: SSHServerSession

   +---------------------------------+
   | General session handlers        |
   +=================================+
   | .. automethod:: connection_made |
   | .. automethod:: connection_lost |
   | .. automethod:: session_started |
   +---------------------------------+

   +-------------------------------------+
   | Server session open handlers        |
   +=====================================+
   | .. automethod:: pty_requested       |
   | .. automethod:: shell_requested     |
   | .. automethod:: exec_requested      |
   | .. automethod:: subsystem_requested |
   +-------------------------------------+

   +-------------------------------+
   | General session read handlers |
   +===============================+
   | .. automethod:: data_received |
   | .. automethod:: eof_received  |
   +-------------------------------+

   +--------------------------------+
   | General session write handlers |
   +================================+
   | .. automethod:: pause_writing  |
   | .. automethod:: resume_writing |
   +--------------------------------+

   +---------------------------------------+
   | Other server session handlers         |
   +=======================================+
   | .. automethod:: break_received        |
   | .. automethod:: signal_received       |
   | .. automethod:: terminal_size_changed |
   +---------------------------------------+

SSHTCPSession
-------------

.. autoclass:: SSHTCPSession

   +---------------------------------+
   | General session handlers        |
   +=================================+
   | .. automethod:: connection_made |
   | .. automethod:: connection_lost |
   | .. automethod:: session_started |
   +---------------------------------+

   +-------------------------------+
   | General session read handlers |
   +===============================+
   | .. automethod:: data_received |
   | .. automethod:: eof_received  |
   +-------------------------------+

   +--------------------------------+
   | General session write handlers |
   +================================+
   | .. automethod:: pause_writing  |
   | .. automethod:: resume_writing |
   +--------------------------------+

Channel Classes
===============

SSHClientChannel
----------------

.. autoclass:: SSHClientChannel()

   +--------------------------------+
   | General channel methods        |
   +================================+
   | .. automethod:: get_extra_info |
   +--------------------------------+

   +--------------------------------+
   | Client channel read methods    |
   +================================+
   | .. automethod:: pause_reading  |
   | .. automethod:: resume_reading |
   +--------------------------------+

   +-----------------------------------------+
   | Client channel write methods            |
   +=========================================+
   | .. automethod:: can_write_eof           |
   | .. automethod:: get_write_buffer_size   |
   | .. automethod:: set_write_buffer_limits |
   | .. automethod:: write                   |
   | .. automethod:: writelines              |
   | .. automethod:: write_eof               |
   +-----------------------------------------+

   +---------------------------------------+
   | Other client channel methods          |
   +=======================================+
   | .. automethod:: get_exit_status       |
   | .. automethod:: get_exit_signal       |
   | .. automethod:: change_terminal_size  |
   | .. automethod:: send_break            |
   | .. automethod:: send_signal           |
   | .. automethod:: kill                  |
   | .. automethod:: terminate             |
   +---------------------------------------+

   +-------------------------------+
   | General channel close methods |
   +===============================+
   | .. automethod:: abort         |
   | .. automethod:: close         |
   | .. automethod:: wait_closed   |
   +-------------------------------+

SSHServerChannel
----------------

.. autoclass:: SSHServerChannel()

   +--------------------------------+
   | General channel methods        |
   +================================+
   | .. automethod:: get_extra_info |
   +--------------------------------+

   +-----------------------------------+
   | Server channel info methods       |
   +===================================+
   | .. automethod:: get_environment   |
   | .. automethod:: get_command       |
   | .. automethod:: get_subsystem     |
   | .. automethod:: get_terminal_type |
   | .. automethod:: get_terminal_size |
   | .. automethod:: get_terminal_mode |
   +-----------------------------------+

   +--------------------------------+
   | Server channel read methods    |
   +================================+
   | .. automethod:: pause_reading  |
   | .. automethod:: resume_reading |
   +--------------------------------+

   +-----------------------------------------+
   | Server channel write methods            |
   +=========================================+
   | .. automethod:: can_write_eof           |
   | .. automethod:: get_write_buffer_size   |
   | .. automethod:: set_write_buffer_limits |
   | .. automethod:: write                   |
   | .. automethod:: writelines              |
   | .. automethod:: write_stderr            |
   | .. automethod:: writelines_stderr       |
   | .. automethod:: write_eof               |
   +-----------------------------------------+

   +-----------------------------------+
   | Other server channel methods      |
   +===================================+
   | .. automethod:: set_xon_xoff      |
   | .. automethod:: exit              |
   | .. automethod:: exit_with_signal  |
   +-----------------------------------+

   +-------------------------------+
   | General channel close methods |
   +===============================+
   | .. automethod:: abort         |
   | .. automethod:: close         |
   | .. automethod:: wait_closed   |
   +-------------------------------+

SSHTCPChannel
-------------

.. autoclass:: SSHTCPChannel()

   +--------------------------------+
   | General channel methods        |
   +================================+
   | .. automethod:: get_extra_info |
   +--------------------------------+

   +--------------------------------+
   | General channel read methods   |
   +================================+
   | .. automethod:: pause_reading  |
   | .. automethod:: resume_reading |
   +--------------------------------+

   +-----------------------------------------+
   | General channel write methods           |
   +=========================================+
   | .. automethod:: can_write_eof           |
   | .. automethod:: get_write_buffer_size   |
   | .. automethod:: set_write_buffer_limits |
   | .. automethod:: write                   |
   | .. automethod:: writelines              |
   | .. automethod:: write_eof               |
   +-----------------------------------------+

   +-------------------------------+
   | General channel close methods |
   +===============================+
   | .. automethod:: abort         |
   | .. automethod:: close         |
   | .. automethod:: wait_closed   |
   +-------------------------------+

Listener Classes
================

SSHListener
-----------

.. autoclass:: SSHListener

   .. automethod:: get_port
   .. automethod:: close
   .. automethod:: wait_closed

Stream Classes
==============

SSHReader
---------

.. autoclass:: SSHReader

   .. autoattribute:: channel

   .. automethod:: get_extra_info
   .. automethod:: at_eof
   .. automethod:: read
   .. automethod:: readline
   .. automethod:: readexactly

SSHWriter
---------

.. autoclass:: SSHWriter

   .. autoattribute:: channel

   .. automethod:: get_extra_info
   .. automethod:: can_write_eof
   .. automethod:: close
   .. automethod:: drain
   .. automethod:: write
   .. automethod:: writelines
   .. automethod:: write_eof

.. index:: Public key support
.. _PublicKeyFunctions:

Public Key Support
==================

.. index:: Specifying private keys
.. _SpecifyingPrivateKeys:

Specifying private keys
-----------------------

Private keys may be passed into AsyncSSH in a variety of forms. The
simplest option is to pass the name of a file containing the list of
private keys to read in using :func:`read_private_key_list`. However,
this form can only be used for unencrypted private keys and does not
allow any of the private keys to have associated certificates.

An alternate form involves passing in a list of values which can be
either a reference to a private key or a tuple containing a reference
to a private key and a reference to a matching certificate.

Key references can either be the name of a file to load a key from,
a byte string to import it from, or an already loaded :class:`SSHKey`
private key. See the function :func:`import_private_key` for the list
of supported private key formats.

Certificate references can be the name of a file to load the
certificate from, a byte string to import it from, an already loaded
:class:`SSHCertificate`, or ``None`` if no certificate should be
associated with the key.

When a filename is provided as a value in the list, an attempt is
made to load a private key from that file and a certificate from a
file constructed by appending '-cert.pub' to the end of the name.

Encrypted private keys can be loaded by making an explicit call to
:func:`import_private_key` or :func:`read_private_key` with the
correct passphrase. The resulting :class:`SSHKey` objects can then
be included in thie list, each with an optional matching certificate.

.. index:: Specifying private keys
.. _SpecifyingPublicKeys:

Specifying public keys
----------------------

Public keys may be passed into AsyncSSH in a variety of forms. The
simplest option is to pass the name of a file containing the list of
public keys to read in using :func:`read_public_key_list`.

An alternate form involves passing in a list of values each of which
can be either the name of a file to load a key from, a byte string
to import it from, or an already loaded :class:`SSHKey` public key.
See the function :func:`import_public_key` for the list of supported
public key formats.

SSHKey
------

.. autoclass:: SSHKey()

   .. automethod:: export_private_key
   .. automethod:: export_public_key
   .. automethod:: write_private_key
   .. automethod:: write_public_key

SSHCertificate
--------------

.. autoclass:: SSHCertificate()

   .. automethod:: validate

import_private_key
------------------

.. autofunction:: import_private_key

import_public_key
-----------------

.. autofunction:: import_public_key

import_certificate
------------------

.. autofunction:: import_certificate

read_private_key
----------------

.. autofunction:: read_private_key

read_public_key
---------------

.. autofunction:: read_public_key

read_certificate
----------------

.. autofunction:: read_certificate

read_private_key_list
---------------------

.. autofunction:: read_private_key_list

read_public_key_list
--------------------

.. autofunction:: read_public_key_list

read_certificate_list
---------------------

.. autofunction:: read_certificate_list

.. index:: Exceptions
.. _Exceptions:

Exceptions
==========

BreakReceived
-------------

.. autoexception:: BreakReceived

SignalReceived
--------------

.. autoexception:: SignalReceived

TerminalSizeChanged
-------------------

.. autoexception:: TerminalSizeChanged

DisconnectError
---------------

.. autoexception:: DisconnectError

ChannelOpenError
----------------

.. autoexception:: ChannelOpenError

KeyImportError
--------------

.. autoexception:: KeyImportError

KeyExportError
--------------

.. autoexception:: KeyExportError

KeyEncryptionError
------------------

.. autoexception:: KeyEncryptionError

.. index:: Supported algorithms
.. _SupportedAlgorithms:

Supported Algorithms
====================

.. index:: Key exchange algorithms
.. _KexAlgs:

Key exchange algorithms
-----------------------

The following are the key exchange algorithms currently supported by AsyncSSH:

  | curve25519-sha256\@libssh.org
  | ecdh-sha2-nistp521
  | ecdh-sha2-nistp384
  | ecdh-sha2-nistp256
  | diffie-hellman-group-exchange-sha256
  | diffie-hellman-group-exchange-sha1
  | diffie-hellman-group14-sha1
  | diffie-hellman-group1-sha1

.. index:: Public key & certificate algorithms
.. _PublicKeyAlgs:

Public key & certificate algorithms
-----------------------------------

The following are the public key and certificate algorithms currently
supported by AsyncSSH:

  | ssh-ed25519-cert-v01\@openssh.com
  | ecdsa-sha2-nistp521-cert-v01\@openssh.com
  | ecdsa-sha2-nistp384-cert-v01\@openssh.com
  | ecdsa-sha2-nistp256-cert-v01\@openssh.com
  | ssh-rsa-cert-v01\@openssh.com
  | ssh-rsa-cert-v00\@openssh.com
  | ssh-dss-cert-v01\@openssh.com
  | ssh-dss-cert-v00\@openssh.com
  | ssh-ed25519
  | ecdsa-sha2-nistp521
  | ecdsa-sha2-nistp384
  | ecdsa-sha2-nistp256
  | ssh-rsa
  | ssh-dss

.. index:: Encryption algorithms
.. _EncryptionAlgs:

Encryption algorithms
---------------------

The following are the encryption algorithms currently supported by AsyncSSH:

  | chacha20-poly1305\@openssh.com
  | aes256-ctr
  | aes192-ctr
  | aes128-ctr
  | aes256-gcm\@openssh.com
  | aes128-gcm\@openssh.com
  | aes256-cbc
  | aes192-cbc
  | aes128-cbc
  | 3des-cbc
  | blowfish-cbc
  | cast128-cbc
  | arcfour256
  | arcfour128
  | arcfour

.. index:: MAC algorithms
.. _MACAlgs:

MAC algorithms
--------------

The following are the MAC algorithms currently supported by AsyncSSH:

  | hmac-sha2-256-etm\@openssh.com
  | hmac-sha2-512-etm\@openssh.com
  | hmac-sha1-etm\@openssh.com
  | hmac-md5-etm\@openssh.com
  | hmac-sha2-256-96-etm\@openssh.com
  | hmac-sha2-512-96-etm\@openssh.com
  | hmac-sha1-96-etm\@openssh.com
  | hmac-md5-96-etm\@openssh.com
  | hmac-sha2-256
  | hmac-sha2-512
  | hmac-sha1
  | hmac-md5
  | hmac-sha2-256-96
  | hmac-sha2-512-96
  | hmac-sha1-96
  | hmac-md5-96

.. index:: Compression algorithms
.. _CompressionAlgs:

Compression algorithms
----------------------

The following are the compression algorithms currently supported by AsyncSSH:

  | zlib\@openssh.com
  | zlib
  | none

.. index:: Constants
.. _Constants:

Constants
=========

.. index:: Certificate types
.. _CertificateTypes:

Certificate types
-----------------

The following values can be specified as certificate types:

  | CERT_TYPE_USER
  | CERT_TYPE_HOST

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
  | DISC_HOST_KEY_NOT_VERIFYABLE
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
  | OPEN_REQUEST_PTY_FAILED
  | OPEN_REQUEST_SESSION_FAILED

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
