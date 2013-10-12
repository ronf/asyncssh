.. module:: asyncssh

API Documentation
*****************

Overview
========

The AsyncSSH API consists of two main classes for applications to derive
from, :class:`SSHClient` and :class:`SSHServer`, and a helper class
:class:`SSHListener` which can be passed a subclass of :class:`SSHServer`
to set up a listening socket and create new SSH server instances as
connections come in.

Each instance of :class:`SSHClient` and :class:`SSHServer` corresponds
to a single SSH connection. Once an SSH connection is established and
authentication is successful, multiple simultaneous channels can be
opened on it.  This is accomplished by deriving from three other classes,
:class:`SSHClientSession`, :class:`SSHServerSession`, and
:class:`SSHTCPConnection`.

A subclass of :class:`SSHClientSession` class can be associated with an
instance of :class:`SSHClient` to request access to a shell, execute a
remote command, or connect to a remote subsystem. A subclass of
:class:`SSHServerSession` class can be associated with an instance of
:class:`SSHServer` to accept incoming requests of this sort. Finally,
a subclass of :class:`SSHTCPConnection` class can be created for clients
to open outbound direct TCP/IP connections or for servers to report
incoming forwarded TCP/IP connections that a client has asked them to
listen for.

Clients can request that the server listen for TCP/IP connections and
forward them over SSH by deriving from :class:`SSHClientListener` and
having it return objects derived from :class:`SSHTCPConnection` to
process each forwarded connection. Servers wishing to accept requests to
forward connections can do so by deriving from :class:`SSHServerListener`
and having it create objects derived from :class:`SSHTCPConnection` for
each forwarded connection.

To set up standard SSH port forwarding, clients can derive from
:class:`SSHClientLocalPortForwarder` or :class:`SSHClientRemotePortForwarder`,
optionally implementing access control via the ``accept_connection`` method
in these classes. Servers can implement standard SSH port forwarding in
a similar manner by deriving from :class:`SSHServerPortForwarder`.

In addition to the above classes, some helper functions for importing
public and private keys can be found below under :ref:`PublicKeyFunctions`,
exceptions can be found under :ref:`Exceptions`, and some useful
constants can be found under :ref:`Constants`.

Main Classes
============

SSHClient
---------

.. autoclass:: SSHClient

   .. rubric:: Methods provided by this class:

   +--------------------------------+
   | General SSH connection methods |
   +================================+
   | .. automethod:: disconnect     |
   | .. automethod:: send_debug     |
   +--------------------------------+

   .. rubric:: Methods which can be provided by a subclass:

   +-----------------------------------+
   | General SSH connection handlers   |
   +===================================+
   | .. automethod:: handle_disconnect |
   | .. automethod:: handle_debug      |
   +-----------------------------------+

   +--------------------------------------+
   | General authentication handlers      |
   +======================================+
   | .. automethod:: handle_auth_banner   |
   | .. automethod:: handle_auth_complete |
   +--------------------------------------+

   +----------------------------------------+
   | Public key authentication handlers     |
   +========================================+
   | .. automethod:: handle_public_key_auth |
   +----------------------------------------+

   +---------------------------------------------------+
   | Password authentication handlers                  |
   +===================================================+
   | .. automethod:: handle_password_auth              |
   | .. automethod:: handle_password_change_request    |
   | .. automethod:: handle_password_change_successful |
   | .. automethod:: handle_password_change_failed     |
   +---------------------------------------------------+

   +----------------------------------------------+
   | Keyboard-interactive authentication handlers |
   +==============================================+
   | .. automethod:: handle_kbdint_auth           |
   | .. automethod:: handle_kbdint_challenge      |
   +----------------------------------------------+

SSHServer
---------

.. autoclass:: SSHServer

   .. rubric:: Methods provided by this class:

   +--------------------------------+
   | General SSH connection methods |
   +================================+
   | .. automethod:: disconnect     |
   | .. automethod:: send_debug     |
   +--------------------------------+

   +----------------------------------+
   | General authentication methods   |
   +==================================+
   | .. automethod:: get_username     |
   | .. automethod:: send_auth_banner |
   +----------------------------------+

   .. rubric:: Methods which can be provided by a subclass:

   +-----------------------------------+
   | General SSH connection handlers   |
   +===================================+
   | .. automethod:: handle_disconnect |
   | .. automethod:: handle_debug      |
   +-----------------------------------+

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

   +------------------------------------------+
   | Channel open handlers                    |
   +==========================================+
   | .. automethod:: handle_session           |
   | .. automethod:: handle_direct_connection |
   +------------------------------------------+

   +--------------------------------------+
   | Connection forwarding handlers       |
   +======================================+
   | .. automethod:: handle_listen        |
   +--------------------------------------+

SSHListener
-----------

.. autoclass:: SSHListener

Channel Classes
===============

SSHClientSession
----------------

.. autoclass:: SSHClientSession

   .. rubric:: Methods provided by this class:

   +----------------------------------+
   | SSH client session setup methods |
   +==================================+
   | .. automethod:: set_environment  |
   | .. automethod:: set_terminal     |
   | .. automethod:: set_window_size  |
   +----------------------------------+

   +---------------------------------+
   | SSH client session open methods |
   +=================================+
   | .. automethod:: open_shell      |
   | .. automethod:: exec            |
   | .. automethod:: open_subsystem  |
   +---------------------------------+

   +-----------------------------+
   | SSH client send methods     |
   +=============================+
   | .. automethod:: send        |
   | .. automethod:: send_eof    |
   | .. automethod:: send_signal |
   | .. automethod:: send_break  |
   +-----------------------------+

   +------------------------------+
   | SSH client receive methods   |
   +==============================+
   | .. automethod:: block_recv   |
   | .. automethod:: unblock_recv |
   +------------------------------+

   +----------------------------------+
   | SSH client session close methods |
   +==================================+
   | .. automethod:: close            |
   +----------------------------------+

   .. rubric:: Methods which can be provided by a subclass:

   +-----------------------------------+
   | SSH client session open handlers  |
   +===================================+
   | .. automethod:: handle_open       |
   | .. automethod:: handle_open_error |
   +-----------------------------------+

   +----------------------------------+
   | SSH client flow control handlers |
   +==================================+
   | .. automethod:: handle_xon_xoff  |
   +----------------------------------+

   +---------------------------------------+
   | SSH client send handlers              |
   +=======================================+
   | .. automethod:: handle_send_blocked   |
   | .. automethod:: handle_send_unblocked |
   +---------------------------------------+

   +---------------------------------+
   | SSH client receive handlers     |
   +=================================+
   | .. automethod:: handle_data     |
   | .. automethod:: handle_eof      |
   +---------------------------------+

   +------------------------------------+
   | SSH client session close handlers  |
   +====================================+
   | .. automethod:: handle_exit        |
   | .. automethod:: handle_exit_signal |
   | .. automethod:: handle_close       |
   +------------------------------------+

SSHServerSession
----------------

.. autoclass:: SSHServerSession

   .. rubric:: Methods provided by this class:

   +-----------------------------------+
   | SSH server session query methods  |
   +===================================+
   | .. automethod:: get_environment   |
   | .. automethod:: get_terminal_type |
   | .. automethod:: get_terminal_mode |
   | .. automethod:: get_window_size   |
   +-----------------------------------+

   +-----------------------------------------+
   | SSH server session flow control methods |
   +=========================================+
   | .. automethod:: set_xon_xoff            |
   +-----------------------------------------+

   +---------------------------------+
   | SSH server session send methods |
   +=================================+
   | .. automethod:: send            |
   | .. automethod:: send_stderr     |
   | .. automethod:: send_eof        |
   +---------------------------------+

   +------------------------------------+
   | SSH server session receive methods |
   +====================================+
   | .. automethod:: block_recv         |
   | .. automethod:: unblock_recv       |
   +------------------------------------+

   +----------------------------------+
   | SSH server session close methods |
   +==================================+
   | .. automethod:: exit             |
   | .. automethod:: exit_with_signal |
   | .. automethod:: close            |
   +----------------------------------+

   .. rubric:: Methods which can be provided by a subclass:

   +--------------------------------------+
   | SSH server session setup handlers    |
   +======================================+
   | .. automethod:: handle_pty_request   |
   | .. automethod:: handle_window_change |
   +--------------------------------------+

   +------------------------------------------+
   | SSH server session open handlers         |
   +==========================================+
   | .. automethod:: handle_shell_request     |
   | .. automethod:: handle_exec_request      |
   | .. automethod:: handle_subsystem_request |
   | .. automethod:: handle_open              |
   +------------------------------------------+

   +---------------------------------------+
   | SSH server session send handlers      |
   +=======================================+
   | .. automethod:: handle_send_blocked   |
   | .. automethod:: handle_send_unblocked |
   +---------------------------------------+

   +---------------------------------------+
   | SSH server session receive handlers   |
   +=======================================+
   | .. automethod:: handle_data           |
   | .. automethod:: handle_eof            |
   | .. automethod:: handle_signal         |
   | .. automethod:: handle_break          |
   +---------------------------------------+

   +-----------------------------------+
   | SSH server session close handlers |
   +===================================+
   | .. automethod:: handle_close      |
   +-----------------------------------+

SSHTCPConnection
----------------

.. autoclass:: SSHTCPConnection

   .. rubric:: Methods provided by this class:

   +-----------------------------------+
   | SSH TCP connection open methods   |
   +===================================+
   | .. automethod:: connect           |
   | .. automethod:: accept            |
   | .. automethod:: report_open       |
   | .. automethod:: report_open_error |
   +-----------------------------------+

   +---------------------------------+
   | SSH TCP connection send methods |
   +=================================+
   | .. automethod:: send            |
   | .. automethod:: send_eof        |
   +---------------------------------+

   +------------------------------------+
   | SSH TCP connection receive methods |
   +====================================+
   | .. automethod:: block_recv         |
   | .. automethod:: unblock_recv       |
   +------------------------------------+

   +----------------------------------+
   | SSH TCP connection close methods |
   +==================================+
   | .. automethod:: close            |
   +----------------------------------+

   .. rubric:: Methods which can be provided by a subclass:

   +-------------------------------------+
   | SSH TCP connection open handlers    |
   +=====================================+
   | .. automethod:: handle_open_request |
   | .. automethod:: handle_open         |
   | .. automethod:: handle_open_error   |
   +-------------------------------------+

   +-------------------------------------+
   | SSH TCP connection receive handlers |
   +=====================================+
   | .. automethod:: handle_data         |
   | .. automethod:: handle_eof          |
   +-------------------------------------+

   +-----------------------------------+
   | SSH TCP connection close handlers |
   +===================================+
   | .. automethod:: handle_close      |
   +-----------------------------------+

.. index:: Public key support
.. _PublicKeyFunctions:

Connection Listener Classes
===========================

SSHClientListener
-----------------

.. autoclass:: SSHClientListener

   .. rubric:: Methods provided by this class:

   +-----------------------------+
   | SSH client listener methods |
   +=============================+
   | .. automethod:: close       |
   +-----------------------------+

   .. rubric:: Methods which can be provided by a subclass:

   +-----------------------------------+
   | SSH client listener handlers      |
   +===================================+
   | .. automethod:: handle_open       |
   | .. automethod:: handle_open_error |
   | .. automethod:: handle_connection |
   +-----------------------------------+

SSHServerListener
-----------------

.. autoclass:: SSHServerListener

   .. rubric:: Methods provided by this class:

   +-----------------------------------+
   | SSH server listener methods       |
   +===================================+
   | .. automethod:: report_open       |
   | .. automethod:: report_open_error |
   +-----------------------------------+

   .. rubric:: Methods which can be provided by a subclass:

   +-------------------------------------+
   | SSH server listener handlers        |
   +=====================================+
   | .. automethod:: handle_open_request |
   | .. automethod:: handle_close        |
   +-------------------------------------+

Port Forwarder Classes
======================

SSHClientLocalPortForwarder
---------------------------

.. autoclass:: SSHClientLocalPortForwarder

   .. rubric:: Methods provided by this class:

   +-----------------------------------------+
   | SSH client local port forwarder methods |
   +=========================================+
   | .. automethod:: close                   |
   +-----------------------------------------+

   .. rubric:: Methods which can be provided by a subclass:

   +------------------------------------------+
   | SSH client local port forwarder handlers |
   +==========================================+
   | .. automethod:: handle_open              |
   | .. automethod:: handle_open_error        |
   | .. automethod:: accept_connection        |
   +------------------------------------------+

SSHClientRemotePortForwarder
----------------------------

.. autoclass:: SSHClientRemotePortForwarder

   .. rubric:: Methods provided by this class:

   +------------------------------------------+
   | SSH client remote port forwarder methods |
   +==========================================+
   | .. automethod:: close                    |
   +------------------------------------------+

   .. rubric:: Methods which can be provided by a subclass:

   +-------------------------------------------+
   | SSH client remote port forwarder handlers |
   +===========================================+
   | .. automethod:: handle_open               |
   | .. automethod:: handle_open_error         |
   | .. automethod:: accept_connection         |
   +-------------------------------------------+

SSHServerPortForwarder
----------------------

.. autoclass:: SSHServerPortForwarder

   .. rubric:: Methods which can be provided by a subclass:

   +------------------------------------+
   | SSH server port forwarder handlers |
   +====================================+
   | .. automethod:: accept_connection  |
   +------------------------------------+

Public Key Support
==================

SSHKey
------

.. autoclass::    SSHKey

   .. automethod:: export_private_key
   .. automethod:: export_public_key
   .. automethod:: write_private_key
   .. automethod:: write_public_key

import_private_key
------------------

.. autofunction:: import_private_key

import_public_key
-----------------

.. autofunction:: import_public_key

read_private_key
----------------

.. autofunction:: read_private_key

read_public_key
---------------

.. autofunction:: read_public_key

read_private_key_list
---------------------

.. autofunction:: read_private_key_list

read_public_key_list
--------------------

.. autofunction:: read_public_key_list

.. index:: Exceptions
.. _Exceptions:

Exceptions
==========

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

.. index:: Constants
.. _Constants:

Supported Algorithms
====================

.. index:: Key exchange algorithms
.. _KexAlgs:

Key exchange algorithms
-----------------------

The following are the key exchange algorithms currently supported by AsyncSSH:

  | ecdh-sha2-nistp521
  | ecdh-sha2-nistp384
  | ecdh-sha2-nistp256
  | diffie-hellman-group-exchange-sha256
  | diffie-hellman-group-exchange-sha1
  | diffie-hellman-group14-sha1
  | diffie-hellman-group1-sha1

.. index:: Encryption algorithms
.. _EncryptionAlgs:

Encryption algorithms
---------------------

The following are the encryption algorithms currently supported by AsyncSSH:

  | aes256-ctr
  | aes192-ctr
  | aes128-ctr
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

Constants
=========

.. index:: Disconnect reasons
.. _DisconnectReasons:

Disconnect reasons
------------------

The following values specified in section 11.1 of :rfc:`4253#section-11.1`
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
