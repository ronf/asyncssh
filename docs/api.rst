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

The :class:`SSHClientSession` class can be associated with an instance
of :class:`SSHClient` to request access to a shell, execute a remote
command, or connect to a remote subsystem. The :class:`SSHServerSession`
class can be associated with an instance of :class:`SSHServer` to accept
incoming requests of this sort. Finally, the :class:`SSHTCPConnection`
class can be created for clients to open outbound direct TCP/IP
connections or for servers to report incoming forwarded TCP/IP
connections that a client has asked them to listen for.

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

   +-----------------------------------------------+
   | Connection forwarding methods                 |
   +===============================================+
   | .. automethod:: listen                        |
   | .. automethod:: cancel_listen                 |
   | .. automethod:: forward_local_port            |
   | .. automethod:: cancel_local_port_forwarding  |
   | .. automethod:: forward_remote_port           |
   | .. automethod:: cancel_remote_port_forwarding |
   +-----------------------------------------------+

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

   +-----------------------------------------------------+
   | Connection forwarding handlers                      |
   +=====================================================+
   | .. automethod:: handle_listen                       |
   | .. automethod:: handle_listen_error                 |
   | .. automethod:: handle_forwarded_connection         |
   | .. automethod:: handle_remote_port_forwarding       |
   | .. automethod:: handle_remote_port_forwarding_error |
   +-----------------------------------------------------+

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
   | .. automethod:: handle_cancel_listen |
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

   +---------------------------------+
   | SSH TCP connection open methods |
   +=================================+
   | .. automethod:: connect         |
   | .. automethod:: accept          |
   +---------------------------------+

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

   +-----------------------------------+
   | SSH TCP connection open handlers  |
   +===================================+
   | .. automethod:: handle_open       |
   | .. automethod:: handle_open_error |
   +-----------------------------------+

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

Constants
=========

.. index:: Disconnect reasons
.. _DisconnectReasons:

Disconnect Reasons
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

Channel Open Failure Reasons
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

Extended Data Types
-------------------

The following values defined in section 5.2 of :rfc:`4254#section-5.2` can
be specified as SSH extended channel data types:

  | EXTENDED_DATA_STDERR

.. index:: POSIX terminal modes
.. _PTYModes:

POSIX Terminal Modes
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
