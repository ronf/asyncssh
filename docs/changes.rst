.. currentmodule:: asyncssh

Change Log
==========

Release 0.3.0 (26 Sep 2013)
---------------------------

* Added support in :class:`SSHClient` and :class:`SSHServer` for setting
  the key exchange, encryption, MAC, and compression algorithms allowed
  in the SSH handshake

* Refactored the algorithm selection code to pull a common matching
  function back into ``_SSHConnection`` and simplify other modules

* Extended the listener class to open multiple listening sockets when
  necessary, fixing a bug where sockets opened to listen on ``localhost``
  were not properly accepting both IPv4 and IPv6 connections

  Now, any listen request which resolves to multiple addresses will open
  listening sockets for each address.

* Fixed a bug related to tracking of listeners opened on dynamic ports

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
  standard SSH server-side port forwarding

* Added a client_addr argument and member variable to :class:`SSHServer`
  to hold the client's address information

* Added and updates examples related to port forwarding and using
  :class:`SSHTCPConnection` to open direct and forwarded TCP
  connections in :ref:`ClientExamples` and :ref:`ServerExamples`

* Cleaned up some of the other documentation

* Removed a debug print statement accidentally left in related to
  SSH rekeying

Release 0.1.0 (14 Sep 2013)
---------------------------

* Initial release
