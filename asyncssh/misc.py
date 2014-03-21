# Copyright (c) 2013-2014 by Ron Frederick <ronf@timeheart.net>.
# All rights reserved.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v1.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-v10.html
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Miscellaneous utility classes and functions"""

import asyncore, socket

from .asyncfunc import *
from .constants import *

def all_ints(seq):
    """Return if a sequence contains all integers"""

    return all(isinstance(i, int) for i in seq)

def mod_inverse(x, m):
    """Compute the modular inverse (x^-1) modulo m"""

    a, b, c, d = m, x % m, 0, 1

    while b:
        q, r = divmod(a, b)
        a, b, c, d = b, r, d, c - q*d

    if a == 1:
        return c if c >= 0 else c + m
    else:
        raise ValueError('%d has no inverse mod %d' % (x, m))


class _ListenSock(asyncore.dispatcher):
    """An asynchronous wrapper around a listening socket"""

    def __init__(self, listener, family, socktype, listen_addr):
        asyncore.dispatcher.__init__(self)

        self._listener = listener

        try:
            self.create_socket(family, socktype)
            self.set_reuse_addr()
            if family == socket.AF_INET6:
                self.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.bind(listen_addr)
            self.listen_addr = self.socket.getsockname()
            self.listen(5)
        except socket.error:
            self.close()
            raise

    def handle_accepted(self, sock, client_addr):
        """Handle a new incoming connection"""

        self._listener.handle_accepted(sock, client_addr)


class Listener:
    """General socket listener parent class

       This class is a helper class which listens for incoming connections
       on the specified host address and port. It is fully asynchronous,
       supports IPv4 and IPv6, and will open multiple listening sockets
       if necessary depending on what the specified host resolves to.

       If the listener is opened successfully, the method :meth:`handle_open`
       will be called. If an error occurs, the method :meth:`handle_open_error`
       is called with exception information.

       When new connections arrive, the method :meth:`handle_accepted` is
       called with the newly open socket, listen address, and client
       address.

       :param string host:
           The host address to listen on
       :param integer port:
           The port to listen on

    """

    def __init__(self, host, port):
        self._listen_socks = []
        self.listen_addrs = []
        self.listen_host = host
        self.listen_port = port

        addrinfo = getaddrinfo(host, port, socket.AF_UNSPEC,
                               socket.SOCK_STREAM, 0, socket.AI_PASSIVE,
                               callback=self._listen)

    def _listen(self, rtype, result):
        """Set up listening sockets"""

        if rtype == 'exception':
            self.handle_open_error(result)
            return

        for family, socktype, proto, canonname, sockaddr in result:
            if sockaddr[1] == 0:
                sockaddr = sockaddr[:1] + (self.listen_port,) + sockaddr[2:]

            try:
                sock = _ListenSock(self, family, socktype, sockaddr)
            except socket.error as exc:
                self.close()
                self.handle_open_error(exc)
                return

            self._listen_socks.append(sock)
            self.listen_addrs.append(sock.listen_addr[0])

            if self.listen_port == 0:
                self.listen_port = sock.listen_addr[1]

        self.handle_open()

    def close(self):
        """Close all listening sockets"""

        for sock in self._listen_socks:
            sock.close()

    def handle_open(self):
        """Handle when the listener is opened successfully

           This method is called when a listener is opened successfully.
           Applications wishing to get details about what addresses
           and port the listener was bound to can check the members
           ``listen_addrs``, ``listen_host``, and ``listen_port`` after
           this method is called.

           By default, nothing is done here.

        """

        pass

    def handle_open_error(self, exc):
        """Handle an error returned when opening the listener

           This method is called when a request to open a listener fails.
           If some listening sockets were successfully opened before this
           error, they are closed before this method is called.

           By default, nothing is done here.

           :param exc:
               The exception raised when opening the listener
           :type exception: :class:`Exception`

        """

        pass

    def handle_accepted(self, sock, client_addr):
        """Handle a new connection to this listener

           This method is called when a new connection arrives on this
           listener. It should be overridden to process new connections
           as they arrive.

           By default, this method immediate closes the new connection.

           :param socket sock:
               The socket for the newly accepted connection
           :param client_addr:
               A tuple containing client address information

        """

        sock.close()


class SSHError(Exception):
    """General SSH error

       This exception is returned when a general SSH error occurs,
       causing the SSH connection to be disconnected. Exception codes
       should be taken from :ref:`disconnect reason codes <DisconnectReasons>`.

       :param integer code:
           Disconnect reason, taken from :ref:`disconnect reason
           codes <DisconnectReasons>`.
       :param string reason:
           A human-readable reason for the disconnect.
       :param string lang:
           The language the reason is in.

    """

    def __init__(self, code, reason, lang=DEFAULT_LANG):
        self.code = code
        self.reason = reason
        self.lang = lang

    def __str__(self):
        return 'SSH Error: %s' % self.reason


class ChannelOpenError(SSHError):
    """SSH channel open error

       This exception is returned by connection handlers to report
       channel open failures.

       :param integer code:
           Channel open failure  reason, taken from :ref:`channel open
           failure reason codes <ChannelOpenFailureReasons>`.
       :param string reason:
           A human-readable reason for the channel open failure.
       :param string lang:
           The language the reason is in.

    """

    def __str__(self):
        return 'Channel Open Error: %s' % self.reason
