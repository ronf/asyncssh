# Copyright (c) 2013 by Ron Frederick <ronf@timeheart.net>.
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

import asyncore, socket, sys, traceback

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

    def __init__(self, family, socktype, listen_addr,
                 callback=None, *args, **kwargs):
        asyncore.dispatcher.__init__(self)

        self._listen_addr = listen_addr

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

        self._callback = callback
        self._args = args
        self._kwargs = kwargs

    def handle_accepted(self, sock, client_addr):
        """Handle a new incoming connection"""

        self._callback(sock, self._listen_addr, client_addr,
                       *self._args, **self._kwargs)

    def handle_error(self):
        """Handle an unexpected error while accepting a connection"""

        traceback.print_exc()
        sys.exit(1)


class Listener(asyncore.dispatcher):
    """General socket listener

       This is a helper class which listens for incoming connections on
       the specified address and port and calls the specified callback
       for each new connection which it accepts. The listen address can
       be either an address and port tuple or just a port to listen on
       that port on all interfaces.

       The callback function will be passed the newly opened socket and
       a tuple of IPv6 client address information, followed by any
       additional arguments passed to this class when it was created.

       :param listen_addr:
           The address and port to listen on
       :param function callback:
           The function to call when new connections arrive
       :param \*args,\ \*\*kwargs:
           Additional arguments to pass to ``callback``
       :type listen_addr: tuple of string and integer, or just integer

    """

    def __init__(self, host, port, callback=None, *args, **kwargs):
        asyncore.dispatcher.__init__(self)

        addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                      socket.SOCK_STREAM, 0, socket.AI_PASSIVE)

        self._listen_socks = []
        self.listen_addrs = []
        self.listen_port = port

        for family, socktype, proto, canonname, sockaddr in addrinfo:
            if sockaddr[1] == 0:
                sockaddr = sockaddr[:1] + (self.listen_port,) + sockaddr[2:]

            try:
                sock = _ListenSock(family, socktype, sockaddr,
                                   callback, *args, **kwargs)
            except socket.error:
                raise

            self._listen_socks.append(sock)
            self.listen_addrs.append(sock.listen_addr[0])

            if self.listen_port == 0:
                self.listen_port = sock.listen_addr[1]

    def close(self):
        """Close all listening sockets"""

        for sock in self._listen_socks:
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
