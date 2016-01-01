# Copyright (c) 2013-2015 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH listeners"""

import asyncio
import socket

from .channel import SSHTCPChannel
from .forward import SSHLocalPortForwarder


class SSHListener(asyncio.AbstractServer):
    """SSH listener for inbound TCP connections"""

    def get_port(self):
        """Return the port number being listened on

           This method returns the port number that the remote listener
           was bound to. When the requested remote listening port is ``0``
           to indicate a dynamic port, this method can be called to
           determine what listening port was selected.

           :returns: The port number being listened on

        """

        raise NotImplementedError

    def close(self):
        """Stop listening for new connections

           This method can be called to stop listening for connections.
           Existing connections will remain open.

        """

        raise NotImplementedError

    @asyncio.coroutine
    def wait_closed(self):
        """Wait for the listener to close

           This method is a coroutine which waits for the associated
           TCP listeners to be closed.

        """

        raise NotImplementedError


class SSHClientListener(SSHListener):
    """SSH client listener used to accept inbound forwarded connections"""

    def __init__(self, conn, loop, session_factory, listen_host, listen_port,
                 encoding, window, max_pktsize):
        self._conn = conn
        self._loop = loop
        self._session_factory = session_factory
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._encoding = encoding
        self._window = window
        self._max_pktsize = max_pktsize
        self._waiters = []

    @asyncio.coroutine
    def _close(self):
        """Close this listener and wake up anything calling wait_closed"""

        yield from self._conn.close_client_listener(self, self._listen_host,
                                                    self._listen_port)

        for waiter in self._waiters:
            if not waiter.done():
                waiter.set_result(None)

        self._waiters = []
        self._conn = None

    def process_connection(self, orig_host, orig_port):
        """Process a forwarded TCP connection"""

        chan = SSHTCPChannel(self._conn, self._loop, self._encoding,
                             self._window, self._max_pktsize)

        chan.set_inbound_peer_names(self._listen_host, self._listen_port,
                                    orig_host, orig_port)

        return chan, self._session_factory(orig_host, orig_port)

    def get_port(self):
        """Return the port number being listened on"""

        return self._listen_port

    def close(self):
        """Close this listener asynchronously"""

        if self._conn:
            self._loop.create_task(self._close())

    @asyncio.coroutine
    def wait_closed(self):
        """Wait for this listener to finish closing"""

        if self._conn:
            waiter = asyncio.Future(loop=self._loop)
            self._waiters.append(waiter)
            yield from waiter


class SSHForwardListener(SSHListener):
    """A TCP listener used when forwarding traffic from local ports"""

    def __init__(self, listen_port, servers):
        self._listen_port = listen_port
        self._servers = servers

    def get_port(self):
        """Return the port number being listened on"""

        return self._listen_port

    def close(self):
        """Close this listener"""

        for server in self._servers:
            server.close()

        self._servers = []

    @asyncio.coroutine
    def wait_closed(self):
        """Wait for this listener to finish closing"""

        for server in self._servers:
            yield from server.wait_closed()


@asyncio.coroutine
def create_forward_listener(loop, coro, listen_host, listen_port):
    """Create a listener to forward traffic from local ports over SSH"""

    def protocol_factory():
        """Start a port forwarder for each new local connection"""

        return SSHLocalPortForwarder(loop, coro)

    if listen_host == '':
        listen_host = None

    addrinfo = yield from loop.getaddrinfo(listen_host, listen_port,
                                           family=socket.AF_UNSPEC,
                                           type=socket.SOCK_STREAM,
                                           flags=socket.AI_PASSIVE)

    if not addrinfo:
        raise OSError('getaddrinfo() returned empty list')

    servers = []

    for family, socktype, proto, _, sa in addrinfo:
        try:
            sock = socket.socket(family, socktype, proto)
        except OSError:
            continue

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, True)

        if sa[1] == 0:
            sa = sa[:1] + (listen_port,) + sa[2:]

        try:
            sock.bind(sa)
        except OSError as exc:
            for server in servers:
                server.close()

            raise OSError(exc.errno, 'error while attempting to bind on '
                          'address %r: %s' % (sa, exc.strerror)) from None

        if listen_port == 0:
            listen_port = sock.getsockname()[1]

        server = yield from loop.create_server(protocol_factory, sock=sock)
        servers.append(server)

    return SSHForwardListener(listen_port, servers)
