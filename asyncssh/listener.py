# Copyright (c) 2013-2020 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""SSH listeners"""

import asyncio
import errno
import socket

from .forward import SSHLocalPortForwarder, SSHLocalPathForwarder
from .socks import SSHSOCKSForwarder


class SSHListener:
    """SSH listener for inbound connections"""

    def __init__(self):
        self._tunnel = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        self.close()
        await self.wait_closed()

    def get_port(self):
        """Return the port number being listened on

           This method returns the port number that the remote listener
           was bound to. When the requested remote listening port is `0`
           to indicate a dynamic port, this method can be called to
           determine what listening port was selected. This function
           only applies to TCP listeners.

           :returns: The port number being listened on

        """

        # pylint: disable=no-self-use

        return 0

    def set_tunnel(self, tunnel):
        """Set tunnel associated with listener"""

        self._tunnel = tunnel

    def close(self):
        """Stop listening for new connections

           This method can be called to stop listening for connections.
           Existing connections will remain open.

        """

        if self._tunnel:
            self._tunnel.close()

    async def wait_closed(self):
        """Wait for the listener to close

           This method is a coroutine which waits for the associated
           listeners to be closed.

        """

        if self._tunnel:
            await self._tunnel.wait_closed()
            self._tunnel = None


class SSHClientListener(SSHListener):
    """Client listener used to accept inbound forwarded connections"""

    def __init__(self, conn, session_factory,
                 encoding, errors, window, max_pktsize):
        super().__init__()

        self._conn = conn
        self._session_factory = session_factory
        self._encoding = encoding
        self._errors = errors
        self._window = window
        self._max_pktsize = max_pktsize
        self._close_event = asyncio.Event()

    async def _close(self):
        """Close this listener"""

        self._close_event.set()
        self._conn = None

    def close(self):
        """Close this listener asynchronously"""

        super().close()

        if self._conn:
            self._conn.create_task(self._close())

    async def wait_closed(self):
        """Wait for this listener to finish closing"""

        await super().wait_closed()

        await self._close_event.wait()


class SSHTCPClientListener(SSHClientListener):
    """Client listener used to accept inbound forwarded TCP connections"""

    def __init__(self, conn, session_factory, listen_host, listen_port,
                 encoding, errors, window, max_pktsize):
        super().__init__(conn, session_factory, encoding,
                         errors, window, max_pktsize)

        self._listen_host = listen_host
        self._listen_port = listen_port

    async def _close(self):
        """Close this listener"""

        if self._conn: # pragma: no branch
            await self._conn.close_client_tcp_listener(self._listen_host,
                                                       self._listen_port)

        await super()._close()

    def process_connection(self, orig_host, orig_port):
        """Process a forwarded TCP connection"""

        chan = self._conn.create_tcp_channel(self._encoding, self._errors,
                                             self._window, self._max_pktsize)

        chan.set_inbound_peer_names(self._listen_host, self._listen_port,
                                    orig_host, orig_port)

        return chan, self._session_factory(orig_host, orig_port)

    def get_port(self):
        """Return the port number being listened on"""

        return self._listen_port


class SSHUNIXClientListener(SSHClientListener):
    """Client listener used to accept inbound forwarded UNIX connections"""

    def __init__(self, conn, session_factory, listen_path,
                 encoding, errors, window, max_pktsize):
        super().__init__(conn, session_factory, encoding,
                         errors, window, max_pktsize)

        self._listen_path = listen_path

    async def _close(self):
        """Close this listener"""

        if self._conn: # pragma: no branch
            await self._conn.close_client_unix_listener(self._listen_path)

        await super()._close()

    def process_connection(self):
        """Process a forwarded UNIX connection"""

        chan = self._conn.create_unix_channel(self._encoding, self._errors,
                                              self._window, self._max_pktsize)

        chan.set_inbound_peer_names(self._listen_path)

        return chan, self._session_factory()


class SSHForwardListener(SSHListener):
    """A listener used when forwarding traffic from local ports"""

    def __init__(self, conn, servers, listen_key, listen_port=0):
        super().__init__()

        self._conn = conn
        self._servers = servers
        self._listen_key = listen_key
        self._listen_port = listen_port

    def get_port(self):
        """Return the port number being listened on"""

        return self._listen_port

    def close(self):
        """Close this listener"""

        super().close()

        if self._conn:
            self._conn.close_forward_listener(self._listen_key)

            for server in self._servers:
                server.close()

            self._conn = None

    async def wait_closed(self):
        """Wait for this listener to finish closing"""

        await super().wait_closed()

        for server in self._servers:
            await server.wait_closed()

        self._servers = []


async def create_tcp_local_listener(conn, loop, protocol_factory,
                                    listen_host, listen_port):
    """Create a listener to forward traffic from a local TCP port over SSH"""

    if listen_host == '':
        listen_host = None

    addrinfo = await loop.getaddrinfo(listen_host, listen_port,
                                      family=socket.AF_UNSPEC,
                                      type=socket.SOCK_STREAM,
                                      flags=socket.AI_PASSIVE)

    if not addrinfo: # pragma: no cover
        raise OSError('getaddrinfo() returned empty list')

    servers = []

    for family, socktype, proto, _, sa in addrinfo:
        try:
            sock = socket.socket(family, socktype, proto)
        except OSError: # pragma: no cover
            continue

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, True)
            except AttributeError: # pragma: no cover
                pass

        if sa[1] == 0:
            sa = sa[:1] + (listen_port,) + sa[2:]

        try:
            sock.bind(sa)
        except (OSError, OverflowError) as exc:
            sock.close()

            for server in servers:
                server.close()

            if isinstance(exc, OverflowError): # pragma: no cover
                exc.errno = errno.EOVERFLOW
                exc.strerror = str(exc)

            # pylint: disable=no-member
            raise OSError(exc.errno, 'error while attempting to bind on '
                          'address %r: %s' % (sa, exc.strerror)) from None

        if listen_port == 0:
            listen_port = sock.getsockname()[1]
            conn.logger.debug1('Assigning dynamic port %d', listen_port)

        server = await loop.create_server(protocol_factory, sock=sock)
        servers.append(server)

    listen_key = listen_host, listen_port
    return SSHForwardListener(conn, servers, listen_key, listen_port)


async def create_tcp_forward_listener(conn, loop, coro,
                                      listen_host, listen_port):
    """Create a listener to forward traffic from a local TCP port over SSH"""

    def protocol_factory():
        """Start a port forwarder for each new local connection"""

        return SSHLocalPortForwarder(conn, coro)

    return await create_tcp_local_listener(conn, loop, protocol_factory,
                                           listen_host, listen_port)


async def create_unix_forward_listener(conn, loop, coro, listen_path):
    """Create a listener to forward a local UNIX domain socket over SSH"""

    def protocol_factory():
        """Start a path forwarder for each new local connection"""

        return SSHLocalPathForwarder(conn, coro)

    server = await loop.create_unix_server(protocol_factory, listen_path)

    return SSHForwardListener(conn, [server], listen_path)


async def create_socks_listener(conn, loop, coro, listen_host, listen_port):
    """Create a SOCKS listener to forward traffic over SSH"""

    def protocol_factory():
        """Start a port forwarder for each new SOCKS connection"""

        return SSHSOCKSForwarder(conn, coro)

    return await create_tcp_local_listener(conn, loop, protocol_factory,
                                           listen_host, listen_port)
