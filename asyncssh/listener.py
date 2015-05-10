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

"""SSH listeners"""

import asyncio, socket

from .channel import *
from .forward import *
from .logging import *


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


class SSHForwardListener(SSHListener):
    """A TCP listener used when forwarding traffic fromm local ports"""

    def __init__(self, listen_port, servers):
        self._listen_port = listen_port
        self._servers = servers

    def get_port(self):
        return self._listen_port

    def close(self):
        for server in self._servers:
            server.close()

        self._servers = []

    @asyncio.coroutine
    def wait_closed(self):
        for server in self._servers:
            yield from server.wait_closed()


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

    def _process_connection(self, orig_host, orig_port):
        """Process a forwarded TCP connection"""

        chan = SSHTCPChannel(self._conn, self._loop, self._encoding,
                             self._window, self._max_pktsize)

        chan._extra['local_peername'] = (self._listen_host, self._listen_port)
        chan._extra['remote_peername'] = (orig_host, orig_port)

        return chan, self._session_factory(orig_host, orig_port)

    def get_port(self):
        return self._listen_port

    def close(self):
        asyncio.async(self._conn._close_client_listener(self, self._listen_host,
                                                        self._listen_port),
                      loop=self._loop)
        self._conn = None

        for waiter in self._waiters:
            if not waiter.cancelled():
                waiter.set_result(None)

    @asyncio.coroutine
    def wait_closed(self):
        if self._conn:
            waiter = asyncio.Future(loop=self._loop)
            self._waiters.append(waiter)
            yield from waiter
