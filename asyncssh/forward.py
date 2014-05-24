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

"""SSH port forwarding handlers"""

import asyncio, socket

from .channel import *
from .misc import *


class SSHPortForwarder(SSHTCPSession):
    """SSH port forwarding connection handler"""

    def __init__(self, conn, loop, peer=None):
        self._conn = conn
        self._loop = loop
        self._transport = None
        self._peer = peer
        self._eof_received = False

        if peer:
            peer._peer = self

    def connection_made(self, transport):
        self._transport = transport

    def connection_lost(self, exc):
        if self._transport:
            self._transport.close()
            self._transport = None

        if self._peer:
            self._peer._transport.close()
            self._peer._transport = None
            self._peer._peer = None
            self._peer = None

    def data_received(self, data, datatype=None):
        self._peer._transport.write(data)

    def eof_received(self):
        self._eof_received = True
        self._peer._transport.write_eof()
        return not self._peer._eof_received

    def pause_writing(self):
        self._peer._transport.pause_reading()

    def resume_writing(self):
        self._peer._transport.resume_reading()


class SSHLocalPortForwarder(SSHPortForwarder):
    """SSH local port forwarding connection handler"""

    def __init__(self, conn, loop, coro, dest_host, dest_port):
        super().__init__(conn, loop)
        self._coro = coro
        self._dest_host = dest_host
        self._dest_port = dest_port

    @asyncio.coroutine
    def _forward(self):
        session_factory = lambda: SSHPortForwarder(self._conn, self._loop,
                                                   self._peer)

        orig_host, orig_port = self._transport.get_extra_info('peername')[:2]

        try:
            _, self._peer = \
                yield from self._coro(session_factory, self._dest_host,
                                      self._dest_port, orig_host, orig_port)
            self._peer._peer = self
            self._transport.resume_reading()
        except DisconnectError as exc:
            self._transport.close()
            self._transport = None

    def connection_made(self, transport):
        super().connection_made(transport)
        transport.pause_reading()
        asyncio.async(self._forward(), loop=self._loop)

class SSHRemotePortForwarder(SSHPortForwarder):
    def __init__(self, conn, loop, peer):
        super().__init__(conn, loop, peer)
        self.pause_writing()

    def connection_made(self, transport):
        super().connection_made(transport)
        self.resume_writing()
