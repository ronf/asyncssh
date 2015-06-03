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

"""SSH port forwarding handlers"""

import asyncio

from .misc import DisconnectError
from .session import SSHTCPSession


class SSHPortForwarder(SSHTCPSession):
    """SSH port forwarding connection handler"""

    def __init__(self, conn, loop, peer=None):
        self._conn = conn
        self._loop = loop
        self._peer = peer
        self._transport = None
        self._eof_received = False

        if peer:
            peer.set_peer(self)

    def set_peer(self, peer):
        self._peer = peer

    def clear_peer(self):
        self._peer = None

    def set_transport(self, transport):
        self._transport = transport

    def clear_transport(self):
        if self._transport:
            self._transport.close()
            self._transport = None

    def write(self, data):
        self._transport.write(data)

    def write_eof(self):
        self._transport.write_eof()

    def was_eof_received(self):
        return self._eof_received

    def pause_reading(self):
        self._transport.pause_reading()

    def resume_reading(self):
        self._transport.resume_reading()

    def connection_made(self, transport):
        self.set_transport(transport)

    def connection_lost(self, exc):
        self.clear_transport()

        if self._peer:
            self._peer.clear_transport()
            self._peer.clear_peer()
            self.clear_peer()

    def data_received(self, data, datatype=None):
        self._peer.write(data)

    def eof_received(self):
        self._eof_received = True
        self._peer.write_eof()
        return not self._peer.was_eof_received()

    def pause_writing(self):
        self._peer.pause_reading()

    def resume_writing(self):
        self._peer.resume_reading()


class SSHLocalPortForwarder(SSHPortForwarder):
    """SSH local port forwarding connection handler"""

    def __init__(self, conn, loop, coro, dest_host, dest_port):
        super().__init__(conn, loop)
        self._coro = coro
        self._dest_host = dest_host
        self._dest_port = dest_port

    @asyncio.coroutine
    def _forward(self):
        def session_factory():
            return SSHPortForwarder(self._conn, self._loop, self._peer)

        orig_host, orig_port = self._transport.get_extra_info('peername')[:2]

        try:
            _, self._peer = \
                yield from self._coro(session_factory, self._dest_host,
                                      self._dest_port, orig_host, orig_port)
            self._peer.set_peer(self)
            self.resume_reading()
        except DisconnectError:
            self.clear_transport()

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
