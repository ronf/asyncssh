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

    def __init__(self, conn, loop, remote_transport=None):
        self._conn = conn
        self._loop = loop
        self._local_transport = None
        self._remote_transport = remote_transport

    def connection_made(self, local_transport):
        self._local_transport = local_transport

    def connection_lost(self, exc):
        if self._local_transport:
            self._local_transport.close()
            self._local_transport = None

        if self._remote_transport:
            self._remote_transport.close()
            self._remote_transport = None

    def data_received(self, data, datatype=None):
        self._remote_transport.write(data)

    def eof_received(self):
        self._remote_transport.write_eof()

    def pause_writing(self):
        self._remote_transport.pause_reading()

    def resume_writing(self):
        self._remote_transport.resume_reading()


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
                                                   self._local_transport)

        orig_host, orig_port = \
            self._local_transport.get_extra_info('peername')[:2]

        try:
            self._remote_transport, _ = \
                yield from self._coro(session_factory, self._dest_host,
                                      self._dest_port, orig_host, orig_port)

            self._local_transport.resume_reading()
        except DisconnectError as exc:
            self._local_transport.close()
            self._local_transport = None

    def connection_made(self, local_transport):
        super().connection_made(local_transport)
        local_transport.pause_reading()
        asyncio.async(self._forward(), loop=self._loop)

class SSHRemotePortForwarder(SSHPortForwarder):
    def __init__(self, conn, loop, remote_transport, remote_protocol):
        super().__init__(conn, loop, remote_transport)
        self._peer = remote_protocol
        remote_transport.pause_reading()

    def connection_made(self, local_transport):
        super().connection_made(local_transport)
        self._peer._remote_transport = local_transport
        self._peer = None
        self._remote_transport.resume_reading()
