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

from .misc import ChannelOpenError
from .session import SSHTCPSession


class SSHPortForwarder(SSHTCPSession):
    """SSH port forwarding connection handler"""

    def __init__(self, peer=None):
        self._peer = peer
        self._transport = None
        self._inpbuf = b''
        self._eof_received = False

        if peer:
            peer.set_peer(self)

    def set_peer(self, peer):
        """Set the peer forwarder to exchange data with"""

        self._peer = peer

    def write(self, data):
        """Write data to the transport"""

        self._transport.write(data)

    def write_eof(self):
        """Write end of file to the transport"""

        self._transport.write_eof()

    def was_eof_received(self):
        """Return whether end of file has been received or not"""

        return self._eof_received

    def pause_reading(self):
        """Pause reading from the transport"""

        self._transport.pause_reading()

    def resume_reading(self):
        """Resume reading on the transport"""

        self._transport.resume_reading()

    def connection_made(self, transport):
        """Handle a newly opened connection"""

        self._transport = transport

    def connection_lost(self, exc):
        """Handle an incoming connection close"""

        self.close()

    def data_received(self, data, datatype=None):
        """Handle incoming data from the transport"""

        if self._peer:
            self._peer.write(data)
        else:
            self._inpbuf += data

    def eof_received(self):
        """Handle an incoming end of file from the transport"""

        self._eof_received = True

        if self._peer:
            self._peer.write_eof()
            return not self._peer.was_eof_received()
        else:
            return False

    def pause_writing(self):
        """Pause writing by asking peer to pause reading"""

        self._peer.pause_reading()

    def resume_writing(self):
        """Resume writing by asking peer to resume reading"""

        self._peer.resume_reading()

    def close(self):
        """Close this port forwarder"""

        if self._transport:
            self._transport.close()
            self._transport = None

        if self._peer:
            peer = self._peer
            self._peer = None
            peer.close()


class SSHLocalPortForwarder(SSHPortForwarder):
    """SSH local port forwarding connection handler"""

    def __init__(self, conn, coro):
        super().__init__()
        self._conn = conn
        self._coro = coro

    @asyncio.coroutine
    def _forward(self, orig_host, orig_port):
        """Set up a port forwarding for a local port"""

        def session_factory():
            """Return an SSH port forwarder"""

            return SSHPortForwarder(self)

        try:
            yield from self._coro(session_factory, orig_host, orig_port)
        except ChannelOpenError:
            self.close()
            return

        if self._inpbuf:
            self.data_received(self._inpbuf)
            self._inpbuf = b''

    def connection_made(self, transport):
        """Handle a newly opened connection"""

        super().connection_made(transport)

        orig_host, orig_port = transport.get_extra_info('peername')[:2]
        self._conn.create_task(self._forward(orig_host, orig_port))
