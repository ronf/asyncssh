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

"""SSH port forwarding handlers"""

import asyncore, socket

from .connection import *
from .constants import *
from .misc import *

class _ForwardDispatcher(asyncore.dispatcher):
    def __init__(self, forwarder, sock):
        super().__init__(sock)

        self._forwarder = forwarder
        self._outbuf = b''
        self._send_blocked = False
        self._eof_pending = False
        self._eof_sent = False
        self._eof_received = False

    def readable(self):
        return not (self._forwarder._send_blocked or self._eof_received)

    def handle_read(self):
        try:
            data = self.socket.recv(self._forwarder._send_pktsize)
            if data:
                self._forwarder.send(data)
            else:
                self._eof_received = True
                self._forwarder.send_eof()
                if self._eof_sent:
                    self.handle_close()
        except socket.error:
            self.handle_close()

    def writable(self):
        return self._outbuf or self._send_blocked or self._eof_pending

    def handle_write(self):
        if self._outbuf:
            try:
                sent = self.socket.send(self._outbuf)
                self._outbuf = self._outbuf[sent:]
            except socket.error:
                self.handle_close()
                return

        if self._outbuf:
            self._send_blocked = True
            self._forwarder.block_recv()
        elif self._send_blocked:
            self._send_blocked = False
            self._forwarder.unblock_recv()
        elif self._eof_pending:
            self.socket.shutdown(socket.SHUT_WR)
            self._eof_pending = False
            self._eof_sent = True
            if self._eof_received:
                self.handle_close()

    def handle_close(self):
        self._forwarder.close()
        self.close()

    def send(self, data):
        self._outbuf += data

    def send_eof(self):
        self._eof_pending = True

class SSHForwarder(SSHTCPConnection):
    @classmethod
    def create_outbound(cls, conn, address):
        """Create a port forwarder to the specified destination address"""

        try:
            # TODO: Switch this over to non-blocking connect. The
            #       problem is how we return channel open errors if
            #       we do this -- it would have to be a callback
            #       instead of a return value.
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.connect(address)
        except socket.error as exc:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, exc.args[1])

        return cls(conn, sock)

    def __init__(self, conn, sock):
        super().__init__(conn)

        self._sock = sock

    def handle_open(self):
        self._sock = _ForwardDispatcher(self, self._sock)

    def handle_open_error(self, code, reason, lang):
        self.handle_close()

    def handle_data(self, data, datatype):
        self._sock.send(data)

    def handle_eof(self):
        self._sock.send_eof()

    def handle_close(self):
        self._sock.close()
        self.close()
