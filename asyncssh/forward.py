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

import asyncore, socket, sys, traceback

from .connection import *
from .constants import *
from .misc import *

class _ForwardDispatcher(asyncore.dispatcher):
    def __init__(self, forwarder, sock=None, dest=None):
        super().__init__(sock)

        self._addrinfo = ()
        self._forwarder = forwarder
        self._outbuf = b''
        self._send_blocked = False
        self._eof_pending = False
        self._eof_sent = False
        self._eof_received = False

        if dest:
            host, port = dest
            try:
                # TODO: Add support for some form of async getaddrinfo
                self._addrinfo = socket.getaddrinfo(host, port,
                                                    socket.AF_UNSPEC,
                                                    socket.SOCK_STREAM)
                self._try_connect()
            except socket.gaierror as exc:
                self._forwarder.report_open_error(OPEN_CONNECT_FAILED,
                                                  exc.args[1])

    def _try_connect(self):
        family, socktype, proto, canonname, sockaddr = self._addrinfo.pop(0)
        self.create_socket(family, socktype)
        self.connect(sockaddr)

    def handle_connect(self):
        self._forwarder.report_open()

    def readable(self):
        return self.connected and not (self._forwarder._send_blocked or
                                       self._eof_received)

    def handle_read(self):
        data = self.socket.recv(self._forwarder._send_pktsize)
        if data:
            self._forwarder.send(data)
        else:
            self._eof_received = True
            self._forwarder.send_eof()
            if self._eof_sent:
                self.handle_close()

    def writable(self):
        return not self.connected or self._outbuf or \
               self._send_blocked or self._eof_pending

    def handle_write(self):
        if self._outbuf:
            sent = self.socket.send(self._outbuf)
            self._outbuf = self._outbuf[sent:]

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

    def handle_error(self):
        exc = sys.exc_info()[1]
        if isinstance(exc, socket.error):
            self.close()

            if self.connected:
                self._forwarder.close()
            elif self._addrinfo:
                self._try_connect()
            else:
                self._forwarder.report_open_error(OPEN_CONNECT_FAILED,
                                                  exc.args[1])
        else:
            traceback.print_exc()
            sys.exit(1)

    def handle_close(self):
        self._forwarder.close()
        self.close()

    def send(self, data):
        self._outbuf += data

    def send_eof(self):
        self._eof_pending = True

class SSHForwarder(SSHTCPConnection):
    def __init__(self, conn, sock=None, dest=None):
        super().__init__(conn)

        self._sock = sock
        self._dest = dest
        self._dispatcher = None

    def handle_open_request(self):
        self._dispatcher = _ForwardDispatcher(self, dest=self._dest)

    def handle_open(self):
        if not self._dispatcher:
            self._dispatcher = _ForwardDispatcher(self, sock=self._sock)
            self._sock = None

    def handle_open_error(self, code, reason, lang):
        self.handle_close()

    def handle_data(self, data, datatype):
        self._dispatcher.send(data)

    def handle_eof(self):
        self._dispatcher.send_eof()

    def handle_close(self):
        if self._dispatcher:
            self._dispatcher.close()

        if self._sock:
            self._sock.close()

        self.close()
