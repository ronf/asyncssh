# Copyright (c) 2018 by Ron Frederick <ronf@timeheart.net>.
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

"""SOCKS forwarding support"""

from ipaddress import ip_address

from .forward import SSHLocalForwarder

# pylint: disable=bad-whitespace

SOCKS4                  = 0x04
SOCKS5                  = 0x05

SOCKS_CONNECT           = 0x01

SOCKS4_OK               = 0x5a
SOCKS5_OK               = 0x00

SOCKS5_AUTH_NONE        = 0x00

SOCKS5_ADDR_IPV4        = 0x01
SOCKS5_ADDR_HOSTNAME    = 0x03
SOCKS5_ADDR_IPV6        = 0x04

SOCKS4_OK_RESPONSE      = bytes((0, SOCKS4_OK, 0, 0, 0, 0, 0, 0))
SOCKS5_OK_RESPONSE      = bytes((SOCKS5, SOCKS5_OK, 0,
                                 SOCKS5_ADDR_HOSTNAME, 0, 0, 0))

_socks5_addr_len = { SOCKS5_ADDR_IPV4: 4, SOCKS5_ADDR_IPV6: 16 }

# pylint: enable=bad-whitespace


class SSHSOCKSForwarder(SSHLocalForwarder):
    """SOCKS dynamic port forwarding connection handler"""

    def __init__(self, conn, coro):
        super().__init__(conn, coro)

        self._inpbuf = b''
        self._bytes_needed = 2
        self._recv_handler = self._recv_version
        self._host = ''
        self._port = 0

    def _connect(self):
        """Send request to open a new tunnel connection"""

        self._recv_handler = None

        orig_host, orig_port = self._transport.get_extra_info('peername')[:2]
        self.forward(self._host, self._port, orig_host, orig_port)

    def _send_socks4_ok(self):
        """Send SOCKS4 success response"""

        self._transport.write(SOCKS4_OK_RESPONSE)

    def _send_socks5_ok(self):
        """Send SOCKS5 success response"""

        self._transport.write(SOCKS5_OK_RESPONSE)

    def _recv_version(self, data):
        """Parse SOCKS version"""

        if data[0] == SOCKS4:
            if data[1] == SOCKS_CONNECT:
                self._bytes_needed = 6
                self._recv_handler = self._recv_socks4_addr
            else:
                self.close()
        elif data[0] == SOCKS5:
            self._bytes_needed = data[1]
            self._recv_handler = self._recv_socks5_authlist
        else:
            self.close()

    def _recv_socks4_addr(self, data):
        """Parse SOCKSv4 address and port"""

        self._port = (data[0] << 8) + data[1]

        # If address is 0.0.0.x, read a hostname later
        if data[2:5] != b'\0\0\0' or data[5] == 0:
            self._host = str(ip_address(data[2:]))

        self._bytes_needed = -1
        self._recv_handler = self._recv_socks4_user

    def _recv_socks4_user(self, data):
        """Parse SOCKSv4 username"""

        # pylint: disable=unused-argument

        if self._host:
            self._send_socks4_ok()
            self._connect()
        else:
            self._bytes_needed = -1
            self._recv_handler = self._recv_socks4_hostname

    def _recv_socks4_hostname(self, data):
        """Parse SOCKSv4 hostname"""

        # pylint: disable=unused-argument

        try:
            self._host = data.decode('utf-8')
        except UnicodeDecodeError:
            self.close()
            return

        self._send_socks4_ok()
        self._connect()

    def _recv_socks5_authlist(self, data):
        """Parse SOCKSv5 list of authentication methods"""

        if SOCKS5_AUTH_NONE in data:
            self._transport.write(bytes((SOCKS5, SOCKS5_AUTH_NONE)))

            self._bytes_needed = 4
            self._recv_handler = self._recv_socks5_command
        else:
            self.close()

    def _recv_socks5_command(self, data):
        """Parse SOCKSv5 command"""

        if data[0] == SOCKS5 and data[1] == SOCKS_CONNECT and data[2] == 0:
            if data[3] == SOCKS5_ADDR_HOSTNAME:
                self._bytes_needed = 1
                self._recv_handler = self._recv_socks5_hostlen
            else:
                addrlen = _socks5_addr_len.get(data[3])

                if addrlen:
                    self._bytes_needed = addrlen
                    self._recv_handler = self._recv_socks5_addr
                else:
                    self.close()
        else:
            self.close()

    def _recv_socks5_addr(self, data):
        """Parse SOCKSv5 address"""

        self._host = str(ip_address(data))

        self._bytes_needed = 2
        self._recv_handler = self._recv_socks5_port

    def _recv_socks5_hostlen(self, data):
        """Parse SOCKSv5 host length"""

        self._bytes_needed = data[0]
        self._recv_handler = self._recv_socks5_host

    def _recv_socks5_host(self, data):
        """Parse SOCKSv5 host"""

        try:
            self._host = data.decode('utf-8')
        except UnicodeDecodeError:
            self.close()
            return

        self._bytes_needed = 2
        self._recv_handler = self._recv_socks5_port

    def _recv_socks5_port(self, data):
        """Parse SOCKSv5 port"""

        self._port = (data[0] << 8) + data[1]
        self._send_socks5_ok()
        self._connect()

    def data_received(self, data, datatype=None):
        """Handle incoming data from the SOCKS client"""

        if self._recv_handler:
            self._inpbuf += data

            while self._recv_handler:
                if self._bytes_needed < 0:
                    idx = self._inpbuf.find(b'\0')
                    if idx >= 0:
                        data = self._inpbuf[:idx]
                        self._inpbuf = self._inpbuf[idx+1:]
                        self._recv_handler(data)
                    elif len(self._inpbuf) > 255:
                        # SOCKSv4 user or hostname too long
                        self.close()
                        return
                    else:
                        return
                else:
                    if len(self._inpbuf) >= self._bytes_needed:
                        data = self._inpbuf[:self._bytes_needed]
                        self._inpbuf = self._inpbuf[self._bytes_needed:]
                        self._recv_handler(data)
                    else:
                        return

            data = self._inpbuf
            self._inpbuf = b''

        if data:
            super().data_received(data, datatype)
