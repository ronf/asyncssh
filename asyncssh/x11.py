# Copyright (c) 2016 by Ron Frederick <ronf@timeheart.net>.
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

"""X11 forwarding support"""

import asyncio
from collections import OrderedDict
import os
import socket

from .constants import OPEN_CONNECT_FAILED
from .forward import SSHForwarder
from .misc import ChannelOpenError, Record

# pylint: disable=bad-whitespace

# Xauth address families
XAUTH_FAMILY_IPV4     = 0
XAUTH_FAMILY_DECNET   = 1
XAUTH_FAMILY_IPV6     = 6
XAUTH_FAMILY_HOSTNAME = 256
XAUTH_FAMILY_WILD     = 65535

# Xauth protocol values
XAUTH_PROTO_COOKIE    = b'MIT-MAGIC-COOKIE-1'

# X11 port numbers
X11_BASE_PORT         = 6000

# pylint: enable=bad-whitespace


@asyncio.coroutine
def lookup_host(loop, host, family):
    """Look up IPv4 or IPv6 addresses of a host name"""

    try:
        addrinfo = yield from loop.getaddrinfo(host, 0, family=family,
                                               type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []

    return [ai[4][0] for ai in addrinfo]


class SSHXAuthorityEntry(Record):
    """An entry in an Xauthority file

       This object hold a single entry in an Xauthority file.

       ======= ================================================== ======
       Field   Description                                        Type
       ======= ================================================== ======
       family  The address family (IPv4=0, IPv6=6, Hostname=256)  int
       addr    The server hostname or address in binary form      bytes
       dpynum  The display number to match against                bytes
       proto   The authentication protocol to use                 bytes
       data    The authentication data to send                    bytes
       ======= ================================================== ======

    """

    __slots__ = OrderedDict((('family', 0), ('addr', b''), ('dpynum', b''),
                             ('proto', b''), ('data', b'')))

    @staticmethod
    def _build_short(value):
        """Construct a big-endian 16-bit integer"""

        return value.to_bytes(2, 'big')

    def _build_string(self, data):
        """Construct a binary string with a 16-bit length"""

        return self._build_short(len(data)) + data

    def to_bytes(self):
        """Construct an Xauthority entry"""

        # pylint: disable=no-member

        return b''.join((self._build_short(self.family),
                         self._build_string(self.addr),
                         self._build_string(self.dpynum),
                         self._build_string(self.proto),
                         self._build_string(self.data)))


class SSHXAuthorityFile:
    """An iterator for Xauthority file entries"""

    def __init__(self, auth_path=None):
        if not auth_path:
            auth_path = os.environ.get('XAUTHORITY')

        if not auth_path:
            auth_path = os.path.join(os.path.expanduser('~'), '.Xauthority')

        try:
            self._file = open(auth_path, 'rb')
        except OSError:
            self._file = None

    def __del__(self):
        self._close()

    def __iter__(self):
        return self

    def _close(self):
        """Close the Xauthority file"""

        if self._file:
            self._file.close()
            self._file = None

    def _read_bytes(self, n):
        """Read a fixed number of bytes"""

        data = self._file.read(n)

        if len(data) != n:
            raise EOFError

        return data

    def _read_short(self):
        """Read a 16-bit integer"""

        return int.from_bytes(self._read_bytes(2), 'big')

    def _read_string(self):
        """Read a binary string"""

        return self._read_bytes(self._read_short())

    def __next__(self):
        if not self._file:
            raise StopIteration

        try:
            family = self._read_short()
        except EOFError:
            self._file.close()
            self._file = None
            raise StopIteration

        try:
            return SSHXAuthorityEntry(family, self._read_string(),
                                      self._read_string(), self._read_string(),
                                      self._read_string())
        except EOFError:
            raise ValueError('Incomplete Xauthority entry') from None


class SSHX11ClientForwarder(SSHForwarder):
    """X11 forwarding connection handler"""

    def __init__(self, listener, peer):
        super().__init__(peer)

        self._listener = listener

        self._inpbuf = b''
        self._bytes_needed = 12
        self._recv_handler = self._recv_prefix

        self._endian = b''
        self._prefix = b''
        self._auth_proto_len = 0
        self._auth_data_len = 0

        self._auth_proto = b''
        self._auth_proto_pad = b''

        self._auth_data = b''
        self._auth_data_pad = b''

    def _encode_uint16(self, value):
        """Encode a 16-bit value using the specified endianness"""

        if self._endian == b'B':
            return bytes((value >> 8, value & 255))
        else:
            return bytes((value & 255, value >> 8))

    def _decode_uint16(self, value):
        """Decode a 16-bit value using the specified endianness"""

        if self._endian == b'B':
            return (value[0] << 8) + value[1]
        else:
            return (value[1] << 8) + value[0]

    @staticmethod
    def _padded_len(length):
        """Return length rounded up to the next multiple of 4 bytes"""

        return ((length + 3) // 4) * 4

    @staticmethod
    def _pad(data):
        """Pad a string to a multiple of 4 bytes"""

        length = len(data) % 4
        return data + ((4 - length) * b'\00' if length else b'')

    def _recv_prefix(self, data):
        """Parse X11 client prefix"""

        self._endian = data[:1]
        self._prefix = data

        self._auth_proto_len = self._decode_uint16(data[6:8])
        self._auth_data_len = self._decode_uint16(data[8:10])

        self._recv_handler = self._recv_auth_proto
        self._bytes_needed = self._padded_len(self._auth_proto_len)

    def _recv_auth_proto(self, data):
        """Extract X11 auth protocol"""

        self._auth_proto = data[:self._auth_proto_len]
        self._auth_proto_pad = data[self._auth_proto_len:]

        self._recv_handler = self._recv_auth_data
        self._bytes_needed = self._padded_len(self._auth_data_len)

    def _recv_auth_data(self, data):
        """Extract X11 auth data"""

        self._auth_data = data[:self._auth_data_len]
        self._auth_data_pad = data[self._auth_data_len:]

        try:
            self._auth_data = self._listener.validate_auth(self._auth_data)
        except KeyError:
            reason = b'Invalid authentication key\n'

            response = b''.join((bytes((0, len(reason))),
                                 self._encode_uint16(11),
                                 self._encode_uint16(0),
                                 self._encode_uint16((len(reason) + 3) // 4),
                                 self._pad(reason)))

            try:
                self.write(response)
                self.write_eof()
            except OSError: # pragma: no cover
                pass

            self._inpbuf = b''
        else:
            self._inpbuf = (self._prefix + self._auth_proto +
                            self._auth_proto_pad + self._auth_data +
                            self._auth_data_pad)

        self._recv_handler = None
        self._bytes_needed = 0

    def data_received(self, data, datatype=None):
        """Handle incoming data from the X11 client"""

        if self._recv_handler:
            self._inpbuf += data

            while self._recv_handler:
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


class SSHX11ClientListener:
    """Client listener used to accept forwarded X11 connections"""

    def __init__(self, display, connect_coro, connect_args, screen,
                 auth_proto, local_auth):
        self._display = display
        self._connect_coro = connect_coro
        self._connect_args = connect_args
        self._screen = screen
        self._auth_proto = auth_proto
        self._auth_len = len(local_auth)
        self._local_auth = local_auth
        self._remote_auth = {}
        self._channel = {}

    @staticmethod
    def _parse_display(display):
        """Parse an X11 display value"""

        try:
            host, dpynum = display.rsplit(':', 1)

            if host.startswith('[') and host.endswith(']'):
                host = host[1:-1]

            idx = dpynum.find('.')
            if idx >= 0:
                screen = int(dpynum[idx+1:])
                dpynum = dpynum[:idx]
            else:
                screen = 0
        except (ValueError, UnicodeEncodeError):
            raise ValueError('Invalid X11 display') from None

        return host, dpynum, screen

    def get_display(self):
        """Return the display this handler is associated with"""

        return self._display

    @classmethod
    @asyncio.coroutine
    def create(cls, loop, display, auth_path):
        """Create a listener for forwarded X11 connections"""

        host, dpynum, screen = cls._parse_display(display)

        if host.startswith('/') or host in ('', 'unix', 'localhost'):
            match_host = socket.gethostname()
        else:
            match_host = host

        match_dpynum = dpynum.encode('ascii')

        ipv4_addrs = []
        ipv6_addrs = []

        # Avoid pylint false positive
        # pylint: disable=undefined-loop-variable
        for entry in SSHXAuthorityFile(auth_path):
            if entry.dpynum and entry.dpynum != match_dpynum:
                continue

            if entry.family == XAUTH_FAMILY_IPV4:
                if not ipv4_addrs:
                    ipv4_addrs = yield from lookup_host(loop, match_host,
                                                        socket.AF_INET)

                addr = socket.inet_ntop(socket.AF_INET, entry.addr)
                match = addr in ipv4_addrs
            elif entry.family == XAUTH_FAMILY_IPV6:
                if not ipv6_addrs:
                    ipv6_addrs = yield from lookup_host(loop, match_host,
                                                        socket.AF_INET6)

                addr = socket.inet_ntop(socket.AF_INET6, entry.addr)
                match = addr in ipv6_addrs
            elif entry.family == XAUTH_FAMILY_HOSTNAME:
                match = entry.addr == match_host.encode('idna')
            elif entry.family == XAUTH_FAMILY_WILD:
                match = True
            else:
                match = False

            if match:
                break
        else:
            raise ValueError('No xauth entry found for display')

        if host.startswith('/'):
            connect_coro = loop.create_unix_connection
            connect_args = (host + ':' + dpynum,)
        elif host in ('', 'unix'):
            connect_coro = loop.create_unix_connection
            connect_args = ('/tmp/.X11-unix/X' + dpynum,)
        else:
            connect_coro = loop.create_connection
            connect_args = (host, X11_BASE_PORT + int(dpynum))

        return cls(display, connect_coro, connect_args, screen,
                   entry.proto, entry.data)

    def attach(self, chan, single_connection):
        """Attach a channel to this listener"""

        remote_auth = os.urandom(self._auth_len)

        self._remote_auth[chan] = remote_auth
        self._channel[remote_auth] = chan, single_connection

        return self._auth_proto, remote_auth, self._screen

    def detach(self, chan):
        """Detach a channel from this listener"""

        try:
            remote_auth = self._remote_auth.pop(chan)
            del self._channel[remote_auth]
        except KeyError:
            # Channel may already be removed in single connection case
            pass

    @asyncio.coroutine
    def forward_connection(self):
        """Forward an incoming connection to the local X server"""

        try:
            _, peer = yield from self._connect_coro(SSHForwarder,
                                                    *self._connect_args)
        except OSError as exc:
            raise ChannelOpenError(OPEN_CONNECT_FAILED, str(exc)) from None

        return SSHX11ClientForwarder(self, peer)

    def validate_auth(self, remote_auth):
        """Validate client auth and enforce single connection flag"""

        chan, single_connection = self._channel[remote_auth]

        if single_connection:
            del self._channel[remote_auth]
            del self._remote_auth[chan]

        return self._local_auth
