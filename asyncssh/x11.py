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
import os
import socket
import time

from collections import namedtuple

from .constants import OPEN_CONNECT_FAILED
from .forward import SSHForwarder
from .listener import create_tcp_forward_listener
from .misc import ChannelOpenError

# pylint: disable=bad-whitespace

# Xauth address families
XAUTH_FAMILY_IPV4     = 0
XAUTH_FAMILY_DECNET   = 1
XAUTH_FAMILY_IPV6     = 6
XAUTH_FAMILY_HOSTNAME = 256
XAUTH_FAMILY_WILD     = 65535

# Xauth protocol values
XAUTH_PROTO_COOKIE    = b'MIT-MAGIC-COOKIE-1'

# Xauth lock information
XAUTH_LOCK_SUFFIX     = '-c'
XAUTH_LOCK_TRIES      = 5
XAUTH_LOCK_DELAY      = 0.2
XAUTH_LOCK_DEAD       = 5

# X11 display and port numbers
X11_BASE_PORT         = 6000
X11_DISPLAY_START     = 10
X11_MAX_DISPLAYS      = 64

# Host to listen on when doing X11 forwarding
X11_LISTEN_HOST       = 'localhost'

# pylint: enable=bad-whitespace


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

@asyncio.coroutine
def _lookup_host(loop, host, family):
    """Look up IPv4 or IPv6 addresses of a host name"""

    try:
        addrinfo = yield from loop.getaddrinfo(host, 0, family=family,
                                               type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []

    return [ai[4][0] for ai in addrinfo]


class SSHXAuthorityEntry(namedtuple('SSHXAuthorityEntry',
                                    'family addr dpynum proto data')):
    """An entry in an Xauthority file"""

    def __bytes__(self):
        """Construct an Xauthority entry"""

        def _uint16(value):
            """Construct a big-endian 16-bit unsigned integer"""

            return value.to_bytes(2, 'big')

        def _string(data):
            """Construct a binary string with a 16-bit length"""

            return _uint16(len(data)) + data

        return b''.join((_uint16(self.family), _string(self.addr),
                         _string(self.dpynum), _string(self.proto),
                         _string(self.data)))


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
        """Encode a 16-bit unsigned integer"""

        if self._endian == b'B':
            return bytes((value >> 8, value & 255))
        else:
            return bytes((value & 255, value >> 8))

    def _decode_uint16(self, value):
        """Decode a 16-bit unsigned integer"""

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

    def __init__(self, loop, host, dpynum, auth_proto, auth_data):
        self._host = host
        self._dpynum = dpynum
        self._auth_proto = auth_proto
        self._local_auth = auth_data

        if host.startswith('/'):
            self._connect_coro = loop.create_unix_connection
            self._connect_args = (host + ':' + dpynum,)
        elif host in ('', 'unix'):
            self._connect_coro = loop.create_unix_connection
            self._connect_args = ('/tmp/.X11-unix/X' + dpynum,)
        else:
            self._connect_coro = loop.create_connection
            self._connect_args = (host, X11_BASE_PORT + int(dpynum))

        self._remote_auth = {}
        self._channel = {}

    def attach(self, display, chan, single_connection):
        """Attach a channel to this listener"""

        host, dpynum, screen = _parse_display(display)

        if self._host != host or self._dpynum != dpynum:
            raise ValueError('Already forwarding to another X11 display')

        remote_auth = os.urandom(len(self._local_auth))

        self._remote_auth[chan] = remote_auth
        self._channel[remote_auth] = chan, single_connection

        return self._auth_proto, remote_auth, screen

    def detach(self, chan):
        """Detach a channel from this listener"""

        try:
            remote_auth = self._remote_auth.pop(chan)
            del self._channel[remote_auth]
        except KeyError:
            pass

        return self._remote_auth == {}

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


class SSHX11ServerListener:
    """Server listener used to forward X11 connections"""

    def __init__(self, tcp_listener, display):
        self._tcp_listener = tcp_listener
        self._display = display
        self._channels = set()

    def attach(self, chan, screen):
        """Attach a channel to this listener and return its display"""

        self._channels.add(chan)

        return '%s.%s' % (self._display, screen)

    def detach(self, chan):
        """Detach a channel from this listener"""

        try:
            self._channels.remove(chan)
        except KeyError:
            pass

        if not self._channels:
            self._tcp_listener.close()
            self._tcp_listener = None
            return True
        else:
            return False


def get_xauth_path(auth_path):
    """Compute the path to the Xauthority file"""

    if not auth_path:
        auth_path = os.environ.get('XAUTHORITY')

    if not auth_path:
        auth_path = os.path.join(os.path.expanduser('~'), '.Xauthority')

    return auth_path


def walk_xauth(auth_path):
    """Walk the entries in an Xauthority file"""

    def _read_bytes(n):
        """Read exactly n bytes"""

        data = auth_file.read(n)

        if len(data) != n:
            raise EOFError

        return data

    def _read_uint16():
        """Read a 16-bit unsigned integer"""

        return int.from_bytes(_read_bytes(2), 'big')

    def _read_string():
        """Read a string"""

        return _read_bytes(_read_uint16())

    try:
        with open(auth_path, 'rb') as auth_file:
            while True:
                try:
                    family = _read_uint16()
                except EOFError:
                    break

                try:
                    yield SSHXAuthorityEntry(family, _read_string(),
                                             _read_string(), _read_string(),
                                             _read_string())
                except EOFError:
                    raise ValueError('Incomplete Xauthority entry') from None
    except OSError:
        pass


@asyncio.coroutine
def lookup_xauth(loop, auth_path, host, dpynum):
    """Look up Xauthority data for the specified display"""

    auth_path = get_xauth_path(auth_path)

    if host.startswith('/') or host in ('', 'unix', 'localhost'):
        host = socket.gethostname()

    dpynum = dpynum.encode('ascii')

    ipv4_addrs = []
    ipv6_addrs = []

    for entry in walk_xauth(auth_path):
        if entry.dpynum and entry.dpynum != dpynum:
            continue

        if entry.family == XAUTH_FAMILY_IPV4:
            if not ipv4_addrs:
                ipv4_addrs = yield from _lookup_host(loop, host,
                                                     socket.AF_INET)

            addr = socket.inet_ntop(socket.AF_INET, entry.addr)
            match = addr in ipv4_addrs
        elif entry.family == XAUTH_FAMILY_IPV6:
            if not ipv6_addrs:
                ipv6_addrs = yield from _lookup_host(loop, host,
                                                     socket.AF_INET6)

            addr = socket.inet_ntop(socket.AF_INET6, entry.addr)
            match = addr in ipv6_addrs
        elif entry.family == XAUTH_FAMILY_HOSTNAME:
            match = entry.addr == host.encode('idna')
        elif entry.family == XAUTH_FAMILY_WILD:
            match = True
        else:
            match = False

        if match:
            return entry.proto, entry.data

    raise ValueError('No xauth entry found for display')

@asyncio.coroutine
def update_xauth(loop, auth_path, host, dpynum, auth_proto, auth_data):
    """Update Xauthority data for the specified display"""

    if host.startswith('/') or host in ('', 'unix', 'localhost'):
        host = socket.gethostname()

    host = host.encode('idna')
    dpynum = str(dpynum).encode('ascii')

    auth_path = get_xauth_path(auth_path)
    new_auth_path = auth_path + XAUTH_LOCK_SUFFIX
    new_file = None

    try:
        if time.time() - os.stat(new_auth_path).st_ctime > XAUTH_LOCK_DEAD:
            os.unlink(new_auth_path)
    except FileNotFoundError:
        pass

    for _ in range(XAUTH_LOCK_TRIES):
        try:
            new_file = open(new_auth_path, 'xb')
        except FileExistsError:
            yield from asyncio.sleep(XAUTH_LOCK_DELAY, loop=loop)
        else:
            break

    if not new_file:
        raise ValueError('Unable to acquire Xauthority lock')

    new_entry = SSHXAuthorityEntry(XAUTH_FAMILY_HOSTNAME, host, dpynum,
                                   auth_proto, auth_data)

    new_file.write(bytes(new_entry))

    for entry in walk_xauth(auth_path):
        if (entry.family != new_entry.family or entry.addr != new_entry.addr or
                entry.dpynum != new_entry.dpynum):
            new_file.write(bytes(entry))

    new_file.close()

    os.rename(new_auth_path, auth_path)


@asyncio.coroutine
def create_x11_client_listener(loop, display, auth_path):
    """Create a listener to accept X11 connections forwarded over SSH"""

    host, dpynum, _ = _parse_display(display)

    auth_proto, auth_data = yield from lookup_xauth(loop, auth_path,
                                                    host, dpynum)

    return SSHX11ClientListener(loop, host, dpynum, auth_proto, auth_data)


@asyncio.coroutine
def create_x11_server_listener(conn, loop, auth_path, auth_proto, auth_data):
    """Create a listener to forward X11 connections over SSH"""

    for dpynum in range(X11_DISPLAY_START, X11_MAX_DISPLAYS):
        try:
            tcp_listener = yield from create_tcp_forward_listener(
                conn, loop, conn.create_x11_connection,
                X11_LISTEN_HOST, X11_BASE_PORT + dpynum)
        except OSError:
            continue

        display = '%s:%d' % (X11_LISTEN_HOST, dpynum)

        try:
            yield from update_xauth(loop, auth_path, X11_LISTEN_HOST, dpynum,
                                    auth_proto, auth_data)
        except ValueError:
            tcp_listener.close()
            break

        return SSHX11ServerListener(tcp_listener, display)

    return None
