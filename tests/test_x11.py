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

"""Unit tests for AsyncSSH X11 forwarding"""

import asyncio
import binascii
import os
import socket

from unittest.mock import patch

import asyncssh

from asyncssh.x11 import XAUTH_FAMILY_IPV4, XAUTH_FAMILY_DECNET
from asyncssh.x11 import XAUTH_FAMILY_IPV6, XAUTH_FAMILY_HOSTNAME
from asyncssh.x11 import XAUTH_FAMILY_WILD, XAUTH_PROTO_COOKIE, X11_BASE_PORT
from asyncssh.x11 import SSHXAuthorityEntry, SSHX11ClientListener

from .server import Server, ServerTestCase
from .util import asynctest


_AUTH_DATA_LEN = 16


@asyncio.coroutine
def _create_process(conn, command=None, x11_display='test:0', **kwargs):
    """Create a client process with X11 forwarding enabled"""

    return (yield from conn.create_process(command, x11_forwarding=True,
                                           x11_display=x11_display, **kwargs))


class _X11Peer:
    """Peer representing X server to forward connections to"""

    expected_auth = b''

    @classmethod
    @asyncio.coroutine
    def connect(cls, session_factory, host, port):
        """Simulate connecting to an X server"""

        # pylint: disable=unused-argument

        if port == X11_BASE_PORT:
            return None, cls()
        else:
            raise OSError('Connection refused')

    def __init__(self):
        self._peer = None
        self._check_auth = True

    def set_peer(self, peer):
        """Set the peer forwarder to exchange data with"""

        self._peer = peer

    def write(self, data):
        """Consume data from the peer"""

        if self._check_auth:
            match = data[32:48] == self.expected_auth
            self._peer.write(b'\x01' if match else b'\xff')
            self._check_auth = False
        else:
            self._peer.write(data)

    def write_eof(self):
        """Consume EOF from the peer"""

        pass # pragma: no cover

    def was_eof_received(self):
        """Report that an incoming EOF has not been reeceived"""

        # pylint: disable=no-self-use

        return False # pragma: no cover

    def pause_reading(self):
        """Ignore flow control requests"""

        # pylint: disable=no-self-use

        pass # pragma: no cover

    def resume_reading(self):
        """Ignore flow control requests"""

        # pylint: disable=no-self-use

        pass # pragma: no cover

    def close(self):
        """Consume close request"""

        pass # pragma: no cover


class _X11ClientListener(SSHX11ClientListener):
    """Unit test X server to forward connections to"""

    @asyncio.coroutine
    def forward_connection(self):
        """Forward a connection to the this server"""

        self._connect_coro = _X11Peer.connect

        return super().forward_connection()

class _X11ServerChannel(asyncssh.SSHServerChannel):
    """Unit test X11 forwarding server channel"""

    def _process_x11_req_request(self, packet):
        """Process request to enable X11 forwarding"""

        # pylint: disable=no-self-use

        _ = packet.get_boolean()                        # single_connection
        auth_proto = packet.get_string()
        auth_data = packet.get_string()
        screen = packet.get_uint32()

        packet.check_end()

        if screen != 0:
            return False

        _X11Server.auth_proto = auth_proto
        _X11Server.auth_data = binascii.a2b_hex(auth_data)

        return True


class _X11Server(Server):
    """Server for testing AsyncSSH X11 forwarding"""

    auth_proto = b''
    auth_data = b''

    @staticmethod
    def _uint16(value, endian):
        """Encode a 16-bit value using the specified endianness"""

        if endian == 'B':
            return bytes((value >> 8, value & 255))
        else:
            return bytes((value & 255, value >> 8))

    @staticmethod
    def _pad(data):
        """Pad a string to a multiple of 4 bytes"""

        length = len(data) % 4
        return data + ((4 - length) * b'\00' if length else b'')

    def _open_x11(self, endian, bad):
        """Open an X11 connection back to the client"""

        try:
            reader, writer = yield from self._conn.open_x11_connection()
        except asyncssh.ChannelOpenError:
            return 2

        auth_data = bytearray(self.auth_data)
        if bad:
            auth_data[-1] ^= 0xff

        request = b''.join((endian.encode('ascii'), b'\x00',
                            self._uint16(11, endian),
                            self._uint16(0, endian),
                            self._uint16(len(self.auth_proto), endian),
                            self._uint16(len(self.auth_data), endian),
                            b'\x00\x00', self._pad(self.auth_proto),
                            self._pad(auth_data)))

        writer.write(request[:24])
        yield from asyncio.sleep(0.1)
        writer.write(request[24:])

        result = yield from reader.read(1)

        if result == b'\x01':
            writer.write(b'\x00')

        return result[0]

    @asyncio.coroutine
    def _begin_session(self, stdin, stdout, stderr):
        """Begin processing a new session"""

        # pylint: disable=unused-argument

        action = stdin.channel.get_command()

        if action:
            if action.startswith('connect '):
                endian = action[8:9]
                bad = bool(action[9:] == 'X')

                result = yield from self._open_x11(endian, bad)
                stdin.channel.exit(result)
            elif action == 'sleep':
                yield from asyncio.sleep(0.1)
            else:
                stdin.channel.exit(255)

        stdin.channel.close()
        yield from stdin.channel.wait_closed()

    def session_requested(self):
        return self._begin_session


@patch('asyncssh.connection.SSHServerChannel', _X11ServerChannel)
@patch('asyncssh.connection.SSHX11ClientListener', _X11ClientListener)
class _TestX11(ServerTestCase):
    """Unit tests for AsyncSSH X11 forwarding"""

    @classmethod
    def setUpClass(cls):
        """Create Xauthority file needed for test"""

        super().setUpClass()

        auth_data = os.urandom(_AUTH_DATA_LEN)

        with open('.Xauthority', 'wb') as f:
            f.write(SSHXAuthorityEntry(XAUTH_FAMILY_HOSTNAME, b'test',
                                       b'1', XAUTH_PROTO_COOKIE,
                                       os.urandom(_AUTH_DATA_LEN)).to_bytes())

            f.write(SSHXAuthorityEntry(XAUTH_FAMILY_HOSTNAME, b'test',
                                       b'0', XAUTH_PROTO_COOKIE,
                                       auth_data).to_bytes())

            f.write(SSHXAuthorityEntry(XAUTH_FAMILY_IPV4,
                                       socket.inet_pton(socket.AF_INET,
                                                        '0.0.0.2'),
                                       b'0', XAUTH_PROTO_COOKIE,
                                       auth_data).to_bytes())

            f.write(SSHXAuthorityEntry(XAUTH_FAMILY_IPV4,
                                       socket.inet_pton(socket.AF_INET,
                                                        '0.0.0.1'),
                                       b'0', XAUTH_PROTO_COOKIE,
                                       auth_data).to_bytes())

            f.write(SSHXAuthorityEntry(XAUTH_FAMILY_IPV6,
                                       socket.inet_pton(socket.AF_INET6,
                                                        '::2'),
                                       b'0', XAUTH_PROTO_COOKIE,
                                       auth_data).to_bytes())

            f.write(SSHXAuthorityEntry(XAUTH_FAMILY_IPV6,
                                       socket.inet_pton(socket.AF_INET6,
                                                        '::1'),
                                       b'0', XAUTH_PROTO_COOKIE,
                                       auth_data).to_bytes())

            # Added to cover case where we don't match on address family
            f.write(SSHXAuthorityEntry(XAUTH_FAMILY_DECNET, b'test',
                                       b'0', XAUTH_PROTO_COOKIE,
                                       auth_data).to_bytes())

            # Wildcard address family match
            f.write(SSHXAuthorityEntry(XAUTH_FAMILY_WILD, b'',
                                       b'0', XAUTH_PROTO_COOKIE,
                                       auth_data).to_bytes())

        with open('.Xauthority-empty', 'wb') as f:
            pass

        with open('.Xauthority-corrupted', 'wb') as f:
            f.write(b'\x00\x00\x00')

        _X11Peer.expected_auth = auth_data

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (yield from cls.create_server(_X11Server))

    @asyncio.coroutine
    def _check_x11(self, command=None, *, exc=None, exit_status=None, **kwargs):
        """Check requesting X11 forwarding"""

        with (yield from self.connect()) as conn:
            if exc:
                with self.assertRaises(exc):
                    yield from _create_process(conn, command, **kwargs)
            else:
                proc = yield from _create_process(conn, command, **kwargs)

                yield from proc.wait()

                self.assertEqual(proc.exit_status, exit_status)

        yield from conn.wait_closed()

    @asynctest
    def test_forward_big(self):
        """Test requesting X11 forwarding with big-endian connect"""

        yield from self._check_x11('connect B', exit_status=1,
                                   x11_display='test:0.0',
                                   x11_single_connection=True)

    @asynctest
    def test_forward_little(self):
        """Test requesting X11 forwarding with little-endian connect"""

        yield from self._check_x11('connect l', exit_status=1)

    @asynctest
    def test_connection_refused_big(self):
        """Test the X server refusing connection with big-endian connect"""

        yield from self._check_x11('connect B', exit_status=2,
                                   x11_display='test:1')

    @asynctest
    def test_connection_refused_little(self):
        """Test the X server refusing connection with little-endian connect"""

        yield from self._check_x11('connect l', exit_status=2,
                                   x11_display='test:1')

    @asynctest
    def test_bad_auth_big(self):
        """Test sending bad auth data with big-endian connect"""

        yield from self._check_x11('connect BX', exit_status=0)

    @asynctest
    def test_bad_auth_little(self):
        """Test sending bad auth data with little-endian connect"""

        yield from self._check_x11('connect lX', exit_status=0)

    @asynctest
    def test_ipv4_address(self):
        """Test matching against an IPv4 address"""

        yield from self._check_x11(x11_display='0.0.0.1:0')

    @asynctest
    def test_ipv6_address(self):
        """Test matching against an IPv6 address"""

        yield from self._check_x11(x11_display='[::1]:0')

    @asynctest
    def test_wildcard_address(self):
        """Test matching against a wildcard host entry"""

        yield from self._check_x11(x11_display='wild:0')

    @asynctest
    def test_local_server(self):
        """Test matching against a local X server"""

        yield from self._check_x11(x11_display=':0')

    @asynctest
    def test_domain_socket(self):
        """Test matching against an explicit domain socket"""

        yield from self._check_x11(x11_display='/test:0')

    @asynctest
    def test_display_environment(self):
        """Test getting X11 display from the environment"""

        os.environ['DISPLAY'] = 'test:0'

        yield from self._check_x11(x11_display=None)

        del os.environ['DISPLAY']

    @asynctest
    def test_display_not_set(self):
        """Test requesting X11 forwarding with no display set"""

        yield from self._check_x11(exc=ValueError, x11_display=None)

    @asynctest
    def test_forwarding_denied(self):
        """Test SSH server denying X11 forwarding"""

        yield from self._check_x11(exc=asyncssh.ChannelOpenError,
                                   x11_display='test:0.1')

    @asynctest
    def test_xauth_environment(self):
        """Test getting Xauthority path from the environment"""

        os.environ['XAUTHORITY'] = '.Xauthority'

        yield from self._check_x11()

        del os.environ['XAUTHORITY']

    @asynctest
    def test_no_xauth_match(self):
        """Test no xauth match"""

        yield from self._check_x11(exc=ValueError, x11_display='no_match:1')

    @asynctest
    def test_invalid_display(self):
        """Test invalid X11 display value"""

        yield from self._check_x11(exc=ValueError, x11_display='test')

    @asynctest
    def test_xauth_missing(self):
        """Test missing .Xauthority file"""

        yield from self._check_x11(exc=ValueError,
                                   x11_auth_path='.Xauthority-missing')

    @asynctest
    def test_xauth_empty(self):
        """Test empty .Xauthority file"""

        yield from self._check_x11(exc=ValueError,
                                   x11_auth_path='.Xauthority-empty')

    @asynctest
    def test_xauth_corrupted(self):
        """Test .Xauthority file with corrupted entry"""

        yield from self._check_x11(exc=ValueError,
                                   x11_auth_path='.Xauthority-corrupted')

    @asynctest
    def test_multiple_sessions(self):
        """Test requesting X11 forwarding from two different sessions"""

        with (yield from self.connect()) as conn:
            yield from _create_process(conn, x11_display='test:0')

            yield from _create_process(conn, x11_display='test:0')

        yield from conn.wait_closed()

    @asynctest
    def test_simultaneous_sessions(self):
        """Test X11 forwarding from multiple sessions simultaneously"""

        with (yield from self.connect()) as conn:
            yield from _create_process(conn, 'sleep', x11_display='test:0')
            yield from _create_process(conn, 'sleep', x11_display='test:0')

        yield from conn.wait_closed()

    @asynctest
    def test_consecutive_different_servers(self):
        """Test X11 forwarding to different X servers consecutively"""

        with (yield from self.connect()) as conn:
            proc = yield from _create_process(conn, x11_display='test:0')
            yield from proc.wait()

            yield from _create_process(conn, x11_display='test1:0')

        yield from conn.wait_closed()

    @asynctest
    def test_simultaneous_different_servers(self):
        """Test X11 forwarding to different X servers simultaneously"""

        with (yield from self.connect()) as conn:
            yield from _create_process(conn, 'sleep', x11_display='test:0')

            with self.assertRaises(ValueError):
                yield from _create_process(conn, x11_display='test1:0')

        yield from conn.wait_closed()

    @asynctest
    def test_forwarding_disabled(self):
        """Test an X11 request coming in with forwarding disabled"""

        with (yield from self.connect()) as conn:
            result = yield from conn.run('connect l')
            self.assertEqual(result.exit_status, 2)

        yield from conn.wait_closed()

    @asynctest
    def test_unknown_action(self):
        """Test unknown action"""

        with (yield from self.connect()) as conn:
            result = yield from conn.run('unknown')
            self.assertEqual(result.exit_status, 255)

        yield from conn.wait_closed()
