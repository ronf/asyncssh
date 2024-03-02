# Copyright (c) 2024 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Unit tests for AsyncSSH TUN/TAP support"""

import asyncio
import builtins
import errno
import socket
import struct
import sys

from unittest import skipIf, skipUnless
from unittest.mock import patch

import asyncssh
from asyncssh.tuntap import IFF_FMT, LINUX_IFF_TUN

from .server import Server, ServerTestCase
from .util import asynctest

if sys.platform != 'win32': # pragma: no branch
    import fcntl


_orig_funcs = {}


class _TunTapSocketMock:
    """TunTap socket mock"""

    def ioctl(self, request, arg):
        """Ignore ioctl requests to bring interface up"""

        # pylint: disable=no-self-use,unused-argument

        return arg

    def close(self):
        """Close this mock"""

        # pylint: disable=no-self-use


class _TunTapMock:
    """Common TUN/TAP mock"""

    _from_intf = {}

    def __init__(self, interface=None):
        if interface in self._from_intf:
            raise OSError(errno.EBUSY, 'Device busy')

        self._loop = asyncio.get_event_loop()

        self._sock1, self._sock2 = socket.socketpair(type=socket.SOCK_DGRAM)
        self._sock2.setblocking(False)

        self._interface = interface

        if interface:
            self._from_intf[interface] = self

    @classmethod
    def lookup_intf(cls, interface):
        """Look up mock by interface"""

        return cls._from_intf[interface]

    def fileno(self):
        """Return the fileno of sock1"""

        return self._sock1.fileno()

    def setblocking(self, blocking):
        """Set blocking mode on the socket"""

        self._sock1.setblocking(blocking)

    async def get_packets(self, count):
        """Get packets written to the TUN/TAP"""

        return [await self._loop.sock_recv(self._sock2, 65536)
                for _ in range(count)]

    def put_packets(self, packets):
        """Put packets for the TUN/TAP to read"""

        for packet in packets:
            self._sock2.send(packet)

    def read(self, size=-1):
        """Read a packet"""

        return self._sock1.recv(size)

    def write(self, packet):
        """Write a packet"""

        return self._sock1.send(packet)

    def close(self):
        """Close this mock"""

        self._from_intf.pop(self._interface, None)

        self._sock2.send(b'')
        self._sock1.close()
        self._sock2.close()


class _TunTapOSXMock(_TunTapMock):
    """TunTapOSX mock"""

    disable = False

    def __init__(self, name):
        if self.disable:
            raise OSError(errno.ENOENT, 'No such device')

        interface = name[5:]

        if int(interface[3:]) >= 16:
            raise OSError(errno.ENOENT, 'No such device')

        super().__init__(interface)


class _DarwinUTunMock(_TunTapMock):
    """Darwin UTun mock"""

    _AF_INET_PREFIX = socket.AF_INET.to_bytes(4, 'big')

    def __init__(self):
        super().__init__()

        self._unit = None

    def ioctl(self, request, arg):
        """Respond to DARWIN_CTLIOCGINFO request"""

        # pylint: disable=no-self-use,unused-argument

        return arg

    def connect(self, addr):
        """Connect to requested unit"""

        _, unit = addr

        if unit == 0:
            for unit in range(16):
                interface = f'utun{unit}'

                if interface not in self._from_intf:
                    break
            else:
                raise OSError(errno.EBUSY, 'No utun devices available')
        elif unit <= 16:
            unit -= 1
            interface = f'utun{unit}'

            if interface in self._from_intf:
                raise OSError(errno.EBUSY, 'Device busy')
        else:
            raise OSError(errno.ENOENT, 'No such device')

        self._unit = unit
        self._interface = interface
        self._from_intf[interface] = self

        return 0

    def getpeername(self):
        """Return utun unit"""

        return (0, self._unit + 1)

    def send(self, packet):
        """Send a packet"""

        return super().write(packet[4:])

    def recv(self, size):
        """Receive a packet"""

        return self._AF_INET_PREFIX + self.read(size)


class _LinuxMock(_TunTapMock):
    """Linux TUN/TAP mock"""

    def __init__(self):
        super().__init__()

        self._sock1.setblocking(False)

    def ioctl(self, request, arg):
        """Respond to LINUX_TUNSETIFF request"""

        # pylint: disable=unused-argument

        name, flags = struct.unpack(IFF_FMT, arg)

        if name[0] == 0:
            prefix = 'tun' if flags & LINUX_IFF_TUN else 'tap'

            for unit in range(16):
                interface = f'{prefix}{unit}'

                if interface not in self._from_intf:
                    break
            else:
                self.close()
                raise OSError(errno.EBUSY, 'No tun devices available')

            arg = struct.pack(IFF_FMT, interface.encode(), flags)
        else:
            interface = name.strip(b'\0').decode()
            unit = int(interface[3:])

            if unit >= 16:
                raise OSError(errno.ENOENT, 'No such device')

        self._interface = interface
        self._from_intf[interface] = self

        return arg

    def read(self, size=-1):
        """Read a packet"""

        try:
            return super().read(size)
        except BlockingIOError:
            return None


def _open(name, mode, *args, **kwargs):
    """Mock file open"""

    name = str(name)

    if name.startswith('/dev/tun') or name.startswith('/dev/tap'):
        return _TunTapOSXMock(name)
    elif name == '/dev/net/tun':
        return _LinuxMock()
    else:
        return _orig_funcs['open'](name, mode, *args, **kwargs)


# pylint: disable=redefined-builtin
def _socket(family=socket.AF_INET, type=socket.SOCK_STREAM,
            proto=0, fileno=None):
    """Mock socket creation"""

    if hasattr(socket, 'PF_SYSTEM') and family == socket.PF_SYSTEM and \
            type == socket.SOCK_DGRAM and proto == socket.SYSPROTO_CONTROL:
        return _DarwinUTunMock()
    elif family == socket.AF_INET and type == socket.SOCK_DGRAM:
        return _TunTapSocketMock()
    else:
        return _orig_funcs['socket'](family, type, proto, fileno)


def _ioctl(file, request, arg):
    """Mock ioctl"""

    if isinstance(file, (_DarwinUTunMock, _LinuxMock, _TunTapSocketMock)):
        return file.ioctl(request, arg)
    else: # pragma: no cover
        return _orig_funcs['ioctl'](file, request, arg)


async def get_packets(interface, count):
    """Return TUN/TAP packets written"""

    return await _TunTapMock.lookup_intf(interface).get_packets(count)


def put_packets(interface, packets):
    """Feed packets to a TUN/TAP mock"""

    _TunTapMock.lookup_intf(interface).put_packets(packets)


def patch_tuntap(cls):
    """Decorator to stub out TUN/TAP functions"""

    _orig_funcs['open'] = builtins.open
    _orig_funcs['socket'] = socket.socket

    cls = patch('builtins.open', _open)(cls)
    cls = patch('socket.socket', _socket)(cls)

    if sys.platform != 'win32': # pragma: no branch
        _orig_funcs['ioctl'] = fcntl.ioctl
        cls = patch('fcntl.ioctl', _ioctl)(cls)

    return cls


class _EchoSession(asyncssh.SSHTunTapSession):
    """Echo packets on a TUN session"""

    def __init__(self):
        self._chan = None

    def connection_made(self, chan):
        """Handle session open"""

        self._chan = chan

    def data_received(self, data, datatype):
        """Handle data from the channel"""

        self._chan.write(data)

    def eof_received(self):
        """Handle EOF from the channel"""

        self._chan.write_eof()


class _TunTapServer(Server):
    """Server for testing TUN/TAP functions"""

    async def _echo_handler(self, reader, writer):
        """Echo packets on a TUN session"""

        try:
            async for packet in reader:
                writer.write(packet)
        finally:
            writer.close()

    def tun_requested(self, unit):
        """Handle TUN requests"""

        if unit is None or unit <= 32:
            return True
        elif unit == 33:
            return _EchoSession()
        elif unit == 34:
            return (self._conn.create_tuntap_channel(), _EchoSession())
        elif unit == 35:
            return self._echo_handler
        else:
            return False

    def tap_requested(self, unit):
        """Handle TAP requests"""

        return True


@skipIf(sys.platform == 'win32', 'skip TUN/TAP tests on Windows')
@patch_tuntap
class _TestTunTap(ServerTestCase):
    """Unit tests for TUN/TAP functions"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server to connect to"""

        #import asyncssh, logging
        #logging.basicConfig(level='DEBUG')
        #asyncssh.set_debug_level(2)

        return await cls.create_server(
            _TunTapServer, authorized_client_keys='authorized_keys')

    async def _check_tuntap(self, coro, interface):
        """Check sending data on a TUN or TAP channel"""

        reader, writer = await coro

        try:
            packets = [b'123', b'456', b'789']
            count = len(packets)

            for packet in packets:
                writer.write(packet)

            self.assertEqual((await get_packets(interface, count)), packets)

            put_packets(interface, packets)

            for packet in packets:
                self.assertEqual((await reader.read()), packet)
        finally:
            writer.close()

    async def _check_tuntap_forward(self, coro, remote_interface):
        """Check sending data on a TUN or TAP channel"""

        async with coro as forw:
            local_interface = forw.get_extra_info('interface')

            packets = [b'123', b'456', b'789']
            count = len(packets)

            put_packets(local_interface, packets)

            self.assertEqual((await get_packets(remote_interface, count)),
                              packets)

            put_packets(remote_interface, packets)

            self.assertEqual((await get_packets(local_interface, count)),
                              packets)

    async def _check_tuntap_echo(self, coro):
        """Check echoing of packets on a TUN channel"""

        reader, writer = await coro

        try:
            writer.write(b'123')
            self.assertEqual((await reader.read()), b'123')
            writer.write_eof()
            self.assertEqual((await reader.read()), b'')
        finally:
            writer.close()
            await writer.wait_closed()

    @skipUnless(sys.platform == 'darwin', 'only run TapTunOSX tests on macOS')
    @asynctest
    async def test_darwin_open_tun(self):
        """Test sending packets on a layer 3 tunnel on macOS"""

        async with self.connect() as conn:
            await self._check_tuntap(conn.open_tun(), 'tun0')

    @skipUnless(sys.platform == 'darwin', 'only run TapTunOSX tests on macOS')
    @asynctest
    async def test_darwin_open_tun_specific_unit(self):
        """Test sending on a layer 3 tunnel with specific unit on macOS"""

        async with self.connect() as conn:
            await self._check_tuntap(conn.open_tun(0), 'tun0')

    @skipUnless(sys.platform == 'darwin', 'only run TapTunOSX tests on macOS')
    @asynctest
    async def test_darwin_open_tun_error(self):
        """Test returning an open error on a layer 3 tunnel on macOS"""

        with self.assertRaises(asyncssh.ChannelOpenError):
            async with self.connect() as conn:
                await conn.open_tun(32)

    @skipUnless(sys.platform == 'darwin', 'only run utun tests on macOS')
    @asynctest
    async def test_darwin_open_utun(self):
        """Test sending packets on a layer 3 tunnel using UTun on macOS"""

        async with self.connect() as conn:
            await self._check_tuntap(conn.open_tun(16), 'utun0')

    @skipUnless(sys.platform == 'darwin', 'only run utun tests on macOS')
    @asynctest
    async def test_darwin_failover_to_utun(self):
        """Test failing over from TunTapOSX to UTun on macOS"""

        try:
            _TunTapOSXMock.disable = True

            async with self.connect() as conn:
                await self._check_tuntap(conn.open_tun(), 'utun0')
        finally:
            _TunTapOSXMock.disable = False

    @skipUnless(sys.platform == 'darwin', 'only run utun tests on macOS')
    @asynctest
    async def test_darwin_utun_in_use(self):
        """Test UTun device already in use on macOS"""

        async with self.connect() as conn:
            _, writer = await conn.open_tun(16)

            try:
                with self.assertRaises(asyncssh.ChannelOpenError):
                    await conn.open_tun(16)
            finally:
                writer.close()
                await writer.wait_closed()

    @skipUnless(sys.platform == 'darwin', 'only run utun tests on macOS')
    @asynctest
    async def test_darwin_utun_all_in_use(self):
        """Test all UTun devices already in use on macOS"""

        async with self.connect() as conn:
            writers = []

            try:
                for unit in range(32):
                    _, writer = await conn.open_tun(unit)
                    writers.append(writer)

                with self.assertRaises(asyncssh.ChannelOpenError):
                    await conn.open_tun()
            finally:
                for writer in writers:
                    writer.close()
                    await writer.wait_closed()

    @skipUnless(sys.platform == 'darwin', 'only run TapTunOSX tests on macOS')
    @asynctest
    async def test_darwin_open_tap(self):
        """Test sending packets on a layer 2 tunnel on macOS"""

        async with self.connect() as conn:
            await self._check_tuntap(conn.open_tap(), 'tap0')

    @skipUnless(sys.platform == 'darwin', 'only run TapTunOSX tests on macOS')
    @asynctest
    async def test_darwin_open_tap_unavailable(self):
        """Test TunTapOSX not being available on macOS"""

        try:
            _TunTapOSXMock.disable = True

            with self.assertRaises(asyncssh.ChannelOpenError):
                async with self.connect() as conn:
                    await conn.open_tap()
        finally:
            _TunTapOSXMock.disable = False

    @skipUnless(sys.platform == 'darwin', 'only run TapTunOSX tests on macOS')
    @asynctest
    async def test_darwin_open_tap_error(self):
        """Test sending packets on a layer 2 tunnel on macOS"""

        with self.assertRaises(asyncssh.ChannelOpenError):
            async with self.connect() as conn:
                await conn.open_tap(16)

    @skipUnless(sys.platform == 'darwin', 'only run TapTunOSX tests on macOS')
    @asynctest
    async def test_darwin_forward_tun(self):
        """Test forwarding packets on a layer 3 tunnel on macOS"""

        async with self.connect() as conn:
            await self._check_tuntap_forward(conn.forward_tun(), 'tun0')

    @skipUnless(sys.platform == 'darwin', 'only run utun tests on macOS')
    @asynctest
    async def test_darwin_forward_utun(self):
        """Test forwarding packets on a layer 3 tunnel on macOS"""

        async with self.connect() as conn:
            await self._check_tuntap_forward(conn.forward_tun(16, 17), 'utun1')

    @skipUnless(sys.platform == 'darwin', 'only run TapTunOSX tests on macOS')
    @asynctest
    async def test_darwin_forward_tap(self):
        """Test forwarding packets on a layer 2 tunnel on macOS"""

        async with self.connect() as conn:
            await self._check_tuntap_forward(conn.forward_tap(), 'tap0')

    @patch('sys.platform', 'linux')
    @asynctest
    async def test_linux_open_tun(self):
        """Test sending packets on a layer 3 tunnel on Linux"""

        async with self.connect() as conn:
            await self._check_tuntap(conn.open_tun(), 'tun0')

    @patch('sys.platform', 'linux')
    @asynctest
    async def test_linux_open_tun_specific_unit(self):
        """Test sending on a layer 3 tunnel with specific unit on Linux"""

        async with self.connect() as conn:
            await self._check_tuntap(conn.open_tun(), 'tun0')

    @patch('sys.platform', 'linux')
    @asynctest
    async def test_linux_open_tun_error(self):
        """Test returning an open error on a layer 3 tunnel on Linux"""

        with self.assertRaises(asyncssh.ChannelOpenError):
            async with self.connect() as conn:
                await conn.open_tun(32)

    @patch('sys.platform', 'linux')
    @asynctest
    async def test_linux_open_tap(self):
        """Test sending packets on a layer 2 tunnel on Linux"""

        async with self.connect() as conn:
            await self._check_tuntap(conn.open_tap(), 'tap0')

    @patch('sys.platform', 'linux')
    @asynctest
    async def test_linux_forward_tun(self):
        """Test forwarding packets on a layer 3 tunnel on Linux"""

        async with self.connect() as conn:
            await self._check_tuntap_forward(conn.forward_tun(), 'tun0')

    @patch('sys.platform', 'linux')
    @asynctest
    async def test_linux_forward_tap(self):
        """Test forwarding packets on a layer 2 tunnel on Linux"""

        async with self.connect() as conn:
            await self._check_tuntap_forward(conn.forward_tap(), 'tap0')

    @patch('sys.platform', 'linux')
    @asynctest
    async def test_linux_all_in_use(self):
        """Test all TUN devices already in use on Linux"""

        async with self.connect() as conn:
            writers = []

            try:
                for unit in range(16):
                    _, writer = await conn.open_tun(unit)
                    writers.append(writer)

                with self.assertRaises(asyncssh.ChannelOpenError):
                    await conn.open_tun()
            finally:
                for writer in writers:
                    writer.close()
                    await writer.wait_closed()

    @patch('sys.platform', 'xxx')
    @asynctest
    async def test_unknown_platform(self):
        """Test unknown platform"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_tun()

    @asynctest
    async def test_open_tun_echo_session(self):
        """Test an echo session on a layer 3 tunnel"""

        async with self.connect() as conn:
            await self._check_tuntap_echo(conn.open_tun(33))

    @asynctest
    async def test_open_tun_echo_session_channel(self):
        """Test an echo session & channel on a layer 3 tunnel"""

        async with self.connect() as conn:
            await self._check_tuntap_echo(conn.open_tun(34))

    @asynctest
    async def test_open_tun_echo_handler(self):
        """Test an echo stream handler on a layer 3 tunnel"""

        async with self.connect() as conn:
            await self._check_tuntap_echo(conn.open_tun(35))

    @asynctest
    async def test_open_tun_denied(self):
        """Test returning an open error on a layer 3 tunnel"""

        with self.assertRaises(asyncssh.ChannelOpenError):
            async with self.connect() as conn:
                await conn.open_tun(36)

    @asynctest
    async def test_tun_forward_error(self):
        """Test returning a forward error on a layer 3 tunnel"""

        with self.assertRaises(asyncssh.ChannelOpenError):
            async with self.connect() as conn:
                await conn.forward_tun(36)

    @asynctest
    async def test_invalid_tun_mode(self):
        """Test sending an invalid mode in a TUN/TAP request"""

        async with self.connect() as conn:
            chan = conn.create_tuntap_channel()

            with self.assertRaises(asyncssh.ChannelOpenError):
                await chan.open(asyncssh.SSHTunTapSession, 32, 0)
