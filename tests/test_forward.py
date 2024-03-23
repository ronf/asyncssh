# Copyright (c) 2016-2022 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH forwarding API"""

import asyncio
import codecs
import os
import socket
import sys
import unittest

from unittest.mock import patch

import asyncssh
from asyncssh.misc import maybe_wait_closed, write_file
from asyncssh.packet import String, UInt32
from asyncssh.public_key import CERT_TYPE_USER
from asyncssh.socks import SOCKS5, SOCKS5_AUTH_NONE
from asyncssh.socks import SOCKS4_OK_RESPONSE, SOCKS5_OK_RESPONSE_HDR

from .server import Server, ServerTestCase
from .util import asynctest, echo, make_certificate, try_remove


def _echo_non_async(stdin, stdout, stderr=None):
    """Non-async version of echo callback"""

    conn = stdin.get_extra_info('connection')
    conn.create_task(echo(stdin, stdout, stderr))


def _listener(_orig_host, _orig_port):
    """Handle a forwarded TCP/IP connection"""

    return echo


def _listener_non_async(_orig_host, _orig_port):
    """Non-async version of handler for a forwarded TCP/IP connection"""

    return _echo_non_async


def _unix_listener():
    """Handle a forwarded UNIX domain connection"""

    return echo


def _unix_listener_non_async():
    """Non-async version of handler for a forwarded UNIX domain connection"""

    return _echo_non_async


async def _pause(reader, writer):
    """Sleep to allow buffered data to build up and trigger a pause"""

    await asyncio.sleep(0.1)
    await reader.read()
    writer.close()
    await maybe_wait_closed(writer)


async def _async_runtime_error(_reader, _writer):
    """Raise a runtime error"""

    raise RuntimeError('Async internal error')

class _ClientConn(asyncssh.SSHClientConnection):
    """Patched SSH client connection for unit testing"""

    async def make_global_request(self, request, *args):
        """Send a global request and wait for the response"""

        return await self._make_global_request(request, *args)


class _EchoPortListener(asyncssh.SSHListener):
    """A TCP listener which opens a connection that echoes data"""

    def __init__(self, conn):
        super().__init__()

        self._conn = conn

        conn.create_task(self._open_connection())

    async def _open_connection(self):
        """Open a forwarded connection that echoes data"""

        await asyncio.sleep(0.1)
        reader, writer = await self._conn.open_connection('open', 65535)
        await echo(reader, writer)

    def close(self):
        """Stop listening for new connections"""

    async def wait_closed(self):
        """Wait for the listener to close"""


class _EchoPathListener(asyncssh.SSHListener):
    """A UNIX domain listener which opens a connection that echoes data"""

    def __init__(self, conn):
        super().__init__()

        self._conn = conn

        conn.create_task(self._open_connection())

    async def _open_connection(self):
        """Open a forwarded connection that echoes data"""

        await asyncio.sleep(0.1)
        reader, writer = await self._conn.open_unix_connection('open')
        await echo(reader, writer)

    def close(self):
        """Stop listening for new connections"""

    async def wait_closed(self):
        """Wait for the listener to close"""


class _TCPConnectionServer(Server):
    """Server for testing direct and forwarded TCP connections"""

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        """Handle a request to create a new connection"""

        if dest_port == 1:
            return False
        elif dest_port == 7:
            return (self._conn.create_tcp_channel(), echo)
        elif dest_port == 8:
            return _pause
        elif dest_port == 9:
            self._conn.close()
            return (self._conn.create_tcp_channel(), echo)
        elif dest_port == 10:
            return _async_runtime_error
        else:
            return True

    def server_requested(self, listen_host, listen_port):
        """Handle a request to create a new socket listener"""

        if listen_host == 'open':
            return _EchoPortListener(self._conn)
        else:
            return listen_host != 'fail'


class _TCPAsyncConnectionServer(_TCPConnectionServer):
    """Server for testing async direct and forwarded TCP connections"""

    async def server_requested(self, listen_host, listen_port):
        """Handle a request to create a new socket listener"""

        if listen_host == 'open':
            return _EchoPortListener(self._conn)
        else:
            return listen_host != 'fail'


class _TCPAcceptHandlerServer(Server):
    """Server for testing forwarding accept handler"""

    async def server_requested(self, listen_host, listen_port):
        """Handle a request to create a new socket listener"""

        def accept_handler(_orig_host: str, _orig_port: int) -> bool:
            return True

        return accept_handler


class _UNIXConnectionServer(Server):
    """Server for testing direct and forwarded UNIX domain connections"""

    def unix_connection_requested(self, dest_path):
        """Handle a request to create a new UNIX domain connection"""

        if dest_path == '':
            return True
        elif dest_path == '/echo':
            return (self._conn.create_unix_channel(), echo)
        else:
            return False

    def unix_server_requested(self, listen_path):
        """Handle a request to create a new UNIX domain listener"""

        if listen_path == 'open':
            return _EchoPathListener(self._conn)
        else:
            return listen_path != 'fail'


class _UNIXAsyncConnectionServer(_UNIXConnectionServer):
    """Server for testing async direct and forwarded UNIX connections"""

    async def unix_server_requested(self, listen_path):
        """Handle a request to create a new UNIX domain listener"""

        if listen_path == 'open':
            return _EchoPathListener(self._conn)
        else:
            return listen_path != 'fail'


class _CheckForwarding(ServerTestCase):
    """Utility functions for AsyncSSH forwarding unit tests"""

    async def _check_echo_line(self, reader, writer,
                               delay=False, encoded=False):
        """Check if an input line is properly echoed back"""

        if delay:
            await asyncio.sleep(delay)

        line = str(id(self)) + '\n'

        if not encoded:
            line = line.encode('utf-8')

        writer.write(line)
        await writer.drain()

        result = await reader.readline()

        writer.close()
        await maybe_wait_closed(writer)

        self.assertEqual(line, result)

    async def _check_echo_block(self, reader, writer):
        """Check if a block of data is properly echoed back"""

        data = 4 * [1025*1024*b'\0']

        writer.writelines(data)
        await writer.drain()
        writer.write_eof()

        result = await reader.read()

        #await reader.channel.wait_closed()
        writer.close()

        self.assertEqual(b''.join(data), result)

    async def _check_local_connection(self, listen_port, delay=None):
        """Open a local connection and test if an input line is echoed back"""

        reader, writer = await asyncio.open_connection('127.0.0.1',
                                                       listen_port)

        await self._check_echo_line(reader, writer, delay=delay)

    async def _check_local_unix_connection(self, listen_path):
        """Open a local connection and test if an input line is echoed back"""

        # pylint doesn't think open_unix_connection exists
        # pylint: disable=no-member
        reader, writer = await asyncio.open_unix_connection(listen_path)
        # pylint: enable=no-member

        await self._check_echo_line(reader, writer)


class _TestTCPForwarding(_CheckForwarding):
    """Unit tests for AsyncSSH TCP connection forwarding"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports TCP connection forwarding"""

        return (await cls.create_server(
            _TCPConnectionServer, authorized_client_keys='authorized_keys'))

    async def _check_connection(self, conn, dest_host='',
                                dest_port=7, **kwargs):
        """Open a connection and test if a block of data is echoed back"""

        reader, writer = await conn.open_connection(dest_host, dest_port,
                                                    *kwargs)

        await self._check_echo_block(reader, writer)

    @asynctest
    async def test_ssh_create_tunnel(self):
        """Test creating a tunneled SSH connection"""

        async with self.connect() as conn:
            conn2, _ = await conn.create_ssh_connection(
                None, self._server_addr, self._server_port)

            async with conn2:
                await self._check_connection(conn2)

    @asynctest
    async def test_ssh_connect_tunnel(self):
        """Test connecting a tunneled SSH connection"""

        async with self.connect() as conn:
            async with conn.connect_ssh(self._server_addr,
                                        self._server_port) as conn2:
                await self._check_connection(conn2)

    @asynctest
    async def test_ssh_connect_tunnel_string(self):
        """Test connecting a tunneled SSH connection via string"""

        async with self.connect(tunnel='%s:%d' % (self._server_addr,
                                                  self._server_port)) as conn:
            await self._check_connection(conn)

    @asynctest
    async def test_ssh_connect_tunnel_string_failed(self):
        """Test failed connection on a tunneled SSH connection via string"""

        with self.assertRaises(asyncssh.ChannelOpenError):
            await asyncssh.connect('\xff',
                                   tunnel='%s:%d' % (self._server_addr,
                                                     self._server_port))

    @asynctest
    async def test_proxy_jump(self):
        """Test connecting a tunnneled SSH connection using ProxyJump"""

        write_file('.ssh/config', 'Host target\n'
                   '  Hostname localhost\n'
                   f'  Port {self._server_port}\n'
                   f'  ProxyJump localhost:{self._server_port}\n'
                   'IdentityFile ckey\n', 'w')

        try:
            async with self.connect(host='target', username='ckey'):
                pass
        finally:
            os.remove('.ssh/config')

    @asynctest
    async def test_proxy_jump_multiple(self):
        """Test connecting a tunnneled SSH connection using ProxyJump"""

        write_file('.ssh/config', 'Host target\n'
                   '  Hostname localhost\n'
                   f'  Port {self._server_port}\n'
                   f'  ProxyJump localhost:{self._server_port},'
                   f'localhost:{self._server_port}\n'
                   'IdentityFile ckey\n', 'w')

        try:
            async with self.connect(host='target', username='ckey'):
                pass
        finally:
            os.remove('.ssh/config')

    @asynctest
    async def test_proxy_jump_encrypted_key(self):
        """Test ProxyJump with encrypted client key"""

        write_file('.ssh/config', 'Host *\n'
                   '  User ckey\n'
                   'Host target\n'
                   '  Hostname localhost\n'
                   f'  Port {self._server_port}\n'
                   f'  ProxyJump localhost:{self._server_port}\n'
                   '  IdentityFile ckey_encrypted\n', 'w')

        try:
            async with self.connect(host='target', username='ckey',
                                    client_keys='ckey_encrypted',
                                    passphrase='passphrase'):
                pass
        finally:
            os.remove('.ssh/config')

    @asynctest
    async def test_proxy_jump_encrypted_key_missing_passphrase(self):
        """Test ProxyJump with encrypted client key and missing passphrase"""

        write_file('.ssh/config', 'Host *\n'
                   '  User ckey\n'
                   'Host target\n'
                   '  Hostname localhost\n'
                   f'  Port {self._server_port}\n'
                   f'  ProxyJump localhost:{self._server_port}\n'
                   '  IdentityFile ckey_encrypted\n', 'w')

        try:
            with self.assertRaises(asyncssh.KeyImportError):
                await self.connect(host='target', username='ckey',
                                   client_keys='ckey_encrypted')
        finally:
            os.remove('.ssh/config')

    @asynctest
    async def test_ssh_connect_reverse_tunnel(self):
        """Test creating a tunneled reverse direction SSH connection"""

        server2 = await self.listen_reverse()
        listen_port = server2.sockets[0].getsockname()[1]

        async with self.connect() as conn:
            async with conn.connect_reverse_ssh('127.0.0.1', listen_port,
                                                server_factory=Server,
                                                server_host_keys=['skey']):
                pass

        server2.close()
        await server2.wait_closed()

    @asynctest
    async def test_ssh_listen_tunnel(self):
        """Test opening a tunneled SSH listener"""

        async with self.connect() as conn:
            async with conn.listen_ssh(port=0, server_factory=Server,
                                       server_host_keys=['skey']) as server:
                listen_port = server.get_port()

                self.assertEqual(server.get_addresses(), [('', listen_port)])

                async with asyncssh.connect('127.0.0.1', listen_port,
                                            known_hosts=(['skey.pub'], [], [])):
                    pass

    @asynctest
    async def test_ssh_listen_tunnel_string(self):
        """Test opening a tunneled SSH listener via string"""

        async with self.listen(tunnel='ckey@%s:%d' % (self._server_addr,
                                                      self._server_port),
                               server_factory=Server,
                               server_host_keys=['skey']) as server:
            listen_port = server.get_port()

            async with asyncssh.connect('127.0.0.1', listen_port,
                                        known_hosts=(['skey.pub'], [], [])):
                pass

    @asynctest
    async def test_ssh_listen_tunnel_string_failed(self):
        """Test open failure on a tunneled SSH listener via string"""

        with self.assertRaises(asyncssh.ChannelListenError):
            await asyncssh.listen('\xff',
                                  tunnel='%s:%d' % (self._server_addr,
                                                    self._server_port),
                                  server_factory=Server,
                                  server_host_keys=['skey'])

    @asynctest
    async def test_ssh_listen_tunnel_default_port(self):
        """Test opening a tunneled SSH listener via string without port"""

        with patch('asyncssh.connection.DEFAULT_PORT', self._server_port):
            async with self.listen(tunnel='localhost', server_factory=Server,
                                   server_host_keys=['skey']) as server:
                listen_port = server.get_port()

                async with asyncssh.connect('127.0.0.1', listen_port,
                                            known_hosts=(['skey.pub'], [], [])):
                    pass

    @asynctest
    async def test_ssh_listen_reverse_tunnel(self):
        """Test creating a tunneled reverse direction SSH connection"""

        async with self.connect() as conn:
            async with conn.listen_reverse_ssh(port=0,
                                               known_hosts=(['skey.pub'],
                                                            [], [])) as server2:
                listen_port = server2.get_port()

                async with asyncssh.connect_reverse('127.0.0.1', listen_port,
                                                    server_factory=Server,
                                                    server_host_keys=['skey']):
                    pass

    @asynctest
    async def test_connection(self):
        """Test opening a remote connection"""

        async with self.connect() as conn:
            await self._check_connection(conn)

    @asynctest
    async def test_connection_failure(self):
        """Test failure in opening a remote connection"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_connection('', 0)

    @asynctest
    async def test_connection_rejected(self):
        """Test rejection in opening a remote connection"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_connection('fail', 0)

    @asynctest
    async def test_connection_not_permitted(self):
        """Test permission denied in opening a remote connection"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-port-forwarding': ''})

        async with self.connect(username='ckey', client_keys=[(ckey, cert)],
                                agent_path=None) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_connection('', 7)

    @asynctest
    async def test_connection_not_permitted_open(self):
        """Test open permission denied in opening a remote connection"""

        async with self.connect(username='ckey', client_keys=['ckey'],
                                agent_path=None) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_connection('fail', 7)

    @asynctest
    async def test_connection_invalid_unicode(self):
        """Test opening a connection with invalid Unicode in host"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_connection(b'\xff', 0)

    @asynctest
    async def test_server(self):
        """Test creating a remote listener"""

        async with self.connect() as conn:
            listener = await conn.start_server(_listener, '', 0)
            await self._check_local_connection(listener.get_port())
            listener.close()
            listener.close()
            await listener.wait_closed()
            listener.close()

    @asynctest
    async def test_server_context_manager(self):
        """Test using a remote listener as a context manager"""

        async with self.connect() as conn:
            async with conn.start_server(_listener, '', 0) as listener:
                await self._check_local_connection(listener.get_port())

    @asynctest
    async def test_server_open(self):
        """Test creating a remote listener which uses open_connection"""

        def new_connection(reader, writer):
            """Handle a forwarded TCP/IP connection"""

            waiter.set_result((reader, writer))

        def handler_factory(_orig_host, _orig_port):
            """Handle all connections using new_connection"""

            return new_connection

        async with self.connect() as conn:
            waiter = self.loop.create_future()

            await conn.start_server(handler_factory, 'open', 0)

            reader, writer = await waiter
            await self._check_echo_line(reader, writer)

            # Clean up the listener during connection close

    @asynctest
    async def test_server_non_async(self):
        """Test creating a remote listener using non-async handler"""

        async with self.connect() as conn:
            async with conn.start_server(_listener_non_async,
                                         '', 0) as listener:
                await self._check_local_connection(listener.get_port())

    @asynctest
    async def test_server_failure(self):
        """Test failure in creating a remote listener"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.start_server(_listener, 'fail', 0)

    @asynctest
    async def test_forward_local_port(self):
        """Test forwarding of a local port"""

        async with self.connect() as conn:
            async with conn.forward_local_port('', 0, '', 7) as listener:
                await self._check_local_connection(listener.get_port(),
                                                   delay=0.1)

    @asynctest
    async def test_forward_local_port_accept_handler(self):
        """Test forwarding of a local port with an accept handler"""

        def accept_handler(_orig_host: str, _orig_port: int) -> bool:
            return True

        async with self.connect() as conn:
            async with conn.forward_local_port('', 0, '', 7,
                                               accept_handler) as listener:
                await self._check_local_connection(listener.get_port(),
                                                   delay=0.1)

    @asynctest
    async def test_forward_local_port_accept_handler_denial(self):
        """Test forwarding of a local port with an accept handler denial"""

        async def accept_handler(_orig_host: str, _orig_port: int) -> bool:
            return False

        async with self.connect() as conn:
            async with conn.forward_local_port('', 0, '', 7,
                                               accept_handler) as listener:
                listen_port = listener.get_port()

                reader, writer = await asyncio.open_connection('127.0.0.1',
                                                               listen_port)

                self.assertEqual((await reader.read()), b'')

                writer.close()
                await maybe_wait_closed(writer)

    @unittest.skipIf(sys.platform == 'win32',
                     'skip UNIX domain socket tests on Windows')
    @asynctest
    async def test_forward_local_path_to_port(self):
        """Test forwarding of a local UNIX domain path to a remote TCP port"""

        async with self.connect() as conn:
            async with conn.forward_local_path_to_port('local', '', 7):
                await self._check_local_unix_connection('local')

        try_remove('local')

    @unittest.skipIf(sys.platform == 'win32',
                     'skip UNIX domain socket tests on Windows')
    @asynctest
    async def test_forward_local_path_to_port_failure(self):
        """Test failure forwarding a local UNIX domain path to a TCP port"""

        open('local', 'w').close()

        async with self.connect() as conn:
            with self.assertRaises(OSError):
                await conn.forward_local_path_to_port('local', '', 7)

        try_remove('local')

    @asynctest
    async def test_forward_local_port_pause(self):
        """Test pause during forwarding of a local port"""

        async with self.connect() as conn:
            async with conn.forward_local_port('', 0, '', 8) as listener:
                listen_port = listener.get_port()

                reader, writer = await asyncio.open_connection('127.0.0.1',
                                                               listen_port)

                writer.write(4*1024*1024*b'\0')
                writer.write_eof()
                await reader.read()

                writer.close()
                await maybe_wait_closed(writer)

    @asynctest
    async def test_forward_local_port_failure(self):
        """Test failure in forwarding a local port"""

        async with self.connect() as conn:
            async with conn.forward_local_port('', 0, '', 65535) as listener:
                listen_port = listener.get_port()

                reader, writer = await asyncio.open_connection('127.0.0.1',
                                                               listen_port)

                self.assertEqual((await reader.read()), b'')

                writer.close()
                await maybe_wait_closed(writer)

    @unittest.skipIf(sys.platform == 'win32',
                     'skip dual-stack tests on Windows')
    @asynctest
    async def test_forward_bind_error_ipv4(self):
        """Test error binding a local forwarding port"""

        async with self.connect() as conn:
            async with conn.forward_local_port('0.0.0.0', 0, '', 7) as listener:
                with self.assertRaises(OSError):
                    await conn.forward_local_port('', listener.get_port(),
                                                  '', 7)

    @unittest.skipIf(sys.platform == 'win32',
                     'skip dual-stack tests on Windows')
    @asynctest
    async def test_forward_bind_error_ipv6(self):
        """Test error binding a local forwarding port"""

        async with self.connect() as conn:
            async with conn.forward_local_port('::', 0, '', 7) as listener:
                with self.assertRaises(OSError):
                    await conn.forward_local_port('', listener.get_port(),
                                                  '', 7)

    @unittest.skipIf(sys.platform == 'win32',
                     'skip UNIX domain socket tests on Windows')
    @asynctest
    async def test_forward_port_to_path_bind_error(self):
        """Test error binding a local port forwarding to remote path"""

        async with self.connect() as conn:
            async with conn.forward_local_port('0.0.0.0', 0, '', 7) as listener:
                with self.assertRaises(OSError):
                    await conn.forward_local_port_to_path(
                            '', listener.get_port(), '')

    @asynctest
    async def test_forward_connect_error(self):
        """Test error connecting a local forwarding port"""

        async with self.connect() as conn:
            async with conn.forward_local_port('', 0, '', 1) as listener:
                listen_port = listener.get_port()

                reader, writer = await asyncio.open_connection('127.0.0.1',
                                                               listen_port)
                self.assertEqual((await reader.read()), b'')

                writer.close()
                await maybe_wait_closed(writer)

    @asynctest
    async def test_forward_immediate_eof(self):
        """Test getting EOF before forwarded connection is fully open"""

        async with self.connect() as conn:
            async with conn.forward_local_port('', 0, '', 7) as listener:
                listen_port = listener.get_port()

                _, writer = await asyncio.open_connection('127.0.0.1',
                                                          listen_port)

                writer.close()
                await maybe_wait_closed(writer)
                await asyncio.sleep(0.1)

    @asynctest
    async def test_forward_remote_port(self):
        """Test forwarding of a remote port"""

        server = await asyncio.start_server(echo, None, 0,
                                            family=socket.AF_INET)
        server_port = server.sockets[0].getsockname()[1]

        async with self.connect() as conn:
            async with conn.forward_remote_port(
                    '', 0, '127.0.0.1', server_port) as listener:
                await self._check_local_connection(listener.get_port())

        server.close()
        await server.wait_closed()

    @unittest.skipIf(sys.platform == 'win32',
                     'skip UNIX domain socket tests on Windows')
    @asynctest
    async def test_forward_remote_port_to_path(self):
        """Test forwarding of a remote port to a local UNIX domain socket"""

        server = await asyncio.start_unix_server(echo, 'local')

        async with self.connect() as conn:
            async with conn.forward_remote_port_to_path(
                    '', 0, 'local') as listener:
                await self._check_local_connection(listener.get_port())

        server.close()
        await server.wait_closed()

        try_remove('local')

    @asynctest
    async def test_forward_remote_specific_port(self):
        """Test forwarding of a specific remote port"""

        server = await asyncio.start_server(echo, None, 0,
                                            family=socket.AF_INET)
        server_port = server.sockets[0].getsockname()[1]

        sock = socket.socket()
        sock.bind(('', 0))
        remote_port = sock.getsockname()[1]
        sock.close()

        async with self.connect() as conn:
            async with conn.forward_remote_port(
                    '', remote_port, '127.0.0.1', server_port) as listener:
                await self._check_local_connection(listener.get_port())

        server.close()
        await server.wait_closed()

    @asynctest
    async def test_forward_remote_port_failure(self):
        """Test failure of forwarding a remote port"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.forward_remote_port('', 65536, '', 0)

    @asynctest
    async def test_forward_remote_port_not_permitted(self):
        """Test permission denied in forwarding of a remote port"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-port-forwarding': ''})

        async with self.connect(username='ckey', client_keys=[(ckey, cert)],
                                agent_path=None) as conn:
            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.forward_remote_port('', 0, '', 0)

    @asynctest
    async def test_forward_remote_port_invalid_unicode(self):
        """Test TCP/IP forwarding with invalid Unicode in host"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.forward_remote_port(b'\xff', 0, '', 0)

    @asynctest
    async def test_cancel_forward_remote_port_invalid_unicode(self):
        """Test canceling TCP/IP forwarding with invalid Unicode in host"""

        with patch('asyncssh.connection.SSHClientConnection', _ClientConn):
            async with self.connect() as conn:
                pkttype, _ = await conn.make_global_request(
                    b'cancel-tcpip-forward', String(b'\xff'), UInt32(0))

                self.assertEqual(pkttype, asyncssh.MSG_REQUEST_FAILURE)

    @asynctest
    async def test_add_channel_after_close(self):
        """Test opening a connection after a close"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_connection('', 9)

    @asynctest
    async def test_async_runtime_error(self):
        """Test runtime error in async listener"""

        async with self.connect() as conn:
            reader, _ = await conn.open_connection('', 10)
            with self.assertRaises(asyncssh.ConnectionLost):
                await reader.read()

    @asynctest
    async def test_multiple_global_requests(self):
        """Test sending multiple global requests in parallel"""

        async with self.connect() as conn:
            listeners = await asyncio.gather(
                conn.forward_remote_port('', 0, '', 7),
                conn.forward_remote_port('', 0, '', 7))

            for listener in listeners:
                listener.close()
                await listener.wait_closed()

    @asynctest
    async def test_listener_close_on_conn_close(self):
        """Test listener closes when connection closes"""

        async with self.connect() as conn:
            listener = await conn.forward_local_port('', 0, '', 80)
            await conn.open_connection('', 10)
            await listener.wait_closed()


class _TestTCPForwardingAcceptHandler(_CheckForwarding):
    """Unit tests for TCP forwarding with accept handler"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports TCP connection forwarding"""

        return await cls.create_server(
            _TCPAcceptHandlerServer, authorized_client_keys='authorized_keys')

    @asynctest
    async def test_forward_remote_port_accept_handler(self):
        """Test forwarding of a remote port with accept handler"""

        server = await asyncio.start_server(echo, None, 0,
                                            family=socket.AF_INET)
        server_port = server.sockets[0].getsockname()[1]

        async with self.connect() as conn:
            async with conn.forward_remote_port(
                    '', 0, '127.0.0.1', server_port) as listener:
                await self._check_local_connection(listener.get_port())

        server.close()
        await server.wait_closed()


class _TestAsyncTCPForwarding(_TestTCPForwarding):
    """Unit tests for AsyncSSH TCP connection forwarding with async return"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports TCP connection forwarding"""

        return await cls.create_server(
            _TCPAsyncConnectionServer, authorized_client_keys='authorized_keys')


@unittest.skipIf(sys.platform == 'win32',
                 'skip UNIX domain socket tests on Windows')
class _TestUNIXForwarding(_CheckForwarding):
    """Unit tests for AsyncSSH UNIX connection forwarding"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports UNIX connection forwarding"""

        return (await cls.create_server(
            _UNIXConnectionServer, authorized_client_keys='authorized_keys'))

    async def _check_unix_connection(self, conn, dest_path='/echo', **kwargs):
        """Open a UNIX connection and test if an input line is echoed back"""

        reader, writer = await conn.open_unix_connection(dest_path,
                                                         encoding='utf-8',
                                                         *kwargs)

        await self._check_echo_line(reader, writer, encoded=True)

    @asynctest
    async def test_unix_connection(self):
        """Test opening a remote UNIX connection"""

        async with self.connect() as conn:
            await self._check_unix_connection(conn)

    @asynctest
    async def test_unix_connection_failure(self):
        """Test failure in opening a remote UNIX connection"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_unix_connection('')

    @asynctest
    async def test_unix_connection_rejected(self):
        """Test rejection in opening a remote UNIX connection"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_unix_connection('/fail')

    @asynctest
    async def test_unix_connection_not_permitted(self):
        """Test permission denied in opening a remote UNIX connection"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-port-forwarding': ''})

        async with self.connect(username='ckey', client_keys=[(ckey, cert)],
                                agent_path=None) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_unix_connection('/echo')

    @asynctest
    async def test_unix_connection_invalid_unicode(self):
        """Test opening a UNIX connection with invalid Unicode in path"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_unix_connection(b'\xff')

    @asynctest
    async def test_unix_server(self):
        """Test creating a remote UNIX listener"""

        path = os.path.abspath('echo')

        async with self.connect() as conn:
            listener = await conn.start_unix_server(_unix_listener, path)
            await self._check_local_unix_connection('echo')
            listener.close()
            listener.close()
            await listener.wait_closed()
            listener.close()

        try_remove('echo')

    @asynctest
    async def test_unix_server_open(self):
        """Test creating a UNIX listener which uses open_unix_connection"""

        def new_connection(reader, writer):
            """Handle a forwarded UNIX domain connection"""

            waiter.set_result((reader, writer))

        def handler_factory():
            """Handle all connections using new_connection"""

            return new_connection

        async with self.connect() as conn:
            waiter = self.loop.create_future()

            async with conn.start_unix_server(handler_factory, 'open'):
                reader, writer = await waiter
                await self._check_echo_line(reader, writer)

    @asynctest
    async def test_unix_server_non_async(self):
        """Test creating a remote UNIX listener using non-async handler"""

        path = os.path.abspath('echo')

        async with self.connect() as conn:
            async with conn.start_unix_server(_unix_listener_non_async, path):
                await self._check_local_unix_connection('echo')

        try_remove('echo')

    @asynctest
    async def test_unix_server_failure(self):
        """Test failure in creating a remote UNIX listener"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.start_unix_server(_unix_listener, 'fail')

    @asynctest
    async def test_forward_local_path(self):
        """Test forwarding of a local UNIX domain path"""

        async with self.connect() as conn:
            async with conn.forward_local_path('local', '/echo'):
                await self._check_local_unix_connection('local')

        try_remove('local')

    @asynctest
    async def test_forward_local_port_to_path_accept_handler(self):
        """Test forwarding of port to UNIX path with accept handler"""

        def accept_handler(_orig_host: str, _orig_port: int) -> bool:
            return True

        async with self.connect() as conn:
            async with conn.forward_local_port_to_path(
                    '', 0, '/echo', accept_handler) as listener:
                await self._check_local_connection(listener.get_port(),
                                                   delay=0.1)

    @asynctest
    async def test_forward_local_port_to_path_accept_handler_denial(self):
        """Test forwarding of port to UNIX path with accept handler denial"""

        async def accept_handler(_orig_host: str, _orig_port: int) -> bool:
            return False

        async with self.connect() as conn:
            async with conn.forward_local_port_to_path(
                    '', 0, '/echo', accept_handler) as listener:
                listen_port = listener.get_port()

                reader, writer = await asyncio.open_connection('127.0.0.1',
                                                               listen_port)

                self.assertEqual((await reader.read()), b'')

                writer.close()
                await maybe_wait_closed(writer)

    @asynctest
    async def test_forward_local_port_to_path(self):
        """Test forwarding of a local port to a remote UNIX domain socket"""

        async with self.connect() as conn:
            async with conn.forward_local_port_to_path('', 0,
                                                       '/echo') as listener:
                await self._check_local_connection(listener.get_port(),
                                                   delay=0.1)

    @asynctest
    async def test_forward_specific_local_port_to_path(self):
        """Test forwarding of a specific local port to a UNIX domain socket"""

        sock = socket.socket()
        sock.bind(('', 0))
        listen_port = sock.getsockname()[1]
        sock.close()

        async with self.connect() as conn:
            async with conn.forward_local_port_to_path(
                    '', listen_port, '/echo') as listener:
                await self._check_local_connection(listener.get_port(),
                                                   delay=0.1)

    @asynctest
    async def test_forward_remote_path(self):
        """Test forwarding of a remote UNIX domain path"""

        # pylint doesn't think start_unix_server exists
        # pylint: disable=no-member
        server = await asyncio.start_unix_server(echo, 'local')
        # pylint: enable=no-member

        path = os.path.abspath('echo')

        async with self.connect() as conn:
            async with conn.forward_remote_path(path, 'local'):
                await self._check_local_unix_connection('echo')

        server.close()
        await server.wait_closed()

        try_remove('echo')
        try_remove('local')

    @asynctest
    async def test_forward_remote_path_to_port(self):
        """Test forwarding of a remote UNIX domain path to a local TCP port"""

        server = await asyncio.start_server(echo, None, 0,
                                            family=socket.AF_INET)
        server_port = server.sockets[0].getsockname()[1]

        path = os.path.abspath('echo')

        async with self.connect() as conn:
            async with conn.forward_remote_path_to_port(
                    path, '127.0.0.1', server_port):
                await self._check_local_unix_connection('echo')

        server.close()
        await server.wait_closed()

        try_remove('echo')

    @asynctest
    async def test_forward_remote_path_failure(self):
        """Test failure of forwarding a remote UNIX domain path"""

        open('echo', 'w').close()

        path = os.path.abspath('echo')

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.forward_remote_path(path, 'local')

        try_remove('echo')

    @asynctest
    async def test_forward_remote_path_not_permitted(self):
        """Test permission denied in forwarding a remote UNIX domain path"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-port-forwarding': ''})

        async with self.connect(username='ckey', client_keys=[(ckey, cert)],
                                agent_path=None) as conn:
            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.forward_remote_path('', 'local')

    @asynctest
    async def test_forward_remote_path_invalid_unicode(self):
        """Test forwarding a UNIX domain path with invalid Unicode in it"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ChannelListenError):
                await conn.forward_remote_path(b'\xff', 'local')

    @asynctest
    async def test_cancel_forward_remote_path_invalid_unicode(self):
        """Test canceling UNIX forwarding with invalid Unicode in path"""

        with patch('asyncssh.connection.SSHClientConnection', _ClientConn):
            async with self.connect() as conn:
                pkttype, _ = await conn.make_global_request(
                    b'cancel-streamlocal-forward@openssh.com', String(b'\xff'))

                self.assertEqual(pkttype, asyncssh.MSG_REQUEST_FAILURE)


class _TestAsyncUNIXForwarding(_TestUNIXForwarding):
    """Unit tests for AsyncSSH UNIX connection forwarding with async return"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports UNIX connection forwarding"""

        return await cls.create_server(
            _UNIXAsyncConnectionServer,
            authorized_client_keys='authorized_keys')


class _TestSOCKSForwarding(_CheckForwarding):
    """Unit tests for AsyncSSH SOCKS dynamic port forwarding"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports TCP connection forwarding"""

        return (await cls.create_server(
            _TCPConnectionServer, authorized_client_keys='authorized_keys'))

    async def _check_early_error(self, reader, writer, data):
        """Check errors in the initial SOCKS message"""

        writer.write(data)

        self.assertEqual((await reader.read()), b'')

    async def _check_socks5_error(self, reader, writer, data):
        """Check SOCKSv5 errors after auth"""

        writer.write(bytes((SOCKS5, 1, SOCKS5_AUTH_NONE)))
        self.assertEqual((await reader.readexactly(2)),
                         bytes((SOCKS5, SOCKS5_AUTH_NONE)))

        writer.write(data)

        self.assertEqual((await reader.read()), b'')

    async def _check_socks4_connect(self, reader, writer, data, result):
        """Check SOCKSv4 connect requests"""

        writer.write(data)

        response = await reader.readexactly(len(SOCKS4_OK_RESPONSE))
        self.assertEqual(response, SOCKS4_OK_RESPONSE)

        if result:
            await self._check_echo_line(reader, writer)
        else:
            self.assertEqual((await reader.read()), b'')

    async def _check_socks5_connect(self, reader, writer, data,
                                    addrtype, addrlen, result):
        """Check SOCKSv5 connect_requests"""

        writer.write(bytes((SOCKS5, 1, SOCKS5_AUTH_NONE)))
        self.assertEqual((await reader.readexactly(2)),
                         bytes((SOCKS5, SOCKS5_AUTH_NONE)))

        writer.write(data[:20])
        await asyncio.sleep(0.1)
        writer.write(data[20:])

        expected = SOCKS5_OK_RESPONSE_HDR + bytes((addrtype,)) + \
                   (addrlen + 2) * b'\0'

        response = await reader.readexactly(len(expected))
        self.assertEqual(response, expected)

        if result:
            await self._check_echo_line(reader, writer)
        else:
            self.assertEqual((await reader.read()), b'')

    async def _check_socks(self, handler, listen_port, msg,
                           data, *args):
        """Unit test SOCKS dynamic port forwarding"""

        with self.subTest(msg=msg, data=data):
            data = codecs.decode(data, 'hex')

            reader, writer = await asyncio.open_connection('127.0.0.1',
                                                           listen_port)

            try:
                await handler(reader, writer, data, *args)
            finally:
                writer.close()
                await maybe_wait_closed(writer)

    @asynctest
    async def test_forward_socks(self):
        """Test dynamic port forwarding via SOCKS"""

        _socks_early_errors = [
            ('Bad version',               '0000'),
            ('Bad SOCKSv4 command',       '0400'),
            ('Bad SOCKSv4 Unicode data',  '040100010000000100ff00'),
            ('SOCKSv4 hostname too long', '040100010000000100' + 256 * 'ff'),
            ('Bad SOCKSv5 auth list',     '050101')
        ]

        _socks5_postauth_errors = [
            ('Bad command',      '05000001'),
            ('Bad address',      '05010000'),
            ('Bad Unicode data', '0501000301ff0007')
        ]

        _socks4_connects = [
            ('IPv4',          '040100077f00000100',                     True),
            ('Hostname',      '0401000700000001006c6f63616c686f737400', True),
            ('Rejected',      '04010001000000010000',                   False)
        ]

        _socks5_connects = [
            ('IPv4',     '050100017f0000010007',             1,  4, True),
            ('Hostname', '05010003096c6f63616c686f73740007', 1,  4, True),
            ('IPv6',     '05010004' + 15*'00' + '010007',    4, 16, True),
            ('Rejected', '05010003000001',                   1,  4, False)
        ]

        async with self.connect() as conn:
            async with  conn.forward_socks('', 0) as listener:
                listen_port = listener.get_port()

                for msg, data in _socks_early_errors:
                    await self._check_socks(self._check_early_error,
                                            listen_port, msg, data)

                for msg, data in _socks5_postauth_errors:
                    await self._check_socks(self._check_socks5_error,
                                            listen_port, msg, data)

                for msg, data, result in _socks4_connects:
                    await self._check_socks(self._check_socks4_connect,
                                            listen_port, msg, data, result)

                for msg, data, addrtype, addrlen, result in _socks5_connects:
                    await self._check_socks(self._check_socks5_connect,
                                            listen_port, msg, data,
                                            addrtype, addrlen, result)

    @asynctest
    async def test_forward_socks_specific_port(self):
        """Test dynamic forwarding on a specific port"""

        sock = socket.socket()
        sock.bind(('', 0))
        listen_port = sock.getsockname()[1]
        sock.close()

        async with self.connect() as conn:
            async with conn.forward_socks('', listen_port):
                pass

    @unittest.skipIf(sys.platform == 'win32',
                     'Avoid issue with SO_REUSEADDR on Windows')
    @asynctest
    async def test_forward_bind_error_socks(self):
        """Test error binding a local dynamic forwarding port"""

        async with self.connect() as conn:
            async with conn.forward_socks('', 0) as listener:
                with self.assertRaises(OSError):
                    await conn.forward_socks('', listener.get_port())
