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

"""Unit tests for AsyncSSH forwarding API"""

import asyncio
import os
import socket

from unittest.mock import patch

import asyncssh
from asyncssh.packet import String, UInt32
from asyncssh.public_key import CERT_TYPE_USER

from .server import ServerTestCase
from .util import asynctest, echo, make_certificate


def _echo_non_async(stdin, stdout, stderr=None):
    """Non-async version of echo callback"""

    conn = stdin.get_extra_info('connection')
    conn.create_task(echo(stdin, stdout, stderr))


def _listener(orig_host, orig_port):
    """Handle a forwarded TCP/IP connection"""

    # pylint: disable=unused-argument

    return echo


def _listener_non_async(orig_host, orig_port):
    """Non-async version of handler for a forwarded TCP/IP connection"""

    # pylint: disable=unused-argument

    return _echo_non_async


def _unix_listener():
    """Handle a forwarded UNIX domain connection"""

    # pylint: disable=unused-argument

    return echo


def _unix_listener_non_async():
    """Non-async version of handler for a forwarded UNIX domain connection"""

    # pylint: disable=unused-argument

    return _echo_non_async


class _ClientConn(asyncssh.SSHClientConnection):
    """Patched SSH client connection for unit testing"""

    @asyncio.coroutine
    def make_global_request(self, request, *args):
        """Send a global request and wait for the response"""

        return self._make_global_request(request, *args)


class _TestForwarding(ServerTestCase):
    """Unit tests for AsyncSSH forwarding API"""

    @asyncio.coroutine
    def _check_echo_line(self, reader, writer, delay=False, encoded=False):
        """Check if an input line is properly echoed back"""

        if delay:
            yield from asyncio.sleep(delay)

        line = str(id(self)) + '\n'

        if not encoded:
            line = line.encode('utf-8')

        writer.write(line)
        yield from writer.drain()

        result = yield from reader.readline()

        writer.close()

        self.assertEqual(line, result)

    @asyncio.coroutine
    def _check_echo_block(self, reader, writer):
        """Check if a block of data is properly echoed back"""

        data = 4 * [1025*1024*b'\0']

        writer.writelines(data)
        yield from writer.drain()
        writer.write_eof()

        result = yield from reader.read()

        yield from reader.channel.wait_closed()
        writer.close()

        self.assertEqual(b''.join(data), result)

    @asyncio.coroutine
    def _check_connection(self, conn, dest_host='', dest_port=7, **kwargs):
        """Open a connection and test if a block of data is echoed back"""

        reader, writer = yield from conn.open_connection(dest_host, dest_port,
                                                         *kwargs)

        yield from self._check_echo_block(reader, writer)

    @asyncio.coroutine
    def _check_unix_connection(self, conn, dest_path='/echo', **kwargs):
        """Open a UNIX connection and test if an input line is echoed back"""

        reader, writer = yield from conn.open_unix_connection(dest_path,
                                                              encoding='utf-8',
                                                              *kwargs)

        yield from self._check_echo_line(reader, writer, encoded=True)

    @asyncio.coroutine
    def _check_local_connection(self, listen_port, delay=None):
        """Open a local connection and test if an input line is echoed back"""

        reader, writer = yield from asyncio.open_connection('localhost',
                                                            listen_port)

        yield from self._check_echo_line(reader, writer, delay=delay)

    @asyncio.coroutine
    def _check_local_unix_connection(self, listen_path):
        """Open a local connection and test if an input line is echoed back"""

        # pylint doesn't think open_unix_connection exists
        # pylint: disable=no-member
        reader, writer = yield from asyncio.open_unix_connection(listen_path)
        # pylint: enable=no-member

        yield from self._check_echo_line(reader, writer)

    @asynctest
    def test_connection(self):
        """Test opening a remote connection"""

        with (yield from self.connect()) as conn:
            yield from self._check_connection(conn)

        yield from conn.wait_closed()

    @asynctest
    def test_connection_failure(self):
        """Test failure in opening a remote connection"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_connection('', 0)

        yield from conn.wait_closed()

    @asynctest
    def test_connection_rejected(self):
        """Test rejection in opening a remote connection"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_connection('fail', 0)

        yield from conn.wait_closed()

    @asynctest
    def test_connection_not_permitted(self):
        """Test permission denied in opening a remote connection"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-port-forwarding': ''})

        with (yield from self.connect(username='ckey',
                                      client_keys=[(ckey, cert)])) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_connection('', 7)

        yield from conn.wait_closed()

    @asynctest
    def test_connection_not_permitted_open(self):
        """Test open permission denied in opening a remote connection"""

        with (yield from self.connect(username='ckey',
                                      client_keys=['ckey'])) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_connection('fail', 7)

        yield from conn.wait_closed()

    @asynctest
    def test_connection_invalid_unicode(self):
        """Test opening a connection with invalid Unicode in path"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_connection(b'\xff', 0)

            yield from conn.wait_closed()

    @asynctest
    def test_unix_connection(self):
        """Test opening a remote UNIX connection"""

        with (yield from self.connect()) as conn:
            yield from self._check_unix_connection(conn)

        yield from conn.wait_closed()

    @asynctest
    def test_unix_connection_failure(self):
        """Test failure in opening a remote UNIX connection"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_unix_connection('')

        yield from conn.wait_closed()

    @asynctest
    def test_unix_connection_rejected(self):
        """Test rejection in opening a remote UNIX connection"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_unix_connection('/fail')

        yield from conn.wait_closed()

    @asynctest
    def test_unix_connection_not_permitted(self):
        """Test permission denied in opening a remote UNIX connection"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-port-forwarding': ''})

        with (yield from self.connect(username='ckey',
                                      client_keys=[(ckey, cert)])) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_unix_connection('/echo')

        yield from conn.wait_closed()

    @asynctest
    def test_unix_connection_invalid_unicode(self):
        """Test opening a UNIX connection with invalid Unicode in path"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_unix_connection(b'\xff')

            yield from conn.wait_closed()

    @asynctest
    def test_server(self):
        """Test creating a remote listener"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.start_server(_listener, '', 0)
            yield from self._check_local_connection(listener.get_port())
            listener.close()
            listener.close()
            yield from listener.wait_closed()
            listener.close()

        yield from conn.wait_closed()

    @asynctest
    def test_server_open(self):
        """Test creating a remote listener which uses open_connection"""

        def new_connection(reader, writer):
            """Handle a forwarded TCP/IP connection"""

            waiter.set_result((reader, writer))

        def handler_factory(orig_host, orig_port):
            """Handle all connections using new_connection"""

            # pylint: disable=unused-argument

            return new_connection

        with (yield from self.connect()) as conn:
            waiter = asyncio.Future(loop=self.loop)

            yield from conn.start_server(handler_factory, 'open', 0)

            reader, writer = yield from waiter
            yield from self._check_echo_line(reader, writer)

            # Clean up the listener during connection close

        yield from conn.wait_closed()

    @asynctest
    def test_server_non_async(self):
        """Test creating a remote listener using non-async handler"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.start_server(_listener_non_async, '', 0)
            yield from self._check_local_connection(listener.get_port())
            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_server_failure(self):
        """Test failure in creating a remote listener"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.start_server(_listener, 'fail', 0)
            self.assertIsNone(listener)

        yield from conn.wait_closed()

    @asynctest
    def test_unix_server(self):
        """Test creating a remote UNIX listener"""

        path = os.path.abspath('echo')

        with (yield from self.connect()) as conn:
            listener = yield from conn.start_unix_server(_unix_listener, path)
            yield from self._check_local_unix_connection('echo')
            listener.close()
            listener.close()
            yield from listener.wait_closed()
            listener.close()

        yield from conn.wait_closed()

        os.remove('echo')

    @asynctest
    def test_unix_server_open(self):
        """Test creating a UNIX listener which uses open_unix_connection"""

        def new_connection(reader, writer):
            """Handle a forwarded UNIX domain connection"""

            waiter.set_result((reader, writer))

        def handler_factory():
            """Handle all connections using new_connection"""

            # pylint: disable=unused-argument

            return new_connection

        with (yield from self.connect()) as conn:
            waiter = asyncio.Future(loop=self.loop)

            listener = yield from conn.start_unix_server(handler_factory,
                                                         'open')

            reader, writer = yield from waiter
            yield from self._check_echo_line(reader, writer)

            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_unix_server_non_async(self):
        """Test creating a remote UNIX listener using non-async handler"""

        path = os.path.abspath('echo')

        with (yield from self.connect()) as conn:
            listener = yield from conn.start_unix_server(
                _unix_listener_non_async, path)
            yield from self._check_local_unix_connection('echo')
            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

        os.remove('echo')

    @asynctest
    def test_unix_server_failure(self):
        """Test failure in creating a remote UNIX listener"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.start_unix_server(_unix_listener,
                                                         'fail')
            self.assertIsNone(listener)

        yield from conn.wait_closed()

    @asynctest
    def test_forward_local_port(self):
        """Test forwarding of a local port"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_local_port('', 0,
                                                          'localhost', 7)

            yield from self._check_local_connection(listener.get_port(),
                                                    delay=0.1)

            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_forward_local_port_pause(self):
        """Test pause during forwarding of a local port"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_local_port('', 0,
                                                          'localhost', 8)
            listen_port = listener.get_port()

            reader, writer = yield from asyncio.open_connection('localhost',
                                                                listen_port)

            writer.write(4*1024*1024*b'\0')
            writer.write_eof()
            yield from reader.read()

            writer.close()
            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_forward_local_port_failure(self):
        """Test failure in forwarding a local port"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_local_port('', 0,
                                                          'localhost', 65535)
            listen_port = listener.get_port()

            reader, writer = yield from asyncio.open_connection('localhost',
                                                                listen_port)

            self.assertEqual((yield from reader.read()), b'')

            writer.close()
            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_forward_bind_error(self):
        """Test error binding a local forwarding port"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_local_port('::', 0,
                                                          'localhost', 7)

            with self.assertRaises(OSError):
                yield from conn.forward_local_port(None, listener.get_port(),
                                                   'localhost', 7)

            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_forward_connect_error(self):
        """Test error connecting a local forwarding port"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_local_port('', 0, '', 0)
            listen_port = listener.get_port()

            reader, writer = yield from asyncio.open_connection('localhost',
                                                                listen_port)

            self.assertEqual((yield from reader.read()), b'')

            writer.close()
            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_forward_immediate_eof(self):
        """Test getting EOF before forwarded connection is fully open"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_local_port('', 0,
                                                          'localhost', 7)
            listen_port = listener.get_port()

            _, writer = yield from asyncio.open_connection('localhost',
                                                           listen_port)

            writer.close()
            yield from asyncio.sleep(0.1)

            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_forward_remote_port(self):
        """Test forwarding of a remote port"""

        server = yield from asyncio.start_server(echo, '', 0)
        server_port = server.sockets[0].getsockname()[1]

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_remote_port('', 0, 'localhost',
                                                           server_port)

            yield from self._check_local_connection(listener.get_port())

            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

        server.close()
        yield from server.wait_closed()

    @asynctest
    def test_forward_remote_specific_port(self):
        """Test forwarding of a specific remote port"""

        server = yield from asyncio.start_server(echo, '', 0)
        server_port = server.sockets[0].getsockname()[1]

        sock = socket.socket()
        sock.bind(('', 0))
        remote_port = sock.getsockname()[1]
        sock.close()

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_remote_port('', remote_port,
                                                           'localhost',
                                                           server_port)

            yield from self._check_local_connection(listener.get_port())

            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

        server.close()
        yield from server.wait_closed()

    @asynctest
    def test_forward_remote_port_failure(self):
        """Test failure of forwarding a remote port"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_remote_port('', 65536,
                                                           'localhost', 0)

            self.assertIsNone(listener)

        yield from conn.wait_closed()

    @asynctest
    def test_forward_remote_port_not_permitted(self):
        """Test permission denied in forwarding of a remote port"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-port-forwarding': ''})

        with (yield from self.connect(username='ckey',
                                      client_keys=[(ckey, cert)])) as conn:
            listener = yield from conn.forward_remote_port('', 0,
                                                           'localhost', 0)

            self.assertIsNone(listener)

        yield from conn.wait_closed()

    @asynctest
    def test_forward_remote_port_invalid_unicode(self):
        """Test TCP/IP forwarding with invalid Unicode in host"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_remote_port(b'\xff', 0,
                                                           'localhost', 0)

            self.assertIsNone(listener)

        yield from conn.wait_closed()

    @asynctest
    def test_cancel_forward_remote_port_invalid_unicode(self):
        """Test canceling TCP/IP forwarding with invalid Unicode in host"""

        with patch('asyncssh.connection.SSHClientConnection', _ClientConn):
            with (yield from self.connect()) as conn:
                pkttype, _ = yield from conn.make_global_request(
                    b'cancel-tcpip-forward', String(b'\xff'), UInt32(0))

                self.assertEqual(pkttype, asyncssh.MSG_REQUEST_FAILURE)

            yield from conn.wait_closed()

    @asynctest
    def test_forward_local_path(self):
        """Test forwarding of a local UNIX domain path"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_local_path('local', '/echo')

            yield from self._check_local_unix_connection('local')

            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

        os.remove('local')

    @asynctest
    def test_forward_remote_path(self):
        """Test forwarding of a remote UNIX domain path"""

        # pylint doesn't think start_unix_server exists
        # pylint: disable=no-member
        server = yield from asyncio.start_unix_server(echo, 'local')
        # pylint: enable=no-member

        path = os.path.abspath('echo')

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_remote_path(path, 'local')

            yield from self._check_local_unix_connection('echo')

            listener.close()
            yield from listener.wait_closed()

        yield from conn.wait_closed()

        server.close()
        yield from server.wait_closed()

        os.remove('echo')
        os.remove('local')

    @asynctest
    def test_forward_remote_path_failure(self):
        """Test failure of forwarding a remote UNIX domain path"""

        open('echo', 'w').close()

        path = os.path.abspath('echo')

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_remote_path(path, 'local')

            self.assertIsNone(listener)

        yield from conn.wait_closed()

        os.remove('echo')

    @asynctest
    def test_forward_remote_path_not_permitted(self):
        """Test permission denied in forwarding a remote UNIX domain path"""

        ckey = asyncssh.read_private_key('ckey')
        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'],
                                extensions={'no-port-forwarding': ''})

        with (yield from self.connect(username='ckey',
                                      client_keys=[(ckey, cert)])) as conn:
            listener = yield from conn.forward_remote_path('', 'local')

            self.assertIsNone(listener)

        yield from conn.wait_closed()

    @asynctest
    def test_forward_remote_path_invalid_unicode(self):
        """Test forwarding a UNIX domain path with invalid Unicode in it"""

        with (yield from self.connect()) as conn:
            listener = yield from conn.forward_remote_path(b'\xff', 'local')

            self.assertIsNone(listener)

        yield from conn.wait_closed()

    @asynctest
    def test_cancel_forward_remote_path_invalid_unicode(self):
        """Test canceling UNIX forwarding with invalid Unicode in path"""

        with patch('asyncssh.connection.SSHClientConnection', _ClientConn):
            with (yield from self.connect()) as conn:
                pkttype, _ = yield from conn.make_global_request(
                    b'cancel-streamlocal-forward@openssh.com', String(b'\xff'))

                self.assertEqual(pkttype, asyncssh.MSG_REQUEST_FAILURE)

            yield from conn.wait_closed()
