# Copyright (c) 2019 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH subprocess API"""

import asyncio
from signal import SIGINT

import asyncssh

from .server import Server, ServerTestCase
from .util import asynctest, echo

class _SubprocessProtocol(asyncssh.SSHSubprocessProtocol):
    """Unit test SSH subprocess protocol"""

    def __init__(self):
        self._chan = None

        self.recv_buf = {1: [], 2: []}
        self.exc = {1: None, 2: None}

    def pipe_connection_lost(self, fd, exc):
        """Handle remote process close"""

        self.exc[fd] = exc

    def pipe_data_received(self, fd, data):
        """Handle data from the remote process"""

        self.recv_buf[fd].append(data)


async def _create_subprocess(conn, command=None, **kwargs):
    """Create a client subprocess"""

    return await conn.create_subprocess(_SubprocessProtocol, command, **kwargs)


class _SubprocessServer(Server):
    """Server for testing the AsyncSSH subprocess API"""

    def begin_auth(self, username):
        """Handle client authentication request"""

        return False

    def session_requested(self):
        """Handle a request to create a new session"""

        return self._begin_session

    async def _begin_session(self, stdin, stdout, stderr):
        """Begin processing a new session"""

        # pylint: disable=no-self-use

        action = stdin.channel.get_command()

        if not action:
            action = 'echo'

        if action == 'exit_status':
            stdout.channel.exit(1)
        elif action == 'signal':
            try:
                await stdin.readline()
            except asyncssh.SignalReceived as exc:
                stdout.channel.exit_with_signal(exc.signal)
        else:
            await echo(stdin, stdout, stderr)

class _TestSubprocess(ServerTestCase):
    """Unit tests for AsyncSSH subprocess API"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (await cls.create_server(
            _SubprocessServer, authorized_client_keys='authorized_keys'))

    async def _check_subprocess(self, conn, command=None, *,
                                encoding=None, **kwargs):
        """Start a subprocess and test if an input line is echoed back"""

        transport, protocol = await _create_subprocess(conn, command,
                                                       encoding=encoding,
                                                       *kwargs)

        data = str(id(self))

        if encoding is None:
            data = data.encode('ascii')

        stdin = transport.get_pipe_transport(0)

        self.assertTrue(stdin.can_write_eof())

        stdin.writelines([data])

        self.assertFalse(transport.is_closing())
        stdin.write_eof()
        self.assertTrue(transport.is_closing())

        await transport.wait_closed()

        sep = '' if encoding else b''

        for buf in protocol.recv_buf.values():
            self.assertEqual(sep.join([data]), sep.join(buf))

        transport.close()

    @asynctest
    async def test_shell(self):
        """Test starting a shell"""

        async with self.connect() as conn:
            await self._check_subprocess(conn)

    @asynctest
    async def test_exec(self):
        """Test execution of a remote command"""

        async with self.connect() as conn:
            await self._check_subprocess(conn, 'echo')

    @asynctest
    async def test_encoding(self):
        """Test setting encoding"""

        async with self.connect() as conn:
            await self._check_subprocess(conn, 'echo', encoding='ascii')

    @asynctest
    async def test_input(self):
        """Test providing input when creating a subprocess"""

        data = str(id(self)).encode('ascii')

        async with self.connect() as conn:
            transport, protocol = await _create_subprocess(conn, input=data)

            await transport.wait_closed()

        for buf in protocol.recv_buf.values():
            self.assertEqual(b''.join(buf), data)

    @asynctest
    async def test_redirect_stderr(self):
        """Test redirecting stderr to file"""

        data = str(id(self)).encode('ascii')

        async with self.connect() as conn:
            transport, protocol = await _create_subprocess(conn,
                                                           stderr='stderr')

            stdin = transport.get_pipe_transport(0)
            stdin.write(data)
            stdin.write_eof()

            await transport.wait_closed()

        with open('stderr', 'rb') as f:
            stderr_data = f.read()

        self.assertEqual(b''.join(protocol.recv_buf[1]), data)
        self.assertEqual(b''.join(protocol.recv_buf[2]), b'')
        self.assertEqual(stderr_data, data)

    @asynctest
    async def test_close(self):
        """Test closing transport"""

        async with self.connect() as conn:
            transport, protocol = await _create_subprocess(conn)

            transport.close()

        for buf in protocol.recv_buf.values():
            self.assertEqual(b''.join(buf), b'')

    @asynctest
    async def test_exit_status(self):
        """Test reading exit status"""

        async with self.connect() as conn:
            transport, protocol = await _create_subprocess(conn, 'exit_status')

            await transport.wait_closed()

        for buf in protocol.recv_buf.values():
            self.assertEqual(b''.join(buf), b'')

        self.assertEqual(transport.get_returncode(), 1)

    @asynctest
    async def test_stdin_abort(self):
        """Test abort on stdin"""

        async with self.connect() as conn:
            transport, protocol = await _create_subprocess(conn)

            stdin = transport.get_pipe_transport(0)
            stdin.abort()

        for buf in protocol.recv_buf.values():
            self.assertEqual(b''.join(buf), b'')

    @asynctest
    async def test_stdin_close(self):
        """Test closing stdin"""

        async with self.connect() as conn:
            transport, protocol = await _create_subprocess(conn)

            stdin = transport.get_pipe_transport(0)
            stdin.close()

        for buf in protocol.recv_buf.values():
            self.assertEqual(b''.join(buf), b'')

    @asynctest
    async def test_read_pause(self):
        """Test read pause"""

        async with self.connect() as conn:
            transport, protocol = await _create_subprocess(conn)

            stdin = transport.get_pipe_transport(0)
            stdout = transport.get_pipe_transport(1)

            stdout.pause_reading()
            stdin.write(b'\n')
            await asyncio.sleep(0.1)

            for buf in protocol.recv_buf.values():
                self.assertEqual(b''.join(buf), b'')

            stdout.resume_reading()

            for buf in protocol.recv_buf.values():
                self.assertEqual(b''.join(buf), b'\n')

            stdin.close()

    @asynctest
    async def test_signal(self):
        """Test sending a signal"""

        async with self.connect() as conn:
            transport, _ = await _create_subprocess(conn, 'signal')

            transport.send_signal(SIGINT)

            await transport.wait_closed()

            self.assertEqual(transport.get_returncode(), -SIGINT)

    @asynctest
    async def test_misc(self):
        """Test other transport and pipe methods"""

        async with self.connect() as conn:
            transport, _ = await _create_subprocess(conn)

            self.assertEqual(transport.get_pid(), None)

            stdin = transport.get_pipe_transport(0)

            self.assertEqual(transport.get_extra_info('socket'),
                             stdin.get_extra_info('socket'))

            stdin.set_write_buffer_limits()
            self.assertEqual(stdin.get_write_buffer_size(), 0)

            stdin.close()
