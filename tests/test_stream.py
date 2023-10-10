# Copyright (c) 2016-2020 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH stream API"""

import asyncio
import re

import asyncssh

from .server import Server, ServerTestCase
from .util import asynctest, echo


class _StreamServer(Server):
    """Server for testing the AsyncSSH stream API"""

    async def _begin_session(self, stdin, stdout, stderr):
        """Begin processing a new session"""

        # pylint: disable=no-self-use

        action = stdin.channel.get_command()
        if not action:
            action = 'echo'

        if action == 'echo':
            await echo(stdin, stdout)
        elif action == 'echo_stderr':
            await echo(stdin, stdout, stderr)
        elif action == 'close':
            await stdin.read(1)
            stdout.write('\n')
        elif action == 'disconnect':
            stdout.write((await stdin.read(1)))
            raise asyncssh.ConnectionLost('Connection lost')
        elif action == 'custom_disconnect':
            await stdin.read(1)
            raise asyncssh.DisconnectError(99, 'Disconnect')
        elif action == 'partial':
            try:
                await stdin.readexactly(10)
            except asyncio.IncompleteReadError as exc:
                stdout.write(exc.partial)

            try:
                await stdin.read()
            except asyncssh.TerminalSizeChanged:
                pass

            stdout.write(await stdin.readexactly(5))
        else:
            stdin.channel.exit(255)

        stdin.channel.close()
        await stdin.channel.wait_closed()

    def _begin_session_non_async(self, stdin, stdout, stderr):
        """Non-async version of session handler"""

        self._conn.create_task(self._begin_session(stdin, stdout, stderr))

    def begin_auth(self, username):
        """Handle client authentication request"""

        return False

    def session_requested(self):
        """Handle a request to create a new session"""

        username = self._conn.get_extra_info('username')

        if username == 'non_async':
            return self._begin_session_non_async
        elif username != 'no_channels':
            return self._begin_session
        else:
            return False


class _TestStream(ServerTestCase):
    """Unit tests for AsyncSSH stream API"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(_StreamServer)

    async def _check_session(self, conn, large_block=False):
        """Open a session and test if an input line is echoed back"""

        stdin, stdout, stderr = await conn.open_session('echo_stderr')

        if large_block:
            data = 4 * [1025*1024*'\0']
        else:
            data = [str(id(self))]

        stdin.writelines(data)
        await stdin.drain()

        self.assertTrue(stdin.can_write_eof())
        self.assertFalse(stdin.is_closing())
        stdin.write_eof()
        self.assertTrue(stdin.is_closing())

        stdout_data, stderr_data = await asyncio.gather(stdout.read(),
                                                        stderr.read())

        data = ''.join(data)
        self.assertEqual(data, stdout_data)
        self.assertEqual(data, stderr_data)

        await stdin.channel.wait_closed()
        await stdin.drain()
        stdin.close()


    @asynctest
    async def test_shell(self):
        """Test starting a shell"""

        async with self.connect() as conn:
            await self._check_session(conn)

    @asynctest
    async def test_shell_failure(self):
        """Test failure to start a shell"""

        async with self.connect(username='no_channels') as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                await conn.open_session()

    @asynctest
    async def test_shell_non_async(self):
        """Test starting a shell using non-async handler"""

        async with self.connect(username='non_async') as conn:
            await self._check_session(conn)

    @asynctest
    async def test_large_block(self):
        """Test sending and receiving a large block of data"""

        async with self.connect() as conn:
            await self._check_session(conn, large_block=True)

    @asynctest
    async def test_feed(self):
        """Test feeding data into an SSHReader"""

        async with self.connect() as conn:
            _, stdout, stderr = await conn.open_session()

            stdout.feed_data('stdout')
            stderr.feed_data('stderr')
            stdout.feed_eof()

            self.assertEqual(await stdout.read(), 'stdout')
            self.assertEqual(await stderr.read(), 'stderr')

    @asynctest
    async def test_async_iterator(self):
        """Test reading lines by using SSHReader as an async iterator"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session()

            data = ['Line 1\n', 'Line 2\n']

            stdin.writelines(data)
            stdin.write_eof()

            async for line in stdout:
                self.assertEqual(line, data.pop(0))

            self.assertEqual(data, [])

    @asynctest
    async def test_write_broken_pipe(self):
        """Test close while we're writing"""

        async with self.connect() as conn:
            stdin, _, _ = await conn.open_session('close')
            stdin.write(4*1024*1024*'\0')

            with self.assertRaises((ConnectionError, asyncssh.ConnectionLost)):
                await stdin.drain()

    @asynctest
    async def test_write_disconnect(self):
        """Test disconnect while we're writing"""

        async with self.connect() as conn:
            stdin, _, _ = await conn.open_session('disconnect')
            stdin.write(6*1024*1024*'\0')

            with self.assertRaises((ConnectionError, asyncssh.ConnectionLost)):
                await stdin.drain()

    @asynctest
    async def test_read_exception(self):
        """Test read returning an exception"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session('disconnect')

            stdin.write('\0')

            self.assertEqual((await stdout.read()), '\0')

            with self.assertRaises(asyncssh.ConnectionLost):
                await stdout.read(1)

            stdin.close()

    @asynctest
    async def test_readline_exception(self):
        """Test readline returning an exception"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session('disconnect')

            stdin.write('\0')

            self.assertEqual((await stdout.readline()), '\0')

            with self.assertRaises(asyncssh.ConnectionLost):
                await stdout.readline()

    @asynctest
    async def test_readexactly_partial_exception(self):
        """Test readexactly returning partial data before an exception"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session('partial')

            stdin.write('abcde')
            stdout.channel.change_terminal_size(80, 24)
            stdin.write('fghij')

            self.assertEqual((await stdout.read()), 'abcdefghij')

    @asynctest
    async def test_custom_disconnect(self):
        """Test receiving a custom disconnect message"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session('custom_disconnect')

            stdin.write('\0')

            with self.assertRaises(asyncssh.DisconnectError) as exc:
                await stdout.read()

        self.assertEqual(exc.exception.code, 99)
        self.assertEqual(exc.exception.reason, 'Disconnect (error 99)')

    @asynctest
    async def test_readuntil_bigger_than_window(self):
        """Test readuntil getting data bigger than the receive window"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session()

            stdin.write(4*1024*1024*'\0')

            with self.assertRaises(asyncio.IncompleteReadError) as exc:
                await stdout.readuntil('\n')

            self.assertEqual(exc.exception.partial,
                             stdin.channel.get_recv_window()*'\0')

            stdin.close()

        await conn.wait_closed()

    @asynctest
    async def test_readline_timeout(self):
        """Test receiving a timeout while calling readline"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session()

            stdin.write('ab')

            try:
                await asyncio.wait_for(stdout.readline(), timeout=0.1)
            except asyncio.TimeoutError:
                pass

            stdin.write('c\n')

            self.assertEqual((await stdout.readline()), 'abc\n')

            stdin.close()

    @asynctest
    async def test_pause_read(self):
        """Test pause reading"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session()

            stdin.write(6*1024*1024*'\0')

            await asyncio.sleep(0.01)
            await stdout.read(1)

            await asyncio.sleep(0.01)
            await stdout.read(1)

    @asynctest
    async def test_readuntil(self):
        """Test readuntil with multi-character separator"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session()

            stdin.write('abc\r')
            await asyncio.sleep(0.01)
            stdin.write('\ndef')
            await asyncio.sleep(0.01)
            stdin.write('\r\n')
            await asyncio.sleep(0.01)
            stdin.write('ghi')
            stdin.write_eof()

            self.assertEqual((await stdout.readuntil('\r\n')), 'abc\r\n')
            self.assertEqual((await stdout.readuntil('\r\n')), 'def\r\n')

            with self.assertRaises(asyncio.IncompleteReadError) as exc:
                await stdout.readuntil('\r\n')

            self.assertEqual(exc.exception.partial, 'ghi')

            stdin.close()

    @asynctest
    async def test_readuntil_separator_list(self):
        """Test readuntil with a list of separators"""

        seps = ('+', '-', '\r\n')

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session()

            stdin.write('ab')
            await asyncio.sleep(0.01)
            stdin.write('c+d')
            await asyncio.sleep(0.01)
            stdin.write('ef-gh')
            await asyncio.sleep(0.01)
            stdin.write('i\r')
            await asyncio.sleep(0.01)
            stdin.write('\n')
            stdin.write_eof()

            self.assertEqual((await stdout.readuntil(seps)), 'abc+')
            self.assertEqual((await stdout.readuntil(seps)), 'def-')
            self.assertEqual((await stdout.readuntil(seps)), 'ghi\r\n')

            stdin.close()

    @asynctest
    async def test_readuntil_empty_separator(self):
        """Test readuntil with empty separator"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session()

            with self.assertRaises(ValueError):
                await stdout.readuntil('')

            stdin.close()

    @asynctest
    async def test_readuntil_regex(self):
        """Test readuntil with a regex pattern"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session()
            stdin.write("hello world\nhello world")
            output = await stdout.readuntil(
                re.compile('hello world'), len('hello world')
            )
            self.assertEqual(output, "hello world")

            output = await stdout.readuntil(
                re.compile('hello world'), len('hello world')
            )
            self.assertEqual(output, "\nhello world")

            stdin.close()

        await conn.wait_closed()

    @asynctest
    async def test_abort(self):
        """Test abort on a channel"""

        async with self.connect() as conn:
            stdin, _, _ = await conn.open_session()

            stdin.channel.abort()

    @asynctest
    async def test_abort_closed(self):
        """Test abort on an already-closed channel"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session('close')

            stdin.write('\n')
            await stdout.read()
            stdin.channel.abort()

    @asynctest
    async def test_get_extra_info(self):
        """Test get_extra_info on streams"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session()

            self.assertEqual(stdin.get_extra_info('connection'),
                             stdout.get_extra_info('connection'))

            stdin.close()

    @asynctest
    async def test_unknown_action(self):
        """Test unknown action"""

        async with self.connect() as conn:
            stdin, _, _ = await conn.open_session('unknown')

            await stdin.channel.wait_closed()
            self.assertEqual(stdin.channel.get_exit_status(), 255)
