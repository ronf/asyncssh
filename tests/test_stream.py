# Copyright (c) 2016-2018 by Ron Frederick <ronf@timeheart.net> and others.
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

import asyncssh

from .server import Server, ServerTestCase
from .util import asynctest, echo


class _StreamServer(Server):
    """Server for testing the AsyncSSH stream API"""

    def _begin_session(self, stdin, stdout, stderr):
        """Begin processing a new session"""

        # pylint: disable=no-self-use

        action = stdin.channel.get_command()
        if not action:
            action = 'echo'

        if action == 'echo':
            yield from echo(stdin, stdout)
        elif action == 'echo_stderr':
            yield from echo(stdin, stdout, stderr)
        elif action == 'close':
            yield from stdin.read(1)
            stdout.write('\n')
        elif action == 'disconnect':
            stdout.write((yield from stdin.read(1)))
            raise asyncssh.ConnectionLost('Connection lost')
        elif action == 'custom_disconnect':
            yield from stdin.read(1)
            raise asyncssh.DisconnectError(99, 'Disconnect')
        else:
            stdin.channel.exit(255)

        stdin.channel.close()
        yield from stdin.channel.wait_closed()

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
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (yield from cls.create_server(_StreamServer))

    @asyncio.coroutine
    def _check_session(self, conn, large_block=False):
        """Open a session and test if an input line is echoed back"""

        stdin, stdout, stderr = yield from conn.open_session('echo_stderr')

        if large_block:
            data = 4 * [1025*1024*'\0']
        else:
            data = [str(id(self))]

        stdin.writelines(data)

        yield from stdin.drain()

        self.assertTrue(stdin.can_write_eof())
        stdin.write_eof()

        stdout_data, stderr_data = yield from asyncio.gather(stdout.read(),
                                                             stderr.read())

        data = ''.join(data)
        self.assertEqual(data, stdout_data)
        self.assertEqual(data, stderr_data)

        yield from stdin.channel.wait_closed()
        yield from stdin.drain()
        stdin.close()


    @asynctest
    def test_shell(self):
        """Test starting a shell"""

        with (yield from self.connect()) as conn:
            yield from self._check_session(conn)

        yield from conn.wait_closed()

    @asynctest
    def test_shell_failure(self):
        """Test failure to start a shell"""

        with (yield from self.connect(username='no_channels')) as conn:
            with self.assertRaises(asyncssh.ChannelOpenError):
                yield from conn.open_session()

        yield from conn.wait_closed()

    @asynctest
    def test_shell_non_async(self):
        """Test starting a shell using non-async handler"""

        with (yield from self.connect(username='non_async')) as conn:
            yield from self._check_session(conn)

        yield from conn.wait_closed()

    @asynctest
    def test_large_block(self):
        """Test sending and receiving a large block of data"""

        with (yield from self.connect()) as conn:
            yield from self._check_session(conn, large_block=True)

        yield from conn.wait_closed()

    @asynctest
    def test_write_broken_pipe(self):
        """Test close while we're writing"""

        with (yield from self.connect()) as conn:
            stdin, _, _ = yield from conn.open_session('close')
            stdin.write(4*1024*1024*'\0')

            with self.assertRaises((ConnectionError, asyncssh.ConnectionLost)):
                yield from stdin.drain()

        yield from conn.wait_closed()

    @asynctest
    def test_write_disconnect(self):
        """Test disconnect while we're writing"""

        with (yield from self.connect()) as conn:
            stdin, _, _ = yield from conn.open_session('disconnect')
            stdin.write(6*1024*1024*'\0')

            with self.assertRaises((ConnectionError, asyncssh.ConnectionLost)):
                yield from stdin.drain()

        yield from conn.wait_closed()

    @asynctest
    def test_read_exception(self):
        """Test read returning an exception"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session('disconnect')

            stdin.write('\0')

            self.assertEqual((yield from stdout.read()), '\0')

            with self.assertRaises(asyncssh.ConnectionLost):
                yield from stdout.read(1)

            stdin.close()

        yield from conn.wait_closed()

    @asynctest
    def test_readline_exception(self):
        """Test readline returning an exception"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session('disconnect')

            stdin.write('\0')

            self.assertEqual((yield from stdout.readline()), '\0')

            with self.assertRaises(asyncssh.ConnectionLost):
                yield from stdout.readline()

        yield from conn.wait_closed()

    @asynctest
    def test_custom_disconnect(self):
        """Test receiving a custom disconnect message"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session('custom_disconnect')

            stdin.write('\0')

            with self.assertRaises(asyncssh.DisconnectError) as exc:
                yield from stdout.read()

        yield from conn.wait_closed()

        self.assertEqual(exc.exception.code, 99)
        self.assertEqual(exc.exception.reason, 'Disconnect (error 99)')

    @asynctest
    def test_readuntil_bigger_than_window(self):
        """Test readuntil getting data bigger than the receive window"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session()

            stdin.write(4*1024*1024*'\0')

            with self.assertRaises(asyncio.IncompleteReadError) as exc:
                yield from stdout.readuntil('\n')

            self.assertEqual(exc.exception.partial,
                             stdin.channel.get_recv_window()*'\0')

            stdin.close()

        yield from conn.wait_closed()

    @asynctest
    def test_readline_timeout(self):
        """Test receiving a timeout while calling readline"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session()

            stdin.write('ab')

            try:
                yield from asyncio.wait_for(stdout.readline(), timeout=0.1)
            except asyncio.TimeoutError:
                pass

            stdin.write('c\n')

            self.assertEqual((yield from stdout.readline()), 'abc\n')

            stdin.close()

        yield from conn.wait_closed()

    @asynctest
    def test_pause_read(self):
        """Test pause reading"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session()

            stdin.write(6*1024*1024*'\0')

            yield from asyncio.sleep(0.01)
            yield from stdout.read(1)

            yield from asyncio.sleep(0.01)
            yield from stdout.read(1)

        yield from conn.wait_closed()

    @asynctest
    def test_readuntil(self):
        """Test readuntil with multi-character separator"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session()

            stdin.write('abc\r')
            yield from asyncio.sleep(0.01)
            stdin.write('\ndef')
            yield from asyncio.sleep(0.01)
            stdin.write('\r\n')
            yield from asyncio.sleep(0.01)
            stdin.write('ghi')
            stdin.write_eof()

            self.assertEqual((yield from stdout.readuntil('\r\n')), 'abc\r\n')
            self.assertEqual((yield from stdout.readuntil('\r\n')), 'def\r\n')

            with self.assertRaises(asyncio.IncompleteReadError) as exc:
                yield from stdout.readuntil('\r\n')

            self.assertEqual(exc.exception.partial, 'ghi')

            stdin.close()

        yield from conn.wait_closed()

    @asynctest
    def test_readuntil_separator_list(self):
        """Test readuntil with a list of separators"""

        seps = ('+', '-', '\r\n')

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session()

            stdin.write('ab')
            yield from asyncio.sleep(0.01)
            stdin.write('c+d')
            yield from asyncio.sleep(0.01)
            stdin.write('ef-gh')
            yield from asyncio.sleep(0.01)
            stdin.write('i\r')
            yield from asyncio.sleep(0.01)
            stdin.write('\n')
            stdin.write_eof()

            self.assertEqual((yield from stdout.readuntil(seps)), 'abc+')
            self.assertEqual((yield from stdout.readuntil(seps)), 'def-')
            self.assertEqual((yield from stdout.readuntil(seps)), 'ghi\r\n')

            stdin.close()

        yield from conn.wait_closed()

    @asynctest
    def test_readuntil_empty_separator(self):
        """Test readuntil with empty separator"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session()

            with self.assertRaises(ValueError):
                yield from stdout.readuntil('')

            stdin.close()

        yield from conn.wait_closed()

    @asynctest
    def test_abort(self):
        """Test abort on a channel"""

        with (yield from self.connect()) as conn:
            stdin, _, _ = yield from conn.open_session()

            stdin.channel.abort()

        yield from conn.wait_closed()

    @asynctest
    def test_abort_closed(self):
        """Test abort on an already-closed channel"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session('close')

            stdin.write('\n')
            yield from stdout.read()
            stdin.channel.abort()

        yield from conn.wait_closed()

    @asynctest
    def test_get_extra_info(self):
        """Test get_extra_info on streams"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session()

            self.assertEqual(stdin.get_extra_info('connection'),
                             stdout.get_extra_info('connection'))

            stdin.close()

        yield from conn.wait_closed()

    @asynctest
    def test_unknown_action(self):
        """Test unknown action"""

        with (yield from self.connect()) as conn:
            stdin, _, _ = yield from conn.open_session('unknown')

            yield from stdin.channel.wait_closed()
            self.assertEqual(stdin.channel.get_exit_status(), 255)

        yield from conn.wait_closed()
