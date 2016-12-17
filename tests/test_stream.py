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

            raise asyncssh.DisconnectError(asyncssh.DISC_CONNECTION_LOST,
                                           'Connection lost')
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

            with self.assertRaises((ConnectionError,
                                    asyncssh.DisconnectError)):
                yield from stdin.drain()

        yield from conn.wait_closed()

    @asynctest
    def test_write_disconnect(self):
        """Test disconnect while we're writing"""

        with (yield from self.connect()) as conn:
            stdin, _, _ = yield from conn.open_session('disconnect')
            stdin.write(6*1024*1024*'\0')

            with self.assertRaises((ConnectionError,
                                    asyncssh.DisconnectError)):
                yield from stdin.drain()

        yield from conn.wait_closed()

    @asynctest
    def test_multiple_read(self):
        """Test calling blocking read multiple times"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session()

            done, _ = yield from asyncio.wait(
                [stdout.read(), stdout.read()],
                return_when=asyncio.FIRST_EXCEPTION)

            with self.assertRaises(RuntimeError):
                yield from done

            stdin.close()

        yield from conn.wait_closed()

    @asynctest
    def test_read_exception(self):
        """Test read returning an exception"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session('disconnect')

            stdin.write('\0')

            self.assertEqual((yield from stdout.read()), '\0')

            with self.assertRaises(asyncssh.DisconnectError):
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

            with self.assertRaises(asyncssh.DisconnectError):
                yield from stdout.readline()

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

            stdin.channel.abort()

        yield from conn.wait_closed()

    @asynctest
    def test_pause_readline(self):
        """Test pause reading while calling readline"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session()

            stdin.write('\n'+2*1024*1024*'\0')
            stdin.write_eof()

            yield from asyncio.sleep(0.01)
            yield from stdout.readline()

            yield from asyncio.sleep(0.01)
            yield from stdout.readline()

            stdin.channel.abort()

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
    def test_readuntil_empty_separator(self):
        """Test readuntil with empty separator"""

        with (yield from self.connect()) as conn:
            stdin, stdout, _ = yield from conn.open_session()

            with self.assertRaises(ValueError):
                yield from stdout.readuntil('')

            stdin.close()

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
