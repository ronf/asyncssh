# Copyright (c) 2016-2018 by Ron Frederick <ronf@timeheart.net>.
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

"""Unit tests for AsyncSSH process API"""

import asyncio
import io
import os
from pathlib import Path
import socket
import sys
import unittest

import asyncssh

from .server import ServerTestCase
from .util import asynctest, echo

try:
    import aiofiles
    _aiofiles_available = True
except ImportError: # pragma: no cover
    _aiofiles_available = False

@asyncio.coroutine
def _handle_client(process):
    """Handle a new client request"""

    action = process.command or process.subsystem
    if not action:
        action = 'echo'

    if action == 'break':
        try:
            yield from process.stdin.readline()
        except asyncssh.BreakReceived as exc:
            process.exit_with_signal('ABRT', False, str(exc.msec))
    elif action == 'delay':
        yield from asyncio.sleep(1)
        yield from echo(process.stdin, process.stdout, process.stderr)
    elif action == 'echo':
        yield from echo(process.stdin, process.stdout, process.stderr)
    elif action == 'exit_status':
        process.channel.set_encoding('utf-8')
        process.stderr.write('Exiting with status 1')
        process.exit(1)
    elif action == 'env':
        process.channel.set_encoding('utf-8')
        process.stdout.write(process.env.get('TEST', ''))
    elif action == 'redirect_stdin':
        yield from process.redirect_stdin(process.stdout)
        yield from process.stdout.drain()
    elif action == 'redirect_stdout':
        yield from process.redirect_stdout(process.stdin)
        yield from process.stdout.drain()
    elif action == 'redirect_stderr':
        yield from process.redirect_stderr(process.stdin)
        yield from process.stderr.drain()
    elif action == 'term':
        info = str((process.get_terminal_type(), process.get_terminal_size(),
                    process.get_terminal_mode(asyncssh.PTY_OP_OSPEED)))
        process.channel.set_encoding('utf-8')
        process.stdout.write(info)
    elif action == 'term_size':
        try:
            yield from process.stdin.readline()
        except asyncssh.TerminalSizeChanged as exc:
            process.exit_with_signal('ABRT', False,
                                     '%sx%s' % (exc.width, exc.height))
    else:
        process.exit(255)

    process.close()
    yield from process.wait_closed()


class _TestProcess(ServerTestCase):
    """Unit tests for AsyncSSH process API"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (yield from cls.create_server(process_factory=_handle_client,
                                             session_encoding=None))


class _TestProcessBasic(_TestProcess):
    """Unit tests for AsyncSSH process basic functions"""

    @asynctest
    def test_shell(self):
        """Test starting a remote shell"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process(env={'TEST': 'test'})

            process.stdin.write(data)
            process.stdin.write_eof()

            result = yield from process.wait()

        self.assertEqual(result.env, {'TEST': 'test'})
        self.assertEqual(result.command, None)
        self.assertEqual(result.subsystem, None)
        self.assertEqual(result.exit_status, None)
        self.assertEqual(result.exit_signal, None)
        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_command(self):
        """Test executing a remote command"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process('echo')

            process.stdin.write(data)
            process.stdin.write_eof()

            result = yield from process.wait()

        self.assertEqual(result.command, 'echo')
        self.assertEqual(result.subsystem, None)
        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_subsystem(self):
        """Test starting a remote subsystem"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process(subsystem='echo')

            process.stdin.write(data)
            process.stdin.write_eof()

            result = yield from process.wait()

        self.assertEqual(result.command, None)
        self.assertEqual(result.subsystem, 'echo')
        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_communicate(self):
        """Test communicate"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            with (yield from conn.create_process()) as process:
                stdout_data, stderr_data = yield from process.communicate(data)

        self.assertEqual(stdout_data, data)
        self.assertEqual(stderr_data, data)

    @asynctest
    def test_communicate_paused(self):
        """Test communicate when reading is already paused"""

        data = 4*1024*1024*'*'

        with (yield from self.connect()) as conn:
            with (yield from conn.create_process(input=data)) as process:
                yield from asyncio.sleep(1)
                stdout_data, stderr_data = yield from process.communicate()

        self.assertEqual(stdout_data, data)
        self.assertEqual(stderr_data, data)

    @asynctest
    def test_env(self):
        """Test sending environment"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process('env',
                                                     env={'TEST': 'test'})
            result = yield from process.wait()

        self.assertEqual(result.stdout, 'test')

    @asynctest
    def test_terminal_info(self):
        """Test sending terminal information"""

        modes = {asyncssh.PTY_OP_OSPEED: 9600}

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process('term', term_type='ansi',
                                                     term_size=(80, 24),
                                                     term_modes=modes)
            result = yield from process.wait()

        self.assertEqual(result.stdout, "('ansi', (80, 24, 0, 0), 9600)")

    @asynctest
    def test_change_terminal_size(self):
        """Test changing terminal size"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process('term_size',
                                                     term_type='ansi')
            process.change_terminal_size(80, 24)
            result = yield from process.wait()

        self.assertEqual(result.exit_signal[2], '80x24')

    @asynctest
    def test_break(self):
        """Test sending a break"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process('break')
            process.send_break(1000)
            result = yield from process.wait()

        self.assertEqual(result.exit_signal[2], '1000')

    @asynctest
    def test_signal(self):
        """Test sending a signal"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process()
            process.send_signal('HUP')
            result = yield from process.wait()

        self.assertEqual(result.exit_signal[0], 'HUP')

    @asynctest
    def test_terminate(self):
        """Test sending a terminate signal"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process()
            process.terminate()
            result = yield from process.wait()

        self.assertEqual(result.exit_signal[0], 'TERM')

    @asynctest
    def test_kill(self):
        """Test sending a kill signal"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process()
            process.kill()
            result = yield from process.wait()

        self.assertEqual(result.exit_signal[0], 'KILL')

    @asynctest
    def test_exit_status(self):
        """Test checking exit status"""

        with (yield from self.connect()) as conn:
            result = yield from conn.run('exit_status')

        self.assertEqual(result.exit_status, 1)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'Exiting with status 1')

    @asynctest
    def test_raise_on_exit_status(self):
        """Test raising an exception on non-zero exit status"""

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.ProcessError) as exc:
                yield from conn.run('exit_status', env={'TEST': 'test'},
                                    check=True)

        self.assertEqual(exc.exception.env, {'TEST': 'test'})
        self.assertEqual(exc.exception.command, 'exit_status')
        self.assertEqual(exc.exception.subsystem, None)
        self.assertEqual(exc.exception.exit_status, 1)
        self.assertEqual(exc.exception.reason,
                         'Process exited with non-zero exit status 1')

    @asynctest
    def test_exit_signal(self):
        """Test checking exit signal"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process()
            process.send_signal('HUP')
            result = yield from process.wait()

        self.assertEqual(result.exit_status, -1)
        self.assertEqual(result.exit_signal[0], 'HUP')

    @asynctest
    def test_raise_on_exit_signal(self):
        """Test raising an exception on exit signal"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process()

            with self.assertRaises(asyncssh.ProcessError) as exc:
                process.send_signal('HUP')
                yield from process.wait(check=True)

        self.assertEqual(exc.exception.exit_status, -1)
        self.assertEqual(exc.exception.exit_signal[0], 'HUP')
        self.assertEqual(exc.exception.reason,
                         'Process exited with signal HUP')

    @asynctest
    def test_split_unicode(self):
        """Test Unicode split across blocks"""

        data = '\u2000test\u2000'

        with open('stdin', 'w', encoding='utf-8') as file:
            file.write(data)

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin='stdin', bufsize=2)

        self.assertEqual(result.stdout, data)

    @asynctest
    def test_invalid_unicode(self):
        """Test invalid Unicode data"""

        data = b'\xfftest'

        with open('stdin', 'wb') as file:
            file.write(data)

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.DisconnectError):
                yield from conn.run('echo', stdin='stdin')

    @asynctest
    def test_incomplete_unicode(self):
        """Test incomplete Unicode data"""

        data = '\u2000'.encode('utf-8')[:2]

        with open('stdin', 'wb') as file:
            file.write(data)

        with (yield from self.connect()) as conn:
            with self.assertRaises(asyncssh.DisconnectError):
                yield from conn.run('echo', stdin='stdin')

    @asynctest
    def test_disconnect(self):
        """Test collecting output from a disconnected channel"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process()

            process.stdin.write(data)
            process.send_signal('ABRT')

            result = yield from process.wait()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_unknown_action(self):
        """Test unknown action"""

        with (yield from self.connect()) as conn:
            result = yield from conn.run('unknown')

        self.assertEqual(result.exit_status, 255)


class _TestProcessRedirection(_TestProcess):
    """Unit tests for AsyncSSH process I/O redirection"""

    @asynctest
    def test_input(self):
        """Test with input from a string"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_devnull(self):
        """Test with stdin redirected to DEVNULL"""

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=asyncssh.DEVNULL)

        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    @asynctest
    def test_stdin_file(self):
        """Test with stdin redirected to a file"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin='stdin')

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_binary_file(self):
        """Test with stdin redirected to a file in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        with open('stdin', 'wb') as file:
            file.write(data)

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin='stdin',
                                         encoding=None)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_pathlib(self):
        """Test with stdin redirected to a file name specified by pathlib"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=Path('stdin'))

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_open_file(self):
        """Test with stdin redirected to an open file"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        file = open('stdin', 'r')

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=file)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_open_binary_file(self):
        """Test with stdin redirected to an open file in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        with open('stdin', 'wb') as file:
            file.write(data)

        file = open('stdin', 'rb')

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=file,
                                         encoding=None)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_stringio(self):
        """Test with stdin redirected to a StringIO object"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        file = io.StringIO(data)

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=file)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_bytesio(self):
        """Test with stdin redirected to a BytesIO object"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        file = io.BytesIO(data.encode('ascii'))

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=file)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_process(self):
        """Test with stdin redirected to another SSH process"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            proc1 = yield from conn.create_process(input=data)
            proc2 = yield from conn.create_process(stdin=proc1.stdout)
            result = yield from proc2.wait()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_devnull(self):
        """Test with stdout redirected to DEVNULL"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data,
                                         stdout=asyncssh.DEVNULL)

        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_file(self):
        """Test with stdout redirected to a file"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout='stdout')

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_binary_file(self):
        """Test with stdout redirected to a file in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout='stdout',
                                         encoding=None)

        with open('stdout', 'rb') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_pathlib(self):
        """Test with stdout redirected to a file name specified by pathlib"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data,
                                         stdout=Path('stdout'))

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_open_file(self):
        """Test with stdout redirected to an open file"""

        data = str(id(self))

        file = open('stdout', 'w')

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout=file)

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_open_binary_file(self):
        """Test with stdout redirected to an open binary file"""

        data = str(id(self)).encode() + b'\xff'

        file = open('stdout', 'wb')

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout=file,
                                         encoding=None)

        with open('stdout', 'rb') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_stringio(self):
        """Test with stdout redirected to a StringIO"""

        class _StringIOTest(io.StringIO):
            """Test class for StringIO which preserves output after close"""

            def __init__(self):
                super().__init__()
                self.output = None

            def close(self):
                if self.output is None:
                    self.output = self.getvalue()
                    super().close()

        data = str(id(self))

        file = _StringIOTest()

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout=file)

        self.assertEqual(file.output, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_bytesio(self):
        """Test with stdout redirected to a BytesIO"""

        class _BytesIOTest(io.BytesIO):
            """Test class for BytesIO which preserves output after close"""

            def __init__(self):
                super().__init__()
                self.output = None

            def close(self):
                if self.output is None:
                    self.output = self.getvalue()
                    super().close()

        data = str(id(self))

        file = _BytesIOTest()

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout=file)

        self.assertEqual(file.output, data.encode('ascii'))
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_process(self):
        """Test with stdout redirected to another SSH process"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            with (yield from conn.create_process()) as proc2:
                proc1 = yield from conn.create_process(stdout=proc2.stdin)

                proc1.stdin.write(data)
                proc1.stdin.write_eof()

                result = yield from proc2.wait()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_change_stdout(self):
        """Test changing stdout of an open process"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process(stdout='stdout')

            process.stdin.write('xxx')

            yield from asyncio.sleep(0.1)

            yield from process.redirect_stdout(asyncssh.PIPE)
            process.stdin.write('yyy')
            process.stdin.write_eof()

            result = yield from process.wait()

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, 'xxx')
        self.assertEqual(result.stdout, 'yyy')
        self.assertEqual(result.stderr, 'xxxyyy')

    @asynctest
    def test_change_stdin_process(self):
        """Test changing stdin of an open process reading from another"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            with (yield from conn.create_process()) as proc2:
                proc1 = yield from conn.create_process(stdout=proc2.stdin)

                proc1.stdin.write(data)
                yield from asyncio.sleep(0.1)

                yield from proc2.redirect_stdin(asyncssh.PIPE)
                proc2.stdin.write(data)
                yield from asyncio.sleep(0.1)

                yield from proc2.redirect_stdin(proc1.stdout)
                proc1.stdin.write_eof()

                result = yield from proc2.wait()

        self.assertEqual(result.stdout, data+data)
        self.assertEqual(result.stderr, data+data)

    @asynctest
    def test_change_stdout_process(self):
        """Test changing stdout of an open process sending to another"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            with (yield from conn.create_process()) as proc2:
                proc1 = yield from conn.create_process(stdout=proc2.stdin)

                proc1.stdin.write(data)
                yield from asyncio.sleep(0.1)

                yield from proc1.redirect_stdout(asyncssh.DEVNULL)
                proc1.stdin.write(data)
                yield from asyncio.sleep(0.1)

                yield from proc1.redirect_stdout(proc2.stdin)
                proc1.stdin.write_eof()

                result = yield from proc2.wait()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stderr_stdout(self):
        """Test with stderr redirected to stdout"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data,
                                         stderr=asyncssh.STDOUT)

        self.assertEqual(result.stdout, data+data)

    @asynctest
    def test_server_redirect_stdin(self):
        """Test redirect on server of stdin"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            result = yield from conn.run('redirect_stdin', input=data)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, '')

    @asynctest
    def test_server_redirect_stdout(self):
        """Test redirect on server of stdout"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            result = yield from conn.run('redirect_stdout', input=data)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, '')

    @asynctest
    def test_server_redirect_stderr(self):
        """Test redirect on server of stderr"""

        data = str(id(self))

        with (yield from self.connect()) as conn:
            result = yield from conn.run('redirect_stderr', input=data)

        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_pause_file_reader(self):
        """Test pausing and resuming reading from a file"""

        data = 4*1024*1024*'*'

        with open('stdin', 'w') as file:
            file.write(data)

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin='stdin',
                                         stderr=asyncssh.DEVNULL)

        self.assertEqual(result.stdout, data)

    @asynctest
    def test_pause_process_reader(self):
        """Test pausing and resuming reading from another SSH process"""

        data = 4*1024*1024*'*'

        with (yield from self.connect()) as conn:
            proc1 = yield from conn.create_process(input=data)

            proc2 = yield from conn.create_process('delay', stdin=proc1.stdout,
                                                   stderr=asyncssh.DEVNULL)
            proc3 = yield from conn.create_process('delay', stdin=proc1.stderr,
                                                   stderr=asyncssh.DEVNULL)

            result2, result3 = yield from asyncio.gather(proc2.wait(),
                                                         proc3.wait())

        self.assertEqual(result2.stdout, data)
        self.assertEqual(result3.stdout, data)

    @asynctest
    def test_redirect_stdin_when_paused(self):
        """Test redirecting stdin when write is paused"""

        data = 4*1024*1024*'*'

        with open('stdin', 'w') as file:
            file.write(data)

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process()

            process.stdin.write(data)

            yield from process.redirect_stdin('stdin')

            result = yield from process.wait()

        self.assertEqual(result.stdout, data+data)
        self.assertEqual(result.stderr, data+data)

    @asynctest
    def test_redirect_process_when_paused(self):
        """Test redirecting away from a process when write is paused"""

        data = 4*1024*1024*'*'

        with (yield from self.connect()) as conn:
            proc1 = yield from conn.create_process(input=data)
            proc2 = yield from conn.create_process('delay', stdin=proc1.stdout)
            proc3 = yield from conn.create_process('delay', stdin=proc1.stderr)

            yield from proc1.redirect_stderr(asyncssh.DEVNULL)

            result = yield from proc2.wait()
            proc3.close()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_consecutive_redirect(self):
        """Test consecutive redirects using drain"""

        data = 4*1024*1024*'*'

        with open('stdin', 'w') as file:
            file.write(data)

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process()

            yield from process.redirect_stdin('stdin', send_eof=False)
            yield from process.stdin.drain()

            yield from process.redirect_stdin('stdin')

            result = yield from process.wait()

        self.assertEqual(result.stdout, data+data)
        self.assertEqual(result.stderr, data+data)


@unittest.skipUnless(_aiofiles_available, 'Async file I/O not available')
class _TestAsyncFileRedirection(_TestProcess):
    """Unit tests for AsyncSSH async file redirection"""

    @asynctest
    def test_stdin_aiofile(self):
        """Test with stdin redirected to an aiofile"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        file = yield from aiofiles.open('stdin', 'r')

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=file)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_binary_aiofile(self):
        """Test with stdin redirected to an aiofile in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        with open('stdin', 'wb') as file:
            file.write(data)

        file = yield from aiofiles.open('stdin', 'rb')

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=file,
                                         encoding=None)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_aiofile(self):
        """Test with stdout redirected to an aiofile"""

        data = str(id(self))

        file = open('stdout', 'w')

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout=file)

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_binary_aiofile(self):
        """Test with stdout redirected to an aiofile in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        file = yield from aiofiles.open('stdout', 'wb')

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout=file,
                                         encoding=None)

        with open('stdout', 'rb') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_pause_async_file_reader(self):
        """Test pausing and resuming reading from an aiofile"""

        data = 4*1024*1024*'*'

        with open('stdin', 'w') as file:
            file.write(data)

        file = yield from aiofiles.open('stdin', 'r')

        with (yield from self.connect()) as conn:
            result = yield from conn.run('delay', stdin=file,
                                         stderr=asyncssh.DEVNULL)

        self.assertEqual(result.stdout, data)


@unittest.skipIf(sys.platform == 'win32', 'skip pipe tests on Windows')
class _TestProcessPipes(_TestProcess):
    """Unit tests for AsyncSSH process I/O using pipes"""

    @asynctest
    def test_stdin_pipe(self):
        """Test with stdin redirected to a pipe"""

        data = str(id(self))

        rpipe, wpipe = os.pipe()

        os.write(wpipe, data.encode())
        os.close(wpipe)

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=rpipe)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_text_pipe(self):
        """Test with stdin redirected to a pipe in text mode"""

        data = str(id(self))

        rpipe, wpipe = os.pipe()

        rpipe = os.fdopen(rpipe, 'r')
        wpipe = os.fdopen(wpipe, 'w')

        wpipe.write(data)
        wpipe.close()

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=rpipe)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdin_binary_pipe(self):
        """Test with stdin redirected to a pipe in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        rpipe, wpipe = os.pipe()

        os.write(wpipe, data)
        os.close(wpipe)

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=rpipe,
                                         encoding=None)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_pipe(self):
        """Test with stdout redirected to a pipe"""

        data = str(id(self))

        rpipe, wpipe = os.pipe()

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout=wpipe)

        stdout_data = os.read(rpipe, 1024)
        os.close(rpipe)

        self.assertEqual(stdout_data.decode(), data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_text_pipe(self):
        """Test with stdout redirected to a pipe in text mode"""

        data = str(id(self))

        rpipe, wpipe = os.pipe()

        rpipe = os.fdopen(rpipe, 'r')
        wpipe = os.fdopen(wpipe, 'w')

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout=wpipe)

        stdout_data = rpipe.read(1024)
        rpipe.close()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_stdout_binary_pipe(self):
        """Test with stdout redirected to a pipe in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        rpipe, wpipe = os.pipe()

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout=wpipe,
                                         encoding=None)

        stdout_data = os.read(rpipe, 1024)
        os.close(rpipe)

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, data)


@unittest.skipIf(sys.platform == 'win32', 'skip socketpair tests on Windows')
class _TestProcessSocketPair(_TestProcess):
    """Unit tests for AsyncSSH process I/O using socketpair"""

    @asynctest
    def test_stdin_socketpair(self):
        """Test with stdin redirected to a socketpair"""

        data = str(id(self))

        sock1, sock2 = socket.socketpair()

        sock1.send(data.encode())
        sock1.close()

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', stdin=sock2)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_change_stdin(self):
        """Test changing stdin of an open process"""

        sock1, sock2 = socket.socketpair()
        sock3, sock4 = socket.socketpair()

        sock1.send(b'xxx')
        sock3.send(b'yyy')

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process(stdin=sock2)

            yield from asyncio.sleep(0.1)
            yield from process.redirect_stdin(sock4)

            sock1.close()
            sock3.close()

            result = yield from process.wait()

        self.assertEqual(result.stdout, 'xxxyyy')
        self.assertEqual(result.stderr, 'xxxyyy')

    @asynctest
    def test_stdout_socketpair(self):
        """Test with stdout redirected to a socketpair"""

        data = str(id(self))

        sock1, sock2 = socket.socketpair()

        with (yield from self.connect()) as conn:
            result = yield from conn.run('echo', input=data, stdout=sock1)

        stdout_data = sock2.recv(1024)
        sock2.close()

        self.assertEqual(stdout_data.decode(), data)
        self.assertEqual(result.stderr, data)

    @asynctest
    def test_pause_socketpair_reader(self):
        """Test pausing and resuming reading from a socketpair"""

        data = 4*1024*1024*'*'

        sock1, sock2 = socket.socketpair()

        _, writer = yield from asyncio.open_unix_connection(sock=sock1)
        writer.write(data.encode())
        writer.close()

        with (yield from self.connect()) as conn:
            result = yield from conn.run('delay', stdin=sock2,
                                         stderr=asyncssh.DEVNULL)

        self.assertEqual(result.stdout, data)

    @asynctest
    def test_pause_socketpair_writer(self):
        """Test pausing and resuming writing to a socketpair"""

        data = 4*1024*1024*'*'

        rsock1, wsock1 = socket.socketpair()
        rsock2, wsock2 = socket.socketpair()

        reader1, writer1 = yield from asyncio.open_unix_connection(sock=rsock1)
        reader2, writer2 = yield from asyncio.open_unix_connection(sock=rsock2)

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process(input=data)

            yield from asyncio.sleep(1)

            yield from process.redirect_stdout(wsock1)
            yield from process.redirect_stderr(wsock2)

            stdout_data, stderr_data = \
                yield from asyncio.gather(reader1.read(), reader2.read())

            writer1.close()
            writer2.close()

            yield from process.wait()

        self.assertEqual(stdout_data.decode(), data)
        self.assertEqual(stderr_data.decode(), data)
