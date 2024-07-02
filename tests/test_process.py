# Copyright (c) 2016-2021 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH process API"""

import asyncio
import io
import os
from pathlib import Path
from signal import SIGINT
import socket
import sys
import unittest

import asyncssh

from .server import ServerTestCase
from .util import asynctest, echo

if sys.platform != 'win32': # pragma: no branch
    import fcntl
    import struct
    import termios

try:
    import aiofiles
    _aiofiles_available = True
except ImportError: # pragma: no cover
    _aiofiles_available = False


async def _handle_client(process):
    """Handle a new client request"""

    action = process.command or process.subsystem
    if not action:
        action = 'echo'

    if action == 'break':
        try:
            await process.stdin.readline()
        except asyncssh.BreakReceived as exc:
            process.exit_with_signal('ABRT', False, str(exc.msec))
    elif action == 'delay':
        await asyncio.sleep(1)
        await echo(process.stdin, process.stdout, process.stderr)
    elif action == 'echo':
        await echo(process.stdin, process.stdout, process.stderr)
    elif action == 'exit_status':
        process.channel.set_encoding('utf-8')
        process.stderr.write('Exiting with status 1')
        process.exit(1)
    elif action == 'env':
        process.channel.set_encoding('utf-8')
        process.stdout.write(process.env.get('TEST', ''))
    elif action.startswith('redirect '):
        _, addr, port, action = action.split(None, 3)

        async with asyncssh.connect(addr, int(port)) as conn:
            upstream_process = await conn.create_process(
                command=action, encoding=None, term_type=process.term_type,
                stdin=process.stdin, stdout=process.stdout)

            result = await upstream_process.wait()
            process.exit_with_signal(*result.exit_signal)
    elif action == 'redirect_stdin':
        await process.redirect_stdin(process.stdout)
        await process.stdout.drain()
    elif action == 'redirect_stdout':
        await process.redirect_stdout(process.stdin)
        await process.stdout.drain()
    elif action == 'redirect_stderr':
        await process.redirect_stderr(process.stdin)
        await process.stderr.drain()
    elif action == 'old_term':
        info = str((process.get_terminal_type(), process.get_terminal_size(),
                    process.get_terminal_mode(asyncssh.PTY_OP_OSPEED)))
        process.channel.set_encoding('utf-8')
        process.stdout.write(info)
    elif action == 'term':
        info = str((process.term_type, process.term_size,
                    process.term_modes.get(asyncssh.PTY_OP_OSPEED),
                    sorted(process.term_modes.items())))
        process.channel.set_encoding('utf-8')
        process.stdout.write(info)
    elif action == 'term_size':
        try:
            await process.stdin.readline()
        except asyncssh.TerminalSizeChanged as exc:
            process.exit_with_signal('ABRT', False,
                                     '%sx%s' % (exc.width, exc.height))
    elif action == 'term_size_tty':
        master, slave = os.openpty()
        await process.redirect_stdin(master, recv_eof=False)
        process.stdout.write(b'\n')

        await process.stdin.readline()
        size = fcntl.ioctl(slave, termios.TIOCGWINSZ, 8*b'\0')
        height, width, _, _ = struct.unpack('hhhh', size)
        process.stdout.write(('%sx%s' % (width, height)).encode())
        os.close(slave)
    elif action == 'term_size_nontty':
        rpipe, wpipe = os.pipe()
        await process.redirect_stdin(wpipe)
        process.stdout.write(b'\n')

        await process.stdin.readline()
        os.close(rpipe)
    elif action == 'timeout':
        process.channel.set_encoding('utf-8')
        process.stdout.write('Sleeping')
        await asyncio.sleep(1)
    else:
        process.exit(255)

    process.close()
    await process.wait_closed()


class _TestProcess(ServerTestCase):
    """Unit tests for AsyncSSH process API"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(process_factory=_handle_client,
                                       encoding=None)


class _TestProcessBasic(_TestProcess):
    """Unit tests for AsyncSSH process basic functions"""

    @asynctest
    async def test_shell(self):
        """Test starting a remote shell"""

        data = str(id(self))

        async with self.connect() as conn:
            process = await conn.create_process(env={'TEST': 'test'})

            process.stdin.write(data)

            self.assertFalse(process.is_closing())
            process.stdin.write_eof()
            self.assertTrue(process.is_closing())

            result = await process.wait()

        self.assertEqual(result.env, {'TEST': 'test'})
        self.assertEqual(result.command, None)
        self.assertEqual(result.subsystem, None)
        self.assertEqual(result.exit_status, None)
        self.assertEqual(result.exit_signal, None)
        self.assertEqual(result.returncode, None)
        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_command(self):
        """Test executing a remote command"""

        data = str(id(self))

        async with self.connect() as conn:
            process = await conn.create_process('echo')

            process.stdin.write(data)
            process.stdin.write_eof()

            result = await process.wait()

        self.assertEqual(result.command, 'echo')
        self.assertEqual(result.subsystem, None)
        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_subsystem(self):
        """Test starting a remote subsystem"""

        data = str(id(self))

        async with self.connect() as conn:
            process = await conn.create_process(subsystem='echo')

            process.stdin.write(data)
            process.stdin.write_eof()

            result = await process.wait()

        self.assertEqual(result.command, None)
        self.assertEqual(result.subsystem, 'echo')
        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_communicate(self):
        """Test communicate"""

        data = str(id(self))

        async with self.connect() as conn:
            async with conn.create_process() as process:
                stdout_data, stderr_data = await process.communicate(data)

        self.assertEqual(stdout_data, data)
        self.assertEqual(stderr_data, data)

    @asynctest
    async def test_communicate_paused(self):
        """Test communicate when reading is already paused"""

        data = 4*1024*1024*'*'

        async with self.connect() as conn:
            async with conn.create_process(input=data) as process:
                await asyncio.sleep(1)
                stdout_data, stderr_data = await process.communicate()

        self.assertEqual(stdout_data, data)
        self.assertEqual(stderr_data, data)

    @asynctest
    async def test_env(self):
        """Test sending environment"""

        async with self.connect() as conn:
            process = await conn.create_process('env', env={'TEST': 'test'})
            result = await process.wait()

        self.assertEqual(result.stdout, 'test')

    @asynctest
    async def test_old_terminal_info(self):
        """Test setting and retrieving terminal information with old API"""

        modes = {asyncssh.PTY_OP_OSPEED: 9600}

        async with self.connect() as conn:
            process = await conn.create_process('old_term', term_type='ansi',
                                                term_size=(80, 24),
                                                term_modes=modes)
            result = await process.wait()

        self.assertEqual(result.stdout, "('ansi', (80, 24, 0, 0), 9600)")

    @asynctest
    async def test_terminal_info(self):
        """Test setting and retrieving terminal information"""

        modes = {asyncssh.PTY_OP_ISPEED: 9600, asyncssh.PTY_OP_OSPEED: 9600}

        async with self.connect() as conn:
            process = await conn.create_process('term', term_type='ansi',
                                                term_size=(80, 24),
                                                term_modes=modes)
            result = await process.wait()

        self.assertEqual(result.stdout, "('ansi', (80, 24, 0, 0), 9600, "
                                        "[(128, 9600), (129, 9600)])")

    @asynctest
    async def test_change_terminal_size(self):
        """Test changing terminal size"""

        async with self.connect() as conn:
            process = await conn.create_process('term_size', term_type='ansi')
            process.change_terminal_size(80, 24)
            result = await process.wait()

        self.assertEqual(result.exit_signal[2], '80x24')

    @asynctest
    async def test_break(self):
        """Test sending a break"""

        async with self.connect() as conn:
            process = await conn.create_process('break')
            process.send_break(1000)
            result = await process.wait()

        self.assertEqual(result.exit_signal[2], '1000')

    @asynctest
    async def test_signal(self):
        """Test sending a signal"""

        async with self.connect() as conn:
            process = await conn.create_process()
            process.send_signal('INT')
            result = await process.wait()

        self.assertEqual(result.exit_signal[0], 'INT')
        self.assertEqual(result.returncode, -SIGINT)

    @asynctest
    async def test_numeric_signal(self):
        """Test sending a signal using a numeric value"""

        async with self.connect() as conn:
            process = await conn.create_process()
            process.send_signal(SIGINT)
            result = await process.wait()

        self.assertEqual(result.exit_signal[0], 'INT')
        self.assertEqual(result.returncode, -SIGINT)

    @asynctest
    async def test_terminate(self):
        """Test sending a terminate signal"""

        async with self.connect() as conn:
            process = await conn.create_process()
            process.terminate()
            result = await process.wait()

        self.assertEqual(result.exit_signal[0], 'TERM')

    @asynctest
    async def test_kill(self):
        """Test sending a kill signal"""

        async with self.connect() as conn:
            process = await conn.create_process()
            process.kill()
            result = await process.wait()

        self.assertEqual(result.exit_signal[0], 'KILL')

    @asynctest
    async def test_exit_status(self):
        """Test checking exit status"""

        async with self.connect() as conn:
            result = await conn.run('exit_status')

        self.assertEqual(result.exit_status, 1)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'Exiting with status 1')

    @asynctest
    async def test_raise_on_exit_status(self):
        """Test raising an exception on non-zero exit status"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ProcessError) as exc:
                await conn.run('exit_status', env={'TEST': 'test'}, check=True)

        self.assertEqual(exc.exception.env, {'TEST': 'test'})
        self.assertEqual(exc.exception.command, 'exit_status')
        self.assertEqual(exc.exception.subsystem, None)
        self.assertEqual(exc.exception.exit_status, 1)
        self.assertEqual(exc.exception.reason,
                         'Process exited with non-zero exit status 1')
        self.assertEqual(exc.exception.returncode, 1)

    @asynctest
    async def test_raise_on_timeout(self):
        """Test raising an exception on timeout"""

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ProcessError) as exc:
                await conn.run('timeout', timeout=0.1)

        self.assertEqual(exc.exception.command, 'timeout')
        self.assertEqual(exc.exception.reason, '')
        self.assertEqual(exc.exception.stdout, 'Sleeping')

    @asynctest
    async def test_exit_signal(self):
        """Test checking exit signal"""

        async with self.connect() as conn:
            process = await conn.create_process()
            process.send_signal('INT')
            result = await process.wait()

        self.assertEqual(result.exit_status, -1)
        self.assertEqual(result.exit_signal[0], 'INT')
        self.assertEqual(result.returncode, -SIGINT)

    @asynctest
    async def test_raise_on_exit_signal(self):
        """Test raising an exception on exit signal"""

        async with self.connect() as conn:
            process = await conn.create_process()

            with self.assertRaises(asyncssh.ProcessError) as exc:
                process.send_signal('INT')
                await process.wait(check=True)

        self.assertEqual(exc.exception.exit_status, -1)
        self.assertEqual(exc.exception.exit_signal[0], 'INT')
        self.assertEqual(exc.exception.reason,
                         'Process exited with signal INT')
        self.assertEqual(exc.exception.returncode, -SIGINT)

    @asynctest
    async def test_split_unicode(self):
        """Test Unicode split across blocks"""

        data = '\u2000test\u2000'

        with open('stdin', 'w', encoding='utf-8') as file:
            file.write(data)

        async with self.connect() as conn:
            result = await conn.run('echo', stdin='stdin', bufsize=2)

        self.assertEqual(result.stdout, data)

    @asynctest
    async def test_invalid_unicode(self):
        """Test invalid Unicode data"""

        data = b'\xfftest'

        with open('stdin', 'wb') as file:
            file.write(data)

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ProtocolError):
                await conn.run('echo', stdin='stdin')

    @asynctest
    async def test_ignoring_invalid_unicode(self):
        """Test ignoring invalid Unicode data"""

        data = b'\xfftest'

        with open('stdin', 'wb') as file:
            file.write(data)

        async with self.connect() as conn:
            await conn.run('echo', stdin='stdin',
                           encoding='utf-8', errors='ignore')

    @asynctest
    async def test_incomplete_unicode(self):
        """Test incomplete Unicode data"""

        data = '\u2000'.encode('utf-8')[:2]

        with open('stdin', 'wb') as file:
            file.write(data)

        async with self.connect() as conn:
            with self.assertRaises(asyncssh.ProtocolError):
                await conn.run('echo', stdin='stdin')

    @asynctest
    async def test_disconnect(self):
        """Test collecting output from a disconnected channel"""

        data = str(id(self))

        async with self.connect() as conn:
            process = await conn.create_process()

            process.stdin.write(data)
            process.send_signal('ABRT')

            result = await process.wait()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_get_extra_info(self):
        """Test get_extra_info on streams"""

        async with self.connect() as conn:
            process = await conn.create_process()
            self.assertEqual(process.get_extra_info('connection'), conn)
            process.stdin.write_eof()

            await process.wait()

    @asynctest
    async def test_unknown_action(self):
        """Test unknown action"""

        async with self.connect() as conn:
            result = await conn.run('unknown')

        self.assertEqual(result.exit_status, 255)


class _TestProcessRedirection(_TestProcess):
    """Unit tests for AsyncSSH process I/O redirection"""

    @asynctest
    async def test_input(self):
        """Test with input from a string"""

        data = str(id(self))

        async with self.connect() as conn:
            result = await conn.run('echo', input=data)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_devnull(self):
        """Test with stdin redirected to DEVNULL"""

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=asyncssh.DEVNULL)

        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')

    @asynctest
    async def test_stdin_file(self):
        """Test with stdin redirected to a file"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        async with self.connect() as conn:
            result = await conn.run('echo', stdin='stdin')

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_binary_file(self):
        """Test with stdin redirected to a file in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        with open('stdin', 'wb') as file:
            file.write(data)

        async with self.connect() as conn:
            result = await conn.run('echo', stdin='stdin', encoding=None)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_pathlib(self):
        """Test with stdin redirected to a file name specified by pathlib"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=Path('stdin'))

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_open_file(self):
        """Test with stdin redirected to an open file"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        file = open('stdin', 'r')

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=file)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_open_binary_file(self):
        """Test with stdin redirected to an open file in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        with open('stdin', 'wb') as file:
            file.write(data)

        file = open('stdin', 'rb')

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=file, encoding=None)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_stringio(self):
        """Test with stdin redirected to a StringIO object"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        file = io.StringIO(data)

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=file)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_bytesio(self):
        """Test with stdin redirected to a BytesIO object"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        file = io.BytesIO(data.encode('ascii'))

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=file)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_process(self):
        """Test with stdin redirected to another SSH process"""

        data = str(id(self))

        async with self.connect() as conn:
            proc1 = await conn.create_process(input=data)
            proc2 = await conn.create_process(stdin=proc1.stdout)
            result = await proc2.wait()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_forward_terminal_size(self):
        """Test forwarding a terminal size change"""

        async with self.connect() as conn:
            cmd = f'redirect {self._server_addr} {self._server_port} term_size'
            process = await conn.create_process(cmd, term_type='ansi')
            process.change_terminal_size(80, 24)
            result = await process.wait()

        self.assertEqual(result.exit_signal[2], '80x24')

    @unittest.skipIf(sys.platform == 'win32',
                     'skip TTY terminal size tests on Windows')
    @asynctest
    async def test_forward_terminal_size_tty(self):
        """Test forwarding a terminal size change to a remote tty"""

        async with self.connect() as conn:
            process = await conn.create_process('term_size_tty',
                                                term_type='ansi')
            await process.stdout.readline()
            process.change_terminal_size(80, 24)
            process.stdin.write_eof()
            result = await process.wait()

        self.assertEqual(result.stdout, '80x24')

    @unittest.skipIf(sys.platform == 'win32',
                     'skip TTY terminal size tests on Windows')
    @asynctest
    async def test_forward_terminal_size_nontty(self):
        """Test forwarding a terminal size change to a remote non-tty"""

        async with self.connect() as conn:
            process = await conn.create_process('term_size_nontty',
                                                term_type='ansi')
            await process.stdout.readline()
            process.change_terminal_size(80, 24)
            process.stdin.write_eof()
            result = await process.wait()

        self.assertEqual(result.stdout, '')

    @asynctest
    async def test_forward_break(self):
        """Test forwarding a break"""

        async with self.connect() as conn:
            cmd = f'redirect {self._server_addr} {self._server_port} break'
            process = await conn.create_process(cmd)
            process.send_break(1000)
            result = await process.wait()

        self.assertEqual(result.exit_signal[2], '1000')

    @asynctest
    async def test_forward_signal(self):
        """Test forwarding a signal"""

        async with self.connect() as conn:
            cmd = f'redirect {self._server_addr} {self._server_port} echo'
            process = await conn.create_process(cmd)
            process.stdin.write('\n')
            await process.stdout.readline()
            process.send_signal('INT')
            result = await process.wait()

        self.assertEqual(result.exit_signal[0], 'INT')
        self.assertEqual(result.returncode, -SIGINT)

    @unittest.skipIf(sys.platform == 'win32',
                     'skip asyncio.subprocess tests on Windows')
    @asynctest
    async def test_stdin_stream(self):
        """Test with stdin redirected to an asyncio stream"""

        data = 4*1024*1024*'*'

        async with self.connect() as conn:
            proc1 = await asyncio.create_subprocess_shell(
                'cat', stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE)
            proc1.stdin.write(data.encode('ascii'))
            proc1.stdin.write_eof()

            proc2 = await conn.create_process('delay', stdin=proc1.stdout)
            result = await proc2.wait()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_devnull(self):
        """Test with stdout redirected to DEVNULL"""

        data = str(id(self))

        async with self.connect() as conn:
            result = await conn.run('echo', input=data,
                                    stdout=asyncssh.DEVNULL)

        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_file(self):
        """Test with stdout redirected to a file"""

        data = str(id(self))

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout='stdout')

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_binary_file(self):
        """Test with stdout redirected to a file in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout='stdout',
                                    encoding=None)

        with open('stdout', 'rb') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_pathlib(self):
        """Test with stdout redirected to a file name specified by pathlib"""

        data = str(id(self))

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=Path('stdout'))

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_open_file(self):
        """Test with stdout redirected to an open file"""

        data = str(id(self))

        file = open('stdout', 'w')

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=file)

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_open_file_keep_open(self):
        """Test with stdout redirected to an open file which remains open"""

        data = str(id(self))

        with open('stdout', 'w') as file:
            async with self.connect() as conn:
                await conn.run('echo', input=data, stdout=file, recv_eof=False)
                await conn.run('echo', input=data, stdout=file, recv_eof=False)

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, 2*data)

    @asynctest
    async def test_stdout_open_binary_file(self):
        """Test with stdout redirected to an open binary file"""

        data = str(id(self)).encode() + b'\xff'

        file = open('stdout', 'wb')

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=file,
                                    encoding=None)

        with open('stdout', 'rb') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_stringio(self):
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

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=file)

        self.assertEqual(file.output, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_bytesio(self):
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

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=file)

        self.assertEqual(file.output, data.encode('ascii'))
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_process(self):
        """Test with stdout redirected to another SSH process"""

        data = str(id(self))

        async with self.connect() as conn:
            async with conn.create_process() as proc2:
                proc1 = await conn.create_process(stdout=proc2.stdin)

                proc1.stdin.write(data)
                proc1.stdin.write_eof()

                result = await proc2.wait()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @unittest.skipIf(sys.platform == 'win32',
                     'skip asyncio.subprocess tests on Windows')
    @asynctest
    async def test_stdout_stream(self):
        """Test with stdout redirected to an asyncio stream"""

        data = str(id(self))

        async with self.connect() as conn:
            proc2 = await asyncio.create_subprocess_shell(
                'cat', stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE)

            proc1 = await conn.create_process(stdout=proc2.stdin,
                                              stderr=asyncssh.DEVNULL)

            proc1.stdin.write(data)
            proc1.stdin.write_eof()

            stdout_data = await proc2.stdout.read()

        self.assertEqual(stdout_data, data.encode('ascii'))

    @unittest.skipIf(sys.platform == 'win32',
                     'skip asyncio.subprocess tests on Windows')
    @asynctest
    async def test_stdout_stream_keep_open(self):
        """Test with stdout redirected to asyncio stream which remains open"""

        data = str(id(self))

        async with self.connect() as conn:
            proc2 = await asyncio.create_subprocess_shell(
                'cat', stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE)

            await conn.run('echo', input=data, stdout=proc2.stdin,
                           stderr=asyncssh.DEVNULL, recv_eof=False)
            await conn.run('echo', input=data, stdout=proc2.stdin,
                           stderr=asyncssh.DEVNULL)

            stdout_data = await proc2.stdout.read()

        self.assertEqual(stdout_data, 2*data.encode('ascii'))

    @asynctest
    async def test_change_stdout(self):
        """Test changing stdout of an open process"""

        async with self.connect() as conn:
            process = await conn.create_process(stdout='stdout')

            process.stdin.write('xxx')

            await asyncio.sleep(0.1)

            await process.redirect_stdout(asyncssh.PIPE)
            process.stdin.write('yyy')
            process.stdin.write_eof()

            result = await process.wait()

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, 'xxx')
        self.assertEqual(result.stdout, 'yyy')
        self.assertEqual(result.stderr, 'xxxyyy')

    @asynctest
    async def test_change_stdin_process(self):
        """Test changing stdin of an open process reading from another"""

        data = str(id(self))

        async with self.connect() as conn:
            async with conn.create_process() as proc2:
                proc1 = await conn.create_process(stdout=proc2.stdin)

                proc1.stdin.write(data)
                await asyncio.sleep(0.1)

                await proc2.redirect_stdin(asyncssh.PIPE)
                proc2.stdin.write(data)
                await asyncio.sleep(0.1)

                await proc2.redirect_stdin(proc1.stdout)
                proc1.stdin.write_eof()

                result = await proc2.wait()

        self.assertEqual(result.stdout, data+data)
        self.assertEqual(result.stderr, data+data)

    @asynctest
    async def test_change_stdout_process(self):
        """Test changing stdout of an open process sending to another"""

        data = str(id(self))

        async with self.connect() as conn:
            async with conn.create_process() as proc2:
                proc1 = await conn.create_process(stdout=proc2.stdin)

                proc1.stdin.write(data)
                await asyncio.sleep(0.1)

                await proc1.redirect_stdout(asyncssh.DEVNULL)
                proc1.stdin.write(data)
                await asyncio.sleep(0.1)

                await proc1.redirect_stdout(proc2.stdin)
                proc1.stdin.write_eof()

                result = await proc2.wait()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stderr_stdout(self):
        """Test with stderr redirected to stdout"""

        data = str(id(self))

        async with self.connect() as conn:
            result = await conn.run('echo', input=data,
                                    stderr=asyncssh.STDOUT)

        self.assertEqual(result.stdout, data+data)

    @asynctest
    async def test_server_redirect_stdin(self):
        """Test redirect on server of stdin"""

        data = str(id(self))

        async with self.connect() as conn:
            result = await conn.run('redirect_stdin', input=data)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, '')

    @asynctest
    async def test_server_redirect_stdout(self):
        """Test redirect on server of stdout"""

        data = str(id(self))

        async with self.connect() as conn:
            result = await conn.run('redirect_stdout', input=data)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, '')

    @asynctest
    async def test_server_redirect_stderr(self):
        """Test redirect on server of stderr"""

        data = str(id(self))

        async with self.connect() as conn:
            result = await conn.run('redirect_stderr', input=data)

        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_pause_file_reader(self):
        """Test pausing and resuming reading from a file"""

        data = 4*1024*1024*'*'

        with open('stdin', 'w') as file:
            file.write(data)

        async with self.connect() as conn:
            result = await conn.run('echo', stdin='stdin',
                                    stderr=asyncssh.DEVNULL)

        self.assertEqual(result.stdout, data)

    @asynctest
    async def test_pause_process_reader(self):
        """Test pausing and resuming reading from another SSH process"""

        data = 4*1024*1024*'*'

        async with self.connect() as conn:
            proc1 = await conn.create_process(input=data)

            proc2 = await conn.create_process('delay', stdin=proc1.stdout,
                                              stderr=asyncssh.DEVNULL)
            proc3 = await conn.create_process('delay', stdin=proc1.stderr,
                                              stderr=asyncssh.DEVNULL)

            result2, result3 = await asyncio.gather(proc2.wait(), proc3.wait())

        self.assertEqual(result2.stdout, data)
        self.assertEqual(result3.stdout, data)

    @asynctest
    async def test_redirect_stdin_when_paused(self):
        """Test redirecting stdin when write is paused"""

        data = 4*1024*1024*'*'

        with open('stdin', 'w') as file:
            file.write(data)

        async with self.connect() as conn:
            process = await conn.create_process()

            process.stdin.write(data)

            await process.redirect_stdin('stdin')

            result = await process.wait()

        self.assertEqual(result.stdout, data+data)
        self.assertEqual(result.stderr, data+data)

    @asynctest
    async def test_redirect_process_when_paused(self):
        """Test redirecting away from a process when write is paused"""

        data = 4*1024*1024*'*'

        async with self.connect() as conn:
            proc1 = await conn.create_process(input=data)
            proc2 = await conn.create_process('delay', stdin=proc1.stdout)
            proc3 = await conn.create_process('delay', stdin=proc1.stderr)

            await proc1.redirect_stderr(asyncssh.DEVNULL)

            result = await proc2.wait()
            proc3.close()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_consecutive_redirect(self):
        """Test consecutive redirects using drain"""

        data = 4*1024*1024*'*'

        with open('stdin', 'w') as file:
            file.write(data)

        async with self.connect() as conn:
            process = await conn.create_process()

            await process.redirect_stdin('stdin', send_eof=False)
            await process.stdin.drain()

            await process.redirect_stdin('stdin')

            result = await process.wait()

        self.assertEqual(result.stdout, data+data)
        self.assertEqual(result.stderr, data+data)


@unittest.skipUnless(_aiofiles_available, 'Async file I/O not available')
class _TestAsyncFileRedirection(_TestProcess):
    """Unit tests for AsyncSSH async file redirection"""

    @asynctest
    async def test_stdin_aiofile(self):
        """Test with stdin redirected to an aiofile"""

        data = str(id(self))

        with open('stdin', 'w') as file:
            file.write(data)

        file = await aiofiles.open('stdin', 'r')

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=file)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_binary_aiofile(self):
        """Test with stdin redirected to an aiofile in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        with open('stdin', 'wb') as file:
            file.write(data)

        file = await aiofiles.open('stdin', 'rb')

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=file, encoding=None)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_aiofile(self):
        """Test with stdout redirected to an aiofile"""

        data = str(id(self))

        file = await aiofiles.open('stdout', 'w')

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=file)

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_aiofile_keep_open(self):
        """Test with stdout redirected to an aiofile which remains open"""

        data = str(id(self))

        async with aiofiles.open('stdout', 'w') as file:
            async with self.connect() as conn:
                await conn.run('echo', input=data, stdout=file, recv_eof=False)
                await conn.run('echo', input=data, stdout=file, recv_eof=False)

        with open('stdout', 'r') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, 2*data)

    @asynctest
    async def test_stdout_binary_aiofile(self):
        """Test with stdout redirected to an aiofile in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        file = await aiofiles.open('stdout', 'wb')

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=file,
                                    encoding=None)

        with open('stdout', 'rb') as file:
            stdout_data = file.read()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_pause_async_file_reader(self):
        """Test pausing and resuming reading from an aiofile"""

        data = 4*1024*1024*'*'

        with open('stdin', 'w') as file:
            file.write(data)

        file = await aiofiles.open('stdin', 'r')

        async with self.connect() as conn:
            result = await conn.run('delay', stdin=file,
                                    stderr=asyncssh.DEVNULL)

        self.assertEqual(result.stdout, data)

    @asynctest
    async def test_pause_async_file_writer(self):
        """Test pausing and resuming writing to an aiofile"""

        data = 4*1024*1024*'*'

        async with aiofiles.open('stdout', 'w') as file:
            async with self.connect() as conn:
                await conn.run('delay', input=data, stdout=file,
                               stderr=asyncssh.DEVNULL)

        with open('stdout', 'r') as file:
            self.assertEqual(file.read(), data)


@unittest.skipIf(sys.platform == 'win32', 'skip pipe tests on Windows')
class _TestProcessPipes(_TestProcess):
    """Unit tests for AsyncSSH process I/O using pipes"""

    @asynctest
    async def test_stdin_pipe(self):
        """Test with stdin redirected to a pipe"""

        data = str(id(self))

        rpipe, wpipe = os.pipe()

        os.write(wpipe, data.encode())
        os.close(wpipe)

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=rpipe)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_text_pipe(self):
        """Test with stdin redirected to a pipe in text mode"""

        data = str(id(self))

        rpipe, wpipe = os.pipe()

        rpipe = os.fdopen(rpipe, 'r')
        wpipe = os.fdopen(wpipe, 'w')

        wpipe.write(data)
        wpipe.close()

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=rpipe)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdin_binary_pipe(self):
        """Test with stdin redirected to a pipe in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        rpipe, wpipe = os.pipe()

        os.write(wpipe, data)
        os.close(wpipe)

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=rpipe, encoding=None)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_pipe(self):
        """Test with stdout redirected to a pipe"""

        data = str(id(self))

        rpipe, wpipe = os.pipe()

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=wpipe)

        stdout_data = os.read(rpipe, 1024)
        os.close(rpipe)

        self.assertEqual(stdout_data.decode(), data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_pipe_keep_open(self):
        """Test with stdout redirected to a pipe which remains open"""

        data = str(id(self))

        rpipe, wpipe = os.pipe()

        os.write(wpipe, data.encode())

        async with self.connect() as conn:
            await conn.run('echo', input=data, stdout=wpipe, recv_eof=False)
            await conn.run('echo', input=data, stdout=wpipe, recv_eof=False)

        os.write(wpipe, data.encode())
        os.close(wpipe)

        stdout_data = os.read(rpipe, 1024)
        os.close(rpipe)

        self.assertEqual(stdout_data.decode(), 4*data)

    @asynctest
    async def test_stdout_text_pipe(self):
        """Test with stdout redirected to a pipe in text mode"""

        data = str(id(self))

        rpipe, wpipe = os.pipe()

        rpipe = os.fdopen(rpipe, 'r')
        wpipe = os.fdopen(wpipe, 'w')

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=wpipe)

        stdout_data = rpipe.read(1024)
        rpipe.close()

        self.assertEqual(stdout_data, data)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_stdout_text_pipe_keep_open(self):
        """Test with stdout to a pipe in text mode which remains open"""

        data = str(id(self))

        rpipe, wpipe = os.pipe()

        rpipe = os.fdopen(rpipe, 'r')
        wpipe = os.fdopen(wpipe, 'w')

        wpipe.write(data)

        async with self.connect() as conn:
            await conn.run('echo', input=data, stdout=wpipe, recv_eof=False)
            await conn.run('echo', input=data, stdout=wpipe, recv_eof=False)

        wpipe.write(data)
        wpipe.close()

        stdout_data = rpipe.read(1024)
        rpipe.close()

        self.assertEqual(stdout_data, 4*data)

    @asynctest
    async def test_stdout_binary_pipe(self):
        """Test with stdout redirected to a pipe in binary mode"""

        data = str(id(self)).encode() + b'\xff'

        rpipe, wpipe = os.pipe()

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=wpipe,
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
    async def test_stdin_socketpair(self):
        """Test with stdin redirected to a socketpair"""

        data = str(id(self))

        sock1, sock2 = socket.socketpair()

        sock1.send(data.encode())
        sock1.close()

        async with self.connect() as conn:
            result = await conn.run('echo', stdin=sock2)

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_change_stdin(self):
        """Test changing stdin of an open process"""

        sock1, sock2 = socket.socketpair()
        sock3, sock4 = socket.socketpair()

        sock1.send(b'xxx')
        sock3.send(b'yyy')

        async with self.connect() as conn:
            process = await conn.create_process(stdin=sock2)

            await asyncio.sleep(0.1)
            await process.redirect_stdin(sock4)

            sock1.close()
            sock3.close()

            result = await process.wait()

        self.assertEqual(result.stdout, 'xxxyyy')
        self.assertEqual(result.stderr, 'xxxyyy')

    @asynctest
    async def test_stdout_socketpair(self):
        """Test with stdout redirected to a socketpair"""

        data = str(id(self))

        sock1, sock2 = socket.socketpair()

        async with self.connect() as conn:
            result = await conn.run('echo', input=data, stdout=sock1)

        stdout_data = sock2.recv(1024)
        sock2.close()

        self.assertEqual(stdout_data.decode(), data)
        self.assertEqual(result.stderr, data)

    @asynctest
    async def test_pause_socketpair_pipes(self):
        """Test pausing and resuming reading from and writing to pipes"""

        data = 4*1024*1024*b'*'

        sock1, sock2 = socket.socketpair()
        sock3, sock4 = socket.socketpair()

        _, writer1 = await asyncio.open_unix_connection(sock=sock1)
        writer1.write(data)
        writer1.close()

        reader2, writer2 = await asyncio.open_unix_connection(sock=sock4)

        async with self.connect() as conn:
            process = await conn.create_process('delay', encoding=None,
                                                stdin=sock2, stdout=sock3,
                                                stderr=asyncssh.DEVNULL)

            self.assertEqual((await reader2.read()), data)
            await process.wait()

        writer2.close()

    @asynctest
    async def test_pause_socketpair_streams(self):
        """Test pausing and resuming reading from and writing to streams"""

        data = 4*1024*1024*b'*'

        sock1, sock2 = socket.socketpair()
        sock3, sock4 = socket.socketpair()

        _, writer1 = await asyncio.open_unix_connection(sock=sock1)
        writer1.write(data)
        writer1.close()

        reader2, writer2 = await asyncio.open_unix_connection(sock=sock2)
        _, writer3 = await asyncio.open_unix_connection(sock=sock3)
        reader4, writer4 = await asyncio.open_unix_connection(sock=sock4)

        async with self.connect() as conn:
            process = await conn.create_process('delay', encoding=None,
                                                stdin=reader2, stdout=writer3,
                                                stderr=asyncssh.DEVNULL)

            self.assertEqual((await reader4.read()), data)
            await process.wait()

        writer2.close()
        writer3.close()
        writer4.close()
