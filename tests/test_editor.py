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

"""Unit tests for AsyncSSH line editor"""

import asyncio
import asyncssh

from .server import ServerTestCase
from .util import asynctest


async def _handle_session(stdin, stdout, stderr):
    """Accept lines of input and echo them with a prefix"""

    encoding = stdin.channel.get_encoding()[0]
    prefix = '>>>' if encoding else b'>>>'
    data = '' if encoding else b''

    while not stdin.at_eof():
        try:
            data += await stdin.readline()
        except asyncssh.SignalReceived as exc:
            if exc.signal == 'CLEAR':
                stdin.channel.clear_input()
            elif exc.signal == 'ECHO_OFF':
                # Set twice to get coverage of when echo isn't changing
                stdin.channel.set_echo(False)
                stdin.channel.set_echo(False)
            elif exc.signal == 'ECHO_ON':
                stdin.channel.set_echo(True)
            elif exc.signal == 'LINE_OFF':
                stdin.channel.set_line_mode(False)
            else:
                break
        except asyncssh.BreakReceived:
            stdin.channel.set_input('BREAK', 0)
        except asyncssh.TerminalSizeChanged:
            continue

        stderr.write('.' if encoding else b'.')

    stdout.write(prefix + data)
    stdout.close()


async def _handle_ansi_attrs(_stdin, stdout, _stderr):
    """Output a line which has ANSI attributes in it"""

    stdout.write('\x1b[2m' + 72*'*' + '\x1b[0m')
    stdout.close()


async def _handle_output_wrap(_stdin, stdout, _stderr):
    """Output a line which needs to wrap early"""

    stdout.write(79*'*' + '\uff10')
    stdout.close()


async def _handle_soft_eof(stdin, stdout, _stderr):
    """Accept soft EOF using read()"""

    while not stdin.at_eof():
        data = await stdin.read()
        stdout.write(data or 'EOF\n')

    stdout.close()


async def _handle_app_line_echo(stdin, stdout, _stderr):
    """Perform line echo in the application"""

    while not stdin.at_eof():
        stdout.write('> ')
        data = await stdin.readline()
        stdout.write(data)

    stdout.close()


def _trigger_signal(line, pos):
    """Trigger a signal when Ctrl-Z is input"""

    # pylint: disable=unused-argument

    return 'SIG', -1


def _handle_key(_line, pos):
    """Handle exclamation point being input"""

    if pos == 0:
        return 'xyz', 3
    elif pos == 1:
        return True
    else:
        return False


async def _handle_register(stdin, stdout, _stderr):
    """Accept input using read() and echo it back"""

    while not stdin.at_eof():
        try:
            data = await stdin.readline()
        except asyncssh.SignalReceived:
            stdout.write('SIGNAL')
            break

        if data == 'R\n':
            stdin.channel.register_key('!', _handle_key)
            stdin.channel.register_key('"', _handle_key)
            stdin.channel.register_key('\u2013', _handle_key)
            stdin.channel.register_key('\x1bOP', _handle_key)
            stdin.channel.register_key('\x1a', _trigger_signal)
        elif data == 'U\n':
            stdin.channel.unregister_key('!')
            stdin.channel.unregister_key('"')
            stdin.channel.unregister_key('\u2013')
            stdin.channel.unregister_key('\x1bOP')
            stdin.channel.unregister_key('\x1bOQ') # Test unregistered key
            stdin.channel.unregister_key('\x1b[25~') # Test unregistered prefix
            stdin.channel.unregister_key('\x1a')

    stdout.close()


class _CheckEditor(ServerTestCase):
    """Utility functions for AsyncSSH line editor unit tests"""

    async def check_input(self, input_data, expected_result,
                          term_type='ansi', set_width=False):
        """Feed input data and compare echoed back result"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type=term_type)

            process.stdin.write(input_data)
            await process.stderr.readexactly(1)

            if set_width:
                process.change_terminal_size(132, 24)

            process.stdin.write_eof()

            output_data = (await process.wait()).stdout

        idx = output_data.rfind('>>>')
        self.assertNotEqual(idx, -1)
        output_data = output_data[idx+3:]

        self.assertEqual(output_data, expected_result)


class _TestEditor(_CheckEditor):
    """Unit tests for AsyncSSH line editor"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(session_factory=_handle_session)

    @asynctest
    async def test_editor(self):
        """Test line editing"""

        tests = (
            ('Simple line', 'abc\n', 'abc\r\n'),
            ('EOF', '\x04', ''),
            ('Erase left', 'abcd\x08\n', 'abc\r\n'),
            ('Erase left', 'abcd\x08\n', 'abc\r\n'),
            ('Erase left at beginning', '\x08abc\n', 'abc\r\n'),
            ('Erase right', 'abcd\x02\x04\n', 'abc\r\n'),
            ('Erase right at end', 'abc\x04\n', 'abc\r\n'),
            ('Erase line', 'abcdef\x15abc\n', 'abc\r\n'),
            ('Erase to end', 'abcdef\x02\x02\x02\x0b\n', 'abc\r\n'),
            ('Wrapping erase to end', 80*'*' + '\x02\x0b\n', 79*'*' + '\r\n'),
            ('History previous', 'abc\n\x10\n', 'abc\r\nabc\r\n'),
            ('History previous at top', '\x10abc\n', 'abc\r\n'),
            ('History next', 'a\nb\n\x10\x10\x0e\x08c\n', 'a\r\nb\r\nc\r\n'),
            ('History next to bottom', 'abc\n\x10\x0e\n', 'abc\r\n\r\n'),
            ('History next at bottom', '\x0eabc\n', 'abc\r\n'),
            ('Move left', 'abc\x02\n', 'abc\r\n'),
            ('Move left at beginning', '\x02abc\n', 'abc\r\n'),
            ('Move left arrow', 'abc\x1b[D\n', 'abc\r\n'),
            ('Move right', 'abc\x02\x06\n', 'abc\r\n'),
            ('Move right at end', 'abc\x06\n', 'abc\r\n'),
            ('Move to start', 'abc\x01\n', 'abc\r\n'),
            ('Move to end', 'abc\x02\x05\n', 'abc\r\n'),
            ('Redraw', 'abc\x12\n', 'abc\r\n'),
            ('Insert erased', 'abc\x15\x19\x19\n', 'abcabc\r\n'),
            ('Send break', 'abc\x03', 'BREAK'),
            ('Long line', 100*'*' + '\x02\x01\x05\n', 100*'*' + '\r\n'),
            ('Wide char wrap', 79*'*' + '\U0001F910\x08\n', 79*'*' + '\r\n'),
            ('Line length limit', 1024*'*' + '\x05*\n', 1024*'*' + '\r\n'),
            ('Unknown key', '\x07abc\n', 'abc\r\n')
        )

        for testname, input_data, expected_result in tests:
            with self.subTest(testname):
                await self.check_input(input_data, expected_result)

    @asynctest
    async def test_non_wrap(self):
        """Test line editing in non-wrap mode"""

        tests = (
            ('Simple line', 'abc\n', 'abc\r\n'),
            ('Long line', 100*'*' + '\x02\x01\x05\n', 100*'*' + '\r\n'),
            ('Long line 2', 101*'*' + 30*'\x02' + '\x08\n', 100*'*' + '\r\n'),
            ('Redraw', 'abc\x12\n', 'abc\r\n')
        )

        for testname, input_data, expected_result in tests:
            with self.subTest(testname):
                await self.check_input(input_data, expected_result,
                                       term_type='dumb')

    @asynctest
    async def test_no_terminal(self):
        """Test that editor is disabled when no pseudo-terminal is requested"""

        await self.check_input('abc\n', 'abc\n', term_type=None)

    @asynctest
    async def test_change_width(self):
        """Test changing the terminal width"""

        await self.check_input('abc\n', 'abc\r\n', set_width=True)

    @asynctest
    async def test_change_width_non_wrap(self):
        """Test changing the terminal width when not wrapping"""

        await self.check_input('abc\n', 'abc\r\n', term_type='dumb',
                               set_width=True)

    @asynctest
    async def test_editor_clear_input(self):
        """Test clearing editor's input line"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')

            process.stdin.write('abc')

            process.send_signal('CLEAR')
            await process.stderr.readexactly(1)

            process.stdin.write('\n')
            await process.stderr.readexactly(1)

            process.stdin.write_eof()
            output_data = (await process.wait()).stdout

        self.assertEqual(output_data, 'abc\x1b[3D   \x1b[3D\r\n>>>\r\n')

    @asynctest
    async def test_editor_echo_off(self):
        """Test editor with echo disabled"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')

            process.send_signal('ECHO_OFF')
            await process.stderr.readexactly(1)

            process.stdin.write('abcd\x08\n')
            await process.stderr.readexactly(1)

            process.stdin.write_eof()
            output_data = (await process.wait()).stdout

        self.assertEqual(output_data, '\r\n>>>abc\r\n')

    @asynctest
    async def test_editor_echo_on(self):
        """Test editor with echo re-enabled"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')

            process.send_signal('ECHO_OFF')
            await process.stderr.readexactly(1)

            process.stdin.write('abc')

            process.send_signal('ECHO_ON')
            await process.stderr.readexactly(1)

            process.stdin.write('d\x08\n')
            await process.stderr.readexactly(1)

            process.stdin.write_eof()
            output_data = (await process.wait()).stdout

        self.assertEqual(output_data, 'abcd\x1b[1D \x1b[1D\r\n>>>abc\r\n')

    @asynctest
    async def test_editor_line_mode_off(self):
        """Test editor with line mode disabled"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')

            process.send_signal('LINE_OFF')
            await process.stderr.readexactly(1)

            process.stdin.write('abc\n')
            await process.stderr.readexactly(1)

            process.stdin.write_eof()
            output_data = (await process.wait()).stdout

        self.assertEqual(output_data, '>>>abc\r\n')

    @asynctest
    async def test_unknown_signal(self):
        """Test unknown signal"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')
            process.send_signal('XXX')
            output_data = (await process.wait()).stdout

        self.assertEqual(output_data, '>>>')


class _TestEditorDisabled(_CheckEditor):
    """Unit tests for AsyncSSH line editor being disabled"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (await cls.create_server(session_factory=_handle_session,
                                        line_editor=False))

    @asynctest
    async def test_editor_disabled(self):
        """Test that editor is disabled"""

        await self.check_input('abc\n', 'abc\n')


class _TestEditorEncodingNone(_CheckEditor):
    """Unit tests for AsyncSSH line editor disabled due to encoding None"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (await cls.create_server(session_factory=_handle_session,
                                        encoding=None))

    @asynctest
    async def test_editor_disabled_encoding_none(self):
        """Test that editor is disabled when encoding is None"""

        await self.check_input('abc\n', 'abc\n')

    @asynctest
    async def test_change_width(self):
        """Test changing the terminal width"""

        await self.check_input('abc\n', 'abc\n', set_width=True)


class _TestEditorUnlimitedLength(_CheckEditor):
    """Unit tests for AsyncSSH line editor with no line length limit"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(session_factory=_handle_session,
                                       max_line_length=None)

    @asynctest
    async def test_editor_unlimited_length(self):
        """Test that editor can handle very long lines"""

        await self.check_input(32768*'*' + '\n', 32768*'*' + '\r\n')


class _TestEditorANSI(_CheckEditor):
    """Unit tests for AsyncSSH line editor handling ANSI attributes"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(session_factory=_handle_ansi_attrs)

    @asynctest
    async def test_editor_ansi(self):
        """Test that editor properly handles ANSI attributes in output"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')
            output_data = (await process.wait()).stdout
            self.assertEqual(output_data, '\x1b[2m' + 72*'*' + '\x1b[0m')


class _TestEditorOutputWrap(_CheckEditor):
    """Unit tests for AsyncSSH line editor wrapping output text"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(session_factory=_handle_output_wrap)

    @asynctest
    async def test_editor_output_wrap(self):
        """Test that editor properly wraps wide characters during output"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')
            output_data = (await process.wait()).stdout
            self.assertEqual(output_data, 79*'*' + '\uff10')


class _TestEditorSoftEOF(ServerTestCase):
    """Unit tests for AsyncSSH line editor sending soft EOF"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(session_factory=_handle_soft_eof)

    @asynctest
    async def test_editor_soft_eof(self):
        """Test editor sending soft EOF"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')

            process.stdin.write('\x04')

            self.assertEqual((await process.stdout.readline()), 'EOF\r\n')

            process.stdin.write('abc\n\x04')

            self.assertEqual((await process.stdout.readline()), 'abc\r\n')
            self.assertEqual((await process.stdout.readline()), 'abc\r\n')
            self.assertEqual((await process.stdout.readline()), 'EOF\r\n')

            process.stdin.write('abc\n')
            process.stdin.write_eof()

            self.assertEqual((await process.stdout.read()),
                             'abc\r\nabc\r\n')


class _TestEditorRegisterKey(ServerTestCase):
    """Unit tests for AsyncSSH line editor register key callback"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(session_factory=_handle_register)

    @asynctest
    async def test_editor_register_key(self):
        """Test editor register key functionality"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')

            for inp, result in (('R', 'R'),
                                ('!a', 'xyza'),
                                ('\u2013a', 'xyza'),
                                ('a!b', 'a!b'),
                                ('ab!', 'ab\x07'),
                                ('ab!!', 'ab\x07'),
                                ('\x1bOPa', 'xyza'),
                                ('a\x1bOPb', 'a\x07b'),
                                ('ab\x1bOP', 'ab\x07'),
                                ('U', 'U'),
                                ('!', '!'),
                                ('\x1bOP', '\x07')):
                process.stdin.write(inp + '\n')
                self.assertEqual((await process.stdout.readline()),
                                 result + '\r\n')

            process.stdin.write_eof()

    @asynctest
    async def test_editor_signal(self):
        """Test editor register key triggering a signal"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')

            process.stdin.write('R\n')
            await process.stdout.readline()

            process.stdin.write('\x1a')
            self.assertEqual((await process.stdout.read()), 'SIGNAL')


class _TestEditorLineEcho(_CheckEditor):
    """Unit tests for AsyncSSH line editor with line echo in application"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (await cls.create_server(session_factory=_handle_app_line_echo,
                                        line_echo=False))

    @asynctest
    async def test_editor_line_echo(self):
        """Test line echo handled by application"""

        async with self.connect() as conn:
            process = await conn.create_process(term_type='ansi')

            process.stdin.write('abc\rdef\r')
            await asyncio.sleep(0.1)
            process.stdin.write('ghi\r')
            await asyncio.sleep(0.1)
            process.stdin.write_eof()

            self.assertEqual((await process.stdout.read()),
                             '> abc\x1b[3D   \x1b[3Ddef\x1b[3D   \x1b[3D'
                             'abc\r\n> def\r\n> ghi\r\n> ')
