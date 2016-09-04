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

"""Unit tests for AsyncSSH line editor"""

import asyncio

import asyncssh

from .server import ServerTestCase
from .util import asynctest


def _handle_session(stdin, stdout, stderr):
    """Accept a single line of input and echo it with a prefix"""

    # pylint: disable=unused-argument

    break_count = 0
    prefix = '>>>' if stdin.channel.get_encoding() else b'>>>'
    data = '' if stdin.channel.get_encoding() else b''

    while not stdin.at_eof():
        try:
            data += yield from stdin.readline()
        except asyncssh.BreakReceived:
            break_count += 1
            stdout.write('B')

            if break_count == 1:
                # Set twice to get coverage of when echo isn't changing
                stdin.channel.set_echo(False)
                stdin.channel.set_echo(False)
            elif break_count == 2:
                stdin.channel.set_echo(True)
            elif break_count == 3:
                stdin.channel.set_line_mode(False)
            else:
                data = 'BREAK'
        except asyncssh.TerminalSizeChanged:
            continue

    stdout.write(prefix + data)
    stdout.close()


class _CheckEditor(ServerTestCase):
    """Utility functions for AsyncSSH line editor unit tests"""

    @asyncio.coroutine
    def check_input(self, input_data, expected_result,
                    term_type='ansi', set_width=False):
        """Feed input data and compare echoed back result"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process(term_type=term_type)

            process.stdin.write(input_data)

            if set_width:
                process.change_terminal_size(132, 24)

            process.stdin.write_eof()

            output_data = (yield from process.wait()).stdout

        idx = output_data.rfind('>>>')
        self.assertNotEqual(idx, -1)
        output_data = output_data[idx+3:]

        self.assertEqual(output_data, expected_result)


class _TestEditor(_CheckEditor):
    """Unit tests for AsyncSSH line editor"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (yield from cls.create_server(session_factory=_handle_session))

    @asynctest
    def test_editor(self):
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
            ('Send break', '\x03\x03\x03\x03', 'BREAK'),
            ('Long line', 100*'*' + '\x02\x01\x05\n', 100*'*' + '\r\n'),
            ('Wide char wrap', 79*'*' + '\uff10\n', 79*'*' + '\uff10\r\n'),
            ('Unknown key', '\x07abc\n', 'abc\r\n')
        )

        for testname, input_data, expected_result in tests:
            with self.subTest(testname):
                yield from self.check_input(input_data, expected_result)

    @asynctest
    def test_non_wrap(self):
        """Test line editing in non-wrap mode"""

        tests = (
            ('Simple line', 'abc\n', 'abc\r\n'),
            ('Long line', 100*'*' + '\x02\x01\x05\n', 100*'*' + '\r\n'),
            ('Long line 2', 101*'*' + 30*'\x02' + '\x08\n', 100*'*' + '\r\n'),
            ('Redraw', 'abc\x12\n', 'abc\r\n')
        )

        for testname, input_data, expected_result in tests:
            with self.subTest(testname):
                yield from self.check_input(input_data, expected_result,
                                            term_type='dumb')

    @asynctest
    def test_no_terminal(self):
        """Test that editor is disabled when no pseudo-terminal is requested"""

        yield from self.check_input('abc\n', 'abc\n', term_type=None)

    @asynctest
    def test_change_width(self):
        """Test changing the terminal width"""

        yield from self.check_input('abc\n', 'abc\r\n', set_width=True)

    @asynctest
    def test_change_width_non_wrap(self):
        """Test changing the terminal width when not wrapping"""

        yield from self.check_input('abc\n', 'abc\r\n', term_type='dumb',
                                    set_width=True)

    @asynctest
    def test_editor_echo_off(self):
        """Test editor with echo disabled"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process(term_type='ansi')

            process.stdin.write('\x03')
            yield from process.stdout.readexactly(1)

            process.stdin.write('abcd\x08\n')
            process.stdin.write_eof()
            output_data = (yield from process.wait()).stdout

        self.assertEqual(output_data, '\r\n>>>abc\r\n')

    @asynctest
    def test_editor_echo_on(self):
        """Test editor with echo re-enabled"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process(term_type='ansi')

            process.stdin.write('\x03')
            yield from process.stdout.readexactly(1)

            process.stdin.write('abc')

            process.stdin.write('\x03')
            yield from process.stdout.readexactly(1)

            process.stdin.write('\n')
            process.stdin.write_eof()
            output_data = (yield from process.wait()).stdout

        self.assertEqual(output_data, 'abc\r\n>>>abc\r\n')

    @asynctest
    def test_editor_line_mode_off(self):
        """Test editor with line mode disabled"""

        with (yield from self.connect()) as conn:
            process = yield from conn.create_process(term_type='ansi')

            process.stdin.write('\x03\x03')
            yield from process.stdout.readexactly(2)

            process.stdin.write('abc\x03')
            yield from process.stdout.readexactly(15)

            process.stdin.write('\n')
            process.stdin.write_eof()
            output_data = (yield from process.wait()).stdout

        self.assertEqual(output_data, 'abc\x1b[3D   \x1b[3D>>>abc\r\n')


class _TestEditorDisabled(_CheckEditor):
    """Unit tests for AsyncSSH line editor being disabled"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (yield from cls.create_server(session_factory=_handle_session,
                                             line_editor=False))

    @asynctest
    def test_editor_disabled(self):
        """Test that editor is disabled"""

        yield from self.check_input('abc\n', 'abc\n')


class _TestEditorEncodingNone(_CheckEditor):
    """Unit tests for AsyncSSH line editor disabled due to encoding None"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server for the tests to use"""

        return (yield from cls.create_server(session_factory=_handle_session,
                                             session_encoding=None))

    @asynctest
    def test_editor_disabled_encoding_none(self):
        """Test that editor is disabled when encoding is None"""

        yield from self.check_input('abc\n', 'abc\n')

    @asynctest
    def test_change_width(self):
        """Test changing the terminal width"""

        yield from self.check_input('abc\n', 'abc\n', set_width=True)
