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

"""Input line editor"""

from unicodedata import east_asian_width


_DEFAULT_WIDTH = 80

_ansi_terminals = ('ansi', 'cygwin', 'linux', 'putty', 'screen', 'teraterm',
                   'cit80', 'vt100', 'vt102', 'vt220', 'vt320', 'xterm',
                   'xterm-color', 'xterm-16color', 'xterm-256color', 'rxvt',
                   'rxvt-color')


def _is_wide(ch):
    """Return display width of character"""

    return east_asian_width(ch) in 'WF'


class SSHLineEditor:
    """Input line editor"""

    def __init__(self, chan, session, history_size, term_type, width):
        self._chan = chan
        self._session = session
        self._history_size = history_size if history_size > 0 else 0
        self._wrap = term_type in _ansi_terminals
        self._width = width or _DEFAULT_WIDTH
        self._line_mode = True
        self._echo = True
        self._start_column = 0
        self._end_column = 0
        self._cursor = 0
        self._left_pos = 0
        self._right_pos = 0
        self._pos = 0
        self._line = ''
        self._key_state = self._keymap
        self._erased = ''
        self._history = []
        self._history_index = 0

    @classmethod
    def build_keymap(cls):
        """Build keyboard input map"""

        cls._keymap = {}

        for func, keys in cls._keylist:
            for key in keys:
                keymap = cls._keymap

                for ch in key[:-1]:
                    if ch not in keymap:
                        keymap[ch] = {}

                    keymap = keymap[ch]

                keymap[key[-1]] = func

    def _determine_column(self, data, start):
        """Determine new output column after output occurs"""

        column = start

        for ch in data:
            if ch == '\b':
                column -= 1
            else:
                if _is_wide(ch) and (column % self._width) == self._width - 1:
                    column += 1

                column += 2 if _is_wide(ch) else 1

        return column

    def _column(self, pos):
        """Determine output column of end of current input line"""

        return self._determine_column(self._line[self._left_pos:pos],
                                      self._start_column)

    def _output(self, data):
        """Generate output and calculate new output column"""

        self._chan.write(data.replace('\n', '\r\n'))

        idx = data.rfind('\n')

        if idx >= 0:
            tail = data[idx+1:]
            self._cursor = 0
        else:
            tail = data

        self._cursor = self._determine_column(tail, self._cursor)

        if (self._line_mode and self._cursor and
                self._cursor % self._width == 0):
            self._chan.write(' \b')

    def _ring_bell(self):
        """Ring the terminal bell"""

        self._chan.write('\a')

    def _update_input_window(self, pos):
        """Update visible input window when not wrapping onto multiple lines"""

        if pos < self._left_pos:
            self._left_pos = pos
        else:
            if pos < len(self._line):
                pos += 1

            if self._column(pos) >= self._width:
                while self._column(pos) >= self._width:
                    self._left_pos += 1
            else:
                while self._left_pos > 0:
                    self._left_pos -= 1
                    if self._column(pos) >= self._width:
                        self._left_pos += 1
                        break

        column = self._start_column
        self._right_pos = self._left_pos

        while self._right_pos < len(self._line):
            column += 1 + _is_wide(self._line[self._right_pos])

            if column < self._width:
                self._right_pos += 1
            else:
                break

    def _update_line(self, start_pos=None, end_pos=None):
        """Update display of selected portion of input line"""

        self._output(self._line[start_pos:end_pos])

        if self._end_column > self._cursor:
            new_end_column = self._cursor
            self._output(' ' * (self._end_column - new_end_column))
            self._end_column = new_end_column
        else:
            self._end_column = self._cursor

    def _move_cursor(self, pos):
        """Move the cursor to selected position in input line"""

        if self._wrap:
            new_column = self._column(pos)

            start_row = self._cursor // self._width
            start_col = self._cursor % self._width

            end_row = new_column // self._width
            end_col = new_column % self._width

            if end_row < start_row:
                self._chan.write('\x1b[' + str(start_row-end_row) + 'A')
            elif end_row > start_row:
                self._chan.write('\x1b[' + str(end_row-start_row) + 'B')

            if end_col > start_col:
                self._chan.write('\x1b[' + str(end_col-start_col) + 'C')
            elif end_col < start_col:
                self._chan.write('\x1b[' + str(start_col-end_col) + 'D')

            self._cursor = new_column
        else:
            self._update_input_window(pos)
            self._output('\b' * (self._cursor - self._start_column))
            self._update_line(self._left_pos, self._right_pos)
            self._output('\b' * (self._cursor - self._column(pos)))

    def _reposition(self, new_pos):
        """Reposition the cursor to selected position in input"""

        if self._line_mode and self._echo:
            self._move_cursor(new_pos)

        self._pos = new_pos

    def _erase_input(self):
        """Erase current input line"""

        if self._start_column != self._end_column:
            self._move_cursor(0)
            self._output(' ' * (self._end_column - self._cursor))
            self._move_cursor(0)
            self._end_column = self._start_column

    def _draw_input(self):
        """Draw current input line"""

        if (self._line_mode and self._echo and self._line and
                self._start_column == self._end_column):
            if self._wrap:
                self._update_line()
            else:
                self._update_input_window(self._pos)
                self._update_line(self._left_pos, self._right_pos)

            self._move_cursor(self._pos)

    def _update_input(self, start_pos, new_pos):
        """Update selected portion of current input line"""

        if self._line_mode and self._echo:
            self._move_cursor(start_pos)

            if self._wrap:
                self._update_line(start_pos)

        self._reposition(new_pos)

    def _insert_printable(self, data):
        """Insert data into the input line"""

        data_len = len(data)
        self._line = self._line[:self._pos] + data + self._line[self._pos:]
        self._pos += data_len

        if self._line_mode and self._echo:
            self._update_input(self._pos - data_len, self._pos)

    def _end_line(self):
        """End the current input line and send it to the session"""

        if (self._echo and not self._wrap and
                (self._left_pos > 0 or self._right_pos < len(self._line))):
            self._output('\b' * (self._cursor - self._start_column) +
                         self._line)
        else:
            self._reposition(len(self._line))

        self._output('\n')

        self._start_column = 0
        self._end_column = 0
        self._cursor = 0
        self._left_pos = 0
        self._right_pos = 0
        self._pos = 0

        if self._echo and self._history_size and self._line:
            self._history.append(self._line)
            self._history = self._history[-self._history_size:]

        self._history_index = len(self._history)

        data = self._line + '\n'
        self._line = ''

        self._session.data_received(data, None)

    def _eof_or_delete(self):
        """Erase character to the right, or send EOF if input line is empty"""

        if not self._line:
            self._session.eof_received()
        else:
            self._erase_right()

    def _erase_left(self):
        """Erase character to the left"""

        if self._pos > 0:
            self._line = self._line[:self._pos-1] + self._line[self._pos:]
            self._update_input(self._pos - 1, self._pos - 1)
        else:
            self._ring_bell()

    def _erase_right(self):
        """Erase character to the right"""

        if self._pos < len(self._line):
            self._line = self._line[:self._pos] + self._line[self._pos+1:]
            self._update_input(self._pos, self._pos)
        else:
            self._ring_bell()

    def _erase_line(self):
        """Erase entire input line"""

        self._erased = self._line
        self._line = ''
        self._update_input(0, 0)

    def _erase_to_end(self):
        """Erase to end of input line"""

        self._erased = self._line[self._pos:]
        self._line = self._line[:self._pos]
        self._update_input(self._pos, self._pos)

    def _history_prev(self):
        """Replace input with previous line in history"""

        if self._history_index > 0:
            self._history_index -= 1
            self._line = self._history[self._history_index]
            self._update_input(0, len(self._line))
        else:
            self._ring_bell()

    def _history_next(self):
        """Replace input with next line in history"""

        if self._history_index < len(self._history):
            self._history_index += 1

            if self._history_index < len(self._history):
                self._line = self._history[self._history_index]
            else:
                self._line = ''

            self._update_input(0, len(self._line))
        else:
            self._ring_bell()

    def _move_left(self):
        """Move left in input line"""

        if self._pos > 0:
            self._reposition(self._pos - 1)
        else:
            self._ring_bell()

    def _move_right(self):
        """Move right in input line"""

        if self._pos < len(self._line):
            self._reposition(self._pos + 1)
        else:
            self._ring_bell()

    def _move_to_start(self):
        """Move to start of input line"""

        self._reposition(0)

    def _move_to_end(self):
        """Move to end of input line"""

        self._reposition(len(self._line))

    def _redraw(self):
        """Redraw input line"""

        self._erase_input()
        self._draw_input()

    def _insert_erased(self):
        """Insert previously erased input"""

        self._insert_printable(self._erased)

    def _send_break(self):
        """Send break to session"""

        self._session.break_received(0)

    # pylint: disable=bad-whitespace

    _keylist = ((_end_line,      ('\n', '\r', '\x1bOM')),
                (_eof_or_delete, ('\x04',)),
                (_erase_left,    ('\x08', '\x7f')),
                (_erase_right,   ('\x1b[3~',)),
                (_erase_line,    ('\x15',)),
                (_erase_to_end,  ('\x0b',)),
                (_history_prev,  ('\x10', '\x1b[A', '\x1bOA')),
                (_history_next,  ('\x0e', '\x1b[B', '\x1bOB')),
                (_move_left,     ('\x02', '\x1b[D', '\x1bOD')),
                (_move_right,    ('\x06', '\x1b[C', '\x1bOC')),
                (_move_to_start, ('\x01', '\x1b[H', '\x1b[1~')),
                (_move_to_end,   ('\x05', '\x1b[F', '\x1b[4~')),
                (_redraw,        ('\x12',)),
                (_insert_erased, ('\x19',)),
                (_send_break,    ('\x03', '\x1b[33~')))

    # pylint: enable=bad-whitespace

    def set_line_mode(self, line_mode):
        """Enable/disable input line editing"""

        if self._line and not line_mode:
            data = self._line
            self._erase_input()
            self._line = ''

            self._session.data_received(data, None)

        self._line_mode = line_mode

    def set_echo(self, echo):
        """Enable/disable echoing of input in line mode"""

        if self._echo and not echo:
            self._erase_input()
            self._echo = False
        elif echo and not self._echo:
            self._echo = True
            self._draw_input()

    def set_width(self, width):
        """Set terminal line width"""

        self._width = width or _DEFAULT_WIDTH

        if self._wrap:
            self._cursor = self._column(self._pos)

        self._redraw()

    def process_input(self, data, datatype):
        """Process input from channel"""

        if self._line_mode:
            for ch in data:
                if ch in self._key_state:
                    self._key_state = self._key_state[ch]
                    if callable(self._key_state):
                        try:
                            self._key_state(self)
                        finally:
                            self._key_state = self._keymap
                elif self._key_state == self._keymap and ch.isprintable():
                    self._insert_printable(ch)
                else:
                    self._key_state = self._keymap
                    self._ring_bell()
        else:
            self._session.data_received(data, datatype)

    def process_output(self, data):
        """Process output to channel"""

        self._erase_input()
        self._output(data)
        self._start_column = self._cursor
        self._end_column = self._cursor
        self._draw_input()

class SSHLineEditorChannel:
    """Input line editor channel wrapper

       When creating server channels with ``line_editor`` set to ``True``,
       this class is wrapped around the channel, providing the caller with
       the ability to enable and disable input line editing and echoing.

       .. note:: Line editing is only available when a psuedo-terminal
                 is requested on the server channel and the character
                 encoding on the channel is not set to ``None``.

    """

    def __init__(self, orig_chan, orig_session, history_size):
        self._orig_chan = orig_chan
        self._orig_session = orig_session
        self._history_size = history_size
        self._editor = None

    def __getattr__(self, attr):
        """Delegate most channel functions to original channel"""

        return getattr(self._orig_chan, attr)

    def create_editor(self):
        """Create input line editor if encoding and terminal type are set"""

        if self._encoding and self._term_type:
            self._editor = SSHLineEditor(self._orig_chan, self._orig_session,
                                         self._history_size, self._term_type,
                                         self._term_size[0])

        return self._editor

    def set_line_mode(self, line_mode):
        """Enable/disable input line editing

           This method enabled or disables input line editing. When set,
           only full lines of input are sent to the session, and each
           line of input can be edited before it is sent.

           :param bool line_mode:
               Whether or not to process input a line at a time

        """

        self._editor.set_line_mode(line_mode)

    def set_echo(self, echo):
        """Enable/disable echoing of input in line mode

           This method enables or disables echoing of input data when
           input line editing is enabled.

           :param bool echo:
               Whether or not input to echo input as it is entered

        """

        self._editor.set_echo(echo)

    def write(self, data, datatype=None):
        """Process data written to the channel"""

        if self._editor:
            self._editor.process_output(data)
        else:
            self._orig_chan.write(data, datatype)


class SSHLineEditorSession:
    """Input line editor session wrapper"""

    def __init__(self, chan, orig_session):
        self._chan = chan
        self._orig_session = orig_session
        self._editor = None

    def __getattr__(self, attr):
        """Delegate most channel functions to original session"""

        return getattr(self._orig_session, attr)

    def session_started(self):
        """Start a session for this newly opened server channel"""

        self._editor = self._chan.create_editor()
        self._orig_session.session_started()

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        """The terminal size has changed"""

        if self._editor:
            self._editor.set_width(width)

        self._orig_session.terminal_size_changed(width, height,
                                                 pixwidth, pixheight)

    def data_received(self, data, datatype):
        """Process data received from the channel"""

        if self._editor:
            self._editor.process_input(data, datatype)
        else:
            self._orig_session.data_received(data, datatype)

    def eof_received(self):
        """Process EOF received from the channel"""

        if self._editor:
            self._editor.set_line_mode(False)

        return self._orig_session.eof_received()


SSHLineEditor.build_keymap()
