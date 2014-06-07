# Copyright (c) 2013-2014 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH channel and session handlers"""

import asyncio

from .constants import *
from .misc import *
from .packet import *

_EOF = object()


class SSHChannel(SSHPacketHandler):
    """Parent class for SSH channels"""

    _read_datatypes = set()
    _write_datatypes = set()

    def __init__(self, conn, loop, encoding, window, max_pktsize):
        """Initialize an SSH channel

           If encoding is set, data sent and received will be in the form
           of strings, converted on the wire to bytes using the specified
           encoding. If encoding is None, data sent and received must be
           provided as bytes.

           Window specifies the initial receive window size.

           Max_pktsize specifies the maximum length of a single data packet.

        """

        self._conn = conn
        self._loop = loop
        self._session = None
        self._encoding = encoding
        self._extra = { 'connection': conn }

        self._send_state = 'closed'
        self._send_chan = None
        self._send_window = None
        self._send_pktsize = None
        self._send_paused = False
        self._send_buf = []
        self._send_buf_len = 0

        self._recv_state = 'closed'
        self._recv_chan = conn._get_recv_chan()
        self._init_recv_window = window
        self._recv_window = window
        self._recv_pktsize = max_pktsize
        self._recv_paused = False
        self._recv_buf = []

        self._open_waiter = None
        self._request_waiters = []
        self._close_waiters = []

        self.set_write_buffer_limits()

        conn._channels[self._recv_chan] = self

    def _cleanup(self, exc=None):
        if self._open_waiter:
            self._open_waiter.set_exception(
                    ChannelOpenError(OPEN_CONNECT_FAILED,
                                     'SSH connection closed'))
            self._open_waiter = None

        if self._request_waiters:
            for waiter in self._request_waiters:
                waiter.set_exception(exc)

            self._request_waiters = []

        if self._close_waiters:
            for waiter in self._close_waiters:
                waiter.set_result(None)

            self._close_waiters = []

        if self._session:
            self._session.connection_lost(exc)
            self._session = None

        if self._conn:
            if self._recv_chan:
                del self._conn._channels[self._recv_chan]
                self._recv_chan = None

            self._conn = None

        self._send_state = 'closed'
        self._recv_state = 'closed'

    def _pause_resume_writing(self):
        if self._send_paused:
            if self._send_buf_len <= self._send_low_water:
                self._send_paused = False
                self._session.resume_writing()
        else:
            if self._send_buf_len > self._send_high_water:
                self._send_paused = True
                self._session.pause_writing()

    def _flush_send_buf(self):
        while self._send_buf and self._send_window:
            pktsize = min(self._send_window, self._send_pktsize)
            buf, datatype = self._send_buf[0]

            if len(buf) > pktsize:
                data = buf[:pktsize]
                del buf[:pktsize]
            else:
                data = buf
                del self._send_buf[0]

            self._send_buf_len -= len(data)
            self._send_window -= len(data)

            if datatype is None:
                self._send_packet(MSG_CHANNEL_DATA, String(data))
            else:
                self._send_packet(MSG_CHANNEL_EXTENDED_DATA,
                                  UInt32(datatype), String(data))

        self._pause_resume_writing()

        if not self._send_buf:
            if self._send_state == 'eof_pending':
                self._send_packet(MSG_CHANNEL_EOF)
                self._send_state = 'eof_sent'
            elif self._send_state == 'close_pending':
                self._send_packet(MSG_CHANNEL_CLOSE)
                self._send_state = 'close_sent'

    def _deliver_data(self, data, datatype):
        if data == _EOF:
            if not self._session.eof_received():
                self.close()
        else:
            self._recv_window -= len(data)

            if self._recv_window < self._init_recv_window / 2:
                self._send_packet(MSG_CHANNEL_WINDOW_ADJUST,
                                  UInt32(self._init_recv_window -
                                         self._recv_window))
                self._recv_window = self._init_recv_window

            if self._encoding:
                try:
                    data = data.decode(self._encoding)
                except UnicodeDecodeError:
                    raise DisconnectError(DISC_PROTOCOL_ERROR,
                                          'Unicode decode error')

            self._session.data_received(data, datatype)

    def _accept_data(self, data, datatype=None):
        if not data:
            return

        if self._send_state in {'close_pending', 'close_sent', 'closed'}:
            return

        if data != _EOF and len(data) > self._recv_window:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Window exceeded')

        if self._recv_paused:
            self._recv_buf.append((data, datatype))
        else:
            self._deliver_data(data, datatype)

    def _process_connection_close(self, exc):
        """Process the SSH connection closing"""

        self._cleanup(exc)

    def _process_open(self, send_chan, send_window, send_pktsize, session):
        """Process a channel open request"""

        if self._recv_state != 'closed':
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Channel already open')

        self._send_state = 'open_received'
        self._send_chan = send_chan
        self._send_window = send_window
        self._send_pktsize = send_pktsize

        asyncio.async(self._finish_open_request(session), loop=self._loop)

    @asyncio.coroutine
    def _finish_open_request(self, session):
        """Finish processing a channel open request"""

        try:
            if asyncio.iscoroutine(session):
                session = yield from session

            self._session = session

            self._conn._send_channel_open_confirmation(self._send_chan,
                                                       self._recv_chan,
                                                       self._recv_window,
                                                       self._recv_pktsize)

            self._send_state = 'open'
            self._recv_state = 'open'

            self._session.connection_made(self)
        except ChannelOpenError as exc:
            self._conn._send_channel_open_failure(self._send_chan, exc.code,
                                                  exc.reason, exc.lang)
            self._cleanup()

    def _process_open_confirmation(self, send_chan, send_window, send_pktsize,
                                   packet):
        """Process a channel open confirmation"""

        if not self._open_waiter:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Channel not being opened')

        self._send_chan = send_chan
        self._send_window = send_window
        self._send_pktsize = send_pktsize

        self._send_state = 'open'
        self._recv_state = 'open'

        self._open_waiter.set_result(packet)
        self._open_waiter = None

    def _process_open_failure(self, code, reason, lang):
        """Process a channel open failure"""

        if not self._open_waiter:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Channel not being opened')

        self._open_waiter.set_exception(ChannelOpenError(code, reason, lang))
        self._open_waiter = None
        self._cleanup()

    def _process_window_adjust(self, pkttype, packet):
        if self._recv_state not in {'open', 'eof_received'}:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Channel not open')

        adjust = packet.get_uint32()
        packet.check_end()

        self._send_window += adjust
        self._flush_send_buf()

    def _process_data(self, pkttype, packet):
        if self._recv_state != 'open':
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Channel not open for sending')

        data = packet.get_string()
        packet.check_end()

        self._accept_data(data)

    def _process_extended_data(self, pkttype, packet):
        if self._recv_state != 'open':
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Channel not open for sending')

        datatype = packet.get_uint32()
        data = packet.get_string()
        packet.check_end()

        if datatype not in self._read_datatypes:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid extended data type')

        self._accept_data(data, datatype)

    def _process_eof(self, pkttype, packet):
        if self._recv_state != 'open':
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Channel not open for sending')

        packet.check_end()

        self._recv_state = 'eof_received'
        self._accept_data(_EOF)

    def _process_close(self, pkttype, packet):
        if self._recv_state not in {'open', 'eof_received'}:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Channel not open')

        packet.check_end()

        # Flush any unsent data
        self._send_buf = []
        self._send_buf_len = 0

        # If we haven't yet sent a close, send one now
        if self._send_state not in {'close_sent', 'closed'}:
            self._send_packet(MSG_CHANNEL_CLOSE)

        self._cleanup()

    def _process_request(self, pkttype, packet):
        if self._recv_state not in {'open', 'eof_received'}:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Channel not open')

        if self._send_state in {'close_pending', 'close_sent', 'closed'}:
            return

        request = packet.get_string()
        want_reply = packet.get_boolean()

        try:
            request = request.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid channel request')

        name = '_process_' + request.replace('-', '_') + '_request'
        handler = getattr(self, name, None)
        result = handler(packet) if callable(handler) else False

        if want_reply:
            if result:
                self._send_packet(MSG_CHANNEL_SUCCESS)
            else:
                self._send_packet(MSG_CHANNEL_FAILURE)

        if result and request in ('shell', 'exec', 'subsystem'):
            self._session.session_started()

    def _process_response(self, pkttype, packet):
        if self._send_state not in {'open', 'eof_pending', 'eof_sent',
                                    'close_pending', 'close_sent'}:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Channel not open')

        packet.check_end()

        if self._request_waiters:
            waiter = self._request_waiters.pop(0)
            waiter.set_result(pkttype == MSG_CHANNEL_SUCCESS)
        else:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected channel response')

    packet_handlers = {
        MSG_CHANNEL_WINDOW_ADJUST:      _process_window_adjust,
        MSG_CHANNEL_DATA:               _process_data,
        MSG_CHANNEL_EXTENDED_DATA:      _process_extended_data,
        MSG_CHANNEL_EOF:                _process_eof,
        MSG_CHANNEL_CLOSE:              _process_close,
        MSG_CHANNEL_REQUEST:            _process_request,
        MSG_CHANNEL_SUCCESS:            _process_response,
        MSG_CHANNEL_FAILURE:            _process_response
    }

    @asyncio.coroutine
    def _open(self, chantype, *args):
        """Make a request to open the channel"""

        if self._send_state != 'closed':
            raise OSError('Channel already open')

        self._open_waiter = asyncio.Future(loop=self._loop)

        self._conn._send_packet(Byte(MSG_CHANNEL_OPEN), String(chantype),
                                UInt32(self._recv_chan),
                                UInt32(self._recv_window),
                                UInt32(self._recv_pktsize), *args)

        self._send_state = 'open_sent'
        return (yield from self._open_waiter)

    def _send_packet(self, pkttype, *args):
        """Send a packet on the channel"""

        if self._send_chan is None:
            raise OSError('Channel not open')

        self._conn._send_packet(Byte(pkttype), UInt32(self._send_chan), *args)

    def _send_request(self, request, *args, want_reply=False):
        """Send a channel request"""

        self._send_packet(MSG_CHANNEL_REQUEST, String(request),
                          Boolean(want_reply), *args)

    @asyncio.coroutine
    def _make_request(self, request, *args):
        """Make a channel request and wait for the response"""

        waiter = asyncio.Future(loop=self._loop)
        self._request_waiters.append(waiter)
        self._send_request(request, *args, want_reply=True)
        return (yield from waiter)

    def abort(self):
        """Forcibly close the channel

           This method can be called to forcibly close the channel, after
           which no more data can be sent or received. Any unsent buffered
           data and any incoming data in flight will be discarded.

        """

        if self._send_state not in {'close_sent', 'closed'}:
            self._send_packet(MSG_CHANNEL_CLOSE)
            self._send_state = 'close_sent'

    def close(self):
        """Cleanly close the channel

           This method can be called to cleanly close the channel, after
           which no more data can be sent or received. Any unsent buffered
           data will be flushed asynchronously before the channel is
           closed.

        """

        if self._send_state not in {'close_pending', 'close_sent', 'closed'}:
            self._send_state = 'close_pending'
            self._flush_send_buf()

    @asyncio.coroutine
    def wait_closed(self):
        """Wait for this channel to close

           This method is a coroutine which can be called to block until
           this channel has finished closing.

        """

        if self._session:
            waiter = asyncio.Future(loop=self._loop)
            self._close_waiters.append(waiter)
            yield from waiter

    def get_extra_info(self, name, default=None):
        """Get additional information about the channel

           This method returns extra information about the channel once
           it is established. Supported values include ``'connection'``
           to return the SSH connection this channel is running over plus
           all of the values supported on that connection.

           For TCP channels, the values ``'local_peername'`` and
           ``'remote_peername'`` are added to return the local and remote
           host and port information for the tunneled TCP connection.

        """

        return self._extra.get(name, self._conn.get_extra_info(name, default))

    def can_write_eof(self):
        """Return whether the channel supports :meth:`write_eof`

           This method always returns ``True``.

        """

        return True

    def get_write_buffer_size(self):
        """Return the current size of the channel's output buffer

           This method returns how many bytes are currently in the
           channel's output buffer waiting to be written.

        """

        return self._send_buf_len

    def set_write_buffer_limits(self, high=None, low=None):
        """Set the high- and low-water limits for write flow control

           This method sets the limits used when deciding when to call
           the ``pause_writing()`` and ``resume_writing()`` methods on
           SSH sessions. Writing will be paused when the write buffer
           size exceeds the high-water mark, and resumed when the
           write buffer size equals or drops below the low-water mark.
        """

        if high is None:
            high = 4*low if low is not None else 65536

        if low is None:
            low = high // 4

        if not 0 <= low <= high:
            raise ValueError('high (%r) must be >= low (%r) must be >= 0' %
                             (high, low))

        self._send_high_water = high
        self._send_low_water = low
        self._pause_resume_writing()

    def write(self, data, datatype=None):
        """Write data on the channel

           This method can be called to send data on the channel. If
           an encoding was specified when the channel was created, the
           data should be provided as a string and will be converted
           using that encoding. Otherwise, the data should be provided
           as bytes.

           An extended data type can optionally be provided. For
           instance, this is used from a :class:`SSHServerSession`
           to write data to ``stderr``.

           :param data:
               The data to send on the channel
           :param integer datatype: (optional)
               The extended data type of the data, from :ref:`extended
               data types <ExtendedDataTypes>`
           :type data: string or bytes

           :raises: :exc:`OSError` if the channel isn't open for sending
                    or the extended data type is not valid for this type
                    of channel

        """

        if self._send_state != 'open':
            raise BrokenPipeError('Channel not open for sending')

        if datatype is not None and datatype not in self._write_datatypes:
            raise OSError('Invalid extended data type')

        if len(data) == 0:
            return

        if self._encoding:
            data = data.encode(self._encoding)

        self._send_buf.append((bytearray(data), datatype))
        self._send_buf_len += len(data)
        self._flush_send_buf()

    def writelines(self, list_of_data, datatype=None):
        """Write a list of data bytes on the channel

           This method can be called to write a list (or any iterable) of
           data bytes to the channel. It is functionality equivalent to
           calling :meth:`write` on each element in the list.

           :param list_of_data:
               The data to send on the channel
           :param integer datatype: (optional)
               The extended data type of the data, from :ref:`extended
               data types <ExtendedDataTypes>`
           :type list_of_data: iterable of ``string`` or ``bytes`` objects

           :raises: :exc:`OSError` if the channel isn't open for sending
                    or the extended data type is not valid for this type
                    of channel

        """

        sep = '' if self._encoding else b''
        return self.write(sep.join(list_of_data), datatype)

    def write_eof(self):
        """Write EOF on the channel

           This method sends an end-of-file indication on the
           channel, after which no more data can be sent. The
           channel remains open, though, and data may still be
           sent in the other direction.

           :raises: :exc:`OSError` if the channel isn't open for sending

        """

        if self._send_state != 'open':
            raise BrokenPipeError('Channel not open for sending')

        self._send_state = 'eof_pending'
        self._flush_send_buf()

    def pause_reading(self):
        """Pause delivery of incoming data

           This method is used to temporarily suspend delivery of incoming
           channel data. After this call, incoming data will no longer
           be delivered until :meth:`resume_reading` is called. Data will be
           buffered locally up to the configured SSH channel window size,
           but window updates will no longer be sent, eventually causing
           back pressure on the remote system.

           .. note:: Channel close notifications are not suspended by this
                     call. If the remote system closes the channel while
                     delivery is suspended, the channel will be closed even
                     though some buffered data may not have been delivered.

        """

        self._recv_paused = True

    def resume_reading(self):
        """Resume delivery of incoming data

           This method can be called to resume delivery of incoming data
           which was suspended by a call to :meth:`pause_reading`. As soon
           as this method is called, any buffered data will be delivered
           immediately.  A pending end-of-file notication may also be
           delivered if one was queued while reading was paused.

        """

        self._recv_paused = False

        while self._recv_buf and not self._recv_paused:
            self._deliver_data(*self._recv_buf.pop(0))


class SSHClientChannel(SSHChannel):
    """SSH client channel"""

    _read_datatypes = {EXTENDED_DATA_STDERR}

    def __init__(self, conn, loop, encoding, window, max_pktsize):
        super().__init__(conn, loop, encoding, window, max_pktsize)

        self._exit_status = None
        self._exit_signal = None

    @asyncio.coroutine
    def _create(self, session_factory, command, subsystem, env,
                term_type, term_size, term_modes):
        """Create an SSH client session"""

        packet = yield from self._open(b'session')

        # Client sessions should have no extra data in the open confirmation
        packet.check_end()

        self._session = session_factory()
        self._session.connection_made(self)

        for name, value in env.items():
            name = str(name).encode('utf-8')
            value = str(value).encode('utf-8')
            self._send_request(b'env', String(name), String(value))

        if term_type:
            term_type = term_type.encode('ascii')

            if len(term_size) == 4:
                width, height, pixwidth, pixheight = term_size
            elif len(term_size) == 2:
                width, height = term_size
                pixwidth = pixheight = 0
            elif not term_size:
                width = height = pixwidth = pixheight = 0
            else:
                raise ValueError('If set, terminal size must be a tuple of '
                                 '2 or 4 integers')

            modes = b''
            for mode, value in term_modes.items():
                if mode <= PTY_OP_END or mode >= PTY_OP_RESERVED:
                    raise ValueError('Invalid pty mode: %s' % mode)

                modes += Byte(mode) + UInt32(value)

            modes += Byte(PTY_OP_END)

            if not (yield from self._make_request(b'pty-req',
                                                  String(term_type),
                                                  UInt32(width),
                                                  UInt32(height),
                                                  UInt32(pixwidth),
                                                  UInt32(pixheight),
                                                  String(modes))):
                self.close()
                raise ChannelOpenError(OPEN_REQUEST_PTY_FAILED,
                                       'PTY request failed')

        if command:
            result = yield from self._make_request(b'exec', String(command))
        elif subsystem:
            result = yield from self._make_request(b'subsystem',
                                                   String(subsystem))
        else:
            result = yield from self._make_request(b'shell')

        if not result:
            self.close()
            raise ChannelOpenError(OPEN_REQUEST_SESSION_FAILED,
                                   'Session request failed')

        self._session.session_started()
        return self, self._session

    def _process_xon_xoff_request(self, packet):
        """Process a request to set up XON/XOFF processing"""

        client_can_do = packet.get_boolean()
        packet.check_end()

        self._session.xon_xoff_requested(client_can_do)
        return True

    def _process_exit_status_request(self, packet):
        """Process a request to deliver exit status"""

        status = packet.get_uint32()
        packet.check_end()

        self._exit_status = status
        self._session.exit_status_received(status)
        return True

    def _process_exit_signal_request(self, packet):
        """Process a request to deliver an exit signal"""

        signal = packet.get_string()
        core_dumped = packet.get_boolean()
        msg = packet.get_string()
        lang = packet.get_string()
        packet.check_end()

        try:
            signal = signal.decode('ascii')
            msg = msg.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid exit signal request')

        self._exit_signal = (signal, core_dumped, msg, lang)
        self._session.exit_signal_received(signal, core_dumped, msg, lang)
        return True

    def get_exit_status(self):
        """Return the session's exit status

           This method returns the exit status of the session if one has
           been sent. If an exit signal was received, this method
           returns -1 and the exit signal information can be collected
           by calling :meth:`get_exit_signal`. If neither has been sent,
           this method returns ``None``.

        """

        if self._exit_status is not None:
            return self._exit_status
        elif self._exit_signal:
            return -1
        else:
            return None

    def get_exit_signal(self):
        """Return the session's exit signal, if one was sent

           This method returns information about the exit signal sent on
           this session. If an exit signal was sent, a tuple is returned
           containing the signal name, a boolean for whether a core dump
           occurred, a message associated with the signal, and the language
           the message was in. If no exit signal was sent, ``None`` is
           returned.

        """

        return self._exit_signal

    def change_terminal_size(self, width, height, pixwidth=0, pixheight=0):
        """Change the terminal window size for this session

           This method changes the width and height of the terminal
           associated with this session.

           :param integer width:
               The width of the terminal in characters
           :param integer height:
               The height of the terminal in characters
           :param integer pixwidth: (optional)
               The width of the terminal in pixels
           :param integer pixheight: (optional)
               The height of the terminal in pixels

        """

        self._send_request(b'window-change', UInt32(width), UInt32(height),
                           UInt32(pixwidth), UInt32(pixheight))

    def send_break(self, msec):
        """Send a break to the remote process

           This method requests that the server perform a break
           operation on the remote process or service as described in
           :rfc:`4335`.

           :param integer msec:
               The duration of the break in milliseconds

           :raises: :exc:`OSError` if the channel is not open

        """

        self._send_request(b'break', UInt32(msec))

    def send_signal(self, signal):
        """Send a signal to the remote process

           This method can be called to deliver a signal to the remote
           process or service. Signal names should be as described in
           section 6.10 of :rfc:`4254#section-6.10`.

           :param string signal:
               The signal to deliver

           :raises: :exc:`OSError` if the channel is not open

        """

        signal = signal.encode('ascii')

        self._send_request(b'signal', String(signal))

    def terminate(self):
        """Terminate the remote process

           This method can be called to terminate the remote process or
           service by sending it a ``TERM`` signal.

           :raises: :exc:`OSError` if the channel is not open

        """

        self.send_signal('TERM')

    def kill(self):
        """Forcibly kill the remote process

           This method can be called to forcibly stop  the remote process
           or service by sending it a ``KILL`` signal.

           :raises: :exc:`OSError` if the channel is not open

        """

        self.send_signal('KILL')


class SSHServerChannel(SSHChannel):
    """SSH server channel"""

    _write_datatypes = {EXTENDED_DATA_STDERR}

    def __init__(self, conn, loop, encoding, window, max_pktsize):
        """Initialize an SSH server channel"""

        super().__init__(conn, loop, encoding, window, max_pktsize)

        self._env = {}
        self._command = None
        self._subsystem = None
        self._term_type = None
        self._term_size = (0, 0, 0, 0)
        self._term_modes = {}

    def _process_pty_req_request(self, packet):
        """Process a request to open a pseudo-terminal"""

        term_type = packet.get_string()
        width = packet.get_uint32()
        height = packet.get_uint32()
        pixwidth = packet.get_uint32()
        pixheight = packet.get_uint32()
        modes = packet.get_string()
        packet.check_end()

        try:
            self._term_type = term_type.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Invalid pty request')

        self._term_size = (width, height, pixwidth, pixheight)

        idx = 0
        while idx < len(modes):
            mode = modes[idx]
            idx += 1
            if mode == PTY_OP_END or mode >= PTY_OP_RESERVED:
                break

            if idx+4 <= len(modes):
                self._term_modes[mode] = int.from_bytes(modes[idx:idx+4], 'big')
                idx += 4
            else:
                raise DisconnectError(DISC_PROTOCOL_ERROR,
                                      'Invalid pty modes string')

        return self._session.pty_requested(self._term_type, self._term_size,
                                           self._term_modes)

    def _process_env_request(self, packet):
        """Process a request to set an environment variable"""

        name = packet.get_string()
        value = packet.get_string()
        packet.check_end()

        try:
            name = name.decode('utf-8')
            value = value.decode('utf-8')
        except UnicodeDecodeError:
            return False

        self._env[name] = value
        return True

    def _process_shell_request(self, packet):
        """Process a request to open a shell"""

        packet.check_end()

        return self._session.shell_requested()

    def _process_exec_request(self, packet):
        """Process a request to execute a command"""

        command = packet.get_string()
        packet.check_end()

        try:
            command = command.decode('utf-8')
        except UnicodeDecodeError:
            return False

        self._command = command
        return self._session.exec_requested(command)

    def _process_subsystem_request(self, packet):
        """Process a request to open a subsystem"""

        subsystem = packet.get_string()
        packet.check_end()

        try:
            subsystem = subsystem.decode('ascii')
        except UnicodeDecodeError:
            return False

        self._subsystem = subsystem
        return self._session.subsystem_requested(subsystem)

    def _process_window_change_request(self, packet):
        """Process a request to change the window size"""

        width = packet.get_uint32()
        height = packet.get_uint32()
        pixwidth = packet.get_uint32()
        pixheight = packet.get_uint32()
        packet.check_end()

        self._term_size = (width, height, pixwidth, pixheight)
        self._session.terminal_size_changed(width, height, pixwidth, pixheight)
        return True

    def _process_signal_request(self, packet):
        """Process a request to send a signal"""

        signal = packet.get_string()
        packet.check_end()

        try:
            signal = signal.decode('ascii')
        except UnicodeDecodeError:
            return False

        self._session.signal_received(signal)
        return True

    def _process_break_request(self, packet):
        """Process a request to send a break"""

        msec = packet.get_uint32()
        packet.check_end()

        return self._session.break_received(msec)

    def get_environment(self):
        """Return the environment for this session

           This method returns the environment set by the client
           when the session was opened. Calls to this method should
           only be made after :meth:`session_started
           <SSHServerSession.session_started>` has been called on
           the :class:`SSHServerSession`.

           :returns: A dictionary containing the environment variables
                     set by the client

        """

        return self._env

    def get_command(self):
        """Return the command the client requested to execute, if any

           This method returns the command the client requested to
           execute when the session was opened, if any. If the client
           did not request that a command be executed, this method
           will return ``None``. Calls to this method should only be made
           after :meth:`session_started <SSHServerSession.session_started>`
           has been called on the :class:`SSHServerSession`. When using
           the stream-based API, calls to this can be made at any time
           after the handler function has started up.

        """

        return self._command

    def get_subsystem(self):
        """Return the subsystem the client requested to open, if any

           This method returns the subsystem the client requested to
           open when the session was opened, if any. If the client
           did not request that a subsystem be opened, this method will
           return ``None``. Calls to this method should only be made
           after :meth:`session_started <SSHServerSession.session_started>`
           has been called on the :class:`SSHServerSession`. When using
           the stream-based API, calls to this can be made at any time
           after the handler function has started up.

        """

        return self._subsystem

    def get_terminal_type(self):
        """Return the terminal type for this session

           This method returns the terminal type set by the client
           when the session was opened. If the client didn't request
           a pseudo-terminal, this method will return ``None``. Calls
           to this method should only be made after :meth:`session_started
           <SSHServerSession.session_started>` has been called on the
           :class:`SSHServerSession`. When using the stream-based API,
           calls to this can be made at any time after the handler
           function has started up.

           :returns: A string containing the terminal type or ``None`` if
                     no pseudo-terminal was requested

        """

        return self._term_type

    def get_terminal_size(self):
        """Return terminal size information for this session

           This method returns the latest terminal size information set
           by the client. If the client didn't set any terminal size
           information, all values returned will be zero. Calls to
           this method should only be made after :meth:`session_started
           <SSHServerSession.session_started>` has been called on the
           :class:`SSHServerSession`. When using the stream-based API,
           calls to this can be made at any time after the handler
           function has started up.

           Also see :meth:`terminal_size_changed()
           <SSHServerSession.terminal_size_changed>` or the
           :exc:`TerminalSizeChanged` exception for how to get notified
           when the terminal size changes.

           :returns: A tuple of four integers containing the width and
                     height of the terminal in characters and the width
                     and height of the terminal in pixels

        """

        return self._term_size

    def get_terminal_mode(self, mode):
        """Return the requested TTY mode for this session

           This method looks up the value of a POSIX terminal mode
           set by the client when the session was opened. If the client
           didn't request a pseudo-terminal or didn't set the requested
           TTY mode opcode, this method will return ``None``. Calls to
           this method should only be made after :meth:`session_started
           <SSHServerSession.session_started>` has been called on the
           :class:`SSHServerSession`. When using the stream-based API,
           calls to this can be made at any time after the handler
           function has started up.

           :param integer mode:
               POSIX terminal mode taken from :ref:`POSIX terminal modes
               <PTYModes>` to look up

           :returns: An integer containing the value of the requested
                     POSIX terminal mode or ``None`` if the requested
                     mode was not set

        """

        return self._term_modes.get(mode)

    def set_xon_xoff(self, client_can_do):
        """Set whether the client should enable XON/XOFF flow control

           This method can be called to tell the client whether or not
           to enable XON/XOFF flow control, indicating that it should
           intercept Control-S and Control-Q coming from its local
           terminal to pause and resume output, respectively.
           Applications should set client_can_do to ``True`` to
           enable this functionality or to ``False`` to tell the client
           to forward Control-S and Control-Q through as normal input.

           :param boolean client_can_do:
               Whether or not the client should enable XON/XOFF flow control

        """

        self._send_request(b'xon-xoff', Boolean(client_can_do))

    def write_stderr(self, data):
        """Write output to stderr

           This method can be called to send output to the client which
           is intended to be displayed on stderr. If an encoding was
           specified when the channel was created, the data should be
           provided as a string and will be converted using that
           encoding. Otherwise, the data should be provided as bytes.

           :param data:
               The data to send to stderr
           :type data: string or bytes

           :raises: :exc:`OSError` if the channel isn't open for sending

        """

        self.write(data, EXTENDED_DATA_STDERR)

    def writelines_stderr(self, list_of_data):
        """Write a list of data bytes to stderr

           This method can be called to write a list (or any iterable) of
           data bytes to the channel. It is functionality equivalent to
           calling :meth:`write_stderr` on each element in the list.

        """

        self.writelines(list_of_data, EXTENDED_DATA_STDERR)

    def exit(self, status):
        """Send exit status and close the channel

           This method can be called to report an exit status for the
           process back to the client and close the channel. A zero
           exit status is generally returned when the operation was
           successful. After reporting the status, the channel is
           closed.

           :param integer status:
               The exit status to report to the client

           :raises: :exc:`OSError` if the channel isn't open

        """

        if self._send_state not in {'open', 'eof_pending', 'eof_sent'}:
            raise OSError('Channel not open')

        self._send_request(b'exit-status', UInt32(status))
        self.close()

    def exit_with_signal(self, signal, core_dumped=False,
                         msg='', lang=DEFAULT_LANG):
        """Send exit signal and close the channel

           This method can be called to report that the process
           terminated abnormslly with a signal. A more detailed
           error message may also provided, along with an indication
           of whether or not the process dumped core. After
           reporting the signal, the channel is closed.

           :param string signal:
               The signal which caused the process to exit
           :param boolean core_dumped: (optional)
               Whether or not the process dumped core
           :param msg: (optional)
               Details about what error occurred
           :param lang: (optional)
               The language the error message is in

           :raises: :exc:`OSError` if the channel isn't open

        """

        if self._send_state not in {'open', 'eof_pending', 'eof_sent'}:
            raise OSError('Channel not open')

        signal = signal.encode('ascii')
        msg = msg.encode('utf-8')
        lang = lang.encode('ascii')

        self._send_request(b'exit-signal', String(signal),
                           Boolean(core_dumped), String(msg), String(lang))
        self.close()


class SSHTCPChannel(SSHChannel):
    """SSH TCP channel"""

    @asyncio.coroutine
    def _finish_open_request(self, session):
        """Finish processing a TCP channel open request"""

        yield from super()._finish_open_request(session)

        if self._session:
            self._session.session_started()

    @asyncio.coroutine
    def _open(self, session_factory, chantype, host, port,
              orig_host, orig_port):
        """Open a TCP channel"""

        self._extra['local_peername'] = (orig_host, orig_port)
        self._extra['remote_peername'] = (host, port)

        host = host.encode('utf-8')
        orig_host = orig_host.encode('utf-8')

        packet = yield from super()._open(chantype, String(host), UInt32(port),
                                          String(orig_host), UInt32(orig_port))

        # TCP sessions should have no extra data in the open confirmation
        packet.check_end()

        self._session = session_factory()
        self._session.connection_made(self)
        self._session.session_started()

        return self, self._session

    @asyncio.coroutine
    def _connect(self, session_factory, host, port, orig_host, orig_port):
        """Create a new outbound TCP session"""

        return (yield from self._open(session_factory, b'direct-tcpip',
                                      host, port, orig_host, orig_port))

    @asyncio.coroutine
    def _accept(self, session_factory, host, port, orig_host, orig_port):
        """Create a new forwarded TCP session"""

        return (yield from self._open(session_factory, b'forwarded-tcpip',
                                      host, port, orig_host, orig_port))


class SSHSession:
    """SSH session handler"""

    def connection_made(self, chan):
        """Called when a channel is opened successfully

           This method is called when a channel is opened successfully. The
           channel parameter should be stored if needed for later use.

           :param chan:
               The channel which was successfully opened.
           :type chan: :class:`SSHClientChannel`

        """

    def connection_lost(self, exc):
        """Called when a channel is closed

           This method is called when a channel is closed. If the channel
           is shut down cleanly, *exc* will be ``None``. Otherwise, it
           will be an exception explaining the reason for the channel close.

           :param exc:
               The exception which caused the channel to close, or
               ``None`` if the channel closed cleanly.
           :type exc: :class:`Exception`

        """

    def session_started(self):
        """Called when the session is started

           This method is called when a session has started up. For
           client and server sessions, this will be called once a
           shell, exec, or subsystem request has been successfully
           completed. For TCP sessions, it will be called immediately
           after the connection is opened.

        """

    def data_received(self, data, datatype):
        """Called when data is received on the channel

           This method is called when data is received on the channel.
           If an encoding was specified when the channel was created,
           the data will be delivered as a string after decoding with
           the requested encoding. Otherwise, the data will be delivered
           as bytes.

           :param data:
               The data received on the channel
           :param datatype:
               The extended data type of the data, from :ref:`extended
               data types <ExtendedDataTypes>`
           :type data: string or bytes

        """

    def eof_received(self):
        """Called when EOF is received on the channel

           This method is called when an end-of-file indication is received
           on the channel, after which no more data will be received. If this
           method returns ``True``, the channel remains half open and data
           may still be sent. Otherwise, the channel is automatically closed
           after this method returns. This is the default behavior.

        """

    def pause_writing(self):
        """Called when the write buffer becomes full

           This method is called when the channel's write buffer becomes
           full and no more data can be sent until the remote system
           adjusts its window. While data can still be buffered locally,
           applications may wish to stop producing new data until the
           write buffer has drained.

        """

    def resume_writing(self):
        """Called when the write buffer has sufficiently drained

           This method is called when the channel's send window reopens
           and enough data has drained from the write buffer to allow the
           application to produce more data.

        """


class SSHClientSession(SSHSession):
    """SSH client session handler

       Applications should subclass this when implementing an SSH client
       session handler. The functions listed below should be implemented
       to define application-specific behavior. In particular, the standard
       ``asyncio`` protocol methods such as :meth:`connection_made`,
       :meth:`connection_lost`, :meth:`data_received`, :meth:`eof_received`,
       :meth:`pause_writing`, and :meth:`resume_writing` are all supported.
       In addition, :meth:`session_started` is called as soon as the SSH
       session is fully started, :meth:`xon_xoff_requested` can be used to
       determine if the server wants the client to support XON/XOFF flow
       control, and :meth:`exit_status_received` and
       :meth:`exit_signal_received` can be used to receive session exit
       information.

    """

    def xon_xoff_requested(self, client_can_do):
        """XON/XOFF flow control has been enabled or disabled

           This method is called to notify the client whether or not
           to enable XON/XOFF flow control. If client_can_do is
           ``True`` and output is being sent to an interactive
           terminal the application should allow input of Control-S
           and Control-Q to pause and resume output, respectively.
           If client_can_do is ``False``, Control-S and Control-Q
           should be treated as normal input and passed through to
           the server. Non-interactive applications can ignore this
           request.

           By default, this message is ignored.

           :param boolean client_can_do:
               Whether or not to enable XON/XOFF flow control

        """

    def exit_status_received(self, status):
        """A remote exit status has been received for this session

           This method is called when the shell, command, or subsystem
           running on the server terminates and returns an exit status.
           A zero exit status generally means that the operation was
           successful. This call will generally be followed by a call
           to :meth:`connection_lost`.

           By default, the exit status is ignored.

           :param integer status:
               The exit status returned by the remote process

        """

    def exit_signal_received(self, signal, core_dumped, msg, lang):
        """A remote exit signal has been received for this session

           This method is called when the shell, command, or subsystem
           running on the server terminates abnormally with a signal.
           A more detailed error may also be provided, along with an
           indication of whether the remote process dumped core. This call
           will generally be followed by a call to :meth:`connection_lost`.

           By default, exit signals are ignored.

           :param string signal:
               The signal which caused the remote process to exit
           :param boolean core_dumped:
               Whether or not the remote process dumped core
           :param msg:
               Details about what error occurred
           :param lang:
               The language the error message is in

        """


class SSHServerSession(SSHSession):
    """SSH server session handler

       Applications should subclass this when implementing an SSH server
       session handler. The functions listed below should be implemented
       to define application-specific behavior. In particular, the
       standard ``asyncio`` protocol methods such as :meth:`connection_made`,
       :meth:`connection_lost`, :meth:`data_received`, :meth:`eof_received`,
       :meth:`pause_writing`, and :meth:`resume_writing` are all supported.
       In addition, :meth:`pty_requested` is called when the client requests a
       pseudo-terminal, one of :meth:`shell_requested`, :meth:`exec_requested`,
       or :meth:`subsystem_requested` is called depending on what type of
       session the client wants to start, :meth:`session_started` is called
       once the SSH session is fully started, :meth:`terminal_size_changed` is
       called when the client's terminal size changes, :meth:`signal_received`
       is called when the client sends a signal, and :meth:`break_received`
       is called when the client sends a break.

    """

    def pty_requested(self, term_type, term_size, term_modes):
        """A psuedo-terminal has been requested

           This method is called when the client sends a request to allocate
           a pseudo-terminal with the requested terminal type, size, and
           POSIX terminal modes. This method should return ``True`` if the
           request for the pseudo-terminal is accepted. Otherwise, it should
           return ``False`` to reject the request.

           By default, requests to allocate a pseudo-terminal are accepted
           but nothing is done with the associated terminal information.
           Applications wishing to use this information should implement
           this method and have it return ``True``, or call
           :meth:`get_terminal_type() <SSHServerChannel.get_terminal_type>`,
           :meth:`get_terminal_size() <SSHServerChannel.get_terminal_size>`,
           or :meth:`get_terminal_mode() <SSHServerChannel.get_terminal_mode>`
           on the :class:`SSHServerChannel` to get the information they need
           after a shell, command, or subsystem is started.

           :param string term:
               Terminal type to set for this session
           :param tuple term_size:
               Terminal size to set for this session provided as a
               tuple of four integers: the width and height of the
               terminal in characters followed by the width and height
               of the terminal in pixels
           :param dictionary term_modes:
               POSIX terminal modes to set for this session, where keys
               are taken from :ref:`POSIX terminal modes <PTYModes>` with
               values defined in section 8 of :rfc:`4254#section-8`.

           :returns: A boolean indicating if the request for a
                     pseudo-terminal was allowed or not

        """

        return True

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        """The terminal size has changed

           This method is called when a client requests a
           pseudo-terminal and again whenever the the size of
           he client's terminal window changes.

           By default, this information is ignored, but applications
           wishing to use the terminal size can implement this method
           to get notified whenever it changes.

           :param integer width:
               The width of the terminal in characters
           :param integer height:
               The height of the terminal in characters
           :param integer pixwidth: (optional)
               The width of the terminal in pixels
           :param integer pixheight: (optional)
               The height of the terminal in pixels

        """

    def shell_requested(self):
        """The client has requested a shell

           This method should be implemented by the application to
           perform whatever processing is required when a client makes
           a request to open an interactive shell. It should return
           ``True`` to accept the request, or ``False`` to reject it.

           If the application returns ``True``, the :meth:`session_started`
           method will be called once the channel is fully open. No output
           should be sent until this method is called.

           By default this method returns ``False`` to reject all requests.

           :returns: A boolean indicating if the shell request was
                     allowed or not

        """

        return False

    def exec_requested(self, command):
        """The client has requested to execute a command

           This method should be implemented by the application to
           perform whatever processing is required when a client makes
           a request to execute a command. It should return ``True`` to
           accept the request, or ``False`` to reject it.

           If the application returns ``True``, the :meth:`session_started`
           method will be called once the channel is fully open. No output
           should be sent until this method is called.

           By default this method returns ``False`` to reject all requests.

           :param string command:
               The command the client has requested to execute

           :returns: A boolean indicating if the exec request was
                     allowed or not

        """

        return False

    def subsystem_requested(self, subsystem):
        """The client has requested to start a subsystem

           This method should be implemented by the application to
           perform whatever processing is required when a client makes
           a request to start a subsystem. It should return ``True`` to
           accept the request, or ``False`` to reject it.

           If the application returns ``True``, the :meth:`session_started`
           method will be called once the channel is fully open. No output
           should be sent until this method is called.

           By default this method returns ``False`` to reject all requests.

           :param string subsystem:
               The subsystem to start

           :returns: A boolean indicating if the request to open the
                     subsystem was allowed or not

        """

        return False

    def break_received(self, msec):
        """The client has sent a break

           This method is called when the client requests that the
           server perform a break operation on the terminal. If the
           break is performed, this method should return ``True``.
           Otherwise, it should return ``False``.

           By default, this method returns ``False`` indicating that
           no break was performed.

           :param integer msec:
               The duration of the break in milliseconds

           :returns: A boolean to indicate if the break operation was
                     performed or not

        """

        return False

    def signal_received(self, signal):
        """The client has sent a signal

           This method is called when the client delivers a signal
           on the channel.

           By default, signals from the client are ignored.

        """


class SSHTCPSession(SSHSession):
    """SSH TCP connection session handler

       Applications should subclass this when implementing a handler for
       SSH direct or forwarded TCP connections.

       SSH client applications wishing to open a direct connection should call
       :meth:`create_connection() <SSHClientConnection.create_connection>`
       on their :class:`SSHClientConnection`, passing in a factory which
       returns instances of this class.

       Server applications wishing to allow direct connections should
       implement the coroutine :meth:`connection_requested()
       <SSHServer.connection_requested>` on their :class:`SSHServer`
       object and have it return instances of this class.

       Server applications wishing to allow connection forwarding back
       to the client should implement the coroutine :meth:`server_requested()
       <SSHServer.server_requested>` on their :class:`SSHServer` object
       and call :meth:`accept_connection()
       <SSHServerConnection.accept_connection>` on their
       :class:`SSHServerConnection` for each new connection, passing it a
       factory which returns instances of this class.

       When a connection is successfully opened, :meth:`session_started`
       will be called, after which the application can begin sending data.
       Received data will be passed to the :meth:`data_received` method.

    """
