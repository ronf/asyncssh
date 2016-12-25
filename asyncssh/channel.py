# Copyright (c) 2013-2016 by Ron Frederick <ronf@timeheart.net>.
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
import binascii

from .constants import DEFAULT_LANG, DISC_PROTOCOL_ERROR, EXTENDED_DATA_STDERR
from .constants import MSG_CHANNEL_OPEN, MSG_CHANNEL_WINDOW_ADJUST
from .constants import MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA
from .constants import MSG_CHANNEL_EOF, MSG_CHANNEL_CLOSE, MSG_CHANNEL_REQUEST
from .constants import MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE
from .constants import OPEN_CONNECT_FAILED, PTY_OP_RESERVED, PTY_OP_END
from .constants import OPEN_REQUEST_X11_FORWARDING_FAILED
from .constants import OPEN_REQUEST_PTY_FAILED, OPEN_REQUEST_SESSION_FAILED
from .editor import SSHLineEditorChannel, SSHLineEditorSession
from .misc import ChannelOpenError, DisconnectError, map_handler_name
from .packet import Boolean, Byte, String, UInt32, SSHPacketHandler


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
        self._extra = {'connection': conn}

        self._send_state = 'closed'
        self._send_chan = None
        self._send_window = None
        self._send_pktsize = None
        self._send_paused = False
        self._send_buf = []
        self._send_buf_len = 0

        self._recv_state = 'closed'
        self._init_recv_window = window
        self._recv_window = window
        self._recv_pktsize = max_pktsize
        self._recv_paused = True
        self._recv_buf = []
        self._recv_partial = {}

        self._request_queue = []

        self._open_waiter = None
        self._request_waiters = []

        self._close_event = asyncio.Event(loop=loop)

        self.set_write_buffer_limits()

        self._recv_chan = conn.add_channel(self)

    def get_connection(self):
        """Return the connection used by this channel"""

        return self._conn

    def get_loop(self):
        """Return the event loop used by this channel"""

        return self._loop

    def get_encoding(self):
        """Return the encoding used by this channel"""

        return self._encoding

    def set_encoding(self, encoding):
        """Set the encoding on this channel"""

        self._encoding = encoding

    def get_recv_window(self):
        """Return the configured receive window for this channel"""

        return self._init_recv_window

    def get_read_datatypes(self):
        """Return the legal read data types for this channel"""

        return self._read_datatypes

    def _cleanup(self, exc=None):
        """Clean up this channel"""

        if self._open_waiter:
            if not self._open_waiter.cancelled(): # pragma: no branch
                self._open_waiter.set_exception(
                    ChannelOpenError(OPEN_CONNECT_FAILED,
                                     'SSH connection closed'))

            self._open_waiter = None

        if self._request_waiters:
            for waiter in self._request_waiters:
                if not waiter.cancelled(): # pragma: no branch
                    waiter.set_exception(exc)

            self._request_waiters = []

        if self._session:
            self._session.connection_lost(exc)
            self._session = None

        self._close_event.set()

        if self._conn: # pragma: no branch
            self._conn.remove_channel(self._recv_chan)
            self._recv_chan = None
            self._conn = None

    def _close_send(self):
        """Discard unsent data and close the channel for sending"""

        # Discard unsent data
        self._send_buf = []
        self._send_buf_len = 0

        if self._send_state != 'closed':
            self._send_packet(MSG_CHANNEL_CLOSE)
            self._send_chan = None
            self._send_state = 'closed'

    def _discard_recv(self):
        """Discard unreceived data and clean up if close received"""

        # Discard unreceived data
        self._recv_buf = []
        self._recv_paused = False

        # If recv is close_pending, we know send is already closed
        if self._recv_state == 'close_pending':
            self._recv_state = 'closed'
            self._loop.call_soon(self._cleanup)

    def _pause_resume_writing(self):
        """Pause or resume writing based on send buffer low/high water marks"""

        if self._send_paused:
            if self._send_buf_len <= self._send_low_water:
                self._send_paused = False
                self._session.resume_writing()
        else:
            if self._send_buf_len > self._send_high_water:
                self._send_paused = True
                self._session.pause_writing()

    def _flush_send_buf(self):
        """Flush as much data in send buffer as the send window allows"""

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
                self._send_state = 'eof'
            elif self._send_state == 'close_pending':
                self._close_send()

    def _flush_recv_buf(self, exc=None):
        """Flush as much data in the recv buffer as the application allows"""

        while self._recv_buf and not self._recv_paused:
            self._deliver_data(*self._recv_buf.pop(0))

        if not self._recv_buf:
            if self._recv_state == 'eof_pending':
                self._recv_state = 'eof'

                if (not self._session.eof_received() and
                        self._send_state == 'open'):
                    self.write_eof()
            elif self._recv_state == 'close_pending':
                self._recv_state = 'closed'

                if self._recv_partial and not exc:
                    exc = DisconnectError(DISC_PROTOCOL_ERROR,
                                          'Unicode decode error')

                self._loop.call_soon(self._cleanup, exc)

    def _deliver_data(self, data, datatype):
        """Deliver incoming data to the session"""

        self._recv_window -= len(data)

        if self._recv_window < self._init_recv_window / 2:
            self._send_packet(MSG_CHANNEL_WINDOW_ADJUST,
                              UInt32(self._init_recv_window -
                                     self._recv_window))
            self._recv_window = self._init_recv_window

        if self._encoding:
            if datatype in self._recv_partial:
                encdata = self._recv_partial.pop(datatype) + data
            else:
                encdata = data

            while encdata:
                try:
                    data = encdata.decode(self._encoding)
                    encdata = b''
                except UnicodeDecodeError as exc:
                    if exc.start > 0:
                        # Avoid pylint false positive
                        # pylint: disable=invalid-slice-index
                        data = encdata[:exc.start].decode()
                        encdata = encdata[exc.start:]
                    elif exc.reason == 'unexpected end of data':
                        break
                    else:
                        raise DisconnectError(DISC_PROTOCOL_ERROR,
                                              'Unicode decode error')

                self._session.data_received(data, datatype)

            if encdata:
                self._recv_partial[datatype] = encdata
        else:
            self._session.data_received(data, datatype)

    def _accept_data(self, data, datatype=None):
        """Accept new data on the channel

           This method accepts new data on the channel, immediately
           delivering it to the session if it hasn't paused reading.
           If it has paused, data is buffered until reading is resumed.

           Data sent after the channel has been closed by the session
           is dropped.

        """

        if not data:
            return

        if self._send_state in {'close_pending', 'closed'}:
            return

        if len(data) > self._recv_window:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Window exceeded')

        if self._recv_paused:
            self._recv_buf.append((data, datatype))
        else:
            self._deliver_data(data, datatype)

    def _service_next_request(self):
        """Process next item on channel request queue"""

        request, packet, _ = self._request_queue[0]

        name = '_process_' + map_handler_name(request) + '_request'
        handler = getattr(self, name, None)
        result = handler(packet) if callable(handler) else False

        if result is not None:
            self._report_response(result)

    def _report_response(self, result):
        """Report back the response to a previously issued channel request"""

        request, _, want_reply = self._request_queue.pop(0)

        if want_reply and self._send_state not in {'close_pending', 'closed'}:
            if result:
                self._send_packet(MSG_CHANNEL_SUCCESS)
            else:
                self._send_packet(MSG_CHANNEL_FAILURE)

        if result and request in {'shell', 'exec', 'subsystem'}:
            self._session.session_started()
            self.resume_reading()

        if self._request_queue:
            self._service_next_request()

    def process_connection_close(self, exc):
        """Process the SSH connection closing"""

        if self._send_state != 'closed':
            self._send_state = 'closed'

        if self._recv_state not in {'close_pending', 'closed'}:
            self._recv_state = 'close_pending'
            self._flush_recv_buf(exc)
        elif self._recv_state == 'closed':
            self._loop.call_soon(self._cleanup, exc)

    def process_open(self, send_chan, send_window, send_pktsize, session):
        """Process a channel open request"""

        self._send_chan = send_chan
        self._send_window = send_window
        self._send_pktsize = send_pktsize

        self._conn.create_task(self._finish_open_request(session))

    def _wrap_session(self, session):
        """Hook to optionally wrap channel and session objects"""

        # By default, return the original channel and session objects
        return self, session

    @asyncio.coroutine
    def _finish_open_request(self, session):
        """Finish processing a channel open request"""

        # pylint: disable=broad-except
        try:
            if asyncio.iscoroutine(session):
                session = yield from session

            chan, self._session = self._wrap_session(session)

            self._conn.send_channel_open_confirmation(self._send_chan,
                                                      self._recv_chan,
                                                      self._recv_window,
                                                      self._recv_pktsize)

            self._send_state = 'open'
            self._recv_state = 'open'

            self._session.connection_made(chan)
        except ChannelOpenError as exc:
            self._conn.send_channel_open_failure(self._send_chan, exc.code,
                                                 exc.reason, exc.lang)
            self._loop.call_soon(self._cleanup)

    def process_open_confirmation(self, send_chan, send_window,
                                  send_pktsize, packet):
        """Process a channel open confirmation"""

        if not self._open_waiter:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Channel not being opened')

        self._send_chan = send_chan
        self._send_window = send_window
        self._send_pktsize = send_pktsize

        self._send_state = 'open'
        self._recv_state = 'open'

        if not self._open_waiter.cancelled(): # pragma: no branch
            self._open_waiter.set_result(packet)

        self._open_waiter = None

    def process_open_failure(self, code, reason, lang):
        """Process a channel open failure"""

        if not self._open_waiter:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Channel not being opened')

        if not self._open_waiter.cancelled(): # pragma: no branch
            self._open_waiter.set_exception(
                ChannelOpenError(code, reason, lang))

        self._open_waiter = None
        self._loop.call_soon(self._cleanup)

    def _process_window_adjust(self, pkttype, packet):
        """Process a send window adjustment"""

        # pylint: disable=unused-argument

        if self._recv_state not in {'open', 'eof_pending', 'eof'}:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Channel not open')

        adjust = packet.get_uint32()
        packet.check_end()

        self._send_window += adjust
        self._flush_send_buf()

    def _process_data(self, pkttype, packet):
        """Process incoming data"""

        # pylint: disable=unused-argument

        if self._recv_state != 'open':
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Channel not open for sending')

        data = packet.get_string()
        packet.check_end()

        self._accept_data(data)

    def _process_extended_data(self, pkttype, packet):
        """Process incoming extended data"""

        # pylint: disable=unused-argument

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
        """Process an incoming end of file"""

        # pylint: disable=unused-argument

        if self._recv_state != 'open':
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Channel not open for sending')

        packet.check_end()

        self._recv_state = 'eof_pending'
        self._flush_recv_buf()

    def _process_close(self, pkttype, packet):
        """Process an incoming channel close"""

        # pylint: disable=unused-argument

        if self._recv_state not in {'open', 'eof_pending', 'eof'}:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Channel not open')

        packet.check_end()

        self._close_send()

        self._recv_state = 'close_pending'
        self._flush_recv_buf()

    def _process_request(self, pkttype, packet):
        """Process an incoming channel request"""

        # pylint: disable=unused-argument

        if self._recv_state not in {'open', 'eof_pending', 'eof'}:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Channel not open')

        request = packet.get_string()
        want_reply = packet.get_boolean()

        try:
            request = request.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid channel request') from None

        self._request_queue.append((request, packet, want_reply))
        if len(self._request_queue) == 1:
            self._service_next_request()

    def _process_response(self, pkttype, packet):
        """Process a success or failure response"""

        packet.check_end()

        if self._request_waiters:
            waiter = self._request_waiters.pop(0)
            if not waiter.cancelled(): # pragma: no branch
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

        self._conn.send_packet(Byte(MSG_CHANNEL_OPEN), String(chantype),
                               UInt32(self._recv_chan),
                               UInt32(self._recv_window),
                               UInt32(self._recv_pktsize), *args)

        return (yield from self._open_waiter)

    def _send_packet(self, pkttype, *args):
        """Send a packet on the channel"""

        if self._send_chan is None: # pragma: no cover
            return

        self._conn.send_packet(Byte(pkttype), UInt32(self._send_chan), *args)

    def _send_request(self, request, *args, want_reply=False):
        """Send a channel request"""

        self._send_packet(MSG_CHANNEL_REQUEST, String(request),
                          Boolean(want_reply), *args)

    @asyncio.coroutine
    def _make_request(self, request, *args):
        """Make a channel request and wait for the response"""

        if self._send_chan is None:
            return False

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

        if self._send_state not in {'close_pending', 'closed'}:
            # Send an immediate close, discarding unsent data
            self._close_send()

        if self._recv_state != 'closed':
            # Discard unreceived data
            self._discard_recv()

    def close(self):
        """Cleanly close the channel

           This method can be called to cleanly close the channel, after
           which no more data can be sent or received. Any unsent buffered
           data will be flushed asynchronously before the channel is
           closed.

        """

        if self._send_state not in {'close_pending', 'closed'}:
            # Send a close only after sending unsent data
            self._send_state = 'close_pending'
            self._flush_send_buf()

        if self._recv_state != 'closed':
            # Discard unreceived data
            self._discard_recv()

    @asyncio.coroutine
    def wait_closed(self):
        """Wait for this channel to close

           This method is a coroutine which can be called to block until
           this channel has finished closing.

        """

        yield from self._close_event.wait()

    def get_extra_info(self, name, default=None):
        """Get additional information about the channel

           This method returns extra information about the channel once
           it is established. Supported values include ``'connection'``
           to return the SSH connection this channel is running over plus
           all of the values supported on that connection.

           For TCP channels, the values ``'local_peername'`` and
           ``'remote_peername'`` are added to return the local and remote
           host and port information for the tunneled TCP connection.

           For UNIX channels, the values ``'local_peername'`` and
           ``'remote_peername'`` are added to return the local and remote
           path information for the tunneled UNIX domain socket connection.
           Since UNIX domain sockets provide no "source" address, only
           one of these will be filled in.

           See :meth:`get_extra_info() <SSHClientConnection.get_extra_info>`
           on :class:`SSHClientConnection` for more information.

        """

        return self._extra.get(name, self._conn.get_extra_info(name, default)
                               if self._conn else default)

    def can_write_eof(self):
        """Return whether the channel supports :meth:`write_eof`

           This method always returns ``True``.

        """

        # pylint: disable=no-self-use
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
           :param int datatype: (optional)
               The extended data type of the data, from :ref:`extended
               data types <ExtendedDataTypes>`
           :type data: str or bytes

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
           :param int datatype: (optional)
               The extended data type of the data, from :ref:`extended
               data types <ExtendedDataTypes>`
           :type list_of_data: iterable of str or bytes objects

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

        if self._send_state == 'open':
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
           immediately. A pending end-of-file notication may also be
           delivered if one was queued while reading was paused.

        """

        if self._recv_paused:
            self._recv_paused = False
            self._flush_recv_buf()


class SSHClientChannel(SSHChannel):
    """SSH client channel"""

    _read_datatypes = {EXTENDED_DATA_STDERR}

    def __init__(self, conn, loop, encoding, window, max_pktsize):
        super().__init__(conn, loop, encoding, window, max_pktsize)

        self._exit_status = None
        self._exit_signal = None

    def _cleanup(self, exc=None):
        """Clean up this channel"""

        if self._conn: # pragma: no branch
            self._conn.detach_x11_listener(self)

        super()._cleanup(exc)

    @asyncio.coroutine
    def create(self, session_factory, command, subsystem, env, term_type,
               term_size, term_modes, x11_forwarding, x11_display,
               x11_auth_path, x11_single_connection, agent_forwarding):
        """Create an SSH client session"""

        packet = yield from self._open(b'session')

        # Client sessions should have no extra data in the open confirmation
        packet.check_end()

        self._session = session_factory()
        self._session.connection_made(self)

        for name, value in env.items():
            self._send_request(b'env', String(str(name)), String(str(value)))

        if term_type:
            if not term_size:
                width = height = pixwidth = pixheight = 0
            elif len(term_size) == 2:
                width, height = term_size
                pixwidth = pixheight = 0
            elif len(term_size) == 4:
                width, height, pixwidth, pixheight = term_size
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

        if x11_forwarding:
            try:
                auth_proto, remote_auth, screen = \
                    yield from self._conn.attach_x11_listener(
                        self, x11_display, x11_auth_path, x11_single_connection)
            except ValueError as exc:
                raise ChannelOpenError(OPEN_REQUEST_X11_FORWARDING_FAILED,
                                       str(exc)) from None

            result = yield from self._make_request(
                b'x11-req', Boolean(x11_single_connection), String(auth_proto),
                String(binascii.b2a_hex(remote_auth)), UInt32(screen))

            if not result:
                self._conn.detach_x11_listener(self)
                raise ChannelOpenError(OPEN_REQUEST_X11_FORWARDING_FAILED,
                                       'X11 forwarding request failed')

        if agent_forwarding:
            self._send_request(b'auth-agent-req@openssh.com')

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
        self.resume_reading()

        return self, self._session

    def _process_xon_xoff_request(self, packet):
        """Process a request to set up XON/XOFF processing"""

        client_can_do = packet.get_boolean()
        packet.check_end()

        self._session.xon_xoff_requested(client_can_do)
        return True

    def _process_exit_status_request(self, packet):
        """Process a request to deliver exit status"""

        status = packet.get_uint32() & 0xff
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
                                  'Invalid exit signal request') from None

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

           :param int width:
               The width of the terminal in characters
           :param int height:
               The height of the terminal in characters
           :param int pixwidth: (optional)
               The width of the terminal in pixels
           :param int pixheight: (optional)
               The height of the terminal in pixels

        """

        self._send_request(b'window-change', UInt32(width), UInt32(height),
                           UInt32(pixwidth), UInt32(pixheight))

    def send_break(self, msec):
        """Send a break to the remote process

           This method requests that the server perform a break
           operation on the remote process or service as described in
           :rfc:`4335`.

           :param int msec:
               The duration of the break in milliseconds

           :raises: :exc:`OSError` if the channel is not open

        """

        self._send_request(b'break', UInt32(msec))

    def send_signal(self, signal):
        """Send a signal to the remote process

           This method can be called to deliver a signal to the remote
           process or service. Signal names should be as described in
           section 6.10 of :rfc:`4254#section-6.10`.

           :param str signal:
               The signal to deliver

           :raises: :exc:`OSError` if the channel is not open

        """

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

           This method can be called to forcibly stop the remote process
           or service by sending it a ``KILL`` signal.

           :raises: :exc:`OSError` if the channel is not open

        """

        self.send_signal('KILL')


class SSHServerChannel(SSHChannel):
    """SSH server channel"""

    _write_datatypes = {EXTENDED_DATA_STDERR}

    def __init__(self, conn, loop, allow_pty, line_editor, line_history,
                 encoding, window, max_pktsize):
        """Initialize an SSH server channel"""

        super().__init__(conn, loop, encoding, window, max_pktsize)

        self._allow_pty = allow_pty
        self._line_editor = line_editor
        self._line_history = line_history
        self._env = self._conn.get_key_option('environment', {})
        self._command = None
        self._subsystem = None
        self._term_type = None
        self._term_size = (0, 0, 0, 0)
        self._term_modes = {}
        self._x11_display = None

    def _cleanup(self, exc=None):
        """Clean up this channel"""

        self._conn.detach_x11_listener(self)

        super()._cleanup(exc)

    def _wrap_session(self, session):
        """Wrap a line editor around the session if enabled"""

        if self._line_editor:
            chan = SSHLineEditorChannel(self, session, self._line_history)
            session = SSHLineEditorSession(chan, session)
        else:
            chan = self

        return chan, session

    def _process_pty_req_request(self, packet):
        """Process a request to open a pseudo-terminal"""

        term_type = packet.get_string()
        width = packet.get_uint32()
        height = packet.get_uint32()
        pixwidth = packet.get_uint32()
        pixheight = packet.get_uint32()
        modes = packet.get_string()
        packet.check_end()

        if not self._allow_pty or \
           not self._conn.check_key_permission('pty') or \
           not self._conn.check_certificate_permission('pty'):
            return False

        try:
            term_type = term_type.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid pty request') from None

        term_size = (width, height, pixwidth, pixheight)
        term_modes = {}

        idx = 0
        while idx < len(modes):
            mode = modes[idx]
            idx += 1
            if mode == PTY_OP_END or mode >= PTY_OP_RESERVED:
                break

            if idx+4 <= len(modes):
                term_modes[mode] = int.from_bytes(modes[idx:idx+4], 'big')
                idx += 4
            else:
                raise DisconnectError(DISC_PROTOCOL_ERROR,
                                      'Invalid pty modes string')

        result = self._session.pty_requested(self._term_type, self._term_size,
                                             self._term_modes)

        if result:
            self._term_type = term_type
            self._term_size = term_size
            self._term_modes = term_modes

        return result

    def _process_x11_req_request(self, packet):
        """Process request to enable X11 forwarding"""

        _ = packet.get_boolean()                        # single_connection
        auth_proto = packet.get_string()
        auth_data = packet.get_string()
        screen = packet.get_uint32()
        packet.check_end()

        try:
            auth_data = binascii.a2b_hex(auth_data)
        except binascii.Error:
            return False

        self._conn.create_task(self._finish_x11_req_request(auth_proto,
                                                            auth_data, screen))

    @asyncio.coroutine
    def _finish_x11_req_request(self, auth_proto, auth_data, screen):
        """Finish processing request to enable X11 forwarding"""

        self._x11_display = yield from self._conn.attach_x11_listener(
            self, auth_proto, auth_data, screen)

        self._report_response(bool(self._x11_display))

    def _process_auth_agent_req_at_openssh_dot_com_request(self, packet):
        """Process a request to enable ssh-agent forwarding"""

        packet.check_end()

        self._conn.create_task(self._finish_agent_req_request())

    @asyncio.coroutine
    def _finish_agent_req_request(self):
        """Finish processing request to enable agent forwarding"""

        self._report_response((yield from self._conn.create_agent_listener()))

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

    def _start_session(self, command=None, subsystem=None):
        """Tell the session what type of channel is being requested"""

        forced_command = self._conn.get_certificate_option('force-command')

        if forced_command is None:
            forced_command = self._conn.get_key_option('command')

        if forced_command is not None:
            command = forced_command

        if command is not None:
            self._command = command
            result = self._session.exec_requested(command)
        elif subsystem is not None:
            self._subsystem = subsystem
            result = self._session.subsystem_requested(subsystem)
        else:
            result = self._session.shell_requested()

        return result

    def _process_shell_request(self, packet):
        """Process a request to open a shell"""

        packet.check_end()

        return self._start_session()

    def _process_exec_request(self, packet):
        """Process a request to execute a command"""

        command = packet.get_string()
        packet.check_end()

        try:
            command = command.decode('utf-8')
        except UnicodeDecodeError:
            return False

        return self._start_session(command=command)

    def _process_subsystem_request(self, packet):
        """Process a request to open a subsystem"""

        subsystem = packet.get_string()
        packet.check_end()

        try:
            subsystem = subsystem.decode('ascii')
        except UnicodeDecodeError:
            return False

        return self._start_session(subsystem=subsystem)

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

           :returns: A str containing the terminal type or ``None`` if
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

           :param int mode:
               POSIX terminal mode taken from :ref:`POSIX terminal modes
               <PTYModes>` to look up

           :returns: An int containing the value of the requested
                     POSIX terminal mode or ``None`` if the requested
                     mode was not set

        """

        return self._term_modes.get(mode)

    def get_x11_display(self):
        """Return the display to use for X11 forwarding

           When X11 forwarding has been requested by the client, this
           method returns the X11 display which should be used to open
           a forwarded connection. If the client did not request X11
           forwarding, this method returns ``None``.

           :returns: A str containing the X11 display or ``None`` if
                     X11 fowarding was not requested

        """

        return self._x11_display

    def get_agent_path(self):
        """Return the path of the ssh-agent listening socket

           When agent forwarding has been requested by the client,
           this method returns the path of the listening socket which
           should be used to open a forwarded agent connection. If the
           client did not request agent forwarding, this method returns
           ``None``.

           :returns: A str containing the ssh-agent socket path or
                     ``None`` if agent fowarding was not requested

        """

        return self._conn.get_agent_path()

    def set_xon_xoff(self, client_can_do):
        """Set whether the client should enable XON/XOFF flow control

           This method can be called to tell the client whether or not
           to enable XON/XOFF flow control, indicating that it should
           intercept Control-S and Control-Q coming from its local
           terminal to pause and resume output, respectively.
           Applications should set client_can_do to ``True`` to
           enable this functionality or to ``False`` to tell the client
           to forward Control-S and Control-Q through as normal input.

           :param bool client_can_do:
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
           :type data: str or bytes

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

           :param int status:
               The exit status to report to the client

           :raises: :exc:`OSError` if the channel isn't open

        """

        if self._send_state not in {'close_pending', 'closed'}:
            self._send_request(b'exit-status', UInt32(status & 0xff))
            self.close()

    def exit_with_signal(self, signal, core_dumped=False,
                         msg='', lang=DEFAULT_LANG):
        """Send exit signal and close the channel

           This method can be called to report that the process
           terminated abnormslly with a signal. A more detailed
           error message may also provided, along with an indication
           of whether or not the process dumped core. After
           reporting the signal, the channel is closed.

           :param str signal:
               The signal which caused the process to exit
           :param bool core_dumped: (optional)
               Whether or not the process dumped core
           :param str msg: (optional)
               Details about what error occurred
           :param str lang: (optional)
               The language the error message is in

           :raises: :exc:`OSError` if the channel isn't open

        """

        if self._send_state not in {'close_pending', 'closed'}:
            self._send_request(b'exit-signal', String(signal),
                               Boolean(core_dumped), String(msg), String(lang))
            self.close()


class SSHForwardChannel(SSHChannel):
    """SSH channel for forwarding TCP and UNIX domain connections"""

    @asyncio.coroutine
    def _finish_open_request(self, session):
        """Finish processing a forward channel open request"""

        yield from super()._finish_open_request(session)

        if self._session:
            self._session.session_started()
            self.resume_reading()

    @asyncio.coroutine
    def _open(self, session_factory, chantype, *args):
        """Open a forward channel"""

        packet = yield from super()._open(chantype, *args)

        # Forward channels should have no extra data in the open confirmation
        packet.check_end()

        self._session = session_factory()
        self._session.connection_made(self)

        self._session.session_started()
        self.resume_reading()

        return self._session


class SSHTCPChannel(SSHForwardChannel):
    """SSH TCP channel"""

    @asyncio.coroutine
    def _open_tcp(self, session_factory, chantype, host, port,
                  orig_host, orig_port):
        """Open a TCP channel"""

        self._extra['peername'] = None
        self._extra['local_peername'] = (orig_host, orig_port)
        self._extra['remote_peername'] = (host, port)

        return (yield from super()._open(session_factory, chantype,
                                         String(host), UInt32(port),
                                         String(orig_host), UInt32(orig_port)))

    @asyncio.coroutine
    def connect(self, session_factory, host, port, orig_host, orig_port):
        """Create a new outbound TCP session"""

        return (yield from self._open_tcp(session_factory, b'direct-tcpip',
                                          host, port, orig_host, orig_port))

    @asyncio.coroutine
    def accept(self, session_factory, host, port, orig_host, orig_port):
        """Create a new forwarded TCP session"""

        return (yield from self._open_tcp(session_factory, b'forwarded-tcpip',
                                          host, port, orig_host, orig_port))

    def set_inbound_peer_names(self, dest_host, dest_port,
                               orig_host, orig_port):
        """Set local and remote peer names for inbound connections"""

        self._extra['local_peername'] = (dest_host, dest_port)
        self._extra['remote_peername'] = (orig_host, orig_port)


class SSHUNIXChannel(SSHForwardChannel):
    """SSH UNIX channel"""

    @asyncio.coroutine
    def _open_unix(self, session_factory, chantype, path, *args):
        """Open a UNIX channel"""

        self._extra['local_peername'] = ''
        self._extra['remote_peername'] = path

        return (yield from super()._open(session_factory, chantype,
                                         String(path), *args))

    @asyncio.coroutine
    def connect(self, session_factory, path):
        """Create a new outbound UNIX session"""

        # OpenSSH appears to have a bug which requires an originator
        # host and port to be sent after the path name to connect to
        # when opening a direct streamlocal channel.
        return (yield from self._open_unix(session_factory,
                                           b'direct-streamlocal@openssh.com',
                                           path, String(''), UInt32(0)))

    @asyncio.coroutine
    def accept(self, session_factory, path):
        """Create a new forwarded UNIX session"""

        return (yield from self._open_unix(session_factory,
                                           b'forwarded-streamlocal@openssh.com',
                                           path, String('')))

    def set_inbound_peer_names(self, dest_path):
        """Set local and remote peer names for inbound connections"""

        self._extra['local_peername'] = dest_path
        self._extra['remote_peername'] = ''


class SSHX11Channel(SSHForwardChannel):
    """SSH X11 channel"""

    @asyncio.coroutine
    def open(self, session_factory, orig_host, orig_port):
        """Open an SSH X11 channel"""

        self._extra['local_peername'] = (orig_host, orig_port)
        self._extra['remote_peername'] = None

        return (yield from self._open(session_factory, b'x11',
                                      String(orig_host), UInt32(orig_port)))

    def set_inbound_peer_names(self, orig_host, orig_port):
        """Set local and remote peer name for inbound connections"""

        self._extra['local_peername'] = None
        self._extra['remote_peername'] = (orig_host, orig_port)


class SSHAgentChannel(SSHForwardChannel):
    """SSH agent channel"""

    @asyncio.coroutine
    def open(self, session_factory):
        """Open an SSH agent channel"""

        return (yield from self._open(session_factory,
                                      b'auth-agent@openssh.com'))
