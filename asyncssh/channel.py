# Copyright (c) 2013 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH channel handlers"""

from .constants import *
from .misc import *
from .packet import *

_DEFAULT_WINDOW = 2*1024*1024
_DEFAULT_MAX_PKTSIZE = 32768
_DEFAULT_PTY_MODES = {}

_EOF = object()

class _SSHChannel(SSHPacketHandler):
    """Parent class for SSH channel handlers"""

    _read_datatypes = set()
    _write_datatypes = set()

    def __init__(self, conn, encoding, window, max_pktsize):
        """Initialize an SSH channel

           If encoding is set, data sent and received will be in the form
           of strings, converted on the wire to bytes using the specified
           encoding. If encoding is None, data sent and received must be
           provided as bytes.

           Window specifies the initial receive window size.

           Max_pktsize specifies the maximum length of a single data packet.

        """

        self.conn = conn

        self._encoding = encoding

        self._send_state = 'closed'
        self._send_chan = None
        self._send_window = None
        self._send_pktsize = None
        self._send_blocked = False
        self._send_buf = []

        self._recv_state = 'closed'
        self._recv_chan = conn._get_recv_chan()
        self._init_recv_window = window
        self._recv_window = window
        self._recv_pktsize = max_pktsize
        self._recv_blocked = False
        self._recv_buf = []

        self._pending_callbacks = []

        conn._channels[self._recv_chan] = self

    def _cleanup(self):
        if self.conn:
            if self._recv_chan:
                del self.conn._channels[self._recv_chan]
                self._recv_chan = None

            self.conn = None
            self._send_state = 'closed'
            self._recv_state = 'closed'

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

            self._send_window -= len(data)

            if not self._send_blocked and self._send_window == 0:
                self._send_blocked = True
                self.handle_send_blocked()

            if datatype is None:
                self._send_packet(MSG_CHANNEL_DATA, String(data))
            else:
                self._send_packet(MSG_CHANNEL_EXTENDED_DATA,
                                  UInt32(datatype), String(data))

        if not self._send_buf:
            if self._send_state == 'eof_pending':
                self._send_state = 'eof_sent'
                self._send_packet(MSG_CHANNEL_EOF)
            elif self._send_state == 'close_pending':
                self._send_state = 'close_sent'
                self._send_packet(MSG_CHANNEL_CLOSE)

    def _deliver_data(self, data, datatype):
        if data == _EOF:
            self.handle_eof()
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
                    raise SSHError(DISC_PROTOCOL_ERROR, 'Unicode decode error')

            self.handle_data(data, datatype)

    def _accept_data(self, data, datatype=None):
        if not data:
            return

        if data != _EOF and len(data) > self._recv_window:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Window exceeded')

        if self._recv_blocked:
            self._recv_buf.append((data, datatype))
        else:
            self._deliver_data(data, datatype)

    def _process_connection_close(self):
        """Process the SSH connection closing"""

        if self._send_state == 'open_sent':
            self.handle_open_error(OPEN_CONNECT_FAILED,
                                   'SSH connection closed', DEFAULT_LANG)
        elif self._recv_state != 'closed':
            self.handle_close()

        self._cleanup()

    def _process_open(self, send_chan, send_window, send_pktsize, packet):
        """Process a channel open request"""

        if self._recv_state != 'closed':
            raise SSHError(DISC_PROTOCOL_ERROR, 'Channel already open')

        self._send_state = 'open'
        self._send_chan = send_chan
        self._send_window = send_window
        self._send_pktsize = send_pktsize

        self._recv_state = 'open'

        self._send_packet(MSG_CHANNEL_OPEN_CONFIRMATION,
                          UInt32(self._recv_chan),
                          UInt32(self._recv_window),
                          UInt32(self._recv_pktsize),
                          self._get_open_result())

        self._finish_open()

    def _process_open_confirmation(self, send_chan, send_window, send_pktsize,
                                   packet):
        """Process a channel open confirmation"""

        if self._send_state != 'open_sent':
            raise SSHError(DISC_PROTOCOL_ERROR, 'Channel not being opened')

        self._parse_open_result(packet)

        self._send_state = 'open'
        self._send_chan = send_chan
        self._send_window = send_window
        self._send_pktsize = send_pktsize

        self._recv_state = 'open'

        self._finish_open()

    def _process_open_failure(self, code, reason, lang):
        """Process a channel open failure"""

        if self._send_state != 'open_sent':
            raise SSHError(DISC_PROTOCOL_ERROR, 'Channel not being opened')

        self._send_state = 'closed'
        self.handle_open_error(code, reason, lang)
        self._cleanup()

    def _process_window_adjust(self, pkttype, packet):
        if self._recv_state not in {'open', 'eof_received'}:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Channel not open')

        adjust = packet.get_uint32()
        packet.check_end()

        self._send_window += adjust
        self._flush_send_buf()

        if self._send_blocked and self._send_window > 0:
            self._send_blocked = False
            self.handle_send_unblocked()

    def _process_data(self, pkttype, packet):
        if self._recv_state != 'open':
            raise SSHError(DISC_PROTOCOL_ERROR, 'Channel not open for sending')

        data = packet.get_string()
        packet.check_end()

        self._accept_data(data)

    def _process_extended_data(self, pkttype, packet):
        if self._recv_state != 'open':
            raise SSHError(DISC_PROTOCOL_ERROR, 'Channel not open for sending')

        datatype = packet.get_uint32()
        data = packet.get_string()
        packet.check_end()

        if datatype not in self._read_datatypes:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid extended data type')

        self._accept_data(data, datatype)

    def _process_eof(self, pkttype, packet):
        if self._recv_state != 'open':
            raise SSHError(DISC_PROTOCOL_ERROR, 'Channel not open for sending')

        packet.check_end()

        self._recv_state = 'eof_received'
        self._accept_data(_EOF)

    def _process_close(self, pkttype, packet):
        if self._recv_state not in {'open', 'eof_received'}:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Channel not open')

        packet.check_end()

        # Flush any unsent data
        self._send_buf = []

        # Notify application that the remote system has closed
        self._recv_state = 'closed'
        self.handle_close()

        # If we haven't yet done a close, force one
        if self._send_state not in {'close_pending', 'close_sent', 'closed'}:
            self.close()

        self._cleanup()

    def _process_request(self, pkttype, packet):
        if self._recv_state not in {'open', 'eof_received'}:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Channel not open')

        request = packet.get_string()
        want_reply = packet.get_boolean()

        try:
            request = request.decode('ascii')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid channel request')

        name = '_process_' + request.replace('-', '_') + '_request'
        handler = getattr(self, name, None)
        result = handler(packet) if callable(handler) else False

        if want_reply:
            if result:
                self._send_packet(MSG_CHANNEL_SUCCESS)
            else:
                self._send_packet(MSG_CHANNEL_FAILURE)

        if result and request in ('shell', 'exec', 'subsystem'):
            self.handle_open()

    def _process_response(self, pkttype, packet):
        if self._send_state not in {'open', 'eof_pending', 'eof_sent',
                                    'close_pending', 'close_sent'}:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Channel not open')

        packet.check_end()

        if self._pending_callbacks:
            callback = self._pending_callbacks.pop(0)
            callback(pkttype == MSG_CHANNEL_SUCCESS)
        else:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Unexpected channel response')

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

    def _get_open_result(self):
        """Return additional data to send in open confirmation"""

        # By default, return no additional data in an open confirmation
        return b''

    def _parse_open_result(self, packet):
        """Parse additional data in an open confirmation"""

        # By default, expect no additional data in an open confirmation
        packet.check_end()
        return True

    def _open(self, chantype, *args):
        """Send a request to open the channel"""

        if self._send_state != 'closed':
            raise IOError('Channel already open')

        self._send_state = 'open_sent'

        self.conn._send_packet(Byte(MSG_CHANNEL_OPEN), String(chantype),
                               UInt32(self._recv_chan),
                               UInt32(self._recv_window),
                               UInt32(self._recv_pktsize), *args)

    def _send_packet(self, pkttype, *args):
        """Send a packet on the channel"""

        if self._send_chan is None:
            raise IOError('Channel not open')

        self.conn._send_packet(Byte(pkttype), UInt32(self._send_chan), *args)

    def _send_request(self, request, *args, callback=None):
        """Send a channel request"""

        if callback:
            self._pending_callbacks.append(callback)

        self._send_packet(MSG_CHANNEL_REQUEST, String(request),
                          Boolean(callback != None), *args)

    def send(self, data, datatype=None):
        """Send data on the channel

           This method can be called to send data on the channel. If
           an encoding was specified when the channel was created, the
           data should be provided as a string and will be converted
           using that encoding. Otherwise, the data should be provided
           as bytes.

           An extended data type can optionally be provided. For
           instance, this is used on :class:`SSHServerSession` channels
           to mark data intended for output to ``stderr``.

           :param data:
               The data to send on the channel
           :param integer datatype: (optional)
               The extended data type of the data, from :ref:`extended
               data types <ExtendedDataTypes>`
           :type data: string or bytes

           :raises: :exc:`IOError` if the channel isn't open for sending
                    or the extended data type is not valid for this type
                    of channel

        """

        if self._send_state != 'open':
            raise IOError('Channel not open for sending')

        if datatype is not None and datatype not in self._write_datatypes:
            raise IOError('Invalid extended data type')

        if len(data) == 0:
            return

        if self._encoding:
            data = data.encode(self._encoding)

        self._send_buf.append((bytearray(data), datatype))
        self._flush_send_buf()

    def send_eof(self):
        """Send EOF on the channel

           This method sends an end-of-file indication on the
           channel, after which no more data can be sent. The
           channel remains open, though, and data may still be
           sent in the other direction.

           :raises: :exc:`IOError` if the channel isn't open for sending

        """

        if self._send_state != 'open':
            raise IOError('Channel not open for sending')

        self._send_state = 'eof_pending'
        self._flush_send_buf()

    def block_recv(self):
        """Temporarily suspend delivery of incoming data

           This method is used to temporarily suspend delivery of incoming
           channel data. After this call, incoming data will no longer
           trigger calls to :meth:`handle_data` until :meth:`unblock_recv`
           is called. Data will be buffered locally up to the configured
           SSH channel window size, but window updates will no longer be
           sent, eventually causing back pressure on the remote system.

           This method is useful when forwarding channel data to another
           file descriptor which has temporarily become no longer writable.

           .. note:: Channel close notifications are not suspended by this
                     call. If the remote system closes the channel while
                     delivery is suspended, :meth:`handle_close` will be
                     called even though some buffered data may not have
                     been delivered.

        """

        self._recv_blocked = True

    def unblock_recv(self):
        """Resume delivery of incoming data

           This method can be called to resume deliver of incoming data
           which was suspended by a call to :meth:`block_recv`. As soon
           as this is called, any buffered data will be delivered via the
           :meth:`handle_data` method. A pending end-of-file notication
           may also be delivered via the :meth:`handle_eof` method.

        """

        self._recv_blocked = False

        while self._recv_buf and not self._recv_blocked:
            self._deliver_data(*self._recv_buf.pop(0))

    def close(self):
        """Close the channel

           This method can be called to close the channel, after which
           no more data can be sent or received. If the send window is
           full, any unsent buffered data will be discarded. However,
           incoming data in flight when the close was issued may still
           be delivered.

        """

        if self._send_state == 'closed':
            self._cleanup()
        else:
            if self._send_state not in ('close_pending', 'close_sent'):
                self._send_state = 'close_pending'

            self._flush_send_buf()

    def handle_open(self):
        """Handle when the channel is opened successfully

           This method is called when a channel is opened successfully.
           It can be overridden by the application to begin sending
           whatever data it needs to on the channel after it is opened.
           Data should not be sent on the channel before this method
           is called.

           By default, nothing is done here.

        """

        pass

    def handle_open_error(self, code, reason, lang):
        """Handle an error returned when opening the channel

           This method is called when a request to open a channel fails.
           More information about the cause of the failure are provided
           in the code and reason arguments.

           By default, this automatically triggers a channel close, but
           it should be overridden by the application so that it is
           notified of the error.

           :param integer code:
               The reason for the open failure, from :ref:`channel open
               failure reasons <ChannelOpenFailureReasons>`.
           :param string reason:
               A human readable reason for the open failure
           :param string lang:
               The language the reason is in

        """

        self.close()

    def handle_data(self, data, datatype):
        """Handle when data is received on the channel

           This method is called when data is received on the channel.
           If an encoding was specified when the channel was created,
           the data will be delivered as a string after decoding with
           the requested encoding. Otherwise, the data will be delivered
           as bytes.

           By default, nothing is done here. This method should be
           overridden if any incoming data needs to be processed.

           :param data:
               The data received on the channel
           :param datatype:
               The extended data type of the data, from :ref:`extended
               data types <ExtendedDataTypes>`
           :type data: string or bytes

        """

        pass

    def handle_eof(self):
        """Handle when EOF is received on the channel

           This method is called when an end-of-file indication is received
           on the channel, after which no more data will be received. The
           channel remains open, though, and data may still be sent.

           By default, nothing is done here. This method should be
           overridden if any incoming data needs to be processed.

        """

        pass

    def handle_send_blocked(self):
        """Handle when the send window becomes full

           This method is called when the channel's send window becomes
           full and no more data can be sent until the remote system
           adjusts the window. While data can still be buffered locally,
           applications may wish to stop sending new data until the
           window opens back up.

           By default, nothing is done here.

        """

        pass

    def handle_send_unblocked(self):
        """Handle when the send window reopens

           This method is called when the channel's send window reopens
           and more data can be sent.

           By default, nothing is done here.

        """

        pass

    def handle_close(self):
        """Handle when the channel is closed by the remote system

           This method is called when the remote system closes the
           channel, after which no more data can be sent or received.
           Applications should call :meth:`close` from within this
           method, and clean up any other state associated with this
           channel.

           By default, nothing is done here, but this class will
           automatically acknowledge the close if the application
           doesn't do so.

        """

        pass


class SSHClientSession(_SSHChannel):
    """SSH client session handler

       Applications should subclass this when implementing an SSH client
       session handler. The handler should set up the environment and/or
       terminal settings and then request a shell, execute a command,
       or request to start a subsystem. In the :meth:`handle_open`
       method, it can then begin sending data. Received data will be
       passed to the :meth:`handle_data` method. See below for other
       methods for handling errors and connection close.

       By default, this class expects string data in its send and
       receive functions, which it encodes on the SSH connection in
       UTF-8 (ISO 10646) format. An optional encoding argument can be
       passed in to select a different encoding, or ``None`` can be
       passed in if the application wishes to send and receive raw bytes.

       Other optional arguments include the SSH receive window size and
       max packet size which default to 2 MB and 32 KB, respectively.

       :param conn:
           The connection this session should be opened on
       :param string encoding: (optional)
           The Unicode encoding to use for data exchanged on the connection
       :param integer window: (optional)
           The receive window size for this session
       :param integer max_pktsize: (optional)
           The maximum packet size for this session
       :type conn: :class:`SSHClient`

    """

    _read_datatypes = {EXTENDED_DATA_STDERR}

    def __init__(self, conn, encoding='utf-8', window=_DEFAULT_WINDOW,
                 max_pktsize=_DEFAULT_MAX_PKTSIZE):
        super().__init__(conn, encoding, window, max_pktsize)

        self._command = None
        self._subsystem = None
        self._env = {}
        self._pty_term = None
        self._pty_width = 0
        self._pty_height = 0
        self._pty_pixwidth = 0
        self._pty_pixheight = 0
        self._pty_modes = {}

    def _finish_open(self):
        """Process the opening of a client session

           After the channel is opened, send requests to set up the
           environment, open a pseudo-terminal  if one is requested, and
           then open a shell or execute a command.

        """

        for name, value in self._env.items():
            name = str(name).encode('utf-8')
            value = str(value).encode('utf-8')
            self._send_request(b'env', String(name), String(value))

        if self._pty_term:
            term = self._pty_term.encode('ascii')

            modes = b''
            for mode, value in self._pty_modes.items():
                if mode <= PTY_OP_END or mode >= PTY_OP_RESERVED:
                    raise ValueError('Invalid pty mode: %s' % mode)

                modes += Byte(mode) + UInt32(value)

            modes += Byte(PTY_OP_END)

            self._send_request(b'pty-req', String(term),
                               UInt32(self._pty_width),
                               UInt32(self._pty_height),
                               UInt32(self._pty_pixwidth),
                               UInt32(self._pty_pixheight),
                               String(modes), callback=self._finish_pty)
        else:
            self._finish_pty(True)

    def _finish_pty(self, result):
        """Process the response to opening a pseudo-terminal"""

        if result:
            if self._command:
                self._send_request(b'exec', String(self._command),
                                   callback=self._finish_session_start)
            elif self._subsystem:
                self._send_request(b'subsystem', String(self._subsystem),
                                   callback=self._finish_session_start)
            else:
                self._send_request(b'shell',
                                   callback=self._finish_session_start)
        else:
            self.handle_open_error(OPEN_REQUEST_PTY_FAILED,
                                   'PTY allocation failed', DEFAULT_LANG)
            self.close()

    def _finish_session_start(self, result):
        """Process the response to starting a session"""

        if result:
            self.handle_open()
        else:
            self.handle_open_error(OPEN_REQUEST_SESSION_FAILED,
                                   'Session startup failed', DEFAULT_LANG)
            self.close()

    def _process_xon_xoff_request(self, packet):
        """Process a request to set up XON/XOFF processing"""

        client_can_do = packet.get_boolean()
        packet.check_end()

        self.handle_xon_xoff(client_can_do)
        return True

    def _process_exit_status_request(self, packet):
        """Process a request to deliver exit status"""

        status = packet.get_uint32()
        packet.check_end()

        self.handle_exit(status)
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
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid exit signal request')

        self.handle_exit_signal(signal, core_dumped, msg, lang)
        return True

    def set_environment(self, env):
        """Set the environment for this session

           This method sets the environment which will be passed to the
           server when the session is opened. It must be called before
           :meth:`open_shell`, :meth:`exec`, or :meth:`open_subsystem`.
           Keys and values passed in here will all be converted to
           Unicode strings encoded as UTF-8 (ISO 10646) for transmission.

           :param dictionary env:
               Environment variable names and values to send

           .. note:: Many SSH servers restrict which environment variables
                     a client is allowed to set. The server's configuration
                     may need to be edited before this method can
                     successfully set the environment.

        """

        if self._send_chan:
            raise IOError('Environment must be set before session is opened')

        if not isinstance(env, dict):
            raise ValueError('Environment must be a dictionary')

        self._env = env

    def set_terminal(self, term, modes=_DEFAULT_PTY_MODES):
        """Set the terminal type and TTY modes for this session

           This method causes a pseudo-terminal to be requested when the
           session is established, with the specified terminal type and
           POSIX terminal modes. It must be called before :meth:`open_shell`,
           :meth:`exec`, or :meth:`open_subsystem`.

           :param string term:
               Terminal type to set for this session
           :param dictionary modes:
               POSIX terminal modes to set for this session, where keys
               are taken from :ref:`POSIX terminal modes <PTYModes>` with
               values defined in section 8 of :rfc:`4254#section-8`.

        """

        if self._send_chan:
            raise IOError('Terminal must be set before session is opened')

        self._pty_term = term
        self._pty_modes = modes

    def set_window_size(self, width, height, pixwidth=0, pixheight=0):
        """Set the window size for this session

           This method sets the width and height of the terminal
           associated with this session. It should be called before
           :meth:`open_shell`, :meth:`exec`, or :meth:`open_subsystem`
           to set the initial terminal size, but may be called again
           any time the terminal size changes.

           :param integer width:
               The width of the terminal in characters
           :param integer height:
               The height of the terminal in characters
           :param integer pixwidth: (optional)
               The width of the terminal in pixels
           :param integer pixheight: (optional)
               The height of the terminal in pixels

        """

        self._pty_width = width
        self._pty_height = height
        self._pty_pixwidth = pixwidth
        self._pty_pixheight = pixheight

        if self._send_chan:
            self._send_request(b'window-change',
                               UInt32(self._pty_width),
                               UInt32(self._pty_height),
                               UInt32(self._pty_pixwidth),
                               UInt32(self._pty_pixheight))

    def open_shell(self):
        """Open a remote shell

           This method requests that the server start up a remote shell.
           If the request succeeds, :meth:`handle_open` will be called,
           after which the application can begin sending input. If the
           request fails, :meth:`handle_open_error` will be called
           with information about the failure.

           :raises: :exc:`IOError` if the channel is already open

        """

        self._command = None
        self._subsystem = None
        self._open(b'session')

    def exec(self, command):
        """Execute a remote command

           This method requests that the server execute a remote command.
           If the request succeeds, :meth:`handle_open` will be called,
           after which the application can begin sending input. If the
           request fails, :meth:`handle_open_error` will be called
           with information about the failure.

           :param string command:
               The remote command to execute

           :raises: :exc:`IOError` if the channel is already open

        """

        self._command = command
        self._subsystem = None
        self._open(b'session')

    def open_subsystem(self, subsystem):
        """Open a remote subsystem

           This method requests that the server start a remote subsystem.
           If the request succeeds, :meth:`handle_open` will be called,
           after which the application can begin sending input. If the
           request fails, :meth:`handle_open_error` will be called
           with information about the failure.

           :param string subsystem:
               The remote subsystem to start

           :raises: :exc:`IOError` if the channel is already open

        """

        self._command = None
        self._subsystem = subsystem
        self._open(b'session')

    def send_signal(self, signal):
        """Send a signal to the server

           This method can be called to deliver a signal to the remote
           process/service. Signal names should be as described in
           section 6.10 of :rfc:`4254#section-6.10`.

           :param string signal:
               The signal to deliver

           :raises: :exc:`IOError` if the channel is not open

        """

        signal = signal.encode('ascii')

        self._send_request(b'signal', String(signal))

    def send_break(self, msec):
        """Send a break to the server

           This method requests that the server perform a break
           operation, as described in :rfc:`4335`.

           :param integer msec:
               The duration of the break in milliseconds

           :raises: :exc:`IOError` if the channel is not open

        """

        self._send_request(b'break', UInt32(msec))

    def handle_xon_xoff(self, client_can_do):
        """Handle whether or not to enable XON/XOFF flow control

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

        pass

    def handle_exit(self, status):
        """Handle the remote exit status for this session

           This method is called when the shell, command, or subsystem
           running on the server terminates and returns an exit status.
           A zero exit status generally means that the operation was
           successful. This call will generally be followed by a call
           to :meth:`handle_close` if the application hasn't already
           called :meth:`close`.

           By default, the exit status is ignored.

           :param integer status:
               The exit status returned by the remote process

        """

        pass

    def handle_exit_signal(self, signal, core_dumped, msg, lang):
        """Handle a remote exit signal for this session

           This method is called when the shell, command, or subsystem
           running on the server terminates abnormally with a signal.
           A more detailed error may also be provided, along with an
           indication of whether the remote process dumped core.

           By default, an exit signal is ignored.

           :param string signal:
               The signal which caused the remote process to exit
           :param boolean core_dumped:
               Whether or not the remote process dumped core
           :param msg:
               Details about what error occurred
           :param lang:
               The language the error message is in

        """

        pass


class SSHServerSession(_SSHChannel):
    """SSH Server Session parent class

       Applications should subclass this when implementing an SSH
       server session handler. The handler should implement one or
       more of :meth:`handle_shell_request`, :meth:`handle_exec_request`,
       or :meth:`handle_subsystem_request` depending on which operations
       it wishes to support. In the method :meth:`handle_open`, it can
       then begin sending data. Received data will be passed to the
       :meth:`handle_data` method. See below for other methods which
       may be implemented to process the environment, terminal
       information, and to handle errors and connection close.

    """

    _write_datatypes = {EXTENDED_DATA_STDERR}

    def __init__(self, conn, encoding='utf-8', window=_DEFAULT_WINDOW,
                 max_pktsize=_DEFAULT_MAX_PKTSIZE):
        """Initialize an SSH server session

           By default, expect data to be sent and received as UTF-8
           strings. Other encodings can also be provided, or None can
           be used to send and receive data as bytes. An optional
           receive window and max packet size can also be set.

        """

        super().__init__(conn, encoding, window, max_pktsize)

        self._env = {}
        self._pty_term = None
        self._pty_width = 0
        self._pty_height = 0
        self._pty_pixwidth = 0
        self._pty_pixheight = 0
        self._pty_modes = {}

    def _finish_open(self):
        """Process the opening of a server session"""

        # On the server side, we wait for requests to set up the environment
        # and/or a psuedo terminal and to start # a shell/command/subsystem
        # before calling handle_open().
        pass

    def _process_pty_req_request(self, packet):
        """Process a request to open a pseudo-terminal"""

        term = packet.get_string()
        self._pty_width = packet.get_uint32()
        self._pty_height = packet.get_uint32()
        self._pty_pixwidth = packet.get_uint32()
        self._pty_pixheight = packet.get_uint32()
        modes = packet.get_string()
        packet.check_end()

        try:
            self._pty_term = term.decode('ascii')
        except UnicodeDecodeError:
            raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid pty request')

        idx = 0
        while idx < len(modes):
            mode = modes[idx]
            idx += 1
            if mode == PTY_OP_END or mode >= PTY_OP_RESERVED:
                break

            if idx+4 <= len(modes):
                self._pty_modes[mode] = int.from_bytes(modes[idx:idx+4], 'big')
                idx += 4
            else:
                raise SSHError(DISC_PROTOCOL_ERROR, 'Invalid pty modes string')

        result = self.handle_pty_request(self._pty_term, self._pty_modes)
        if result:
            self.handle_window_change(self._pty_width, self._pty_height,
                                      self._pty_pixwidth, self._pty_pixheight)

        return result

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

        return self.handle_shell_request()

    def _process_exec_request(self, packet):
        """Process a request to execute a command"""

        command = packet.get_string()
        packet.check_end()

        try:
            command = command.decode('utf-8')
        except UnicodeDecodeError:
            return False

        return self.handle_exec_request(command)

    def _process_subsystem_request(self, packet):
        """Process a request to open a subsystem"""

        subsystem = packet.get_string()
        packet.check_end()

        try:
            subsystem = subsystem.decode('ascii')
        except UnicodeDecodeError:
            return False

        return self.handle_subsystem_request(subsystem)

    def _process_window_change_request(self, packet):
        """Process a request to change the window size"""

        self._pty_width = packet.get_uint32()
        self._pty_height = packet.get_uint32()
        self._pty_pixwidth = packet.get_uint32()
        self._pty_pixheight = packet.get_uint32()
        packet.check_end()

        self.handle_window_change(self._pty_width, self._pty_height,
                                  self._pty_pixwidth, self._pty_pixheight)
        return True

    def _process_signal_request(self, packet):
        """Process a request to send a signal"""

        signal = packet.get_string()
        packet.check_end()

        try:
            signal = signal.decode('ascii')
        except UnicodeDecodeError:
            return False

        self.handle_signal(signal)
        return True

    def _process_break_request(self, packet):
        """Process a request to send a break"""

        msec = packet.get_uint32()
        packet.check_end()

        return self.handle_break(msec)

    def handle_pty_request(self, term, modes):
        """Handle a request for a psuedo-terminal from the client

           This method is called when the client sends a request to
           allocate a pseudo-terminal with the requested terminal type
           POSIX terminal modes. This method should return ``True``
           if the request for the pseudo-terminal is accepted.
           Otherwise, it should return ``False`` to reject the request.

           When a pseudo-terminal is requested, window size
           information is also provided, but it is reported to the
           application via the :meth:`handle_window_change` method.

           By default, requests to allocate a pseudo-terminal are
           accepted but nothing is done with the associated terminal
           information. Applications wishing to use this information
           should implement this method and have it return ``True``,
           or simply call :meth:`get_terminal_type` and/or
           :meth:`get_terminal_mode` to get the information they
           need after :meth:`handle_open` is called.

           :param string term:
               Terminal type to set for this session
           :param dictionary modes:
               POSIX terminal modes to set for this session, where keys
               are taken from :ref:`POSIX terminal modes <PTYModes>` with
               values defined in section 8 of :rfc:`4254#section-8`.

           :returns: A boolean indicating if the request for a
                     pseudo-terminal was allowed or not

        """

        return True

    def handle_window_change(self, width, height, pixwidth, pixheight):
        """Handle an update to the window size information

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

        pass

    def handle_shell_request(self):
        """Handle a shell request

           This method should be overridden by the application to
           perform whatever processing is required when a client makes
           a request to open an interactive shell. It should return
           ``True`` to accept the request, or ``False`` to reject it.

           If the application returns ``True``, the :meth:`handle_open`
           method will be called once the channel is open. No output
           should be sent until this method is called.

           By default this method returns ``False`` to reject all requests.

           :returns: A boolean indicating if the shell request was
                     allowed or not

        """

        return False

    def handle_exec_request(self, command):
        """Handle a request to execute a command

           This method should be overridden by the application to
           perform whatever processing is required when a client makes
           a request to execute a command. It should return ``True`` to
           accept the request, or ``False`` to reject it.

           If the application returns ``True``, the :meth:`handle_open`
           method will be called once the channel is open. No output
           should be sent until this method is called.

           By default this method returns ``False`` to reject all requests.

           :param string command:
               The command the client has requested to execute

           :returns: A boolean indicating if the exec request was
                     allowed or not

        """

        return False

    def handle_subsystem_request(self, subsystem):
        """Handle a request to start a subsystem

           This method should be overridden by the application to
           perform whatever processing is required when a client makes
           a request to start a subsystem. It should return ``True`` to
           accept the request, or ``False`` to reject it.

           If the application returns ``True``, the :meth:`handle_open`
           method will be called once the channel is open. No output
           should be sent until this method is called.

           By default this method returns ``False`` to reject all requests.

           :param string subsystem:
               The subsystem to start

           :returns: A boolean indicating if the request to open the
                     subsystem was allowed or not

        """

        return False

    def get_environment(self):
        """Return the environment for this session

           This method returns the environment set by the client
           when the session was opened. Calls to this method should
           only be made after :meth:`handle_open` has been called.

           :returns: A dictionary containing the environment variables
                     set by the client

        """

        return self._env

    def get_terminal_type(self):
        """Return the terminal type for this session

           This method returns the terminal type set by the client
           when the session was opened. If the client didn't request
           a pseudo-terminal, this method will return ``None``. Calls
           to this method should only be made after :meth:`handle_open`
           has been called.

           :returns: A string containing the terminal type or ``None`` if
                     no pseudo-terminal was requested

        """

        return self._pty_term

    def get_terminal_mode(self, mode):
        """Return the requested TTY mode for this session

           This method looks up the value of a POSIX terminal mode
           set by the client when the session was opened. If the client
           didn't request a pseudo-terminal or didn't set the requested
           TTY mode opcode, this method will return ``None``. Calls to
           this method should only be made after :meth:`handle_open`
           has been called.

           :param integer mode:
               POSIX terminal mode taken from :ref:`POSIX terminal modes
               <PTYModes>` to look up

           :returns: An integer containing the value of the requested
                     POSIX terminal mode or ``None`` if the requested
                     mode was not set

        """

        return self._pty_modes.get(mode)

    def get_window_size(self):
        """Return window size information for this session

           This method returns the latest window size information set
           by the client. If the client didn't set any window size
           information, all values returned will be zero. Calls to
           this method should only be made after :meth:`handle_open`
           has been called. Also see :meth:`handle_window_change` for
           how to get notified asynchronously whenever the reported
           terminal size changes.

           :returns: A tuple of four integers containing the width and
                     height of the terminal in characters and the width
                     and height of the terminal in pixels

        """

        return (self._pty_width, self._pty_height,
                self._pty_pixwidth, self._pty_pixheight)

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

    def send_stderr(self, data):
        """Send output to stderr

           This method can be called to send output to the client which
           is intended to be displayed on stderr. If an encoding was
           specified when the channel was created, the data should be
           provided as a string and will be converted using that
           encoding. Otherwise, the data should be provided as bytes.

           :param data:
               The data to send to stderr
           :type data: string or bytes

           :raises: :exc:`IOError` if the channel isn't open for sending

        """

        self.send(data, EXTENDED_DATA_STDERR)

    def exit(self, status):
        """Send exit status and close the channel

           This method can be called to report an exit status for the
           process back to the client and close the channel. A zero
           exit status is generally returned when the operation was
           successful. After reporting the status, the channel is
           closed.

           :param integer status:
               The exit status to report to the client

           :raises: :exc:`IOError` if the channel isn't open

        """

        if self._send_state not in {'open', 'eof_pending', 'eof_sent'}:
            raise IOError('Channel not open')

        self._send_request(b'exit-status', UInt32(status))
        self.close()

    def exit_with_signal(self, signal, core_dumped, msg, lang=DEFAULT_LANG):
        """Send exit signal and close the channel

           This method can be called to report that the process
           terminated abnormslly with a signal. A more detailed
           error message may also provided, along with an indication
           of whether or not the process dumped core. After
           reporting the signal, the channel is closed.

           :param string signal:
               The signal which caused the process to exit
           :param boolean core_dumped:
               Whether or not the process dumped core
           :param msg:
               Details about what error occurred
           :param lang:
               The language the error message is in

           :raises: :exc:`IOError` if the channel isn't open

        """

        if self._send_state not in {'open', 'eof_pending', 'eof_sent'}:
            raise IOError('Channel not open')

        signal = signal.encode('ascii')
        msg = msg.encode('utf-8')
        lang = lang.encode('ascii')

        self._send_request(b'exit-signal', String(signal),
                           Boolean(core_dumped), String(msg), String(lang))
        self.close()

    def handle_signal(self, signal):
        """Handle the delivery of a signal

           This method is called when the client delivers a signal
           on the channel.

           By default, signals from the client are ignored.

        """

        pass

    def handle_break(self, msec):
        """Handle the delivery of a break from the client

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


class SSHTCPConnection(_SSHChannel):
    """SSH TCP Connection parent class

       Applications should subclass this when implementing a handler for
       an SSH direct or forwarded TCP connection. SSH client applications
       wishing to open a direct connection should create this object and
       call :meth:`connect`. SSH server applications wishing to support
       forwarded connections should implement :meth:`handle_listen()
       <SSHServer.handle_listen>` in a subclass of :class:`SSHServer`
       to be notified about what ports to listen on and then create this
       object and call :meth:`accept` to forward incoming connections
       when they arrive.

       If a connection is successfully opened, :meth:`handle_open` will
       be called, after with the application can begin sending data.
       Received data will be passed to the :meth:`handle_data` method.

       By default, :class:`SSHTCPConnection` expects data to be sent
       and received as raw bytes. However, strings can also be supported
       by specifying what encoding to use when this object is created.

    """

    def __init__(self, conn, encoding=None, window=_DEFAULT_WINDOW,
                 max_pktsize=_DEFAULT_MAX_PKTSIZE):
        super().__init__(conn, encoding, window, max_pktsize)

    def _finish_open(self):
        """Process the opening of a TCP connection"""

        # Call handle_open when a connection is opened successfully
        self.handle_open()

    def accept(self, bind_addr, bind_port, orig_host='', orig_port=0):
        """Report opening of an incoming forwarded TCP/IP connection

           This method can be called to open a channel for a new
           incoming TCP connection which should be forwarded from the
           server to the client. If the connection is successfully
           opened, :meth:`handle_open` will be called and the
           application can begin sending and receiving data. If the
           open fails, :meth:`handle_open_error` will be called with
           information about the failure.

           :param string bind_addr:
               The address the connection was destined to
           :param integer bind_port:
               The port the connection was destined to
           :param string orig_host: (optional)
               The address the connection was originated from
           :param integer orig_port: (optional)
               The port the connection was originated from

        """

        bind_addr = bind_addr.encode('utf-8')
        orig_host = orig_host.encode('utf-8')

        self._open(b'forwarded-tcpip', String(bind_addr), UInt32(bind_port),
                   String(orig_host), UInt32(orig_port))

    def connect(self, dest_host, dest_port, orig_host='', orig_port=0):
        """Open an outgoing direct TCP/IP connection

           This method can be called by a client to request that the
           server open a new outbound TCP connection to the specified
           destination. If the connection is successfully opened,
           :meth:`handle_open` will be called and the application can
           begin sending and receiving data. If the open fails,
           :meth:`handle_open_error` will be called with information
           about the failure.

           :param string dest_host:
               The address the client wishes to connect to
           :param integer dest_port:
               The port the client wishes to connect to
           :param string orig_host: (optional)
               The address the connection was originated from
           :param integer orig_port: (optional)
               The port the connection was originated from

        """

        dest_host = dest_host.encode('utf-8')
        orig_host = orig_host.encode('utf-8')

        self._open(b'direct-tcpip', String(dest_host), UInt32(dest_port),
                   String(orig_host), UInt32(orig_port))
