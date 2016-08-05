# Copyright (c) 2016 by Ron Frederick <ronf@timeheart.net>.else:
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

"""SSH process handlers"""

import asyncio
from asyncio.subprocess import DEVNULL, PIPE, STDOUT
from collections import OrderedDict
import io
import os
import socket
import stat

from .constants import DEFAULT_LANG, DISC_PROTOCOL_ERROR, EXTENDED_DATA_STDERR
from .misc import DisconnectError, Error, Record
from .stream import SSHClientStreamSession, SSHReader, SSHWriter


class _UnicodeReader:
    """Handle buffering partial Unicode data"""

    def __init__(self, encoding):
        self._encoding = encoding
        self._partial = b''

    def decode(self, data):
        """Decode received bytes into Unicode"""

        if self._encoding:
            data = self._partial + data
            self._partial = b''

            try:
                data = data.decode(self._encoding)
            except UnicodeDecodeError as exc:
                if exc.start > 0:
                    # Avoid pylint false positive
                    # pylint: disable=invalid-slice-index
                    self._partial = data[exc.start:]
                    data = data[:exc.start].decode(self._encoding)
                elif exc.reason == 'unexpected end of data':
                    self._partial = data
                    data = ''
                else:
                    self.close()
                    raise DisconnectError(DISC_PROTOCOL_ERROR,
                                          'Unicode decode error')

        return data

    def check_partial(self):
        """Check if there's partial Unicode data left at EOF"""

        if self._partial:
            self.close()
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Unicode decode error')

    def close(self):
        """Perform necessary cleanup on error (provided by derived classes)"""


class _UnicodeWriter:
    """Handle encoding Unicode data before writing it"""

    def __init__(self, encoding):
        self._encoding = encoding

    def encode(self, data):
        """Encode Unicode bytes before writing them"""

        if self._encoding:
            data = data.encode(self._encoding)

        return data


class _FileReader(_UnicodeReader):
    """Forward data from a file"""

    def __init__(self, process, file, bufsize, datatype, encoding):
        super().__init__(encoding)

        self._process = process
        self._file = file
        self._bufsize = bufsize
        self._datatype = datatype
        self._paused = False

    def feed(self):
        """Feed file data"""

        while not self._paused:
            data = self._file.read(self._bufsize)

            if data:
                self._process.feed_data(self.decode(data), self._datatype)
            else:
                self.check_partial()
                self._process.feed_eof(self._datatype)
                break

    def pause_reading(self):
        """Pause reading from the file"""

        self._paused = True

    def resume_reading(self):
        """Resume reading from the file"""

        self._paused = False
        self.feed()

    def close(self):
        """Stop forwarding data from the file"""

        self._file.close()


class _FileWriter(_UnicodeWriter):
    """Forward data to a file"""

    def __init__(self, file, encoding):
        super().__init__(encoding)

        self._file = file

    def write(self, data):
        """Write data to the file"""

        self._file.write(self.encode(data))

    def write_eof(self):
        """Close output file when end of file is received"""

        self.close()

    def close(self):
        """Stop forwarding data to the file"""

        self._file.close()


class _PipeReader(_UnicodeReader, asyncio.Protocol):
    """Forward data from a pipe"""

    def __init__(self, process, datatype, encoding):
        super().__init__(encoding)

        self._process = process
        self._datatype = datatype
        self._transport = None

    def connection_made(self, transport):
        """Handle a newly opened pipe"""

        self._transport = transport

    def data_received(self, data):
        """Forward data from the pipe"""

        self._process.feed_data(self.decode(data), self._datatype)

    def eof_received(self):
        """Forward EOF from the pipe"""

        self.check_partial()
        self._process.feed_eof(self._datatype)

    def pause_reading(self):
        """Pause reading from the pipe"""

        self._transport.pause_reading()

    def resume_reading(self):
        """Resume reading from the pipe"""

        self._transport.resume_reading()

    def close(self):
        """Stop forwarding data from the pipe"""

        self._transport.close()


class _PipeWriter(_UnicodeWriter, asyncio.BaseProtocol):
    """Forward data to a pipe"""

    def __init__(self, process, datatype, encoding):
        super().__init__(encoding)

        self._process = process
        self._datatype = datatype
        self._transport = None

    def connection_made(self, transport):
        """Handle a newly opened pipe"""

        self._transport = transport

    def pause_writing(self):
        """Pause writing to the pipe"""

        self._process.pause_feeding(self._datatype)

    def resume_writing(self):
        """Resume writing to the pipe"""

        self._process.resume_feeding(self._datatype)

    def write(self, data):
        """Write data to the pipe"""

        self._transport.write(self.encode(data))

    def write_eof(self):
        """Write EOF to the pipe"""

        self._transport.write_eof()

    def close(self):
        """Stop forwarding data to the pipe"""

        self._transport.close()


class _ProcessReader:
    """Forward data from another SSH process"""

    def __init__(self, process, datatype):
        self._process = process
        self._datatype = datatype

    def pause_reading(self):
        """Pause reading from the other channel"""

        self._process.pause_feeding(self._datatype)

    def resume_reading(self):
        """Resume reading from the other channel"""

        self._process.resume_feeding(self._datatype)

    def close(self):
        """Stop forwarding data from the other channel"""

        self._process.clear_writer(self._datatype)


class _ProcessWriter:
    """Forward data to another SSH process"""

    def __init__(self, process, datatype):
        self._process = process
        self._datatype = datatype

    def write(self, data):
        """Write data to the other channel"""

        self._process.feed_data(data, self._datatype)

    def write_eof(self):
        """Write EOF to the other channel"""

        self._process.feed_eof(self._datatype)

    def close(self):
        """Stop forwarding data to the other channel"""

        self._process.clear_reader(self._datatype)


class _DevNullWriter:
    """Discard data"""

    def write(self, data):
        """Discard data being written"""

    def write_eof(self):
        """Ignore end of file"""

    def close(self):
        """Ignore close"""


class _StdoutWriter:
    """Forward data to an SSH process' stdout instead of stderr"""

    def __init__(self, process):
        self._process = process

    def write(self, data):
        """Pretend data was received on stdout"""

        self._process.data_received(data, None)

    def write_eof(self):
        """Ignore end of file"""

    def close(self):
        """Ignore close"""


class ProcessError(Error):
    """SSH Process error

       This exception is raised when an :class:`SSHClientProcess` exits
       with a non-zero exit status and error checking is enabled. In
       addition to the usual error code, reason, and language, it
       contains the following fields:

         ============ ======================================= ================
         Field        Description                             Type
         ============ ======================================= ================
         exit_status  The exit status returned, or -1 if an   int
                      exit signal is sent
         exit_signal  The exit signal sent (if any) in the    tuple or ``None``
                      form of a tuple containing the signal
                      name, a bool for whether a core dump
                      occurred, a message associated with the
                      signal, and the language the message
                      was in
         ============ ======================================= ================

    """

    def __init__(self, exit_status, exit_signal):
        self.exit_status = exit_status
        self.exit_signal = exit_signal

        if exit_signal:
            signal, core_dumped, msg, lang = exit_signal
            reason = 'Process exited with signal %s%s%s' % \
                (signal, ': ' + msg if msg else '',
                 ' (core dumped)' if core_dumped else '')
        else:
            reason = 'Process exited with non-zero exit status %s' % \
                exit_status
            lang = DEFAULT_LANG

        super().__init__('Process', exit_status, reason, lang)


class SSHCompletedProcess(Record):
    """Results from running an SSH process

       This object is returned by the :meth:`run <SSHClientConnection.run>`
       method on :class:`SSHClientConnection` when the requested command
       has finished running. It contains the following fields:

         ============ ======================================= ================
         Field        Description                             Type
         ============ ======================================= ================
         exit_status  The exit status returned, or -1 if an   int
                      exit signal is sent
         exit_signal  The exit signal sent (if any) in the    tuple or ``None``
                      form of a tuple containing the signal
                      name, a bool for whether a core dump
                      occurred, a message associated with the
                      signal, and the language the message
                      was in
         stdout       The output sent by the process to       str or bytes
                      stdout (if not redirected)
         stderr       The output sent by the process to       str or bytes
                      stderr (if not redirected)
         ============ ======================================= ================

    """

    __slots__ = OrderedDict((('exit_status', None), ('exit_signal', None),
                             ('stdout', None), ('stderr', None)))


class SSHClientProcess(SSHClientStreamSession):
    """SSH client process handler"""

    def __init__(self):
        super().__init__()

        self._readers = {}
        self._send_eof = {}

        self._writers = {}
        self._paused_write_streams = set()

        self._stdin = None
        self._stdout = None
        self._stderr = None

    def __enter__(self):
        """Allow SSHClientProcess to be used as a context manager"""

        return self

    def __exit__(self, *exc_info):
        """Automatically close the channel when exiting the context"""

        self.close()

    @asyncio.coroutine
    def __aenter__(self):
        """Allow SSHClientProcess to be used as an async context manager"""

        return self

    @asyncio.coroutine
    def __aexit__(self, *exc_info):
        """Wait for a full channel close when exiting the async context"""

        self.close()
        yield from self._chan.wait_closed()

    @asyncio.coroutine
    def _create_reader(self, source, bufsize, send_eof, datatype=None):
        """Create a reader to forward data to the SSH channel"""

        def pipe_factory():
            """Return a pipe read handler"""

            return _PipeReader(self, datatype, self._encoding)

        if source == PIPE:
            reader = None
        elif source == DEVNULL:
            self._chan.write_eof()
            reader = None
        elif isinstance(source, SSHReader):
            reader_process, reader_datatype = source.get_redirect_info()
            writer = _ProcessWriter(self, datatype)
            reader_process.set_writer(writer, reader_datatype)
            reader = _ProcessReader(reader_process, reader_datatype)
        else:
            if isinstance(source, str):
                file = open(source, 'rb', buffering=bufsize)
            elif isinstance(source, int):
                file = os.fdopen(source, 'rb', buffering=bufsize)
            elif isinstance(source, socket.socket):
                file = os.fdopen(source.detach(), 'rb', buffering=bufsize)
            elif hasattr(source, 'encoding'):
                # If file provided was opened in text mode, remove that wrapper
                file = source.buffer
            else:
                file = source

            mode = os.fstat(file.fileno()).st_mode

            if stat.S_ISREG(mode):
                reader = _FileReader(self, file, bufsize,
                                     datatype, self._encoding)
            else:
                _, reader = \
                    yield from self._loop.connect_read_pipe(pipe_factory, file)

        self.set_reader(reader, send_eof, datatype)

        if isinstance(reader, _FileReader):
            reader.feed()
        elif isinstance(reader, _ProcessReader):
            reader_process.feed_recv_buf(reader_datatype, writer)

    @asyncio.coroutine
    def _create_writer(self, target, bufsize, send_eof, datatype=None):
        """Create a writer to forward data from the SSH channel"""

        def pipe_factory():
            """Return a pipe write handler"""

            return _PipeWriter(self, datatype, self._encoding)

        if target == DEVNULL:
            writer = _DevNullWriter()
        elif target == PIPE:
            writer = None
        elif target == STDOUT:
            writer = _StdoutWriter(self)
        elif isinstance(target, SSHWriter):
            writer_process, writer_datatype = target.get_redirect_info()
            reader = _ProcessReader(self, datatype)
            writer_process.set_reader(reader, send_eof, writer_datatype)
            writer = _ProcessWriter(writer_process, writer_datatype)
        else:
            if isinstance(target, str):
                file = open(target, 'wb', buffering=bufsize)
            elif isinstance(target, int):
                file = os.fdopen(target, 'wb', buffering=bufsize)
            elif isinstance(target, socket.socket):
                file = os.fdopen(target.detach(), 'wb', buffering=bufsize)
            elif hasattr(target, 'encoding'):
                # If file was opened in text mode, remove that wrapper
                file = target.buffer
            else:
                file = target

            mode = os.fstat(file.fileno()).st_mode

            if stat.S_ISREG(mode):
                writer = _FileWriter(file, self._encoding)
            else:
                _, writer = \
                    yield from self._loop.connect_write_pipe(pipe_factory,
                                                             file)

        self.set_writer(writer, datatype)

        if writer:
            self.feed_recv_buf(datatype, writer)

    def _should_block_drain(self, datatype):
        """Return whether output is still being written to the channel"""

        return (datatype in self._readers or
                super()._should_block_drain(datatype))

    def _should_pause_reading(self):
        """Return whether to pause reading from the channel"""

        return self._paused_write_streams or super()._should_pause_reading()

    def _collect_output(self, datatype=None):
        """Return output from the process"""

        recv_buf = self._recv_buf[datatype]

        if recv_buf and isinstance(recv_buf[-1], Exception):
            recv_buf = recv_buf[:-1]

        buf = '' if self._encoding else b''
        return buf.join(recv_buf)

    def connection_made(self, chan):
        """Handle a newly created client process"""

        super().connection_made(chan)

        self._stdin = SSHWriter(self, chan)
        self._stdout = SSHReader(self, chan)
        self._stderr = SSHReader(self, chan, EXTENDED_DATA_STDERR)

    def connection_lost(self, exc):
        """Handle a close of the SSH channel"""

        super().connection_lost(exc)

        for reader in self._readers.values():
            reader.close()

        for writer in self._writers.values():
            writer.close()

        self._readers = {}
        self._writers = {}

    def data_received(self, data, datatype):
        """Handle incoming data from the SSH channel"""

        writer = self._writers.get(datatype)

        if writer:
            writer.write(data)
        else:
            super().data_received(data, datatype)

    def eof_received(self):
        """Handle an incoming end of file from the SSH channel"""

        for writer in list(self._writers.values()):
            writer.write_eof()

        return super().eof_received()

    def pause_writing(self):
        """Pause forwarding data to the channel"""

        super().pause_writing()

        for reader in self._readers.values():
            reader.pause_reading()

    def resume_writing(self):
        """Resume forwarding data to the channel"""

        super().resume_writing()

        for reader in list(self._readers.values()):
            reader.resume_reading()

    def feed_data(self, data, datatype):
        """Feed data to the channel"""

        self._chan.write(data, datatype)

    def feed_eof(self, datatype):
        """Feed EOF to the channel"""

        if self._send_eof[datatype]:
            self._chan.write_eof()

        self._readers[datatype].close()
        self.clear_reader(datatype)

    def feed_recv_buf(self, datatype, writer):
        """Feed current receive buffer to a newly set writer"""

        for data in self._recv_buf[datatype]:
            writer.write(data)
            self._recv_buf_len -= len(data)

        self._recv_buf[datatype].clear()

        if self._eof_received:
            writer.write_eof()

        self._maybe_resume_reading()

    def pause_feeding(self, datatype):
        """Pause feeding data from the channel"""

        self._paused_write_streams.add(datatype)
        self._maybe_pause_reading()

    def resume_feeding(self, datatype):
        """Resume feeding data from the channel"""

        self._paused_write_streams.remove(datatype)
        self._maybe_resume_reading()

    def set_reader(self, reader, send_eof, datatype):
        """Set a reader used to forward data to the channel"""

        old_reader = self._readers.get(datatype)

        if old_reader:
            old_reader.close()
            self.clear_reader(datatype)

        if reader:
            self._readers[datatype] = reader
            self._send_eof[datatype] = send_eof

            if self._write_paused:
                reader.pause_reading()

    def clear_reader(self, datatype):
        """Clear a reader forwarding data to the channel"""

        del self._readers[datatype]
        del self._send_eof[datatype]

    def set_writer(self, writer, datatype):
        """Set a writer used to forward data from the channel"""

        old_writer = self._writers.get(datatype)

        if old_writer:
            old_writer.close()
            self.clear_writer(datatype)

        if writer:
            self._writers[datatype] = writer

    def clear_writer(self, datatype):
        """Clear a writer forwarding data from the channel"""

        if datatype in self._paused_write_streams:
            self.resume_feeding(datatype)

        del self._writers[datatype]

    @property
    def exit_status(self):
        """The exit status of the process"""

        return self._chan.get_exit_status()

    @property
    def exit_signal(self):
        """Exit signal information for the process"""

        return self._chan.get_exit_signal()

    @property
    def stdin(self):
        """The :class:`SSHWriter` to use to write to stdin of the process"""

        return self._stdin

    @property
    def stdout(self):
        """The :class:`SSHReader` to use to read from stdout of the process"""

        return self._stdout

    @property
    def stderr(self):
        """The :class:`SSHReader` to use to read from stderr of the process"""

        return self._stderr

    @asyncio.coroutine
    def redirect(self, bufsize, input_, stdin, stdout, stderr):
        """Set up initial redirection for the process"""

        if input_:
            self._chan.write(input_)
            self._chan.write_eof()
        else:
            yield from self.redirect_stdin(stdin, bufsize)

        yield from self.redirect_stdout(stdout, bufsize)

        yield from self.redirect_stderr(stderr, bufsize)

    @asyncio.coroutine
    def redirect_stdin(self, source, bufsize=io.DEFAULT_BUFFER_SIZE,
                       send_eof=True):
        """Redirect standard input of the process

           This method is a coroutine which redirects data from the
           requested source to standard input of the process. The source
           can be any of the following:

               * An :class:`SSHReader` object
               * A file object open for read
               * An int file descriptor open for read
               * A connected socket object
               * A string containing the name of a file or device to open

           File sources passed in can be associated with plain files, pipes,
           sockets, or ttys.

           :param source:
               Source to feed input from
           :param int bufsize:
               Read buffer size to use when forwarding data from a file
           :param bool send_eof:
               Whether or not to send EOF to the channel when redirection
               is complete, defaulting to ``True``. If set to ``False``,
               multiple sources can be sequentially fed to the channel.
               The :meth:`drain <SSHWriter.drain>` method on :attr:`stdin`
               can be used to determine when redirection is complete.

        """

        yield from self._create_reader(source, bufsize, send_eof)

    @asyncio.coroutine
    def redirect_stdout(self, target, bufsize=io.DEFAULT_BUFFER_SIZE,
                        send_eof=True):
        """Redirect standard output of the process

           This method is a coroutine which redirects data from standard
           output of the process to the requested target. The target can
           be any of the following:

               * An :class:`SSHWriter` object
               * A file object open for write
               * An int file descriptor open for write
               * A connected socket object
               * A string containing the name of a file or device to open

           File sources passed in can be associated with plain files, pipes,
           sockets, or ttys.

           :param target:
               Target to feed output to
           :param int bufsize:
               Write buffer size to use when forwarding data to a file
           :param bool send_eof:
               Whether or not to forward EOF to the target when redirecting
               to another SSH process, defaulting to ``True``. If set to
               ``False``, multiple sources can be sequentially fed to
               the target channel. The :meth:`drain <SSHWriter.drain>`
               method on the target can be used to determine when
               redirection is complete.

        """

        yield from self._create_writer(target, bufsize, send_eof)

    @asyncio.coroutine
    def redirect_stderr(self, target, bufsize=io.DEFAULT_BUFFER_SIZE,
                        send_eof=True):
        """Redirect standard error of the process

           This method is a coroutine which redirects data from standard
           error of the process to the requested target. The target can
           be any of the following:

               * An :class:`SSHWriter` object
               * A file object open for write
               * An int file descriptor open for write
               * A connected socket object
               * A string containing the name of a file or device to open

           File sources passed in can be associated with plain files, pipes,
           sockets, or ttys.

           :param target:
               Target to feed output to
           :param int bufsize:
               Write buffer size to use when forwarding data to a file
           :param bool send_eof:
               Whether or not to forward EOF to the target when redirecting
               to another SSH process, defaulting to ``True``. If set to
               ``False``, multiple sources can be sequentially fed to
               the target channel. The :meth:`drain <SSHWriter.drain>`
               method on the target can be used to determine when
               redirection is complete.

        """

        yield from self._create_writer(target, bufsize, send_eof,
                                       EXTENDED_DATA_STDERR)

    # pylint: disable=redefined-builtin
    @asyncio.coroutine
    def communicate(self, input=None):
        """Send input to and/or collect output from the process

           This method is a coroutine which optionally provides input
           to the process and then waits for the process to exit,
           returning a tuple of the data written to stdout and stderr.

           :param input:
               Input data to feed to standard input of the process.
               Data should be a str if encoding is set, or bytes if not.
           :type input: str or bytes

           :returns: A tuple of output to stdout and stderr

        """

        self._limit = None
        self._maybe_resume_reading()

        if input:
            self._chan.write(input)
            self._chan.write_eof()

        yield from self._chan.wait_closed()

        return (self._collect_output(),
                self._collect_output(EXTENDED_DATA_STDERR))
    # pylint: enable=redefined-builtin

    def change_terminal_size(self, width, height, pixwidth=0, pixheight=0):
        """Change the terminal window size for this process

           This method changes the width and height of the terminal
           associated with this process.

           :param int width:
               The width of the terminal in characters
           :param int height:
               The height of the terminal in characters
           :param int pixwidth: (optional)
               The width of the terminal in pixels
           :param int pixheight: (optional)
               The height of the terminal in pixels

           :raises: :exc:`OSError` if the SSH channel is not open

        """

        self._chan.change_terminal_size(width, height, pixwidth, pixheight)

    def send_break(self, msec):
        """Send a break to the process

           :param int msec:
               The duration of the break in milliseconds

           :raises: :exc:`OSError` if the SSH channel is not open

        """

        self._chan.send_break(msec)

    def send_signal(self, signal):
        """Send a signal to the process

           :param str signal:
               The signal to deliver

           :raises: :exc:`OSError` if the SSH channel is not open

        """

        self._chan.send_signal(signal)

    def terminate(self):
        """Terminate the process

           :raises: :exc:`OSError` if the SSH channel is not open

        """

        self._chan.terminate()

    def kill(self):
        """Forcibly kill the process

           :raises: :exc:`OSError` if the SSH channel is not open

        """

        self._chan.kill()

    def close(self):
        """Shut down the process"""

        self._chan.close()

    @asyncio.coroutine
    def wait(self, check=False):
        """Wait for process to exit

           This method is a coroutine which waits for the process to
           exit. It returns an :class:`SSHCompletedProcess` object with
           the exit status or signal information and the output sent
           to stdout and stderr if those are redirected to pipes.

           If the check argument is set to ``True``, a non-zero exit
           status from the process with trigger the :exc:`ProcessError`
           exception to be raised.

           :param bool check:
               Whether or not to raise an error on non-zero exit status

           :returns: :class:`SSHCompletedProcess`

           :raises: :exc:`ProcessError` if check is set to ``True``
                    and the process returns a non-zero exit status

        """

        stdout_data, stderr_data = yield from self.communicate()

        if check and self.exit_status:
            raise ProcessError(self.exit_status, self.exit_signal)
        else:
            return SSHCompletedProcess(self.exit_status, self.exit_signal,
                                       stdout_data, stderr_data)
