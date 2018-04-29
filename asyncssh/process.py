# Copyright (c) 2016-2017 by Ron Frederick <ronf@timeheart.net>.else:
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
from pathlib import PurePath
import socket
import stat

from .constants import DEFAULT_LANG, DISC_PROTOCOL_ERROR, EXTENDED_DATA_STDERR
from .misc import DisconnectError, Error, Record
from .stream import SSHClientStreamSession, SSHServerStreamSession
from .stream import SSHReader, SSHWriter


def _is_regular_file(file):
    """Return if argument is a regular file or file-like object"""

    try:
        return stat.S_ISREG(os.fstat(file.fileno()).st_mode)
    except OSError:
        return True


class _UnicodeReader:
    """Handle buffering partial Unicode data"""

    def __init__(self, encoding, textmode=False):
        self._encoding = encoding
        self._textmode = textmode
        self._partial = b''

    def decode(self, data):
        """Decode Unicode bytes when reading from binary sources"""

        if self._encoding and not self._textmode:
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

    def __init__(self, encoding, textmode=False):
        self._encoding = encoding
        self._textmode = textmode

    def encode(self, data):
        """Encode Unicode bytes when writing to binary targets"""

        if self._encoding and not self._textmode:
            data = data.encode(self._encoding)

        return data


class _FileReader(_UnicodeReader):
    """Forward data from a file"""

    def __init__(self, process, file, bufsize, datatype, encoding):
        super().__init__(encoding, hasattr(file, 'encoding'))

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


class _AsyncFileReader(_FileReader):
    """Forward data from an aiofile"""

    def __init__(self, process, file, bufsize, datatype, encoding):
        super().__init__(process, file, bufsize, datatype, encoding)

        self._conn = process.channel.get_connection()

    @asyncio.coroutine
    def _feed(self):
        """Feed file data"""

        while not self._paused:
            data = yield from self._file.read(self._bufsize)

            if data:
                self._process.feed_data(self.decode(data), self._datatype)
            else:
                self.check_partial()
                self._process.feed_eof(self._datatype)
                break

    def feed(self):
        """Start feeding file data"""

        self._conn.create_task(self._feed())

    def close(self):
        """Stop forwarding data from the file"""

        self._conn.create_task(self._file.close())


class _FileWriter(_UnicodeWriter):
    """Forward data to a file"""

    def __init__(self, file, encoding):
        super().__init__(encoding, hasattr(file, 'encoding'))

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


class _AsyncFileWriter(_FileWriter):
    """Forward data to an aiofile"""

    def __init__(self, process, file, encoding):
        super().__init__(file, encoding)

        self._conn = process.channel.get_connection()

    def write(self, data):
        """Write data to the file"""

        self._conn.create_task(self._file.write(self.encode(data)))

    def close(self):
        """Stop forwarding data to the file"""

        self._conn.create_task(self._file.close())


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

         ============ ======================================= =================
         Field        Description                             Type
         ============ ======================================= =================
         env          The environment the client requested    `str` or `None`
                      to be set for the process
         command      The command the client requested the    `str` or `None`
                      process to execute (if any)
         subsystem    The subsystem the client requested the  `str` or `None`
                      process to open (if any)
         exit_status  The exit status returned, or -1 if an   `int`
                      exit signal is sent
         exit_signal  The exit signal sent (if any) in the    `tuple` or `None`
                      form of a tuple containing the signal
                      name, a `bool` for whether a core dump
                      occurred, a message associated with the
                      signal, and the language the message
                      was in
         stdout       The output sent by the process to       `str` or `bytes`
                      stdout (if not redirected)
         stderr       The output sent by the process to       `str` or `bytes`
                      stderr (if not redirected)
         ============ ======================================= =================

    """

    def __init__(self, env, command, subsystem, exit_status,
                 exit_signal, stdout, stderr):
        self.env = env
        self.command = command
        self.subsystem = subsystem
        self.exit_status = exit_status
        self.exit_signal = exit_signal
        self.stdout = stdout
        self.stderr = stderr

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

         ============ ======================================= =================
         Field        Description                             Type
         ============ ======================================= =================
         env          The environment the client requested    `str` or `None`
                      to be set for the process
         command      The command the client requested the    `str` or `None`
                      process to execute (if any)
         subsystem    The subsystem the client requested the  `str` or `None`
                      process to open (if any)
         exit_status  The exit status returned, or -1 if an   `int`
                      exit signal is sent
         exit_signal  The exit signal sent (if any) in the    `tuple` or `None`
                      form of a tuple containing the signal
                      name, a `bool` for whether a core dump
                      occurred, a message associated with the
                      signal, and the language the message
                      was in
         stdout       The output sent by the process to       `str` or `bytes`
                      stdout (if not redirected)
         stderr       The output sent by the process to       `str` or `bytes`
                      stderr (if not redirected)
         ============ ======================================= =================

    """

    __slots__ = OrderedDict((('env', None), ('command', None),
                             ('subsystem', None), ('exit_status', None),
                             ('exit_signal', None), ('stdout', None),
                             ('stderr', None)))


class SSHProcess:
    """SSH process handler"""

    # Pylint doesn't know that all SSHProcess instances will always be
    # subclasses of SSHStreamSession.
    # pylint: disable=no-member

    def __init__(self):
        self._readers = {}
        self._send_eof = {}

        self._writers = {}
        self._paused_write_streams = set()

        self._stdin = None
        self._stdout = None
        self._stderr = None

    def __enter__(self):
        """Allow SSHProcess to be used as a context manager"""

        return self

    def __exit__(self, *exc_info):
        """Automatically close the channel when exiting the context"""

        self.close()

    @asyncio.coroutine
    def __aenter__(self):
        """Allow SSHProcess to be used as an async context manager"""

        return self

    @asyncio.coroutine
    def __aexit__(self, *exc_info):
        """Wait for a full channel close when exiting the async context"""

        self.close()
        yield from self._chan.wait_closed()

    @property
    def channel(self):
        """The channel associated with the process"""

        return self._chan

    @property
    def logger(self):
        """The logger associated with the process"""

        return self._chan.logger

    @property
    def env(self):
        """The environment set by the client for the process

           This method returns the environment set by the client
           when the session was opened.

           :returns: A dictionary containing the environment variables
                     set by the client

        """

        return self._chan.get_environment()

    @property
    def command(self):
        """The command the client requested to execute, if any

           This method returns the command the client requested to
           execute when the process was started, if any. If the client
           did not request that a command be executed, this method
           will return `None`.

           :returns: A `str` containing the command or `None` if
                     no command was specified

        """

        return self._chan.get_command()

    @property
    def subsystem(self):
        """The subsystem the client requested to open, if any

           This method returns the subsystem the client requested to
           open when the process was started, if any. If the client
           did not request that a subsystem be opened, this method will
           return `None`.

           :returns: A `str` containing the subsystem name or `None`
                     if no subsystem was specified

        """

        return self._chan.get_subsystem()

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
            elif isinstance(source, PurePath):
                file = open(str(source), 'rb', buffering=bufsize)
            elif isinstance(source, int):
                file = os.fdopen(source, 'rb', buffering=bufsize)
            elif isinstance(source, socket.socket):
                file = os.fdopen(source.detach(), 'rb', buffering=bufsize)
            else:
                file = source

            if hasattr(file, 'read') and asyncio.iscoroutinefunction(file.read):
                reader = _AsyncFileReader(self, file, bufsize,
                                          datatype, self._encoding)
            elif _is_regular_file(file):
                reader = _FileReader(self, file, bufsize,
                                     datatype, self._encoding)
            else:
                if hasattr(source, 'buffer'):
                    # If file was opened in text mode, remove that wrapper
                    file = source.buffer

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
            elif isinstance(target, PurePath):
                file = open(str(target), 'wb', buffering=bufsize)
            elif isinstance(target, int):
                file = os.fdopen(target, 'wb', buffering=bufsize)
            elif isinstance(target, socket.socket):
                file = os.fdopen(target.detach(), 'wb', buffering=bufsize)
            else:
                file = target

            if hasattr(file, 'write') and \
                    asyncio.iscoroutinefunction(file.write):
                writer = _AsyncFileWriter(self, file, self._encoding)
            elif _is_regular_file(file):
                writer = _FileWriter(file, self._encoding)
            else:
                if hasattr(target, 'buffer'):
                    # If file was opened in text mode, remove that wrapper
                    file = target.buffer

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

        if reader:
            self._readers[datatype] = reader
            self._send_eof[datatype] = send_eof

            if self._write_paused:
                reader.pause_reading()
        elif old_reader:
            self.clear_reader(datatype)

    def clear_reader(self, datatype):
        """Clear a reader forwarding data to the channel"""

        del self._readers[datatype]
        del self._send_eof[datatype]
        self._unblock_drain(datatype)

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

    def close(self):
        """Shut down the process"""

        self._chan.close()

    @asyncio.coroutine
    def wait_closed(self):
        """Wait for the process to finish shutting down"""

        yield from self._chan.wait_closed()


class SSHClientProcess(SSHProcess, SSHClientStreamSession):
    """SSH client process handler"""

    def __init__(self):
        SSHProcess.__init__(self)
        SSHClientStreamSession.__init__(self)

    def _collect_output(self, datatype=None):
        """Return output from the process"""

        recv_buf = self._recv_buf[datatype]

        if recv_buf and isinstance(recv_buf[-1], Exception):
            recv_buf, self._recv_buf[datatype] = recv_buf[:-1], recv_buf[-1:]
        else:
            self._recv_buf[datatype] = []

        buf = '' if self._encoding else b''
        return buf.join(recv_buf)

    def session_started(self):
        """Start a process for this newly opened client channel"""

        self._stdin = SSHWriter(self, self._chan)
        self._stdout = SSHReader(self, self._chan)
        self._stderr = SSHReader(self, self._chan, EXTENDED_DATA_STDERR)

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
    def redirect(self, stdin=None, stdout=None, stderr=None,
                 bufsize=io.DEFAULT_BUFFER_SIZE, send_eof=True):
        """Perform I/O redirection for the process

           This method redirects data going to or from any or all of
           standard input, standard output, and standard error for
           the process.

           The `stdin` argument can be any of the following:

               * An :class:`SSHReader` object
               * A file object open for read
               * An `int` file descriptor open for read
               * A connected socket object
               * A string or :class:`PurePath <pathlib.PurePath>` containing
                 the name of a file or device to open
               * `DEVNULL` to provide no input to standard input
               * `PIPE` to interactively write standard input

           The `stdout` and `stderr` arguments can be any of the following:

               * An :class:`SSHWriter` object
               * A file object open for write
               * An `int` file descriptor open for write
               * A connected socket object
               * A string or :class:`PurePath <pathlib.PurePath>` containing
                 the name of a file or device to open
               * `DEVNULL` to discard standard error output
               * `PIPE` to interactively read standard error output

           The `stderr` argument also accepts the value `STDOUT` to
           request that standard error output be delivered to stdout.

           File objects passed in can be associated with plain files, pipes,
           sockets, or ttys.

           The default value of `None` means to not change redirection
           for that stream.

           :param stdin:
               Source of data to feed to standard input
           :param stdout:
               Target to feed data from standard output to
           :param stderr:
               Target to feed data from standard error to
           :param bufsize:
               Buffer size to use when forwarding data from a file
           :param send_eof:
               Whether or not to send EOF to the channel when redirection
               is complete, defaulting to `True`. If set to `False`,
               multiple sources can be sequentially fed to the channel.
           :type bufsize: `int`
           :type send_eof: `bool`

        """

        if stdin:
            yield from self._create_reader(stdin, bufsize, send_eof)

        if stdout:
            yield from self._create_writer(stdout, bufsize, send_eof)

        if stderr:
            yield from self._create_writer(stderr, bufsize, send_eof,
                                           EXTENDED_DATA_STDERR)

    @asyncio.coroutine
    def redirect_stdin(self, source, bufsize=io.DEFAULT_BUFFER_SIZE,
                       send_eof=True):
        """Redirect standard input of the process"""

        yield from self.redirect(source, None, None, bufsize, send_eof)

    @asyncio.coroutine
    def redirect_stdout(self, target, bufsize=io.DEFAULT_BUFFER_SIZE,
                        send_eof=True):
        """Redirect standard output of the process"""

        yield from self.redirect(None, target, None, bufsize, send_eof)

    @asyncio.coroutine
    def redirect_stderr(self, target, bufsize=io.DEFAULT_BUFFER_SIZE,
                        send_eof=True):
        """Redirect standard error of the process"""

        yield from self.redirect(None, None, target, bufsize, send_eof)

    def collect_output(self):
        """Collect output from the process without blocking

           This method returns a tuple of the output that the process
           has written to stdout and stderr which has not yet been read.
           It is intended to be called instead of read() by callers
           that want to collect received data without blocking.

           :returns: A tuple of output to stdout and stderr

        """

        return (self._collect_output(),
                self._collect_output(EXTENDED_DATA_STDERR))

    # pylint: disable=redefined-builtin
    @asyncio.coroutine
    def communicate(self, input=None):
        """Send input to and/or collect output from the process

           This method is a coroutine which optionally provides input
           to the process and then waits for the process to exit,
           returning a tuple of the data written to stdout and stderr.

           :param input:
               Input data to feed to standard input of the process. Data
               should be a `str` if encoding is set, or `bytes` if not.
           :type input: `str` or `bytes`

           :returns: A tuple of output to stdout and stderr

        """

        self._limit = None
        self._maybe_resume_reading()

        if input:
            self._chan.write(input)
            self._chan.write_eof()

        yield from self._chan.wait_closed()

        return self.collect_output()
    # pylint: enable=redefined-builtin

    def change_terminal_size(self, width, height, pixwidth=0, pixheight=0):
        """Change the terminal window size for this process

           This method changes the width and height of the terminal
           associated with this process.

           :param width:
               The width of the terminal in characters
           :param height:
               The height of the terminal in characters
           :param pixwidth: (optional)
               The width of the terminal in pixels
           :param pixheight: (optional)
               The height of the terminal in pixels
           :type width: `int`
           :type height: `int`
           :type pixwidth: `int`
           :type pixheight: `int`

           :raises: :exc:`OSError` if the SSH channel is not open

        """

        self._chan.change_terminal_size(width, height, pixwidth, pixheight)

    def send_break(self, msec):
        """Send a break to the process

           :param msec:
               The duration of the break in milliseconds
           :type msec: `int`

           :raises: :exc:`OSError` if the SSH channel is not open

        """

        self._chan.send_break(msec)

    def send_signal(self, signal):
        """Send a signal to the process

           :param signal:
               The signal to deliver
           :type signal: `str`

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

    @asyncio.coroutine
    def wait(self, check=False):
        """Wait for process to exit

           This method is a coroutine which waits for the process to
           exit. It returns an :class:`SSHCompletedProcess` object with
           the exit status or signal information and the output sent
           to stdout and stderr if those are redirected to pipes.

           If the check argument is set to `True`, a non-zero exit
           status from the process with trigger the :exc:`ProcessError`
           exception to be raised.

           :param check:
               Whether or not to raise an error on non-zero exit status
           :type check: `bool`

           :returns: :class:`SSHCompletedProcess`

           :raises: :exc:`ProcessError` if check is set to `True`
                    and the process returns a non-zero exit status

        """

        stdout_data, stderr_data = yield from self.communicate()

        if check and self.exit_status:
            raise ProcessError(self.env, self.command, self.subsystem,
                               self.exit_status, self.exit_signal,
                               stdout_data, stderr_data)
        else:
            return SSHCompletedProcess(self.env, self.command, self.subsystem,
                                       self.exit_status, self.exit_signal,
                                       stdout_data, stderr_data)


class SSHServerProcess(SSHProcess, SSHServerStreamSession):
    """SSH server process handler"""

    def __init__(self, process_factory, sftp_factory, allow_scp):
        SSHProcess.__init__(self)
        SSHServerStreamSession.__init__(self, self._start_process,
                                        sftp_factory, allow_scp)

        self._process_factory = process_factory

    def _start_process(self, stdin, stdout, stderr):
        """Start a new server process"""

        self._stdin = stdin
        self._stdout = stdout
        self._stderr = stderr

        return self._process_factory(self)

    @property
    def stdin(self):
        """The :class:`SSHReader` to use to read from stdin of the process"""

        return self._stdin

    @property
    def stdout(self):
        """The :class:`SSHWriter` to use to write to stdout of the process"""

        return self._stdout

    @property
    def stderr(self):
        """The :class:`SSHWriter` to use to write to stderr of the process"""

        return self._stderr

    @asyncio.coroutine
    def redirect(self, stdin=None, stdout=None, stderr=None,
                 bufsize=io.DEFAULT_BUFFER_SIZE, send_eof=True):
        """Perform I/O redirection for the process

           This method redirects data going to or from any or all of
           standard input, standard output, and standard error for
           the process.

           The `stdin` argument can be any of the following:

               * An :class:`SSHWriter` object
               * A file object open for write
               * An `int` file descriptor open for write
               * A connected socket object
               * A string or :class:`PurePath <pathlib.PurePath>` containing
                 the name of a file or device to open
               * `DEVNULL` to discard standard error output
               * `PIPE` to interactively read standard error output

           The `stdout` and `stderr` arguments can be any of the following:

               * An :class:`SSHReader` object
               * A file object open for read
               * An `int` file descriptor open for read
               * A connected socket object
               * A string or :class:`PurePath <pathlib.PurePath>` containing
                 the name of a file or device to open
               * `DEVNULL` to provide no input to standard input
               * `PIPE` to interactively write standard input

           File objects passed in can be associated with plain files, pipes,
           sockets, or ttys.

           The default value of `None` means to not change redirection
           for that stream.

           :param stdin:
               Target to feed data from standard input to
           :param stdout:
               Source of data to feed to standard output
           :param stderr:
               Source of data to feed to standard error
           :param bufsize:
               Buffer size to use when forwarding data from a file
           :param send_eof:
               Whether or not to send EOF to the channel when redirection
               is complete, defaulting to `True`. If set to `False`,
               multiple sources can be sequentially fed to the channel.
           :type bufsize: `int`
           :type send_eof: `bool`

        """

        if stdin:
            yield from self._create_writer(stdin, bufsize, send_eof)

        if stdout:
            yield from self._create_reader(stdout, bufsize, send_eof)

        if stderr:
            yield from self._create_reader(stderr, bufsize, send_eof,
                                           EXTENDED_DATA_STDERR)

    @asyncio.coroutine
    def redirect_stdin(self, target, bufsize=io.DEFAULT_BUFFER_SIZE,
                       send_eof=True):
        """Redirect standard input of the process"""

        yield from self.redirect(target, None, None, bufsize, send_eof)

    @asyncio.coroutine
    def redirect_stdout(self, source, bufsize=io.DEFAULT_BUFFER_SIZE,
                        send_eof=True):
        """Redirect standard output of the process"""

        yield from self.redirect(None, source, None, bufsize, send_eof)

    @asyncio.coroutine
    def redirect_stderr(self, source, bufsize=io.DEFAULT_BUFFER_SIZE,
                        send_eof=True):
        """Redirect standard error of the process"""

        yield from self.redirect(None, None, source, bufsize, send_eof)

    def get_environment(self):
        """Return the environment set by the client (deprecated)"""

        return self.env # pragma: no cover

    def get_command(self):
        """Return the command the client requested to execute (deprecated)"""

        return self.command # pragma: no cover

    def get_subsystem(self):
        """Return the subsystem the client requested to open (deprecated)"""

        return self.subsystem # pragma: no cover

    def get_terminal_type(self):
        """Return the terminal type set by the client for the process

           This method returns the terminal type set by the client
           when the process was started. If the client didn't request
           a pseudo-terminal, this method will return `None`.

           :returns: A `str` containing the terminal type or `None` if
                     no pseudo-terminal was requested

        """

        return self._chan.get_terminal_type()

    def get_terminal_size(self):
        """Return the terminal size set by the client for the process

           This method returns the latest terminal size information set
           by the client. If the client didn't set any terminal size
           information, all values returned will be zero.

           :returns: A tuple of four `int` values containing the width and
                     height of the terminal in characters and the width
                     and height of the terminal in pixels

        """

        return self._chan.get_terminal_size()

    def get_terminal_mode(self, mode):
        """Return the requested TTY mode for this session

           This method looks up the value of a POSIX terminal mode
           set by the client when the process was started. If the client
           didn't request a pseudo-terminal or didn't set the requested
           TTY mode opcode, this method will return `None`.

           :param mode:
               POSIX terminal mode taken from :ref:`POSIX terminal modes
               <PTYModes>` to look up
           :type mode: `int`

           :returns: An `int` containing the value of the requested
                     POSIX terminal mode or `None` if the requested
                     mode was not set

        """

        return self._chan.get_terminal_mode(mode)

    def exit(self, status):
        """Send exit status and close the channel

           This method can be called to report an exit status for the
           process back to the client and close the channel.

           :param status:
               The exit status to report to the client
           :type status: `int`

        """

        self._chan.exit(status)

    def exit_with_signal(self, signal, core_dumped=False,
                         msg='', lang=DEFAULT_LANG):
        """Send exit signal and close the channel

           This method can be called to report that the process
           terminated abnormslly with a signal. A more detailed
           error message may also provided, along with an indication
           of whether or not the process dumped core. After
           reporting the signal, the channel is closed.

           :param signal:
               The signal which caused the process to exit
           :param core_dumped: (optional)
               Whether or not the process dumped core
           :param msg: (optional)
               Details about what error occurred
           :param lang: (optional)
               The language the error message is in
           :type signal: `str`
           :type core_dumped: `bool`
           :type msg: `str`
           :type lang: `str`

        """

        return self._chan.exit_with_signal(signal, core_dumped, msg, lang)
