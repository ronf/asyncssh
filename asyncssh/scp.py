# Copyright (c) 2017 by Ron Frederick <ronf@timeheart.net>.
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
#     Jonathan Slenders - proposed changes to allow SFTP server callbacks
#                         to be coroutines

"""SCP handlers"""

import argparse
import asyncio
import posixpath
import shlex
import stat

from .constants import DEFAULT_LANG
from .constants import FX_BAD_MESSAGE, FX_CONNECTION_LOST, FX_FAILURE

from .misc import plural

from .sftp import LocalFile, match_glob
from .sftp import SFTP_BLOCK_SIZE, SFTPAttrs, SFTPError, SFTPServerFile


def _parse_cd_args(args):
    """Parse arguments to an SCP copy or dir request"""

    try:
        permissions, size, name = args.split()
        return int(permissions, 8), int(size), name
    except ValueError:
        raise SCPError(FX_BAD_MESSAGE, 'Invalid copy or dir request') from None


def _parse_t_args(args):
    """Parse argument to an SCP time request"""

    try:
        mtime, _, atime, _ = args.split()
        return int(atime), int(mtime)
    except ValueError:
        raise SCPError(FX_BAD_MESSAGE, 'Invalid time request') from None


@asyncio.coroutine
def _parse_path(path):
    """Convert an SCP path into an SSHClientConnection and path"""

    from . import connect

    if isinstance(path, tuple):
        conn, path = path
    elif isinstance(path, str) and ':' in path:
        conn, path = path.split(':')
    elif isinstance(path, bytes) and b':' in path:
        conn, path = path.split(b':')
    elif isinstance(path, (str, bytes)):
        conn = None
    else:
        conn = path
        path = b'.'

    if isinstance(conn, (str, bytes)):
        close_conn = True
        conn = yield from connect(conn)
    elif isinstance(conn, tuple):
        close_conn = True
        conn = yield from connect(*conn)
    else:
        close_conn = False

    return conn, path, close_conn


@asyncio.coroutine
def _start_remote(conn, source, must_be_dir, preserve, recurse, path):
    """Start remote SCP server"""

    if isinstance(path, str):
        path = path.encode('utf-8')

    command = (b'scp ' + (b'-f ' if source else b'-t ') +
               (b'-d ' if must_be_dir else b'') +
               (b'-p ' if preserve else b'') +
               (b'-r ' if recurse else b'') + path)

    conn.logger.get_child('sftp').info('Starting remote SCP, args: %s',
                                       command[4:])

    writer, reader, _ = yield from conn.open_session(command, encoding=None)

    return reader, writer


class SCPError(SFTPError):
    """SCP error"""

    def __init__(self, code, reason, path=None, fatal=False,
                 suppress_send=False, lang=DEFAULT_LANG):
        if isinstance(reason, bytes):
            reason = reason.decode('utf-8', errors='replace')

        if isinstance(path, bytes):
            path = path.decode('utf-8', errors='replace')

        if path:
            reason = reason + ': ' + path

        super().__init__(code, reason, lang)
        self.fatal = fatal
        self.suppress_send = suppress_send


class _SCPArgParser(argparse.ArgumentParser):
    """A parser for SCP arguments"""

    def __init__(self):
        super().__init__(add_help=False)

        group = self.add_mutually_exclusive_group(required=True)
        group.add_argument('-f', dest='source', action='store_true')
        group.add_argument('-t', dest='source', action='store_false')

        self.add_argument('-d', dest='must_be_dir', action='store_true')
        self.add_argument('-p', dest='preserve', action='store_true')
        self.add_argument('-r', dest='recurse', action='store_true')
        self.add_argument('-v', dest='verbose', action='store_true')

        self.add_argument('path')

    def error(self, message):
        raise ValueError(message)

    def parse(self, command):
        """Parse an SCP command"""

        return self.parse_args(shlex.split(command)[1:])


class _SCPHandler:
    """SCP handler"""

    def __init__(self, reader, writer, error_handler=None):
        self._reader = reader
        self._writer = writer
        self._error_handler = error_handler

        self._logger = reader.logger.get_child('sftp')

    @property
    def logger(self):
        """A logger associated with this SCP handler"""

        return self._logger

    @asyncio.coroutine
    def await_response(self):
        """Wait for an SCP response"""

        result = yield from self._reader.read(1)

        if result != b'\0':
            reason = yield from self._reader.readline()

            if not result or not reason.endswith(b'\n'):
                raise SCPError(FX_CONNECTION_LOST, 'Connection lost',
                               fatal=True, suppress_send=True)

            if result not in b'\x01\x02':
                reason = result + reason

            return SCPError(FX_FAILURE, reason[:-1], fatal=result != b'\x01',
                            suppress_send=True)

        self.logger.debug1('Received SCP OK')

        return None

    def send_request(self, *args):
        """Send an SCP request"""

        request = b''.join(args)

        self.logger.debug1('Sending SCP request: %s', request)

        self._writer.write(request + b'\n')

    @asyncio.coroutine
    def make_request(self, *args):
        """Send an SCP request and wait for a response"""

        self.send_request(*args)

        exc = yield from self.await_response()

        if exc:
            raise exc

    @asyncio.coroutine
    def send_data(self, data):
        """Send SCP file data"""

        self.logger.debug1('Sending %s', plural(len(data), 'SCP data byte'))

        self._writer.write(data)
        yield from self._writer.drain()

    def send_ok(self):
        """Send an SCP OK response"""

        self.logger.debug1('Sending SCP OK')

        self._writer.write(b'\0')

    def send_error(self, exc):
        """Send an SCP error response"""

        if isinstance(exc, SFTPError):
            reason = exc.reason.encode('utf-8')
        elif isinstance(exc, OSError): # pragma: no branch (win32)
            reason = exc.strerror.encode('utf-8')

            if exc.filename:
                if isinstance(exc.filename, str): # pragma: no cover (win32)
                    exc.filename = exc.filename.encode('utf-8')

                reason += b': ' + exc.filename
        else: # pragma: no cover (win32)
            reason = str(exc).encode('utf-8')

        fatal = getattr(exc, 'fatal', False)

        self.logger.debug1('Sending SCP %serror: %s',
                           'fatal ' if fatal else '', reason)

        self._writer.write((b'\x02' if fatal else b'\x01') +
                           b'scp: ' + reason + b'\n')

    @asyncio.coroutine
    def recv_request(self):
        """Receive SCP request"""

        request = yield from self._reader.readline()

        if not request:
            return None, None

        action, args = request[:1], request[1:-1]

        if action not in b'\x01\x02':
            self.logger.debug1('Received SCP request: %s%s', action, args)
        else:
            self.logger.debug1('Received SCP %serror: %s',
                               'fatal ' if action != b'\x01'  else '', args)

        return action, args


    @asyncio.coroutine
    def recv_data(self, n):
        """Receive SCP file data"""

        data = (yield from self._reader.read(n))

        self.logger.debug1('Received %s', plural(len(data), 'SCP data byte'))

        return data

    def handle_error(self, exc):
        """Handle an SCP error"""

        if isinstance(exc, BrokenPipeError):
            exc = SCPError(FX_CONNECTION_LOST, 'Connection lost',
                           fatal=True, suppress_send=True)

        if not getattr(exc, 'suppress_send', False):
            self.send_error(exc)

        self.logger.debug1('Handling SCP error: %s', exc)

        if getattr(exc, 'fatal', False) or self._error_handler is None:
            raise exc from None
        elif self._error_handler:
            self._error_handler(exc)

    @asyncio.coroutine
    def close(self):
        """Close an SCP session"""

        self.logger.info('Stopping remote SCP')
        self._writer.close()
        yield from self._writer.channel.wait_closed()


class _SCPSource(_SCPHandler):
    """SCP handler for sending files"""

    def __init__(self, fs, reader, writer, preserve, recurse,
                 block_size=SFTP_BLOCK_SIZE, progress_handler=None,
                 error_handler=None):
        super().__init__(reader, writer, error_handler)

        self._fs = fs
        self._preserve = preserve
        self._recurse = recurse
        self._block_size = block_size
        self._progress_handler = progress_handler

    @asyncio.coroutine
    def _make_cd_request(self, action, attrs, size, path):
        """Make an SCP copy or dir request"""

        args = '%04o %d ' % (attrs.permissions & 0o7777, size)
        yield from self.make_request(action, args.encode('ascii'),
                                     posixpath.basename(path))

    @asyncio.coroutine
    def _make_t_request(self, attrs):
        """Make an SCP time request"""

        self.logger.info('    Preserving attrs: %s',
                         SFTPAttrs(atime=attrs.atime, mtime=attrs.mtime))

        args = '%d 0 %d 0' % (attrs.mtime, attrs.atime)
        yield from self.make_request(b'T', args.encode('ascii'))

    @asyncio.coroutine
    def _send_file(self, srcpath, dstpath, attrs):
        """Send a file over SCP"""

        file_obj = yield from self._fs.open(srcpath, 'rb')
        size = attrs.size
        local_exc = None
        offset = 0

        self.logger.info('  Sending file %s, size %d', srcpath, size)

        try:
            yield from self._make_cd_request(b'C', attrs, size, srcpath)

            while offset < size:
                blocklen = min(size - offset, self._block_size)

                if local_exc:
                    data = blocklen * b'\0'
                else:
                    try:
                        data = yield from file_obj.read(blocklen, offset)

                        if not data:
                            raise SCPError(FX_FAILURE, 'Unexpected EOF')
                    except (OSError, SFTPError) as exc:
                        local_exc = exc

                yield from self.send_data(data)
                offset += len(data)

                if self._progress_handler:
                    self._progress_handler(srcpath, dstpath, offset, size)
        finally:
            yield from file_obj.close()

        if local_exc:
            self.send_error(local_exc)
            local_exc.suppress_send = True
        else:
            self.send_ok()

        remote_exc = yield from self.await_response()
        exc = remote_exc or local_exc

        if exc:
            raise exc

    @asyncio.coroutine
    def _send_dir(self, srcpath, dstpath, attrs):
        """Send directory over SCP"""

        self.logger.info('  Starting send of directory %s', srcpath)

        yield from self._make_cd_request(b'D', attrs, 0, srcpath)

        for name in (yield from self._fs.listdir(srcpath)):
            if name in (b'.', b'..'):
                continue

            yield from self._send_files(posixpath.join(srcpath, name),
                                        posixpath.join(dstpath, name))

        yield from self.make_request(b'E')

        self.logger.info('  Finished send of directory %s', srcpath)

    @asyncio.coroutine
    def _send_files(self, srcpath, dstpath):
        """Send files via SCP"""

        try:
            attrs = yield from self._fs.stat(srcpath)

            if self._preserve:
                yield from self._make_t_request(attrs)

            if self._recurse and stat.S_ISDIR(attrs.permissions):
                yield from self._send_dir(srcpath, dstpath, attrs)
            elif stat.S_ISREG(attrs.permissions):
                yield from self._send_file(srcpath, dstpath, attrs)
            else:
                raise SCPError(FX_FAILURE, 'Not a regular file', srcpath)
        except (OSError, SFTPError, ValueError) as exc:
            self.handle_error(exc)

    @asyncio.coroutine
    def run(self, srcpath):
        """Start SCP transfer"""

        try:
            if isinstance(srcpath, str):
                srcpath = srcpath.encode('utf-8')

            exc = yield from self.await_response()

            if exc:
                raise exc

            for path in (yield from match_glob(self._fs, srcpath)):
                yield from self._send_files(path, b'')
        except (OSError, SFTPError) as exc:
            self.handle_error(exc)
        finally:
            yield from self.close()


class _SCPSink(_SCPHandler):
    """SCP handler for receiving files"""

    def __init__(self, fs, reader, writer, must_be_dir, preserve, recurse,
                 block_size=SFTP_BLOCK_SIZE, progress_handler=None,
                 error_handler=None):
        super().__init__(reader, writer, error_handler)

        self._fs = fs
        self._must_be_dir = must_be_dir
        self._preserve = preserve
        self._recurse = recurse
        self._block_size = block_size
        self._progress_handler = progress_handler

    @asyncio.coroutine
    def _recv_file(self, srcpath, dstpath, size):
        """Receive a file via SCP"""

        file_obj = yield from self._fs.open(dstpath, 'wb')
        local_exc = None
        offset = 0

        self.logger.info('  Receiving file %s, size %d', dstpath, size)

        try:
            self.send_ok()

            while offset < size:
                blocklen = min(size - offset, self._block_size)
                data = yield from self.recv_data(blocklen)

                if not data:
                    raise SCPError(FX_CONNECTION_LOST, 'Connection lost',
                                   fatal=True, suppress_send=True)

                if not local_exc:
                    try:
                        yield from file_obj.write(data, offset)
                    except (OSError, SFTPError) as exc:
                        local_exc = exc

                offset += len(data)

                if self._progress_handler:
                    self._progress_handler(srcpath, dstpath, offset, size)
        finally:
            yield from file_obj.close()

        remote_exc = yield from self.await_response()

        if local_exc:
            self.send_error(local_exc)
            local_exc.suppress_send = True
        else:
            self.send_ok()

        exc = remote_exc or local_exc

        if exc:
            raise exc

    @asyncio.coroutine
    def _recv_dir(self, srcpath, dstpath):
        """Receive a directory over SCP"""

        if not self._recurse:
            raise SCPError(FX_BAD_MESSAGE, 'Directory received without recurse')

        self.logger.info('  Starting receive of directory %s', dstpath)

        if (yield from self._fs.exists(dstpath)):
            if not (yield from self._fs.isdir(dstpath)):
                raise SCPError(FX_FAILURE, 'Not a directory', dstpath)
        else:
            yield from self._fs.mkdir(dstpath)

        yield from self._recv_files(srcpath, dstpath)

        self.logger.info('  Finished receive of directory %s', dstpath)

    @asyncio.coroutine
    def _recv_files(self, srcpath, dstpath):
        """Receive files over SCP"""

        self.send_ok()

        attrs = SFTPAttrs()

        while True:
            action, args = yield from self.recv_request()

            if not action:
                break

            try:
                if action in b'\x01\x02':
                    raise SCPError(FX_FAILURE, args, fatal=action != b'\x01',
                                   suppress_send=True)
                elif action == b'T':
                    if self._preserve:
                        attrs.atime, attrs.mtime = _parse_t_args(args)

                    self.send_ok()
                elif action == b'E':
                    self.send_ok()
                elif action in b'CD':
                    try:
                        attrs.permissions, size, name = _parse_cd_args(args)

                        new_srcpath = posixpath.join(srcpath, name)

                        if (yield from self._fs.isdir(dstpath)):
                            new_dstpath = posixpath.join(dstpath, name)
                        else:
                            new_dstpath = dstpath

                        if action == b'D':
                            yield from self._recv_dir(new_srcpath, new_dstpath)
                        else:
                            yield from self._recv_file(new_srcpath,
                                                       new_dstpath, size)

                        if self._preserve:
                            self.logger.info('    Preserving attrs: %s', attrs)
                            yield from self._fs.setstat(new_dstpath, attrs)
                    finally:
                        attrs = SFTPAttrs()
                else:
                    raise SCPError(FX_BAD_MESSAGE, 'Unknown request')
            except (OSError, SFTPError) as exc:
                self.handle_error(exc)

    @asyncio.coroutine
    def run(self, dstpath):
        """Start SCP file receive"""

        try:
            if isinstance(dstpath, str):
                dstpath = dstpath.encode('utf-8')

            if self._must_be_dir and not (yield from self._fs.isdir(dstpath)):
                self.handle_error(SCPError(FX_FAILURE, 'Not a directory',
                                           dstpath))
            else:
                yield from self._recv_files(b'', dstpath)
        except (OSError, SFTPError, ValueError) as exc:
            self.handle_error(exc)
        finally:
            yield from self.close()


class _SCPCopier:
    """SCP handler for remote-to-remote copies"""

    def __init__(self, src_reader, src_writer, dst_reader, dst_writer,
                 block_size=SFTP_BLOCK_SIZE, progress_handler=None,
                 error_handler=None):
        self._source = _SCPHandler(src_reader, src_writer)
        self._sink = _SCPHandler(dst_reader, dst_writer)
        self._logger = self._source.logger
        self._block_size = block_size
        self._progress_handler = progress_handler
        self._error_handler = error_handler

    @property
    def logger(self):
        """A logger associated with this SCP handler"""

        return self._logger

    def _handle_error(self, exc):
        """Handle an SCP error"""

        if isinstance(exc, BrokenPipeError):
            exc = SCPError(FX_CONNECTION_LOST, 'Connection lost', fatal=True)

        self.logger.debug1('Handling SCP error: %s', exc)

        if self._error_handler and not getattr(exc, 'fatal', False):
            self._error_handler(exc)
        else:
            raise exc

    @asyncio.coroutine
    def _forward_response(self, src, dst):
        """Forward an SCP response between two remote SCP servers"""

        # pylint: disable=no-self-use

        try:
            exc = yield from src.await_response()

            if exc:
                dst.send_error(exc)
                return exc
            else:
                dst.send_ok()
                return None
        except OSError as exc:
            return exc

    @asyncio.coroutine
    def _copy_file(self, path, size):
        """Copy a file from one remote SCP server to another"""

        self.logger.info('  Copying file %s, size %d', path, size)

        offset = 0

        while offset < size:
            blocklen = min(size - offset, self._block_size)
            data = yield from self._source.recv_data(blocklen)

            if not data:
                raise SCPError(FX_CONNECTION_LOST, 'Connection lost',
                               fatal=True)

            yield from self._sink.send_data(data)
            offset += len(data)

            if self._progress_handler:
                self._progress_handler(path, path, offset, size)

        source_exc = yield from self._forward_response(self._source, self._sink)
        sink_exc = yield from self._forward_response(self._sink, self._source)

        exc = sink_exc or source_exc

        if exc:
            self._handle_error(exc)

    @asyncio.coroutine
    def _copy_files(self):
        """Copy files from one SCP server to another"""

        exc = yield from self._forward_response(self._sink, self._source)

        if exc:
            self._handle_error(exc)

        pathlist = []
        attrlist = []
        attrs = SFTPAttrs()

        while True:
            action, args = yield from self._source.recv_request()

            if not action:
                break

            self._sink.send_request(action, args)

            if action in b'\x01\x02':
                exc = SCPError(FX_FAILURE, args, fatal=action != b'\x01')
                self._handle_error(exc)
                continue

            exc = yield from self._forward_response(self._sink,
                                                    self._source)

            if exc:
                self._handle_error(exc)
                continue

            if action in b'CD':
                try:
                    attrs.permissions, size, name = _parse_cd_args(args)

                    if action == b'C':
                        path = b'/'.join(pathlist + [name])
                        yield from self._copy_file(path, size)
                        self.logger.info('    Preserving attrs: %s', attrs)
                    else:
                        pathlist.append(name)
                        attrlist.append(attrs)
                        self.logger.info('  Starting copy of directory %s',
                                         b'/'.join(pathlist))
                finally:
                    attrs = SFTPAttrs()
            elif action == b'E':
                if pathlist:
                    self.logger.info('  Finished copy of directory %s',
                                     b'/'.join(pathlist))

                    pathlist.pop()
                    attrs = attrlist.pop()

                    self.logger.info('    Preserving attrs: %s', attrs)
                else:
                    break
            elif action == b'T':
                attrs.atime, attrs.mtime = _parse_t_args(args)
            else:
                raise SCPError(FX_BAD_MESSAGE, 'Unknown SCP action')

    @asyncio.coroutine
    def run(self):
        """Start SCP remote-to-remote transfer"""

        try:
            yield from self._copy_files()
        except (OSError, SFTPError) as exc:
            self._handle_error(exc)
        finally:
            yield from self._source.close()
            yield from self._sink.close()


@asyncio.coroutine
def scp(srcpaths, dstpath=None, *, preserve=False, recurse=False,
        block_size=SFTP_BLOCK_SIZE, progress_handler=None, error_handler=None):
    """Copy files using SCP

       This function is a coroutine which copies one or more files or
       directories using the SCP protocol. Source and destination paths
       can be `str` or `bytes` values to reference local files or can be
       a tuple of the form `(conn, path)` where `conn` is an open
       :class:`SSHClientConnection` to reference files and directories
       on a remote system.

       For convenience, a host name or tuple of the form `(host, port)`
       can be provided in place of the :class:`SSHClientConnection` to
       request that a new SSH connection be opened to a host using
       default connect arguments. A `str` or `bytes` value of the form
       `'host:path'` may also be used in place of the `(conn, path)`
       tuple to make a new connection to the requested host on the
       default SSH port.

       Either a single source path or a sequence of source paths can be
       provided, and each path can contain '*' and '?' wildcard characters
       which can be used to match multiple source files or directories.

       When copying a single file or directory, the destination path
       can be either the full path to copy data into or the path to an
       existing directory where the data should be placed. In the latter
       case, the base file name from the source path will be used as the
       destination name.

       When copying multiple files, the destination path must refer to
       a directory. If it doesn't already exist, a directory will be
       created with that name.

       If the destination path is an :class:`SSHClientConnection` without
       a path or the path provided is empty, files are copied into the
       default destination working directory.

       If preserve is `True`, the access and modification times and
       permissions of the original files and directories are set on the
       copied files. However, do to the timing of when this information
       is sent, the preserved access time will be what was set on the
       source file before the copy begins. So, the access time on the
       source file will no longer match the destination after the
       transfer completes.

       If recurse is `True` and the source path points at a directory,
       the entire subtree under that directory is copied.

       Symbolic links found on the source will have the contents of their
       target copied rather than creating a destination symbolic link.
       When using this option during a recursive copy, one needs to watch
       out for links that result in loops. SCP does not provide a
       mechanism for preserving links. If you need this, consider using
       SFTP instead.

       The block_size value controls the size of read and write operations
       issued to copy the files. It defaults to 16 KB.

       If progress_handler is specified, it will be called after each
       block of a file is successfully copied. The arguments passed to
       this handler will be the relative path of the file being copied,
       bytes copied so far, and total bytes in the file being copied. If
       multiple source paths are provided or recurse is set to `True`,
       the progress_handler will be called consecutively on each file
       being copied.

       If error_handler is specified and an error occurs during the copy,
       this handler will be called with the exception instead of it being
       raised. This is intended to primarily be used when multiple source
       paths are provided or when recurse is set to `True`, to allow
       error information to be collected without aborting the copy of the
       remaining files. The error handler can raise an exception if it
       wants the copy to completely stop. Otherwise, after an error, the
       copy will continue starting with the next file.

       :param srcpaths:
           The paths of the source files or directories to copy
       :param dstpath: (optional)
           The path of the destination file or directory to copy into
       :param preserve: (optional)
           Whether or not to preserve the original file attributes
       :param recurse: (optional)
           Whether or not to recursively copy directories
       :param block_size: (optional)
           The block size to use for file reads and writes
       :param progress_handler: (optional)
           The function to call to report copy progress
       :param error_handler: (optional)
           The function to call when an error occurs
       :type preserve: `bool`
       :type recurse: `bool`
       :type block_size: `int`
       :type progress_handler: `callable`
       :type error_handler: `callable`

       :raises: | :exc:`OSError` if a local file I/O error occurs
                | :exc:`SFTPError` if the server returns an error
                | :exc:`ValueError` if both source and destination are local

    """

    if (isinstance(srcpaths, (str, bytes)) or
            (isinstance(srcpaths, tuple) and len(srcpaths) == 2)):
        srcpaths = [srcpaths]

    must_be_dir = len(srcpaths) > 1

    dstconn, dstpath, close_dst = yield from _parse_path(dstpath)

    try:
        for srcpath in srcpaths:
            srcconn, srcpath, close_src = yield from _parse_path(srcpath)

            try:
                if srcconn and dstconn:
                    src_reader, src_writer = yield from _start_remote(
                        srcconn, True, must_be_dir, preserve, recurse, srcpath)

                    dst_reader, dst_writer = yield from _start_remote(
                        dstconn, False, must_be_dir, preserve, recurse, dstpath)

                    copier = _SCPCopier(src_reader, src_writer, dst_reader,
                                        dst_writer, block_size,
                                        progress_handler, error_handler)

                    yield from copier.run()
                elif srcconn:
                    reader, writer = yield from _start_remote(
                        srcconn, True, must_be_dir, preserve, recurse, srcpath)

                    sink = _SCPSink(LocalFile, reader, writer, must_be_dir,
                                    preserve, recurse, block_size,
                                    progress_handler, error_handler)

                    yield from sink.run(dstpath)
                elif dstconn:
                    reader, writer = yield from _start_remote(
                        dstconn, False, must_be_dir, preserve, recurse, dstpath)

                    source = _SCPSource(LocalFile, reader, writer,
                                        preserve, recurse, block_size,
                                        progress_handler, error_handler)

                    yield from source.run(srcpath)
                else:
                    raise ValueError('Local copy not supported')
            finally:
                if close_src:
                    srcconn.close()
                    yield from srcconn.wait_closed()
    finally:
        if close_dst:
            dstconn.close()
            yield from dstconn.wait_closed()


@asyncio.coroutine
def run_scp_server(sftp_server, command, stdin, stdout, stderr):
    """Return a handler for an SCP server session"""

    try:
        args = _SCPArgParser().parse(command)
    except ValueError as exc:
        stdin.logger.info('Error starting SCP server: %s', str(exc))
        stderr.write(b'scp: ' + str(exc).encode('utf-8') + b'\n')
        stderr.channel.exit(1)
        return

    stdin.logger.info('Starting SCP server, args: %s', command[4:].strip())

    fs = SFTPServerFile(sftp_server)

    if args.source:
        handler = _SCPSource(fs, stdin, stdout, args.preserve, args.recurse,
                             error_handler=False)
    else:
        handler = _SCPSink(fs, stdin, stdout, args.must_be_dir, args.preserve,
                           args.recurse, error_handler=False)

    try:
        yield from handler.run(args.path)
    finally:
        sftp_server.exit()
