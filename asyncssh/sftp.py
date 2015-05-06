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

"""SFTP handlers"""

import asyncio, os, posixpath, stat, time
from collections import OrderedDict
from os import SEEK_SET, SEEK_CUR, SEEK_END

from .constants import *
from .logging import *
from .misc import *
from .packet import *

_SFTP_VERSION = 3
_SFTP_BLOCK_SIZE = 8192


class _Record:
    __slots__ = ()

    def __init__(self, *args, **kwargs):
        for k, v in self.__slots__.items():
            setattr(self, k, v)

        for k, v in zip(self.__slots__, args):
            setattr(self, k, v)

        for k, v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join('%s=%r' % (k, getattr(self, k))
                                         for k in self.__slots__))


class _LocalFile:
    """A coroutine wrapper around local file I/O"""

    def __init__(self, f):
        self._file = f

    def __enter__(self):
        return self

    def __exit__(self, *excinfo):
        self._file.close()

    @classmethod
    @asyncio.coroutine
    def _compose_path(cls, *elements):
        if elements[-1:] == [None]:
            elements.pop()

        return os.path.join(*elements) if elements else '.'

    @classmethod
    @asyncio.coroutine
    def open(cls, *args):
        return cls(open(*args))

    @classmethod
    @asyncio.coroutine
    def stat(cls, path):
        st = os.stat(path)

        return SFTPAttrs(size=st.st_size, uid=st.st_uid, gid=st.st_gid,
                         permissions=st.st_mode, atime=st.st_atime,
                         mtime=st.st_mtime)

    @classmethod
    @asyncio.coroutine
    def lstat(cls, path):
        st = os.lstat(path)

        return SFTPAttrs(size=st.st_size, uid=st.st_uid, gid=st.st_gid,
                         permissions=st.st_mode, atime=st.st_atime,
                         mtime=st.st_mtime)

    @classmethod
    @asyncio.coroutine
    def setstat(self, path, attrs):
        if attrs.size is not None:
            os.truncate(path, attrs.size)

        if attrs.uid is not None and attrs.gid is not None:
            os.chown(path, attrs.uid, attrs.gid)

        if attrs.permissions is not None:
            os.chmod(path, stat.S_IMODE(attrs.permissions))

        if attrs.atime is not None and attrs.mtime is not None:
            os.utime(path, times=(attrs.atime, attrs.mtime))

    @classmethod
    @asyncio.coroutine
    def truncate(cls, path):
        os.truncate(path)

    @classmethod
    @asyncio.coroutine
    def chown(cls, path, uid, gid):
        os.chown(path, uid, gid)

    @classmethod
    @asyncio.coroutine
    def chmod(cls, path, mode):
        os.chmod(path, mode)

    @classmethod
    @asyncio.coroutine
    def utime(cls, path, times=None):
        os.utime(path, times)

    @classmethod
    @asyncio.coroutine
    def exists(cls, path):
        return os.path.exists(path)

    @classmethod
    @asyncio.coroutine
    def lexists(cls, path):
        return os.path.lexists(path)

    @classmethod
    @asyncio.coroutine
    def getatime(cls, path):
        return os.path.getatime(path)

    @classmethod
    @asyncio.coroutine
    def getmtime(cls, path):
        return os.path.getmtime(path)

    @classmethod
    @asyncio.coroutine
    def getsize(cls, path):
        return os.path.getsize(path)

    @classmethod
    @asyncio.coroutine
    def isdir(cls, path):
        return os.path.isdir(path)

    @classmethod
    @asyncio.coroutine
    def isfile(cls, path):
        return os.path.isfile(path)

    @classmethod
    @asyncio.coroutine
    def islink(cls, path):
        return os.path.islink(path)

    @classmethod
    @asyncio.coroutine
    def remove(cls, path):
        os.remove(path)

    @classmethod
    @asyncio.coroutine
    def unlink(cls, path):
        os.unlink(path)

    @classmethod
    @asyncio.coroutine
    def rename(cls, oldpath, newpath):
        os.rename(oldpath, newpath)

    @classmethod
    @asyncio.coroutine
    def readdir(cls, path):
        names = os.listdir(path)

        return [SFTPName(filename=name, attrs=(yield from cls.stat(name)))
                    for name in names]

    @classmethod
    @asyncio.coroutine
    def listdir(cls, path):
        return os.listdir(path)

    @classmethod
    @asyncio.coroutine
    def mkdir(cls, path):
        os.mkdir(path)

    @classmethod
    @asyncio.coroutine
    def rmdir(cls, path):
        os.rmdir(path)

    @classmethod
    @asyncio.coroutine
    def realpath(cls, path):
        return os.realpath(path)

    @classmethod
    @asyncio.coroutine
    def getcwd(cls):
        return os.getcwd()

    @classmethod
    @asyncio.coroutine
    def chdir(cls, path):
        os.chdir(path)

    @classmethod
    @asyncio.coroutine
    def readlink(cls, path):
        return os.readlink(path)

    @classmethod
    @asyncio.coroutine
    def symlink(cls, srcpath, dstpath):
        os.symlink(srcpath, dstpath)

    @asyncio.coroutine
    def read(self, size=-1, offset=None):
        if offset is not None:
            self._file.seek(offset)

        return self._file.read(size)

    @asyncio.coroutine
    def write(self, data, offset=None):
        if offset is not None:
            self._file.seek(offset)

        return self._file.write(data)

    @asyncio.coroutine
    def seek(self, offset, from_what=SEEK_SET):
        return self._file.seek(offset, from_what)

    @asyncio.coroutine
    def tell(self):
        return self._file.tell()

    @asyncio.coroutine
    def close(self):
        self._file.close()


class SFTPError(Error):
    """SFTP error

       This exception is raised when an error occurs while processing
       an SFTP request. Exception codes should be taken from
       :ref:`SFTP error codes <SFTPErrorCodes>`.

       :param integer code:
           Disconnect reason, taken from :ref:`disconnect reason
           codes <DisconnectReasons>`
       :param string reason:
           A human-readable reason for the disconnect
       :param string lang:
           The language the reason is in

    """

    def __str__(self):
        return 'SFTP Error: %s' % self.reason


class SFTPAttrs(_Record):
    """SFTP file attributes
    
       SFTPAttrs is a simple record class with the following fields:

         ============ =========================================== ======
         Field        Description                                 Type
         ============ =========================================== ======
         size         File size in bytes                          uint64
         uid          User id of file owner                       uint32
         gid          Group id of file owner                      uint32
         permissions  Bit mask of POSIX file permissions,         uint32
         atime        Last access time, UNIX epoch seconds        uint32
         mtime        Last modification time, UNIX epoch seconds  uint32
         ============ =========================================== ======

       Extended attributes can also be added via a field named
       ``extended`` which is a list of string name/value pairs.

       When setting attributes using an :class:`SFTPAttrs`, only fields
       which have been initialized will be changed on the selected file.

    """

    __slots__ = OrderedDict((('size', None), ('uid', None), ('gid', None),
                             ('permissions', None), ('atime', None),
                             ('mtime', None), ('extended', [])))

    def encode(self):
        """Encode SFTP attributes as bytes in an SSH packet"""
        flags = 0
        attrs = []

        if self.size is not None:
            flags |= FILEXFER_ATTR_SIZE
            attrs.append(UInt64(self.size))

        if self.uid is not None and self.gid is not None:
            flags |= FILEXFER_ATTR_UIDGID
            attrs.append(UInt32(self.uid) + UInt32(self.gid))

        if self.permissions is not None:
            flags |= FILEXFER_ATTR_PERMISSIONS
            attrs.append(UInt32(self.permissions))

        if self.atime is not None and self.mtime is not None:
            flags |= FILEXFER_ATTR_ACMODTIME
            attrs.append(UInt32(int(self.atime)) + UInt32(int(self.mtime)))

        if self.extended:
            flags |= FILEXFER_ATTR_EXTENDED
            attrs.append(UInt32(len(self.extended)))
            attrs.extend(String(type) + String(data)
                    for type, data in self.extended)

        return UInt32(flags) + b''.join(attrs)

    @classmethod
    def decode(cls, packet):
        """Decode bytes in an SSH packet as SFTP attributes"""

        flags = packet.get_uint32()
        attrs = cls()

        if flags & FILEXFER_ATTR_UNDEFINED:
            raise SFTPError(FX_BAD_MESSAGE, 'Unsupported attribute flags')

        if flags & FILEXFER_ATTR_SIZE:
            attrs.size = packet.get_uint64()

        if flags & FILEXFER_ATTR_UIDGID:
            attrs.uid = packet.get_uint32()
            attrs.gid = packet.get_uint32()

        if flags & FILEXFER_ATTR_PERMISSIONS:
            attrs.permissions = packet.get_uint32()

        if flags & FILEXFER_ATTR_ACMODTIME:
            attrs.atime = packet.get_uint32()
            attrs.mtime = packet.get_uint32()

        if flags & FILEXFER_ATTR_EXTENDED:
            count = packet.get_uint32()
            attrs.extended = []

            for i in range(count):
                type = packet.get_string()
                data = packet.get_string()
                attrs.extended.append((type, data))

        return attrs


class SFTPName(_Record):
    """SFTP file name and attributes
    
       SFTPName is a simple record class with the following fields:

         ========= ================================== ==================
         Field     Description                        Type
         ========= ================================== ==================
         filename  Filename                           string or bytes
         longname  Expanded form of filename & attrs  string or bytes
         attrs     File attributes                    :class:`SFTPAttrs`
         ========= ================================== ==================

       A list of these is returned by :meth:`readdir() <SFTPClient.readdir>`
       in :class:`SFTPClient` when retrieving the contents of a directory.

    """

    __slots__ = OrderedDict((('filename', ''), ('longname', ''),
                             ('attrs', SFTPAttrs())))


    def encode(self):
        return String(self.filename) + String(self.longname) + \
               self.attrs.encode()

    @classmethod
    def decode(cls, packet):
        filename = packet.get_string()
        longname = packet.get_string()
        attrs = SFTPAttrs.decode(packet)

        return cls(filename, longname, attrs)

    def decode_paths(self, encoding, errors):
        """Convert filename and longname to Unicode strings"""

        try:
            self.filename = self.filename.decode(encoding, errors)
            self.longname = self.longname.decode(encoding, errors)
        except UnicodeDecodeError:
            raise SFTPError(FX_BAD_MESSAGE, 'Unable to decode name')


class SFTPSession:
    """SFTP session handler"""

    # SFTP implementations with broken order for SYMLINK arguments
    _nonstandard_symlink_impls = ['OpenSSH', 'paramiko']

    # Return types by message -- unlisted entries always return FXP_STATUS,
    #                            those below return FXP_STATUS on error
    _return_types = {
        FXP_OPEN:       FXP_HANDLE,
        FXP_READ:       FXP_DATA,
        FXP_LSTAT:      FXP_ATTRS,
        FXP_FSTAT:      FXP_ATTRS,
        FXP_OPENDIR:    FXP_HANDLE,
        FXP_READDIR:    FXP_NAME,
        FXP_REALPATH:   FXP_NAME,
        FXP_STAT:       FXP_ATTRS,
        FXP_READLINK:   FXP_NAME
    }

    def __init__(self, loop):
        self._loop = loop
        self._chan = None
        self._inpbuf = b''
        self._pktlen = 0
        self._recv_handler = self._recv_pkthdr

    def _recv_pkthdr(self):
        if len(self._inpbuf) < 4:
            return False

        self._pktlen = int.from_bytes(self._inpbuf[:4], 'big')
        self._inpbuf = self._inpbuf[4:]

        self._recv_handler = self._recv_packet
        return True

    def _recv_packet(self):
        if len(self._inpbuf) < self._pktlen:
            return False

        packet = SSHPacket(self._inpbuf[:self._pktlen])
        self._inpbuf = self._inpbuf[self._pktlen:]

        pkttype = packet.get_byte()

        if pkttype == FXP_INIT:
            self._process_init(packet)
        elif pkttype ==  FXP_VERSION:
            self._process_version(packet)
        else:
            id = packet.get_uint32()
            self._process_packet(pkttype, id, packet)

        self._recv_handler = self._recv_pkthdr
        return True

    def connection_made(self, chan):
        self._chan = chan

    def data_received(self, data, datatype):
        if data:
            self._inpbuf += data

            while self._inpbuf and self._recv_handler():
                pass

    def eof_received(self):
        self.connection_lost(None)

    def send_packet(self, pkttype, *args):
        payload = Byte(pkttype) + b''.join(args)
        self._chan.write(UInt32(len(payload)) + payload)

    def exit(self):
        if self._chan:
            self._chan.close()
            self._chan = None


class SFTPClientSession(SFTPSession):
    _extensions = []

    def __init__(self, loop, version_waiter):
        super().__init__(loop)

        self._version = None
        self._next_id = 0
        self._requests = { None: (None, version_waiter) }
        self._exc = SFTPError(FX_NO_CONNECTION, 'Connection not yet open')
        self._nonstandard_symlink = False

    def _fail(self, code, reason, lang=DEFAULT_LANG):
        self._exc = SFTPError(code, reason, lang)

        for return_type, waiter in self._requests.values():
            if not waiter.cancelled():
                waiter.set_exception(self._exc)

        self._requests = {}
        self.exit()

    def _send_request(self, pkttype, *args, waiter=None):
        if self._exc:
            raise self._exc

        id = self._next_id
        self._next_id = (self._next_id + 1) & 0xffffffff

        return_type = self._return_types.get(pkttype)
        self._requests[id] = (return_type, waiter)
        self.send_packet(pkttype, UInt32(id), *args)

    @asyncio.coroutine
    def _make_request(self, pkttype, *args):
        waiter = asyncio.Future(loop=self._loop)
        self._send_request(pkttype, *args, waiter=waiter)
        return (yield from waiter)

    def connection_made(self, chan):
        super().connection_made(chan)
        self._exc = None

    def connection_lost(self, exc):
        reason = exc.reason if exc else 'Connection closed'
        self._fail(FX_CONNECTION_LOST, reason)

    def session_started(self):
        extensions = (String(name) + String(data)
                          for name, data in self._extensions)

        self.send_packet(FXP_INIT, UInt32(_SFTP_VERSION), *extensions)

    def _process_init(self, packet):
        self._fail(FX_OP_UNSUPPORTED, 'FXP_INIT not expected on client')

    def _process_version(self, packet):
        try:
            version = packet.get_uint32()
            extensions = []

            while packet:
                name = packet.get_string()
                data = packet.get_string()
                extensions.append((name, data))
        except DisconnectError as exc:
            self._fail(FX_BAD_MESSAGE, exc.reason)
            return

        if version != _SFTP_VERSION:
            self._fail(FX_BAD_MESSAGE, 'Unsupported version: %d' % version)
            return

        try:
            _, version_waiter = self._requests.pop(None)
        except KeyError:
            self._fail(FX_BAD_MESSAGE, 'FXP_VERSION already received')
            return

        self._version = version

        # TODO: Process extensions

        if version == 3:
            # Check if the server has a buggy SYMLINK implementation

            server_version = self._chan.get_extra_info('server_version', '')
            if any(name in server_version
                       for name in self._nonstandard_symlink_impls):
                self._nonstandard_symlink = True

        if not version_waiter.cancelled():
            version_waiter.set_result(None)

    def _process_packet(self, pkttype, id, packet):
        try:
            return_type, waiter = self._requests.pop(id)
        except KeyError:
            self._fail(FX_BAD_MESSAGE, 'Invalid response id')
            return

        if pkttype not in (FXP_STATUS, return_type):
            self._fail(FX_BAD_MESSAGE,
                       'Unexpected response type: %s' % ord(pkttype))
            return

        if waiter and not waiter.cancelled():
            try:
                result = self._packet_handlers[pkttype](self, packet)

                if result is None and return_type is not None:
                    self._fail(FX_BAD_MESSAGE, 'Unexpected FX_OK response')
                    return

                waiter.set_result(result)
            except DisconnectError as exc:
                exc = SFTPError(FX_BAD_MESSAGE, exc.reason, exc.lang)
                waiter.set_exception(exc)
            except SFTPError as exc:
                waiter.set_exception(exc)

    def _process_status(self, packet):
        code = packet.get_uint32()

        try:
            reason = packet.get_string().decode('utf-8')
            lang = packet.get_string().decode('ascii')
        except UnicodeDecodeError:
            raise SFTPError(FX_BAD_MESSAGE, 'Invalid status message')

        packet.check_end()

        if code == FX_OK:
            return None
        else:
            raise SFTPError(code, reason, lang)

    def _process_handle(self, packet):
        handle = packet.get_string()
        packet.check_end()
        return handle

    def _process_data(self, packet):
        data = packet.get_string()
        packet.check_end()
        return data

    def _process_name(self, packet):
        count = packet.get_uint32()
        names = [SFTPName.decode(packet) for i in range(count)]
        packet.check_end()
        return names

    def _process_attrs(self, packet):
        attrs = SFTPAttrs().decode(packet)
        packet.check_end()
        return attrs

    def _process_extended_reply(self, packet):
        # TODO
        pass

    _packet_handlers = {
        FXP_STATUS:         _process_status,
        FXP_HANDLE:         _process_handle,
        FXP_DATA:           _process_data,
        FXP_NAME:           _process_name,
        FXP_ATTRS:          _process_attrs,
        FXP_EXTENDED_REPLY: _process_extended_reply
    }

    def open(self, filename, pflags, attrs):
        return self._make_request(FXP_OPEN, String(filename),
                                  UInt32(pflags), attrs.encode())

    def close(self, handle):
        return self._make_request(FXP_CLOSE, String(handle))

    def nonblocking_close(self, handle):
        # Used by context managers, since they can't block to wait for a reply
        self._send_request(FXP_CLOSE, String(handle))

    def read(self, handle, offset, length):
        return self._make_request(FXP_READ, String(handle),
                                  UInt64(offset), UInt32(length))

    def write(self, handle, offset, data):
        return self._make_request(FXP_WRITE, String(handle),
                                  UInt64(offset), String(data))

    def stat(self, path):
        return self._make_request(FXP_STAT, String(path))

    def lstat(self, path):
        return self._make_request(FXP_LSTAT, String(path))

    def fstat(self, handle):
        return self._make_request(FXP_FSTAT, String(handle))

    def setstat(self, path, attrs):
        return self._make_request(FXP_SETSTAT, String(path), attrs.encode())

    def fsetstat(self, handle, attrs):
        return self._make_request(FXP_FSETSTAT, String(handle), attrs.encode())

    def remove(self, path):
        return self._make_request(FXP_REMOVE, String(path))

    def rename(self, oldpath, newpath):
        return self._make_request(FXP_RENAME, String(oldpath), String(newpath))

    def opendir(self, path):
        return self._make_request(FXP_OPENDIR, String(path))

    def readdir(self, handle):
        return self._make_request(FXP_READDIR, String(handle))

    def mkdir(self, path, attrs):
        return self._make_request(FXP_MKDIR, String(path), attrs.encode())

    def rmdir(self, path):
        return self._make_request(FXP_RMDIR, String(path))

    def realpath(self, path):
        return self._make_request(FXP_REALPATH, String(path))

    def readlink(self, path):
        return self._make_request(FXP_READLINK, String(path))

    def symlink(self, srcpath, dstpath):
        if self._nonstandard_symlink:
            args = String(srcpath) + String(dstpath)
        else:
            args = String(dstpath) + String(srcpath)

        return self._make_request(FXP_SYMLINK, args)


class SFTPFile:
    """Remote SFTP file object

       This class represents an open file on a remote SFTP server. It
       is opened with the :meth:`open() <SFTPClient.open>` method on the
       :class:`SFTPClient` class and provides methods to read and write
       data and get and set attributes on the open file.

    """

    def __init__(self, session, handle, appending, encoding, errors):
        self._session = session
        self._handle = handle
        self._appending = appending
        self._encoding = encoding
        self._errors = errors
        self._offset = None if appending else 0

    def __enter__(self):
        """Allow SFTPFile to be used as a context manager"""

        return self

    def __exit__(self, *exc_info):
        """Automatically close the file when used as a context manager"""

        if self._handle:
            self._session.nonblocking_close(self._handle)
            self._handle = None

    @asyncio.coroutine
    def _end(self):
        attrs = yield from self.stat()
        return attrs.size

    @asyncio.coroutine
    def read(self, size=-1, offset=None):
        """Read data from the remote file

           This method reads and returns up to ``size`` bytes of data
           from the remote file. If size is negative, all data up to
           the end of the file is returned.

           If offset is specified, the read will be performed starting
           at that offset rather than the current file position. This
           argument should be provided if you want to issue parallel
           reads on the same file, since the file position is not
           predictable in that case.

           Data will be returned as a string if an encoding was set when
           the file was opened. Otherwise, data is returned as bytes.

           An empty string or bytes object is returned when at EOF.

           :param integer size:
               The number of bytes to read
           :param integer offset: (optional)
               The offset from the beginning of the file to begin reading

           :returns: data read from the file, as a string or bytes

           :raises: | :exc:`ValueError` if the file has been closed
                    | :exc:`UnicodeDecodeError` if the data can't be
                      decoded using the requested encoding
                    | :exc:`SFTPError` if the server returns an error

        """

        if self._handle is None:
            raise ValueError('I/O operation on closed file')

        if offset is None:
            offset = self._offset

        if offset is None:
            # We're appending and haven't seeked backward in the file
            # since the last write, so there's no data to return
            data = b''
        elif size is None or size < 0:
            data = []

            try:
                while True:
                    result = yield from self._session.read(self._handle, offset,
                                                           _SFTP_BLOCK_SIZE)
                    data.append(result)
                    offset += len(result)
                    self._offset = offset
            except SFTPError as exc:
                if exc.code != FX_EOF:
                    raise

            data = b''.join(data)
        else:
            data = b''

            try:
                data = yield from self._session.read(self._handle, offset, size)
                self._offset = offset + len(data)
            except SFTPError as exc:
                if exc.code != FX_EOF:
                    raise

        if self._encoding:
            data = data.decode(self._encoding, self._errors)

        return data

    @asyncio.coroutine
    def write(self, data, offset=None):
        """Write data to the remote file

           This method writes the specified data at the current
           position in the remote file.

           :param data:
               The data to write to the file
           :param integer offset: (optional)
               The offset from the beginning of the file to begin writing
           :type data: string or bytes

           If offset is specified, the write will be performed starting
           at that offset rather than the current file position. This
           argument should be provided if you want to issue parallel
           writes on the same file, since the file position is not
           predictable in that case.

           :returns: number of bytes written

           :raises: | :exc:`ValueError` if the file has been closed
                    | :exc:`UnicodeEncodeError` if the data can't be
                      encoded using the requested encoding
                    | :exc:`SFTPError` if the server returns an error

        """

        if self._handle is None:
            raise ValueError('I/O operation on closed file')

        if offset is None:
            # Offset is ignored when appending, so fill in an offset of 0
            # if we don't have a current file position
            offset = self._offset or 0

        if self._encoding:
            data = data.encode(self._encoding, self._errors)

        yield from self._session.write(self._handle, offset, data)
        self._offset = None if self._appending else offset + len(data)
        return len(data)

    @asyncio.coroutine
    def seek(self, offset, from_what=SEEK_SET):
        """Seek to a new position in the remote file

           This method changes the position in the remote file. The
           ``offset`` passed in is treated as relative to the beginning
           of the file if ``from_what`` is set to ``SEEK_SET`` (the
           default), relative to the current file position if it is
           set to ``SEEK_CUR``, or relative to the end of the file
           if it is set to ``SEEK_END``.

           :param integer offset:
               The amount to seek
           :param integer from_what: (optional)
               The reference point to use (SEEK_SET, SEEK_CUR, or SEEK_END)

           :returns: The new byte offset from the beginning of the file

        """

        if from_what == SEEK_SET:
            self._offset = offset
        elif from_what == SEEK_CUR:
            self._offset += offset
        elif from_what == SEEK_END:
            self._offset = (yield from self._end()) + offset

        return self._offset

    @asyncio.coroutine
    def tell(self):
        """Return the current position in the remote file

           This method returns the current position in the remote file.

           :returns: The current byte offset from the beginning of the file

        """

        if self._offset is None:
            self._offset = yield from self._end()

        return self._offset

    @asyncio.coroutine
    def stat(self):
        """Return file attributes of the remote file

           This method queries file attributes of the currently open file.

           :returns: An :class:`SFTPAttrs` containing the file attributes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        if self._handle is None:
            raise ValueError('I/O operation on closed file')

        return (yield from self._session.fstat(self._handle))

    @asyncio.coroutine
    def setstat(self, attrs):
        """Change attributes of the remote file

           This method sets file attributes of the currently open file.

           :param attrs:
               File attributes to set on the file
           :type attrs: :class:`SFTPAttrs`

           :raises: :exc:`SFTPError` if the server returns an error

        """

        yield from self._session.fsetstat(self._handle, attrs)

    @asyncio.coroutine
    def truncate(self, size=None):
        """Truncate the remote file to the specified size
        
           This method changes the remote file's size to the specified
           value. If a size is not provided, the current file position
           is used.

           :param integer size: (optional)
               The desired size of the file, in bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        if size is None:
            size = self._offset

        yield from self.setstat(SFTPAttrs(size=size))

    @asyncio.coroutine
    def chown(self, uid, gid):
        """Change the owner user and group id of the remote file

           This method changes the user and group id of the
           currently open file.

           :param integer uid:
               The new user id to assign to the file
           :param integer gid:
               The new group id to assign to the file

           :raises: :exc:`SFTPError` if the server returns an error

        """

        yield from self.setstat(SFTPAttrs(uid=uid, gid=gid))

    @asyncio.coroutine
    def chmod(self, mode):
        """Change the file permissions of the remote file

           This method changes the permissions of the currently
           open file.

           :param integer mode:
               The new file permissions, expressed as an integer

           :raises: :exc:`SFTPError` if the server returns an error

        """

        yield from self.setstat(SFTPAttrs(permissions=mode))

    @asyncio.coroutine
    def utime(self, times=None):
        """Change the access and modify times of the remote file

           This method changes the access and modify times of the
           currently open file. If ``times`` is not provided,
           the times will be changed to the current time.

           :param times: (optional)
               The new access and modify times, as seconds relative to
               the UNIX epoch
           :type times: tuple of two integer or float values

           :raises: :exc:`SFTPError` if the server returns an error

        """

        if times is None:
            atime = mtime = time.time()
        else:
            atime, mtime = times

        yield from self.setstat(SFTPAttrs(atime=atime, mtime=mtime))

    @asyncio.coroutine
    def close(self):
        """Close the remote file"""

        if self._handle:
            yield from self._session.close(self._handle)
            self._handle = None


class SFTPClient:
    """SFTP client

       This class represents the client side of an SFTP session. It is
       started by calling the :meth:`start_sftp_client()
       <SSHClientConnection.start_sftp_client>` method on the
       :class:`SSHClientConnection` class.
    
    """

    _open_modes = {
        'r':  FXF_READ,
        'w':  FXF_WRITE | FXF_CREAT | FXF_TRUNC,
        'a':  FXF_WRITE | FXF_CREAT | FXF_APPEND,
        'x':  FXF_WRITE | FXF_CREAT | FXF_EXCL,

        'r+': FXF_READ | FXF_WRITE,
        'w+': FXF_READ | FXF_WRITE | FXF_CREAT | FXF_TRUNC,
        'a+': FXF_READ | FXF_WRITE | FXF_CREAT | FXF_APPEND,
        'x+': FXF_READ | FXF_WRITE | FXF_CREAT | FXF_EXCL
    }

    def __init__(self, session, path_encoding, path_errors):
        self._session = session
        self._path_encoding = path_encoding
        self._path_errors = path_errors
        self._cwd = None

    def __enter__(self):
        """Allow SFTPClient to be used as a context manager"""

        return self

    def __exit__(self, *exc_info):
        """Automatically close the session when used as a context manager"""

        self.exit()

    @asyncio.coroutine
    def _compose_path(self, *elements):
        """Compose a path relative to the current remote working directory"""

        if self._cwd is not None:
            elements.insert(0, self._cwd)

        # TODO: Do path composition on the server for SFTP version >= 6
        #       For now, use posixpath so separator is always '/' regardless
        #       of the local host OS.

        if elements[-1:] == [None]:
            elements.pop()

        return posixpath.join(*elements) if elements else '.'

    @asyncio.coroutine
    def _mode(self, path, statfunc=None):
        """Return the mode of a remote path, or 0 if it can't be accessed"""

        if statfunc is None:
            statfunc = self.stat

        try:
            return (yield from statfunc(path)).permissions
        except SFTPError as exc:
            if exc.code in (FX_NO_SUCH_FILE, FX_PERMISSION_DENIED):
                return 0
            else:
                raise

    @asyncio.coroutine
    def _copy(self, srcfs, dstfs, srcpath, dstpath, preserve,
              recurse, follow_symlinks, error_handler):
        """Copy a file, directory, or symbolic link"""

        print(srcpath, dstpath)
        if follow_symlinks:
            srcattrs = yield from srcfs.stat(srcpath)
        else:
            srcattrs = yield from srcfs.lstat(srcpath)

        try:
            if stat.S_ISDIR(srcattrs.permissions):
                if not recurse:
                    raise SFTPError(FX_FAILURE, '%s is a directory' % srcpath)

                if not (yield from dstfs.isdir(dstpath)):
                    yield from dstfs.mkdir(dstpath)

                names = yield from srcfs.listdir(srcpath)

                for name in names:
                    if name in ('.', '..'):
                        continue

                    srcfile = yield from srcfs._compose_path(srcpath, name)
                    dstfile = yield from dstfs._compose_path(dstpath, name)

                    yield from self._copy(srcfs, dstfs, srcfile,
                                          dstfile, preserve, recurse,
                                          follow_symlinks, error_handler)
            elif stat.S_ISLNK(srcattrs.permissions):
                targetpath = yield from srcfs.readlink(srcpath)
                yield from dstfs.symlink(targetpath, dstpath)
            else:
                with (yield from srcfs.open(srcpath, 'rb')) as src:
                    with (yield from dstfs.open(dstpath, 'wb')) as dst:
                        while True:
                            data = yield from src.read(_SFTP_BLOCK_SIZE)
                            if not data:
                                break

                            yield from dst.write(data)

            if preserve:
                yield from dstfs.setstat(dstpath,
                    SFTPAttrs(permissions=srcattrs.permissions,
                              atime=srcattrs.atime, mtime=srcattrs.mtime))
        except (OSError, SFTPError) as exc:
            exc.srcpath = srcpath
            exc.dstpath = dstpath

            if error_handler:
                error_handler(exc)
            else:
                raise

    @asyncio.coroutine
    def _begin_copy(self, srcfs, dstfs, srcpaths, dstpath, preserve,
                    recurse, follow_symlinks, error_handler):
        """Kick off a new file upload, download, or copy"""

        dst_isdir = dstpath is None or (yield from dstfs.isdir(dstpath))

        if isinstance(srcpaths, (str, bytes)):
            srcpaths = [srcpaths]
        elif not dst_isdir:
            raise SFTPError(FX_FAILURE, '%s must be a directory' % dstpath)

        for srcfile in srcpaths:
            filename = posixpath.basename(srcfile)

            if dstpath is None:
                dstfile = filename
            elif dst_isdir:
                dstfile = yield from dstfs._compose_path(dstpath, filename)
            else:
                dstfile = dstpath

            yield from self._copy(srcfs, dstfs, srcfile, dstfile, preserve,
                                  recurse, follow_symlinks, error_handler)

    @asyncio.coroutine
    def get(self, remotepaths, localpath=None, *, preserve=False,
            recurse=False, follow_symlinks=False, error_handler=None):
        """Download remote files

           This method downloads one or more files or directories from
           the remote system. Either a single remote path or a sequence
           of remote paths to download can be provided.

           When downloading a single file or directory, the local path can
           be either the full path to download data into or the path to an
           existing directory where the data should be placed. In the
           latter case, the base file name from the remote path will be
           used as the local name.

           When downloading multiple files, the local path must refer to
           an existing directory.

           If no local path is provided, the file is downloaded
           into the current local working directory.

           If preserve is ``True``, the access and modification times
           and permissions of the original file are set on the
           downloaded file.

           If recurse is ``True`` and the remote path points at a
           directory, the entire subtree under that directory is
           downloaded.

           If follow_symlinks is set to ``True``, symbolic links found
           on the remote system will have the contents of their target
           downloaded rather than creating a local symbolic link. When
           using this option during a recursive download, one needs to
           watch out for links that result in loops.

           If error_handler is specified and an error occurs during
           the download, the error_handler will be called with the
           exception instead of it being raised. This is intended to
           primarily be used when recurse is set to ``True``, to allow
           error information to be collected without aborting the
           download of the other files in the tree. The error handler
           can raise an exception if it wants the download to stop.
           Otherwise, after an error, the download will continue
           starting with the next file.

           :param remotepaths:
               The paths of the remote files or directories to download
           :param string localpath: (optional)
               The path of the local file or directory to download into
           :param bool preserve: (optional)
               Whether or not to preserve the original file attributes
           :param bool recurse: (optional)
               Whether or not to recursively copy directories
           :param bool follow_symlinks: (optional)
               Whether or not to follow symbolic links
           :param callable error_handler: (optional)
               The function to call when an error occurs
           :type remotepaths: string or bytes, or a sequence of these

           :raises: | :exc:`OSError` if a local file I/O error occurs
                    | :exc:`SFTPError` if the server returns an error

        """

        yield from self._begin_copy(self, _LocalFile, remotepaths, localpath,
                                    preserve, recurse, follow_symlinks,
                                    error_handler)

    @asyncio.coroutine
    def put(self, localpaths, remotepath=None, *, preserve=False,
            recurse=False, follow_symlinks=False, error_handler=None):
        """Upload local files

           This method uploads one or more files or directories to the
           remote system. Either a single local path or a sequence of
           local paths to upload can be provided.

           When uploading a single file or directory, the remote path can
           be either the full path to upload data into or the path to an
           existing directory where the data should be placed. In the
           latter case, the base file name from the local path will be
           used as the remote name.

           When uploading multiple files, the remote path must refer to
           an existing directory.

           If no remote path is provided, the file is uploaded into the
           current remote working directory.

           If preserve is ``True``, the access and modification times
           and permissions of the original file are set on the
           uploaded file.

           If recurse is ``True`` and the local path points at a
           directory, the entire subtree under that directory is
           uploaded.

           If follow_symlinks is set to ``True``, symbolic links found
           on the local system will have the contents of their target
           uploaded rather than creating a remote symbolic link. When
           using this option during a recursive upload, one needs to
           watch out for links that result in loops.

           If error_handler is specified and an error occurs during
           the upload, the error_handler will be called with the
           exception instead of it being raised. This is intended to
           primarily be used when recurse is set to ``True``, to allow
           error information to be collected without aborting the upload
           of other files in the tree. The error handler can raise an
           exception if it wants the upload to stop. Otherwise, after an
           error, the upload will continue starting with the next file.

           :param localpaths:
               The paths of the local files or directories to upload
           :param remotepath: (optional)
               The path of the remote file or directory to upload into
           :param bool preserve: (optional)
               Whether or not to preserve the original file attributes
           :param bool recurse: (optional)
               Whether or not to recursively copy directories
           :param bool follow_symlinks: (optional)
               Whether or not to follow symbolic links
           :param callable error_handler: (optional)
               The function to call when an error occurs
           :type localpaths: string or bytes, or a sequence of these
           :type remotepath: string or bytes

           :raises: | :exc:`OSError` if a local file I/O error occurs
                    | :exc:`SFTPError` if the server returns an error

        """

        yield from self._begin_copy(_LocalFile, self, localpaths, remotepath,
                                    preserve, recurse, follow_symlinks,
                                    error_handler)

    @asyncio.coroutine
    def copy(self, srcpaths, dstpath=None, *, preserve=False,
             recurse=False, follow_symlinks=False, error_handler=None):
        """Copy remote files to a new location

           This method copies one or more files or directories on the
           remote system to a new location. Either a single source path
           or a sequence of source paths to copy can be provided.

           When copying a single file or directory, the destination path
           can be either the full path to copy data into or the path to
           an existing directory where the data should be placed. In the
           latter case, the base file name from the source path will be
           used as the destination name.

           When copying multiple files, the destination path must refer
           to an existing remote directory.

           If no destination path is provided, the file is copied into
           the current remote working directory.

           If preserve is ``True``, the access and modification times
           and permissions of the original file are set on the
           copied file.

           If recurse is ``True`` and the source path points at a
           directory, the entire subtree under that directory is
           copied.

           If follow_symlinks is set to ``True``, symbolic links found
           in the source will have the contents of their target copied
           rather than creating a copy of the symbolic link. When
           using this option during a recursive copy, one needs to
           watch out for links that result in loops.

           If error_handler is specified and an error occurs during
           the copy, the error_handler will be called with the
           exception instead of it being raised. This is intended to
           primarily be used when recurse is set to ``True``, to allow
           error information to be collected without aborting the copy
           of other files in the tree. The error handler can raise an
           exception if it wants the copy to stop. Otherwise, after an
           error, the copy will continue starting with the next file.

           :param srcpaths:
               The paths of the remote files or directories to copy
           :param dstpath: (optional)
               The path of the remote file or directory to copy into
           :param bool preserve: (optional)
               Whether or not to preserve the original file attributes
           :param bool recurse: (optional)
               Whether or not to recursively copy directories
           :param bool follow_symlinks: (optional)
               Whether or not to follow symbolic links
           :param callable error_handler: (optional)
               The function to call when an error occurs
           :type srcpaths: string or bytes, or a sequence of these
           :type dstpath: string or bytes

           :raises: | :exc:`OSError` if a local file I/O error occurs
                    | :exc:`SFTPError` if the server returns an error

        """

        yield from self._begin_copy(self, self, srcpaths, dstpath, preserve,
                                    recurse, follow_symlinks, error_handler)

    @asyncio.coroutine
    def open(self, path, mode='r', attrs=SFTPAttrs(),
             encoding='utf-8', errors='strict'):
        """Open a remote file

           This method opens a remote file and returns an :class:`SFTPFile`
           object which can be used to read and write data and get and set
           file attributes.

           The path can be either a string or bytes value. If it is a
           string, it will be encoded using the file encoding specified
           when the :class:`SFTPClient` was started.

           The following open modes are supported:

             ==== ===========
             Mode Description
             ==== ===========
             r    Open existing file for reading
             w    Open file for overwrite, creating or truncating it
             a    Open file for appending, creating it if necessary
             x    Open new file for writing, failing if it exists

             r+   Open existing file for reading & writing
             w+   Open file for reading & writing, creating or truncating it
             a+   Open file for reading & appending, creating it if necessary
             x+   Open new file for reading & writing, failing if it exists
             ==== ===========

           If a 'b' is present in the mode, file data will be read and
           written in binary format, as bytes. Otherwise, file data
           will be read and written as strings. By default, UTF-8 encoding
           will be used with strict error checking, but this can be changed
           using the ``encoding`` and ``errors`` parameters.

           The attrs argument is used to set initial attributes of the
           file if it needs to be created. Otherwise, this argument is
           ignored.

           :param path:
               The name of the remote file to open
           :param string mode: (optional)
               The access mode to use for the remote file (see above)
           :param attrs: (optional)
               File attributes to use if the file needs to be created
           :param string encoding: (optional)
               The Unicode encoding to use for data read and written
               to the remote file
           :param string errors: (optional)
               The error-handling mode if an invalid Unicode byte
               sequence is detected, defaulting to 'strict' which
               raises an exception
           :type path: string or bytes
           :type attrs: :class:`SFTPAttrs`

           :returns: An :class:`SFTPFile` to use to access the file

           :raises: | :exc:`ValueError` if the mode is not valid
                    | :exc:`SFTPError` if the server returns an error

        """

        if 'b' in mode:
            mode = mode.replace('b', '')
            encoding = None

        pflags = self._open_modes.get(mode)
        if not pflags:
            raise ValueError('Invalid mode: %r' % mode)

        path = yield from self._compose_path(path)
        handle = yield from self._session.open(path, pflags, attrs)

        return SFTPFile(self._session, handle, pflags & FXF_APPEND,
                        encoding, errors)

    @asyncio.coroutine
    def stat(self, path):
        """Get attributes of a remote file or directory, following symlinks
        
           This method queries the attributes of a remote file or
           directory. If the path provided is a symbolic link, the
           returned attributes will correspond to the target of the
           link.

           :param path:
               The path of the remote file or directory to get attributes for
           :type path: string or bytes

           :returns: An :class:`SFTPAttrs` containing the file attributes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = yield from self._compose_path(path)
        return (yield from self._session.stat(path))

    @asyncio.coroutine
    def lstat(self, path):
        """Get attributes of a remote file, directory, or symlink

           This method queries the attributes of a remote file,
           directory, or symlink. Unlike :meth:`stat`, this method
           returns the attributes of a symlink itself rather than
           the target of that link.

           :param path:
               The path of the remote file, directory, or link to get
               attributes for
           :type path: string or bytes

           :returns: An :class:`SFTPAttrs` containing the file attributes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = yield from self._compose_path(path)
        return (yield from self._session.lstat(path))

    @asyncio.coroutine
    def setstat(self, path, attrs):
        """Set attributes of a remote file or directory

           This method sets attributes of a remote file or directory.
           If the path provided is a symbolic link, the attributes
           will be set on the target of the link. A subset of the
           fields in ``attrs`` can be initialized and only those
           attributes will be changed.

           :param path:
               The path of the remote file or directory to set attributes for
           :param attrs:
               File attributes to set
           :type path: string or bytes
           :type attrs: :class:`SFTPAttrs`

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = yield from self._compose_path(path)
        yield from self._session.setstat(path, attrs)

    @asyncio.coroutine
    def truncate(self, path, size):
        """Truncate a remote file to the specified size

           This method truncates a remote file to the specified size.
           If the path provided is a symbolic link, the target of
           the link will be truncated.

           :param path:
               The path of the remote file to be truncated
           :param integer size:
               The desired size of the file, in bytes
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        yield from self.setstat(path, SFTPAttrs(size=size))

    @asyncio.coroutine
    def chown(self, path, uid, gid):
        """Change the owner user and group id of a remote file or directory

           This method changes the user and group id of a remote
           file or directory. If the path provided is a symbolic
           link, the target of the link will be changed.

           :param path:
               The path of the remote file to change
           :param integer uid:
               The new user id to assign to the file
           :param integer gid:
               The new group id to assign to the file
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        yield from self.setstat(path, SFTPAttrs(uid=uid, gid=gid))

    @asyncio.coroutine
    def chmod(self, path, mode):
        """Change the file permissions of a remote file or directory

           This method changes the permissions of a remote file or
           directory. If the path provided is a symbolic link, the
           target of the link will be changed.

           :param path:
               The path of the remote file to change
           :param integer mode:
               The new file permissions, expressed as an integer
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        yield from self.setstat(path, SFTPAttrs(permissions=mode))

    @asyncio.coroutine
    def utime(self, path, times=None):
        """Change the access and modify times of a remote file or directory

           This method changes the access and modify times of a
           remote file or directory. If ``times`` is not provided,
           the times will be changed to the current time. If the
           path provided is a symbolic link, the target of the link
           will be changed.

           :param path:
               The path of the remote file to change
           :param times: (optional)
               The new access and modify times, as seconds relative to
               the UNIX epoch
           :type path: string or bytes
           :type times: tuple of two integer or float values

           :raises: :exc:`SFTPError` if the server returns an error

        """

        if times is None:
            atime = mtime = time.time()
        else:
            atime, mtime = times

        yield from self.setstat(path, SFTPAttrs(atime=atime, mtime=mtime))

    @asyncio.coroutine
    def exists(self, path):
        """Return if the remote path exists and isn't a broken symbolic link

           :param path:
               The remote path to check
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return bool((yield from self._mode(path)))

    @asyncio.coroutine
    def lexists(self, path):
        """Return if the remote path exists, without following symbolic links

           :param path:
               The remote path to check
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return bool((yield from self._mode(path, statfunc=self.lstat)))

    @asyncio.coroutine
    def getatime(self, path):
        """Return the last access time of a remote file or directory

           :param path:
               The remote path to check
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return (yield from self.stat(path)).atime

    @asyncio.coroutine
    def getmtime(self, path):
        """Return the last modification time of a remote file or directory

           :param path:
               The remote path to check
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return (yield from self.stat(path)).mtime

    @asyncio.coroutine
    def getsize(self, path):
        """Return the size of a remote file or directory

           :param path:
               The remote path to check
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return (yield from self.stat(path)).size

    @asyncio.coroutine
    def isdir(self, path):
        """Return if the remote path refers to a directory

           :param path:
               The remote path to check
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return stat.S_ISDIR((yield from self._mode(path)))

    @asyncio.coroutine
    def isfile(self, path):
        """Return if the remote path refers to a regular file

           :param path:
               The remote path to check
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return stat.S_ISREG((yield from self._mode(path)))

    @asyncio.coroutine
    def islink(self, path):
        """Return if the remote path refers to a symbolic link

           :param path:
               The remote path to check
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return stat.S_ISLNK((yield from self._mode(path, statfunc=self.lstat)))

    @asyncio.coroutine
    def remove(self, path):
        """Remove a remote file

           This method removes a remote file or link.

           :param path:
               The path of the remote file or link to remove
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = yield from self._compose_path(path)
        yield from self._session.remove(path)

    @asyncio.coroutine
    def unlink(self, path):
        """Remove a remote file (see :meth:`remove`)"""

        yield from self.remove(path)

    @asyncio.coroutine
    def rename(self, oldpath, newpath):
        """Rename a remote file, directory, or link

           This method renames a remote file, directory, or link.

           :param oldpath:
               The path of the remote file, directory, or link to rename
           :param newpath:
               The new name for this file, directory, or link
           :type oldpath: string or bytes
           :type newpath: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        oldpath = yield from self._compose_path(oldpath)
        newpath = yield from self._compose_path(newpath)
        yield from self._session.rename(oldpath, newpath)

    @asyncio.coroutine
    def readdir(self, path=None):
        """Read the contents of a remote directory

           This method reads the contents of a directory, returning
           the names and attributes of what is contained there. If no
           path is provided, it defaults to the current remote working
           directory.

           :param path: (optional)
               The path of the remote directory to read
           :type path: string or bytes

           :returns: A list of :class:`SFTPName` entries

           :raises: :exc:`SFTPError` if the server returns an error

        """

        names = []

        path = yield from self._compose_path(path)
        handle = yield from self._session.opendir(path)

        try:
            while True:
                names.extend((yield from self._session.readdir(handle)))
        except SFTPError as exc:
            if exc.code != FX_EOF:
                raise
        finally:
            yield from self._session.close(handle)

        if self._path_encoding:
            for name in names:
                name.decode_paths(self._path_encoding, self._path_errors)

        return names

    @asyncio.coroutine
    def listdir(self, path=None):
        """Read the names of the files in a remote directory

           This method reads the names of files and subdirectories
           in a remote directory. If no path is provided, it defaults
           to the current remote working directory.

           :param path: (optional)
               The path of the remote directory to read
           :type path: string or bytes

           :returns: A list of file/subdirectory names as strings or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        names = yield from self.readdir(path)
        return [name.filename for name in names]

    @asyncio.coroutine
    def mkdir(self, path, attrs=SFTPAttrs()):
        """Create a remote directory with the specified attributes

           This method creates a new remote directory at the
           specified path with requested attributes.

           :param path:
               The path of where the new remote directory should be created
           :param attrs: (optional)
               The file attributes to use when creating the directory
           :type path: string or bytes
           :type attrs: :class:`SFTPAttrs`

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = yield from self._compose_path(path)
        yield from self._session.mkdir(path, attrs)

    @asyncio.coroutine
    def rmdir(self, path):
        """Remove a remote directory

           This method removes a remote directory. The directory
           must be empty for the removal to succeed.

           :param path:
               The path of the remote directory to remove
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = yield from self._compose_path(path)
        yield from self._session.rmdir(path)

    @asyncio.coroutine
    def realpath(self, path=None):
        """Return the canonical version of a path

           This method returns a canonical version of the requested path.
           If no path is specified, the canonical version of the current
           remote working directory is returned.

           :param path: (optional)
               The path of the remote directory to canonicalize
           :type path: string or bytes

           :returns: The canonical path as a string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = yield from self._compose_path(path)
        names = yield from self._session.realpath(path)

        if len(names) > 1:
            raise SFTPError(FX_BAD_MESSAGE, 'Too many names returned')

        name = names[0]
        if self._path_encoding:
            name.decode_paths(self._path_encoding, self._path_errors)

        return name.filename

    @asyncio.coroutine
    def getcwd(self):
        """Return the current remote working directory

           :returns: The current remote working directory as a string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        if self._cwd is None:
            self._cwd = yield from self.realpath()

        return self._cwd

    @asyncio.coroutine
    def chdir(self, path):
        """Change the current remote working directory

           :param path: The path to set as the new remote working directory
           :type path: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        self._cwd = yield from self.realpath(path)

    @asyncio.coroutine
    def readlink(self, path):
        """Return the target of a symbolic link

           This method returns the target of a symbolic link.

           :param path:
               The path of the remote symbolic link to follow
           :type path: string or bytes

           :returns: The target path of the link as a string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = yield from self._compose_path(path)
        names = yield from self._session.readlink(path)

        if len(names) > 1:
            raise SFTPError(FX_BAD_MESSAGE, 'Too many names returned')

        name = names[0]
        if self._path_encoding:
            name.decode_paths(self._path_encoding, self._path_errors)

        return name.filename

    @asyncio.coroutine
    def symlink(self, srcpath, dstpath):
        """Create a symbolic link

           This method creates a symbolic link. The argument order here
           matches the standard Python :meth:`os.symlink` call. The
           argument order sent on the wire is automatically adapted
           depending on the version information sent by the server, as
           a number of servers (OpenSSH in particular) did not follow
           the SFTP standard when implementing this call.

           :param srcpath:
               The path the link should point to
           :param dstpath:
               The path of where to create the remote symbolic link
           :type srcpath: string or bytes
           :type dstpath: string or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        srcpath = yield from self._compose_path(srcpath)
        dstpath = yield from self._compose_path(dstpath)
        yield from self._session.symlink(srcpath, dstpath)

    def exit(self):
        """Exit the SFTP client session
        
           This method exists the SFTP client session, closing the
           corresponding channel opened on the server.

        """

        self._session.exit()


class SFTPServerSession(SFTPSession):
    _extensions = []

    def __init__(self, loop):
        super.__init__(loop)

        self._version = None

    def connection_lost(self, exc):
        self.exit()

    def _process_init(self, packet):
        version = packet.get_uint32()

        version = min(version, _SFTP_VERSION)
        extensions = (String(name) + String(data)
                          for name, data in self._extensions)
        self.send_packet(FXP_INIT, UInt32(version), *extensions)

    def _fail(self, code, reason, lang=DEFAULT_LANG):
        self.send_packet(Byte(FXP_STATUS), UInt32(code),
                         String(reason), String(lang))
        self.exit()

    def _process_version(self, packet):
        self._fail(FX_OP_UNSUPPORTED, 'FXP_VERSION not expected on server')

    def _process_packet(self, pkttype, id, packet):
        handler = self._packet_handlers.get(pkttype)
        if not handler:
            self._fail(FX_OP_UNSUPPORTED,
                       'Unsupported request type: %s' % ord(pkttype))
            return

        try:
            return_type = self._return_types.get(pkttype, FXP_STATUS)
            result = handler(self, packet)

            if return_type == FXP_STATUS:
                result = UInt32(FX_OK) + String('') + String('')
            elif return_type in (FXP_HANDLE, FXP_DATA):
                result = String(result)
            else:
                result = result.encode()
        except SFTPError as exc:
            return_type = FXP_STATUS
            result = UInt32(exc.code) + String(exc.reason) + String(exc.lang)

        send_packet(Byte(return_type), UInt32(id), result)


class SFTPServer:
    """SFTP server

       Coming soon!

    """

    # TODO
    pass
