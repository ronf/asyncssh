# Copyright (c) 2015-2016 by Ron Frederick <ronf@timeheart.net>.
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

"""SFTP handlers"""

import asyncio
from collections import OrderedDict
import errno
from fnmatch import fnmatch
import os
from os import SEEK_SET, SEEK_CUR, SEEK_END
import posixpath
import stat
import time

from .constants import DEFAULT_LANG

from .constants import FXP_INIT, FXP_VERSION, FXP_OPEN, FXP_CLOSE, FXP_READ
from .constants import FXP_WRITE, FXP_LSTAT, FXP_FSTAT, FXP_SETSTAT
from .constants import FXP_FSETSTAT, FXP_OPENDIR, FXP_READDIR, FXP_REMOVE
from .constants import FXP_MKDIR, FXP_RMDIR, FXP_REALPATH, FXP_STAT, FXP_RENAME
from .constants import FXP_READLINK, FXP_SYMLINK, FXP_STATUS, FXP_HANDLE
from .constants import FXP_DATA, FXP_NAME, FXP_ATTRS, FXP_EXTENDED
from .constants import FXP_EXTENDED_REPLY

from .constants import FXF_READ, FXF_WRITE, FXF_APPEND
from .constants import FXF_CREAT, FXF_TRUNC, FXF_EXCL

from .constants import FILEXFER_ATTR_SIZE, FILEXFER_ATTR_UIDGID
from .constants import FILEXFER_ATTR_PERMISSIONS, FILEXFER_ATTR_ACMODTIME
from .constants import FILEXFER_ATTR_EXTENDED, FILEXFER_ATTR_UNDEFINED

from .constants import FX_OK, FX_EOF, FX_NO_SUCH_FILE, FX_PERMISSION_DENIED
from .constants import FX_FAILURE, FX_BAD_MESSAGE, FX_NO_CONNECTION
from .constants import FX_CONNECTION_LOST, FX_OP_UNSUPPORTED

from .misc import async_context_manager, Error, Record

from .packet import Byte, String, UInt32, UInt64, PacketDecodeError, SSHPacket

_SFTP_VERSION = 3
_SFTP_BLOCK_SIZE = 16384
_MAX_SFTP_REQUESTS = 128


def _get_user_name(uid):
    """Return the user name associated with a uid"""

    if uid is not None:
        try:
            import pwd
            user = pwd.getpwuid(uid).pw_name
        except (ImportError, KeyError):
            user = str(uid)
    else:
        user = ''

    return user


def _get_group_name(gid):
    """Return the group name associated with a gid"""

    if gid is not None:
        try:
            import grp
            group = grp.getgrgid(gid).gr_name
        except (ImportError, KeyError):
            group = str(gid)
    else:
        group = ''

    return group


def _setstat(path, attrs):
    """Utility function to set file attributes"""

    if attrs.size is not None:
        os.truncate(path, attrs.size)

    if attrs.uid is not None and attrs.gid is not None:
        os.chown(path, attrs.uid, attrs.gid)

    if attrs.permissions is not None:
        os.chmod(path, stat.S_IMODE(attrs.permissions))

    if attrs.atime is not None and attrs.mtime is not None:
        os.utime(path, times=(attrs.atime, attrs.mtime))


class _LocalFile:
    """A coroutine wrapper around local file I/O"""

    def __init__(self, f):
        self._file = f

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._file.close()

    @classmethod
    def encode(cls, path):
        """Encode path name using filesystem native encoding

           This method has no effect if the path is already bytes.

        """

        return os.fsencode(path)

    @classmethod
    def decode(cls, path, want_string=True):
        """Decode path name using filesystem native encoding

           This method has no effect if want_string is set to ``False``.

        """

        if want_string:
            path = os.fsdecode(path)

        return path

    @classmethod
    def compose_path(cls, path, parent=None):
        """Compose a path

           If parent is not specified, just encode the path.

        """

        path = cls.encode(path)

        return os.path.join(parent, path) if parent else path

    @classmethod
    @asyncio.coroutine
    def open(cls, *args):
        """Open a local file"""

        return cls(open(*args))

    @classmethod
    @asyncio.coroutine
    def stat(cls, path):
        """Get attributes of a local file or directory, following symlinks"""

        return SFTPAttrs.from_local(os.stat(path))

    @classmethod
    @asyncio.coroutine
    def lstat(cls, path):
        """Get attributes of a local file, directory, or symlink"""

        return SFTPAttrs.from_local(os.lstat(path))

    @classmethod
    @asyncio.coroutine
    def setstat(cls, path, attrs):
        """Set attributes of a local file or directory"""

        _setstat(path, attrs)

    @classmethod
    @asyncio.coroutine
    def isdir(cls, path):
        """Return if the local path refers to a directory"""

        return os.path.isdir(path)

    @classmethod
    @asyncio.coroutine
    def listdir(cls, path):
        """Read the names of the files in a local directory"""

        return os.listdir(path)

    @classmethod
    @asyncio.coroutine
    def mkdir(cls, path):
        """Create a local directory with the specified attributes"""

        os.mkdir(path)

    @classmethod
    @asyncio.coroutine
    def readlink(cls, path):
        """Return the target of a local symbolic link"""

        return os.readlink(path)

    @classmethod
    @asyncio.coroutine
    def symlink(cls, oldpath, newpath):
        """Create a local symbolic link"""

        os.symlink(oldpath, newpath)

    @asyncio.coroutine
    def read(self, size, offset):
        """Read data from the local file"""

        self._file.seek(offset)
        return self._file.read(size)

    @asyncio.coroutine
    def write(self, data, offset):
        """Write data to the local file"""

        self._file.seek(offset)
        return self._file.write(data)


class _SFTPFileCopier:
    """SFTP file copier

       This class parforms an SFTP file copy, initiating multiple
       read and write requests to copy chunks of the file in parallel.

    """

    def __init__(self, loop):
        self._loop = loop
        self._src = None
        self._dst = None
        self._bytes_left = 0
        self._offset = 0
        self._pending = set()

    @asyncio.coroutine
    def _copy_block(self, offset, size):
        """Copy the next block of the file"""

        data = yield from self._src.read(size, offset)
        yield from self._dst.write(data, offset)

    def _copy_blocks(self):
        """Create parallel requests to copy blocks from one file to another"""

        while self._bytes_left and len(self._pending) < _MAX_SFTP_REQUESTS:
            size = min(self._bytes_left, _SFTP_BLOCK_SIZE)

            task = asyncio.Task(self._copy_block(self._offset, size),
                                loop=self._loop)
            self._pending.add(task)

            self._offset += size
            self._bytes_left -= size

    @asyncio.coroutine
    def copy(self, srcfs, dstfs, srcpath, dstpath, size):
        """Copy a file"""

        with (yield from srcfs.open(srcpath, 'rb')) as self._src:
            with (yield from dstfs.open(dstpath, 'wb')) as self._dst:
                self._bytes_left = size
                self._copy_blocks()

                while self._pending:
                    done, self._pending = yield from asyncio.wait(
                        self._pending, return_when=asyncio.FIRST_COMPLETED)

                    exceptions = [task.exception() for task in done
                                  if task.exception()]

                    if exceptions:
                        for task in self._pending:
                            task.cancel()

                        raise exceptions[0]

                    self._copy_blocks()


class SFTPError(Error):
    """SFTP error

       This exception is raised when an error occurs while processing
       an SFTP request. Exception codes should be taken from
       :ref:`SFTP error codes <SFTPErrorCodes>`.

       :param int code:
           Disconnect reason, taken from :ref:`disconnect reason
           codes <DisconnectReasons>`
       :param str reason:
           A human-readable reason for the disconnect
       :param str lang:
           The language the reason is in

    """

    def __init__(self, code, reason, lang=DEFAULT_LANG):
        super().__init__('SFTP', code, reason, lang)


class SFTPAttrs(Record):
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

       In addition to the above, an ``nlink`` field is provided which
       stores the number of links to this file, but it is not encoded
       in the SFTP protocol. It's included here only so that it can be
       used to create the default ``longname`` string in :class:`SFTPName`
       objects.

       Extended attributes can also be added via a field named
       ``extended`` which is a list of string name/value pairs.

       When setting attributes using an :class:`SFTPAttrs`, only fields
       which have been initialized will be changed on the selected file.

    """

    # Unfortunately, pylint can't handle attributes defined with setattr
    # pylint: disable=attribute-defined-outside-init

    __slots__ = OrderedDict((('size', None), ('uid', None), ('gid', None),
                             ('permissions', None), ('atime', None),
                             ('mtime', None), ('nlink', None),
                             ('extended', [])))

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

            for _ in range(count):
                attr = packet.get_string()
                data = packet.get_string()
                attrs.extended.append((attr, data))

        return attrs

    @classmethod
    def from_local(cls, result):
        """Convert from local stat attributes"""

        return cls(result.st_size, result.st_uid, result.st_gid,
                   result.st_mode, result.st_atime, result.st_mtime,
                   result.st_nlink)


class SFTPVFSAttrs(Record):
    """SFTP file system attributes

       SFTPVFSAttrs is a simple record class with the following fields:

         ============ =========================================== ======
         Field        Description                                 Type
         ============ =========================================== ======
         bsize        File system block size (I/O size)           uint64
         frsize       Fundamental block size (allocation size)    uint64
         blocks       Total data blocks (in frsize units)         uint64
         bfree        Free data blocks                            uint64
         bavail       Available data blocks (for non-root)        uint64
         files        Total file inodes                           uint64
         ffree        Free file inodes                            uint64
         favail       Available file inodes (for non-root)        uint64
         fsid         File system id                              uint64
         flags        File system flags (read-only, no-setuid)    uint64
         namemax      Maximum filename length                     uint64
         ============ =========================================== ======

    """

    # Unfortunately, pylint can't handle attributes defined with setattr
    # pylint: disable=attribute-defined-outside-init

    __slots__ = OrderedDict((('bsize', 0), ('frsize', 0), ('blocks', 0),
                             ('bfree', 0), ('bavail', 0), ('files', 0),
                             ('ffree', 0), ('favail', 0), ('fsid', 0),
                             ('flags', 0), ('namemax', 0)))

    def encode(self):
        """Encode SFTP statvfs attributes as bytes in an SSH packet"""

        return b''.join((UInt64(self.bsize), UInt64(self.frsize),
                         UInt64(self.blocks), UInt64(self.bfree),
                         UInt64(self.bavail), UInt64(self.files),
                         UInt64(self.ffree), UInt64(self.favail),
                         UInt64(self.fsid), UInt64(self.flags),
                         UInt64(self.namemax)))

    @classmethod
    def decode(cls, packet):
        """Decode bytes in an SSH packet as SFTP statvfs attributes"""

        vfsattrs = cls()

        vfsattrs.bsize = packet.get_uint64()
        vfsattrs.frsize = packet.get_uint64()
        vfsattrs.blocks = packet.get_uint64()
        vfsattrs.bfree = packet.get_uint64()
        vfsattrs.bavail = packet.get_uint64()
        vfsattrs.files = packet.get_uint64()
        vfsattrs.ffree = packet.get_uint64()
        vfsattrs.favail = packet.get_uint64()
        vfsattrs.fsid = packet.get_uint64()
        vfsattrs.flags = packet.get_uint64()
        vfsattrs.namemax = packet.get_uint64()

        return vfsattrs

    @classmethod
    def from_local(cls, result):
        """Convert from local statvfs attributes"""

        return cls(result.f_bsize, result.f_frsize, result.f_blocks,
                   result.f_bfree, result.f_bavail, result.f_files,
                   result.f_ffree, result.f_favail, 0, result.f_flag,
                   result.f_namemax)


class SFTPName(Record):
    """SFTP file name and attributes

       SFTPName is a simple record class with the following fields:

         ========= ================================== ==================
         Field     Description                        Type
         ========= ================================== ==================
         filename  Filename                           str or bytes
         longname  Expanded form of filename & attrs  str or bytes
         attrs     File attributes                    :class:`SFTPAttrs`
         ========= ================================== ==================

       A list of these is returned by :meth:`readdir() <SFTPClient.readdir>`
       in :class:`SFTPClient` when retrieving the contents of a directory.

    """

    __slots__ = OrderedDict((('filename', ''), ('longname', ''),
                             ('attrs', SFTPAttrs())))

    def encode(self):
        """Encode an SFTP name as bytes in an SSH packet"""


        # pylint: disable=no-member
        return (String(self.filename) + String(self.longname) +
                self.attrs.encode())

    @classmethod
    def decode(cls, packet):
        """Decode bytes in an SSH packet as an SFTP name"""


        filename = packet.get_string()
        longname = packet.get_string()
        attrs = SFTPAttrs.decode(packet)

        return cls(filename, longname, attrs)


class SFTPHandler:
    """SFTP session handler"""

    # SFTP implementations with broken order for SYMLINK arguments
    _nonstandard_symlink_impls = ['OpenSSH', 'paramiko']

    # Return types by message -- unlisted entries always return FXP_STATUS,
    #                            those below return FXP_STATUS on error
    _return_types = {
        FXP_OPEN:                 FXP_HANDLE,
        FXP_READ:                 FXP_DATA,
        FXP_LSTAT:                FXP_ATTRS,
        FXP_FSTAT:                FXP_ATTRS,
        FXP_OPENDIR:              FXP_HANDLE,
        FXP_READDIR:              FXP_NAME,
        FXP_REALPATH:             FXP_NAME,
        FXP_STAT:                 FXP_ATTRS,
        FXP_READLINK:             FXP_NAME,
        b'statvfs@openssh.com':   FXP_EXTENDED_REPLY,
        b'fstatvfs@openssh.com':  FXP_EXTENDED_REPLY
    }

    def __init__(self, conn, reader, writer):
        self._conn = conn
        self._reader = reader
        self._writer = writer

    @asyncio.coroutine
    def _cleanup(self, exc):
        """Clean up this SFTP session"""

        # pylint: disable=unused-argument

        if self._writer: # pragma: no branch
            self._writer.close()
            self._reader = None
            self._writer = None

    @asyncio.coroutine
    def _process_packet(self, pkttype, pktid, packet):
        """Abstract method for processing SFTP packets"""

        raise NotImplementedError

    def create_task(self, coro):
        """Create an asynchronous task which catches and reports errors"""

        return self._conn.create_task(coro)

    def send_packet(self, *args):
        """Send an SFTP packet"""

        payload = b''.join(args)

        try:
            self._writer.write(UInt32(len(payload)) + payload)
        except ConnectionError as exc:
            raise SFTPError(FX_CONNECTION_LOST, str(exc)) from None

    @asyncio.coroutine
    def recv_packet(self):
        """Receive an SFTP packet"""

        try:
            pktlen = yield from self._reader.readexactly(4)
            pktlen = int.from_bytes(pktlen, 'big')

            packet = yield from self._reader.readexactly(pktlen)
            packet = SSHPacket(packet)
        except EOFError:
            raise SFTPError(FX_CONNECTION_LOST, 'Channel closed') from None

        return packet

    @asyncio.coroutine
    def recv_packets(self):
        """Receive and process SFTP packets"""

        try:
            while self._reader: # pragma: no branch
                packet = yield from self.recv_packet()

                pkttype = packet.get_byte()
                pktid = packet.get_uint32()

                yield from self._process_packet(pkttype, pktid, packet)
        except PacketDecodeError as exc:
            yield from self._cleanup(SFTPError(FX_BAD_MESSAGE, str(exc)))
        except (OSError, SFTPError) as exc:
            yield from self._cleanup(exc)


class SFTPClientHandler(SFTPHandler):
    """An SFTP client session handler"""

    _extensions = []

    def __init__(self, conn, loop, reader, writer):
        super().__init__(conn, reader, writer)

        self._loop = loop
        self._version = None
        self._next_pktid = 0
        self._requests = {}
        self._nonstandard_symlink = False
        self._supports_posix_rename = False
        self._supports_statvfs = False
        self._supports_fstatvfs = False
        self._supports_hardlink = False
        self._supports_fsync = False

    @asyncio.coroutine
    def _cleanup(self, exc):
        """Clean up this SFTP client session"""

        for waiter in self._requests.values():
            if waiter and not waiter.cancelled():
                waiter.set_exception(exc)

        self._requests = {}

        yield from super()._cleanup(exc)

    @asyncio.coroutine
    def _process_packet(self, pkttype, pktid, packet):
        """Process incoming SFTP responses"""

        try:
            waiter = self._requests.pop(pktid)
        except KeyError:
            yield from self._cleanup(SFTPError(FX_BAD_MESSAGE,
                                               'Invalid response id'))
        else:
            if waiter and not waiter.cancelled():
                waiter.set_result((pkttype, packet))

    def _send_request(self, pkttype, *args, waiter=None):
        """Send an SFTP request"""

        if not self._writer:
            raise SFTPError(FX_NO_CONNECTION, 'Connection not open')

        pktid = self._next_pktid
        self._next_pktid = (self._next_pktid + 1) & 0xffffffff

        self._requests[pktid] = waiter

        if isinstance(pkttype, bytes):
            hdr = Byte(FXP_EXTENDED) + UInt32(pktid) + String(pkttype)
        else:
            hdr = Byte(pkttype) + UInt32(pktid)

        self.send_packet(hdr, *args)

    @asyncio.coroutine
    def _make_request(self, pkttype, *args):
        """Make an SFTP request and wait for a response"""

        waiter = asyncio.Future(loop=self._loop)
        self._send_request(pkttype, *args, waiter=waiter)
        resptype, resp = yield from waiter

        return_type = self._return_types.get(pkttype)

        if resptype not in (FXP_STATUS, return_type):
            raise SFTPError(FX_BAD_MESSAGE,
                            'Unexpected response type: %s' % resptype)

        result = self._packet_handlers[resptype](self, resp)

        if result is not None or return_type is None:
            return result
        else:
            raise SFTPError(FX_BAD_MESSAGE, 'Unexpected FX_OK response')

    def _process_status(self, packet):
        """Process an incoming SFTP status response"""

        # pylint: disable=no-self-use

        code = packet.get_uint32()

        try:
            reason = packet.get_string().decode('utf-8')
            lang = packet.get_string().decode('ascii')
        except UnicodeDecodeError:
            raise SFTPError(FX_BAD_MESSAGE, 'Invalid status message') from None

        packet.check_end()

        if code == FX_OK:
            return None
        else:
            raise SFTPError(code, reason, lang)

    def _process_handle(self, packet):
        """Process an incoming SFTP handle response"""

        # pylint: disable=no-self-use

        handle = packet.get_string()
        packet.check_end()
        return handle

    def _process_data(self, packet):
        """Process an incoming SFTP data response"""

        # pylint: disable=no-self-use

        data = packet.get_string()
        packet.check_end()
        return data

    def _process_name(self, packet):
        """Process an incoming SFTP name response"""

        # pylint: disable=no-self-use

        count = packet.get_uint32()
        names = [SFTPName.decode(packet) for i in range(count)]
        packet.check_end()
        return names

    def _process_attrs(self, packet):
        """Process an incoming SFTP attributes response"""

        # pylint: disable=no-self-use

        attrs = SFTPAttrs().decode(packet)
        packet.check_end()
        return attrs

    def _process_extended_reply(self, packet):
        """Process an incoming SFTP extended reply response"""

        # pylint: disable=no-self-use

        # Let the caller do the decoding for extended replies
        return packet

    _packet_handlers = {
        FXP_STATUS:         _process_status,
        FXP_HANDLE:         _process_handle,
        FXP_DATA:           _process_data,
        FXP_NAME:           _process_name,
        FXP_ATTRS:          _process_attrs,
        FXP_EXTENDED_REPLY: _process_extended_reply
    }

    @asyncio.coroutine
    def start(self):
        """Start a new SFTP client"""

        extensions = (String(name) + String(data)
                      for name, data in self._extensions)

        self.send_packet(Byte(FXP_INIT), UInt32(_SFTP_VERSION), *extensions)

        resp = yield from self.recv_packet()

        resptype = resp.get_byte()

        if resptype != FXP_VERSION:
            raise SFTPError(FX_BAD_MESSAGE, 'Expected version message')

        version = resp.get_uint32()
        extensions = []

        while resp:
            name = resp.get_string()
            data = resp.get_string()
            extensions.append((name, data))

        if version != _SFTP_VERSION:
            raise SFTPError(FX_BAD_MESSAGE,
                            'Unsupported version: %d' % version)

        self._version = version

        for name, data in extensions:
            if name == b'posix-rename@openssh.com' and data == b'1':
                self._supports_posix_rename = True
            elif name == b'statvfs@openssh.com' and data == b'2':
                self._supports_statvfs = True
            elif name == b'fstatvfs@openssh.com' and data == b'2':
                self._supports_fstatvfs = True
            elif name == b'hardlink@openssh.com' and data == b'1':
                self._supports_hardlink = True
            elif name == b'fsync@openssh.com' and data == b'1':
                self._supports_fsync = True

        if version == 3:
            # Check if the server has a buggy SYMLINK implementation

            server_version = self._reader.get_extra_info('server_version', '')
            if any(name in server_version
                   for name in self._nonstandard_symlink_impls):
                self._nonstandard_symlink = True

        self.create_task(self.recv_packets())

    @asyncio.coroutine
    def open(self, filename, pflags, attrs):
        """Make an SFTP open request"""

        return (yield from self._make_request(FXP_OPEN, String(filename),
                                              UInt32(pflags), attrs.encode()))

    @asyncio.coroutine
    def close(self, handle):
        """Make an SFTP close request"""

        return (yield from self._make_request(FXP_CLOSE, String(handle)))

    def nonblocking_close(self, handle):
        """Send an SFTP close request without blocking on the response"""

        # Used by context managers, since they can't block to wait for a reply
        self._send_request(FXP_CLOSE, String(handle))

    @asyncio.coroutine
    def read(self, handle, offset, length):
        """Make an SFTP read request"""

        return (yield from self._make_request(FXP_READ, String(handle),
                                              UInt64(offset), UInt32(length)))

    @asyncio.coroutine
    def write(self, handle, offset, data):
        """Make an SFTP write request"""

        return (yield from self._make_request(FXP_WRITE, String(handle),
                                              UInt64(offset), String(data)))

    @asyncio.coroutine
    def stat(self, path):
        """Make an SFTP stat request"""

        return (yield from self._make_request(FXP_STAT, String(path)))

    @asyncio.coroutine
    def lstat(self, path):
        """Make an SFTP lstat request"""

        return (yield from self._make_request(FXP_LSTAT, String(path)))

    @asyncio.coroutine
    def fstat(self, handle):
        """Make an SFTP fstat request"""

        return (yield from self._make_request(FXP_FSTAT, String(handle)))

    @asyncio.coroutine
    def setstat(self, path, attrs):
        """Make an SFTP setstat request"""

        return (yield from self._make_request(FXP_SETSTAT, String(path),
                                              attrs.encode()))

    @asyncio.coroutine
    def fsetstat(self, handle, attrs):
        """Make an SFTP fsetstat request"""

        return (yield from self._make_request(FXP_FSETSTAT, String(handle),
                                              attrs.encode()))

    @asyncio.coroutine
    def statvfs(self, path):
        """Make an SFTP statvfs request"""

        if self._supports_statvfs:
            packet = yield from self._make_request(b'statvfs@openssh.com',
                                                   String(path))
            vfsattrs = SFTPVFSAttrs.decode(packet)
            packet.check_end()

            return vfsattrs
        else:
            raise SFTPError(FX_OP_UNSUPPORTED, 'statvfs not supported')

    @asyncio.coroutine
    def fstatvfs(self, handle):
        """Make an SFTP fstatvfs request"""

        if self._supports_fstatvfs:
            packet = yield from self._make_request(b'fstatvfs@openssh.com',
                                                   String(handle))
            vfsattrs = SFTPVFSAttrs.decode(packet)
            packet.check_end()

            return vfsattrs
        else:
            raise SFTPError(FX_OP_UNSUPPORTED, 'fstatvfs not supported')

    @asyncio.coroutine
    def remove(self, path):
        """Make an SFTP remove request"""

        return (yield from self._make_request(FXP_REMOVE, String(path)))

    @asyncio.coroutine
    def rename(self, oldpath, newpath):
        """Make an SFTP rename request"""

        return (yield from self._make_request(FXP_RENAME, String(oldpath),
                                              String(newpath)))

    @asyncio.coroutine
    def posix_rename(self, oldpath, newpath):
        """Make an SFTP POSIX rename request"""

        if self._supports_posix_rename:
            return (yield from self._make_request(b'posix-rename@openssh.com',
                                                  String(oldpath),
                                                  String(newpath)))
        else:
            raise SFTPError(FX_OP_UNSUPPORTED, 'POSIX rename not supported')

    @asyncio.coroutine
    def opendir(self, path):
        """Make an SFTP opendir request"""

        return (yield from self._make_request(FXP_OPENDIR, String(path)))

    @asyncio.coroutine
    def readdir(self, handle):
        """Make an SFTP readdir request"""

        return (yield from self._make_request(FXP_READDIR, String(handle)))

    @asyncio.coroutine
    def mkdir(self, path, attrs):
        """Make an SFTP mkdir request"""

        return (yield from self._make_request(FXP_MKDIR, String(path),
                                              attrs.encode()))

    @asyncio.coroutine
    def rmdir(self, path):
        """Make an SFTP rmdir request"""

        return (yield from self._make_request(FXP_RMDIR, String(path)))

    @asyncio.coroutine
    def realpath(self, path):
        """Make an SFTP realpath request"""

        return (yield from self._make_request(FXP_REALPATH, String(path)))

    @asyncio.coroutine
    def readlink(self, path):
        """Make an SFTP readlink request"""

        return (yield from self._make_request(FXP_READLINK, String(path)))

    @asyncio.coroutine
    def symlink(self, oldpath, newpath):
        """Make an SFTP symlink request"""

        if self._nonstandard_symlink:
            args = String(oldpath) + String(newpath)
        else:
            args = String(newpath) + String(oldpath)

        return (yield from self._make_request(FXP_SYMLINK, args))

    @asyncio.coroutine
    def link(self, oldpath, newpath):
        """Make an SFTP link request"""

        if self._supports_hardlink:
            return (yield from self._make_request(b'hardlink@openssh.com',
                                                  String(oldpath),
                                                  String(newpath)))
        else:
            raise SFTPError(FX_OP_UNSUPPORTED, 'link not supported')

    @asyncio.coroutine
    def fsync(self, handle):
        """Make an SFTP fsync request"""

        if self._supports_fsync:
            return (yield from self._make_request(b'fsync@openssh.com',
                                                  String(handle)))
        else:
            raise SFTPError(FX_OP_UNSUPPORTED, 'fsync not supported')

    def exit(self):
        """Handle a request to close the SFTP session"""

        if self._writer:
            self._writer.write_eof()

    @asyncio.coroutine
    def wait_closed(self):
        """Wait for this SFTP session to close"""

        if self._writer:
            yield from self._writer.channel.wait_closed()


class SFTPFile:
    """SFTP client remote file object

       This class represents an open file on a remote SFTP server. It
       is opened with the :meth:`open() <SFTPClient.open>` method on the
       :class:`SFTPClient` class and provides methods to read and write
       data and get and set attributes on the open file.

    """

    def __init__(self, handler, handle, appending, encoding, errors):
        self._handler = handler
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
            self._handler.nonblocking_close(self._handle)
            self._handle = None

    @asyncio.coroutine
    def __aenter__(self):
        """Allow SFTPFile to be used as an async context manager"""

        return self

    @asyncio.coroutine
    def __aexit__(self, *exc_info):
        """Wait for file close when used as an async context manager"""

        yield from self.close()

    @asyncio.coroutine
    def _end(self):
        """Return the offset of the end of the file"""

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

           :param int size:
               The number of bytes to read
           :param int offset: (optional)
               The offset from the beginning of the file to begin reading

           :returns: data read from the file, as a str or bytes

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
                    result = yield from self._handler.read(self._handle,
                                                           offset,
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
                data = yield from self._handler.read(self._handle,
                                                     offset, size)
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
           :param int offset: (optional)
               The offset from the beginning of the file to begin writing
           :type data: str or bytes

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

        yield from self._handler.write(self._handle, offset, data)
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

           :param int offset:
               The amount to seek
           :param int from_what: (optional)
               The reference point to use (SEEK_SET, SEEK_CUR, or SEEK_END)

           :returns: The new byte offset from the beginning of the file

        """

        if self._handle is None:
            raise ValueError('I/O operation on closed file')

        if from_what == SEEK_SET:
            self._offset = offset
        elif from_what == SEEK_CUR:
            self._offset += offset
        elif from_what == SEEK_END:
            self._offset = (yield from self._end()) + offset
        else:
            raise ValueError('Invalid reference point')

        return self._offset

    @asyncio.coroutine
    def tell(self):
        """Return the current position in the remote file

           This method returns the current position in the remote file.

           :returns: The current byte offset from the beginning of the file

        """

        if self._handle is None:
            raise ValueError('I/O operation on closed file')

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

        return (yield from self._handler.fstat(self._handle))

    @asyncio.coroutine
    def setstat(self, attrs):
        """Set attributes of the remote file

           This method sets file attributes of the currently open file.

           :param attrs:
               File attributes to set on the file
           :type attrs: :class:`SFTPAttrs`

           :raises: :exc:`SFTPError` if the server returns an error

        """

        if self._handle is None:
            raise ValueError('I/O operation on closed file')

        yield from self._handler.fsetstat(self._handle, attrs)

    @asyncio.coroutine
    def statvfs(self):
        """Return file system attributes of the remote file

           This method queries attributes of the file system containing
           the currently open file.

           :returns: An :class:`SFTPVFSAttrs` containing the file system
                     attributes

           :raises: :exc:`SFTPError` if the server doesn't support this
                    extension or returns an error

        """

        if self._handle is None:
            raise ValueError('I/O operation on closed file')

        return (yield from self._handler.fstatvfs(self._handle))

    @asyncio.coroutine
    def truncate(self, size=None):
        """Truncate the remote file to the specified size

           This method changes the remote file's size to the specified
           value. If a size is not provided, the current file position
           is used.

           :param int size: (optional)
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

           :param int uid:
               The new user id to assign to the file
           :param int gid:
               The new group id to assign to the file

           :raises: :exc:`SFTPError` if the server returns an error

        """

        yield from self.setstat(SFTPAttrs(uid=uid, gid=gid))

    @asyncio.coroutine
    def chmod(self, mode):
        """Change the file permissions of the remote file

           This method changes the permissions of the currently
           open file.

           :param int mode:
               The new file permissions, expressed as an int

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
           :type times: tuple of two int or float values

           :raises: :exc:`SFTPError` if the server returns an error

        """

        # pylint: disable=unpacking-non-sequence
        if times is None:
            atime = mtime = time.time()
        else:
            atime, mtime = times

        yield from self.setstat(SFTPAttrs(atime=atime, mtime=mtime))

    @asyncio.coroutine
    def fsync(self):
        """Force the remote file data to be written to disk"""

        if self._handle is None:
            raise ValueError('I/O operation on closed file')

        yield from self._handler.fsync(self._handle)

    @asyncio.coroutine
    def close(self):
        """Close the remote file"""

        if self._handle:
            yield from self._handler.close(self._handle)
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

    def __init__(self, loop, handler, path_encoding, path_errors):
        self._loop = loop
        self._handler = handler
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
    def __aenter__(self):
        """Allow SFTPClient to be used as an async context manager"""

        return self

    @asyncio.coroutine
    def __aexit__(self, *exc_info):
        """Wait for client close when used as an async context manager"""

        self.__exit__()
        yield from self.wait_closed()

    def encode(self, path):
        """Encode path name using configured path encoding

           This method has no effect if the path is already bytes.

        """

        if isinstance(path, str):
            if self._path_encoding:
                path = path.encode(self._path_encoding, self._path_errors)
            else:
                raise SFTPError(FX_BAD_MESSAGE, 'Path must be bytes when '
                                'encoding is not set')

        return path

    def decode(self, path, want_string=True):
        """Decode path name using configured path encoding

           This method has no effect if want_string is set to ``False``.

        """

        if want_string and self._path_encoding:
            try:
                path = path.decode(self._path_encoding, self._path_errors)
            except UnicodeDecodeError:
                raise SFTPError(FX_BAD_MESSAGE,
                                'Unable to decode name') from None

        return path

    def compose_path(self, path, parent=...):
        """Compose a path

           If parent is not specified, return a path relative to the
           current remote working directory.

        """

        if parent is ...:
            parent = self._cwd

        path = self.encode(path)

        return posixpath.join(parent, path) if parent else path

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
    def _glob(self, fs, basedir, patlist, decode, result):
        """Match a glob pattern"""

        pattern, patlist = patlist[0], patlist[1:]

        for name in (yield from fs.listdir(basedir or b'.')):
            if pattern != name and name in (b'.', b'..'):
                continue

            if name[:1] == b'.' and not pattern[:1] == b'.':
                continue

            if fnmatch(name, pattern):
                newbase = fs.compose_path(name, parent=basedir)

                if not patlist:
                    result.append(fs.decode(newbase, decode))
                elif (yield from fs.isdir(newbase)):
                    yield from self._glob(fs, newbase, patlist, decode, result)

    @asyncio.coroutine
    def _begin_glob(self, fs, patterns, error_handler):
        """Begin a new glob pattern match"""

        if isinstance(patterns, (str, bytes)):
            patterns = [patterns]

        result = []

        for pattern in patterns:
            if not pattern:
                continue

            decode = isinstance(pattern, str)
            patlist = self.encode(pattern).split(b'/')

            if not patlist[0]:
                basedir = b'/'
                patlist = patlist[1:]
            else:
                basedir = None

            names = []

            try:
                yield from self._glob(fs, basedir, patlist, decode, names)

                if names:
                    result.extend(names)
                else:
                    raise SFTPError(FX_NO_SUCH_FILE, 'No matches found')
            except (OSError, SFTPError) as exc:
                # pylint: disable=attribute-defined-outside-init
                exc.srcpath = pattern

                if error_handler:
                    error_handler(exc)
                else:
                    raise exc

        return result

    @asyncio.coroutine
    def _copy(self, srcfs, dstfs, srcpath, dstpath, preserve,
              recurse, follow_symlinks, error_handler):
        """Copy a file, directory, or symbolic link"""

        if follow_symlinks:
            srcattrs = yield from srcfs.stat(srcpath)
        else:
            srcattrs = yield from srcfs.lstat(srcpath)

        try:
            if stat.S_ISDIR(srcattrs.permissions):
                if not recurse:
                    raise SFTPError(FX_FAILURE, '%s is a directory' %
                                    srcpath.decode('utf-8', errors='replace'))

                if not (yield from dstfs.isdir(dstpath)):
                    yield from dstfs.mkdir(dstpath)

                names = yield from srcfs.listdir(srcpath)

                for name in names:
                    if name in (b'.', b'..'):
                        continue

                    srcfile = srcfs.compose_path(name, parent=srcpath)
                    dstfile = dstfs.compose_path(name, parent=dstpath)

                    yield from self._copy(srcfs, dstfs, srcfile,
                                          dstfile, preserve, recurse,
                                          follow_symlinks, error_handler)
            elif stat.S_ISLNK(srcattrs.permissions):
                targetpath = yield from srcfs.readlink(srcpath)
                yield from dstfs.symlink(targetpath, dstpath)
            else:
                yield from _SFTPFileCopier(self._loop).copy(
                    srcfs, dstfs, srcpath, dstpath, srcattrs.size)

            if preserve:
                srcattrs = yield from srcfs.stat(srcpath)

                yield from dstfs.setstat(
                    dstpath, SFTPAttrs(permissions=srcattrs.permissions,
                                       atime=srcattrs.atime,
                                       mtime=srcattrs.mtime))
        except (OSError, SFTPError) as exc:
            # pylint: disable=attribute-defined-outside-init
            exc.srcpath = srcpath
            exc.dstpath = dstpath

            if error_handler:
                error_handler(exc)
            else:
                raise

    @asyncio.coroutine
    def _begin_copy(self, srcfs, dstfs, srcpaths, dstpath, preserve,
                    recurse, follow_symlinks, error_handler):
        """Begin a new file upload, download, or copy"""

        dst_isdir = dstpath is None or (yield from dstfs.isdir(dstpath))
        dstpath = self.encode(dstpath)

        if isinstance(srcpaths, (str, bytes)):
            srcpaths = [srcpaths]
        elif not dst_isdir:
            raise SFTPError(FX_FAILURE, '%s must be a directory' %
                            dstpath.decode('utf-8', errors='replace'))

        for srcfile in srcpaths:
            srcfile = self.encode(srcfile)
            filename = posixpath.basename(srcfile)

            if dstpath is None:
                dstfile = filename
            elif dst_isdir:
                dstfile = dstfs.compose_path(filename, parent=dstpath)
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
           the download, this handler will be called with the exception
           instead of it being raised. This is intended to primarily be
           used when multiple remote paths are provided or when recurse
           is set to ``True``, to allow error information to be collected
           without aborting the download of the remaining files. The
           error handler can raise an exception if it wants the download
           to completely stop. Otherwise, after an error, the download
           will continue starting with the next file.

           :param remotepaths:
               The paths of the remote files or directories to download
           :param str localpath: (optional)
               The path of the local file or directory to download into
           :param bool preserve: (optional)
               Whether or not to preserve the original file attributes
           :param bool recurse: (optional)
               Whether or not to recursively copy directories
           :param bool follow_symlinks: (optional)
               Whether or not to follow symbolic links
           :param callable error_handler: (optional)
               The function to call when an error occurs
           :type remotepaths: str or bytes, or a sequence of these

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
           the upload, this handler will be called with the exception
           instead of it being raised. This is intended to primarily be
           used when multiple local paths are provided or when recurse
           is set to ``True``, to allow error information to be collected
           without aborting the upload of the remaining files. The
           error handler can raise an exception if it wants the upload
           to completely stop. Otherwise, after an error, the upload
           will continue starting with the next file.

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
           :type localpaths: str or bytes, or a sequence of these
           :type remotepath: str or bytes

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
           the copy, this handler will be called with the exception
           instead of it being raised. This is intended to primarily be
           used when multiple source paths are provided or when recurse
           is set to ``True``, to allow error information to be collected
           without aborting the copy of the remaining files. The error
           handler can raise an exception if it wants the copy to
           completely stop. Otherwise, after an error, the copy will
           continue starting with the next file.

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
           :type srcpaths: str or bytes, or a sequence of these
           :type dstpath: str or bytes

           :raises: | :exc:`OSError` if a local file I/O error occurs
                    | :exc:`SFTPError` if the server returns an error

        """

        yield from self._begin_copy(self, self, srcpaths, dstpath, preserve,
                                    recurse, follow_symlinks, error_handler)

    @asyncio.coroutine
    def mget(self, remotepaths, localpath=None, *, preserve=False,
             recurse=False, follow_symlinks=False, error_handler=None):
        """Download remote files with glob pattern match

           This method downloads files and directories from the remote
           system matching one or more glob patterns.

           The arguments to this method are identical to the :meth:`get`
           method, except that the remote paths specified can contain
           '*' and '?' wildcard characters.

        """

        matches = yield from self._begin_glob(self, remotepaths, error_handler)

        yield from self._begin_copy(self, _LocalFile, matches, localpath,
                                    preserve, recurse, follow_symlinks,
                                    error_handler)

    @asyncio.coroutine
    def mput(self, localpaths, remotepath=None, *, preserve=False,
             recurse=False, follow_symlinks=False, error_handler=None):
        """Upload local files with glob pattern match

           This method uploads files and directories to the remote
           system matching one or more glob patterns.

           The arguments to this method are identical to the :meth:`put`
           method, except that the local paths specified can contain
           '*' and '?' wildcard characters.

        """

        matches = yield from self._begin_glob(_LocalFile, localpaths,
                                              error_handler)

        yield from self._begin_copy(_LocalFile, self, matches, remotepath,
                                    preserve, recurse, follow_symlinks,
                                    error_handler)

    @asyncio.coroutine
    def mcopy(self, srcpaths, dstpath=None, *, preserve=False,
              recurse=False, follow_symlinks=False, error_handler=None):
        """Download remote files with glob pattern match

           This method copies files and directories on the remote
           system matching one or more glob patterns.

           The arguments to this method are identical to the :meth:`copy`
           method, except that the source paths specified can contain
           '*' and '?' wildcard characters.

        """

        matches = yield from self._begin_glob(self, srcpaths, error_handler)

        yield from self._begin_copy(self, self, matches, dstpath, preserve,
                                    recurse, follow_symlinks, error_handler)

    @asyncio.coroutine
    def glob(self, patterns, error_handler=None):
        """Match remote files against glob patterns

           This method matches remote files against one or more glob
           patterns. Either a single pattern or a sequence of patterns
           can be provided to match against.

           If error_handler is specified and an error occurs during
           the match, this handler will be called with the exception
           instead of it being raised. This is intended to primarily be
           used when multiple patterns are provided to allow error
           information to be collected without aborting the match
           against the remaining patterns. The error handler can raise
           an exception if it wants to completely abort the match.
           Otherwise, after an error, the match will continue starting
           with the next pattern.

           An error will be raised if any of the patterns completely
           fail to match, and this can either stop the match against
           the remaining patterns or be handled by the error_handler
           just like other errors.

           :param patterns:
               Glob patterns to try and match remote files against
           :param callable error_handler: (optional)
               The function to call when an error occurs
           :type patterns: str or bytes, or a sequence of these

           :raises: :exc:`SFTPError` if the server returns an error
                    or no match is found

        """

        return (yield from self._begin_glob(self, patterns, error_handler))

    @async_context_manager
    def open(self, path, pflags_or_mode=FXF_READ, attrs=SFTPAttrs(),
             encoding='utf-8', errors='strict'):
        """Open a remote file

           This method opens a remote file and returns an :class:`SFTPFile`
           object which can be used to read and write data and get and set
           file attributes.

           The path can be either a str or bytes value. If it is a
           str, it will be encoded using the file encoding specified
           when the :class:`SFTPClient` was started.

           The following open mode flags are supported:

             ========== ======================================================
             Mode       Description
             ========== ======================================================
             FXF_READ   Open the file for reading.
             FXF_WRITE  Open the file for writing. If both this and FXF_READ
                        are set, open the file for both reading and writing.
             FXF_APPEND Force writes to append data to the end of the file
                        regardless of seek position.
             FXF_CREAT  Create the file if it doesn't exist. Without this,
                        attempts to open a non-existent file will fail.
             FXF_TRUNC  Truncate the file to zero length if it already exists.
             FXF_EXCL   Return an error when trying to open a file which
                        already exists.
             ========== ======================================================

           By default, file data is read and written as strings in UTF-8
           format with strict error checking, but this can be changed
           using the ``encoding`` and ``errors`` parameters. To read and
           write data as bytes in binary format, an ``encoding`` value of
           ``None`` can be used.

           Instead of these flags, a Python open mode string can also be
           provided. Python open modes map to the above flags as follows:

             ==== =============================================
             Mode Flags
             ==== =============================================
             r    FXF_READ
             w    FXF_WRITE | FXF_CREAT | FXF_TRUNC
             a    FXF_WRITE | FXF_CREAT | FXF_APPEND
             x    FXF_WRITE | FXF_CREAT | FXF_EXCL

             r+   FXF_READ | FXF_WRITE
             w+   FXF_READ | FXF_WRITE | FXF_CREAT | FXF_TRUNC
             a+   FXF_READ | FXF_WRITE | FXF_CREAT | FXF_APPEND
             x+   FXF_READ | FXF_WRITE | FXF_CREAT | FXF_EXCL
             ==== =============================================

           Including a 'b' in the mode causes the ``encoding`` to be set
           to ``None``, forcing all data to be read and written as bytes
           in binary format.

           The attrs argument is used to set initial attributes of the
           file if it needs to be created. Otherwise, this argument is
           ignored.

           :param path:
               The name of the remote file to open
           :param pflags_or_mode: (optional)
               The access mode to use for the remote file (see above)
           :param attrs: (optional)
               File attributes to use if the file needs to be created
           :param str encoding: (optional)
               The Unicode encoding to use for data read and written
               to the remote file
           :param str errors: (optional)
               The error-handling mode if an invalid Unicode byte
               sequence is detected, defaulting to 'strict' which
               raises an exception
           :type path: str or bytes
           :type pflags_or_mode: int or str
           :type attrs: :class:`SFTPAttrs`

           :returns: An :class:`SFTPFile` to use to access the file

           :raises: | :exc:`ValueError` if the mode is not valid
                    | :exc:`SFTPError` if the server returns an error

        """

        if isinstance(pflags_or_mode, str):
            mode = pflags_or_mode

            if 'b' in mode:
                # Avoid a false positive where pylint thinks mode is an int
                # pylint: disable=no-member
                mode = mode.replace('b', '')
                encoding = None

            pflags = self._open_modes.get(mode)
            if not pflags:
                raise ValueError('Invalid mode: %r' % mode)
        else:
            pflags = pflags_or_mode

        path = self.compose_path(path)
        handle = yield from self._handler.open(path, pflags, attrs)

        return SFTPFile(self._handler, handle, pflags & FXF_APPEND,
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
           :type path: str or bytes

           :returns: An :class:`SFTPAttrs` containing the file attributes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = self.compose_path(path)
        return (yield from self._handler.stat(path))

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
           :type path: str or bytes

           :returns: An :class:`SFTPAttrs` containing the file attributes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = self.compose_path(path)
        return (yield from self._handler.lstat(path))

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
           :type path: str or bytes
           :type attrs: :class:`SFTPAttrs`

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = self.compose_path(path)
        yield from self._handler.setstat(path, attrs)

    @asyncio.coroutine
    def statvfs(self, path):
        """Get attributes of a remote file system

           This method queries the attributes of the file system containing
           the specified path.

           :param path:
               The path of the remote file system to get attributes for
           :type path: str or bytes

           :returns: An :class:`SFTPVFSAttrs` containing the file system
                     attributes

           :raises: :exc:`SFTPError` if the server doesn't support this
                    extension or returns an error

        """

        path = self.compose_path(path)
        return (yield from self._handler.statvfs(path))

    @asyncio.coroutine
    def truncate(self, path, size):
        """Truncate a remote file to the specified size

           This method truncates a remote file to the specified size.
           If the path provided is a symbolic link, the target of
           the link will be truncated.

           :param path:
               The path of the remote file to be truncated
           :param int size:
               The desired size of the file, in bytes
           :type path: str or bytes

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
           :param int uid:
               The new user id to assign to the file
           :param int gid:
               The new group id to assign to the file
           :type path: str or bytes

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
           :param int mode:
               The new file permissions, expressed as an int
           :type path: str or bytes

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
           :type path: str or bytes
           :type times: tuple of two int or float values

           :raises: :exc:`SFTPError` if the server returns an error

        """

        # pylint: disable=unpacking-non-sequence
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
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return bool((yield from self._mode(path)))

    @asyncio.coroutine
    def lexists(self, path):
        """Return if the remote path exists, without following symbolic links

           :param path:
               The remote path to check
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return bool((yield from self._mode(path, statfunc=self.lstat)))

    @asyncio.coroutine
    def getatime(self, path):
        """Return the last access time of a remote file or directory

           :param path:
               The remote path to check
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return (yield from self.stat(path)).atime

    @asyncio.coroutine
    def getmtime(self, path):
        """Return the last modification time of a remote file or directory

           :param path:
               The remote path to check
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return (yield from self.stat(path)).mtime

    @asyncio.coroutine
    def getsize(self, path):
        """Return the size of a remote file or directory

           :param path:
               The remote path to check
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return (yield from self.stat(path)).size

    @asyncio.coroutine
    def isdir(self, path):
        """Return if the remote path refers to a directory

           :param path:
               The remote path to check
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return stat.S_ISDIR((yield from self._mode(path)))

    @asyncio.coroutine
    def isfile(self, path):
        """Return if the remote path refers to a regular file

           :param path:
               The remote path to check
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return stat.S_ISREG((yield from self._mode(path)))

    @asyncio.coroutine
    def islink(self, path):
        """Return if the remote path refers to a symbolic link

           :param path:
               The remote path to check
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        return stat.S_ISLNK((yield from self._mode(path, statfunc=self.lstat)))

    @asyncio.coroutine
    def remove(self, path):
        """Remove a remote file

           This method removes a remote file or symbolic link.

           :param path:
               The path of the remote file or link to remove
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = self.compose_path(path)
        yield from self._handler.remove(path)

    @asyncio.coroutine
    def unlink(self, path):
        """Remove a remote file (see :meth:`remove`)"""

        yield from self.remove(path)

    @asyncio.coroutine
    def rename(self, oldpath, newpath):
        """Rename a remote file, directory, or link

           This method renames a remote file, directory, or link.

           .. note:: This requests the standard SFTP version of rename
                     which will not overwrite the new path if it already
                     exists. To request POSIX behavior where the new
                     path is removed before the rename, use
                     :meth:`posix_rename`.

           :param oldpath:
               The path of the remote file, directory, or link to rename
           :param newpath:
               The new name for this file, directory, or link
           :type oldpath: str or bytes
           :type newpath: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        oldpath = self.compose_path(oldpath)
        newpath = self.compose_path(newpath)
        yield from self._handler.rename(oldpath, newpath)

    @asyncio.coroutine
    def posix_rename(self, oldpath, newpath):
        """Rename a remote file, directory, or link with POSIX semantics

           This method renames a remote file, directory, or link,
           removing the prior instance of new path if it previously
           existed.

           This method may not be supported by all SFTP servers.

           :param oldpath:
               The path of the remote file, directory, or link to rename
           :param newpath:
               The new name for this file, directory, or link
           :type oldpath: str or bytes
           :type newpath: str or bytes

           :raises: :exc:`SFTPError` if the server doesn't support this
                    extension or returns an error

        """

        oldpath = self.compose_path(oldpath)
        newpath = self.compose_path(newpath)
        yield from self._handler.posix_rename(oldpath, newpath)

    @asyncio.coroutine
    def readdir(self, path='.'):
        """Read the contents of a remote directory

           This method reads the contents of a directory, returning
           the names and attributes of what is contained there. If no
           path is provided, it defaults to the current remote working
           directory.

           :param path: (optional)
               The path of the remote directory to read
           :type path: str or bytes

           :returns: A list of :class:`SFTPName` entries, with path
                     names matching the type used to pass in the path

           :raises: :exc:`SFTPError` if the server returns an error

        """

        names = []

        dirpath = self.compose_path(path)
        handle = yield from self._handler.opendir(dirpath)

        try:
            while True:
                names.extend((yield from self._handler.readdir(handle)))
        except SFTPError as exc:
            if exc.code != FX_EOF:
                raise
        finally:
            yield from self._handler.close(handle)

        if isinstance(path, str):
            for name in names:
                name.filename = self.decode(name.filename)
                name.longname = self.decode(name.longname)

        return names

    @asyncio.coroutine
    def listdir(self, path='.'):
        """Read the names of the files in a remote directory

           This method reads the names of files and subdirectories
           in a remote directory. If no path is provided, it defaults
           to the current remote working directory.

           :param path: (optional)
               The path of the remote directory to read
           :type path: str or bytes

           :returns: A list of file/subdirectory names, matching the
                     type used to pass in the path

           :raises: :exc:`SFTPError` if the server returns an error

        """

        names = yield from self.readdir(path)
        return [name.filename for name in names]

    @asyncio.coroutine
    def mkdir(self, path, attrs=SFTPAttrs()):
        """Create a remote directory with the specified attributes

           This method creates a new remote directory at the
           specified path with the requested attributes.

           :param path:
               The path of where the new remote directory should be created
           :param attrs: (optional)
               The file attributes to use when creating the directory
           :type path: str or bytes
           :type attrs: :class:`SFTPAttrs`

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = self.compose_path(path)
        yield from self._handler.mkdir(path, attrs)

    @asyncio.coroutine
    def rmdir(self, path):
        """Remove a remote directory

           This method removes a remote directory. The directory
           must be empty for the removal to succeed.

           :param path:
               The path of the remote directory to remove
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        path = self.compose_path(path)
        yield from self._handler.rmdir(path)

    @asyncio.coroutine
    def realpath(self, path):
        """Return the canonical version of a remote path

           This method returns a canonical version of the requested path.

           :param path: (optional)
               The path of the remote directory to canonicalize
           :type path: str or bytes

           :returns: The canonical path as a str or bytes, matching
                     the type used to pass in the path

           :raises: :exc:`SFTPError` if the server returns an error

        """

        fullpath = self.compose_path(path)
        names = yield from self._handler.realpath(fullpath)

        if len(names) > 1:
            raise SFTPError(FX_BAD_MESSAGE, 'Too many names returned')

        return self.decode(names[0].filename, isinstance(path, str))

    @asyncio.coroutine
    def getcwd(self):
        """Return the current remote working directory

           :returns: The current remote working directory, decoded using
                     the specified path encoding

           :raises: :exc:`SFTPError` if the server returns an error

        """

        if self._cwd is None:
            self._cwd = yield from self.realpath(b'.')

        return self.decode(self._cwd)

    @asyncio.coroutine
    def chdir(self, path):
        """Change the current remote working directory

           :param path: The path to set as the new remote working directory
           :type path: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        self._cwd = yield from self.realpath(self.encode(path))

    @asyncio.coroutine
    def readlink(self, path):
        """Return the target of a remote symbolic link

           This method returns the target of a symbolic link.

           :param path:
               The path of the remote symbolic link to follow
           :type path: str or bytes

           :returns: The target path of the link as a str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        linkpath = self.compose_path(path)
        names = yield from self._handler.readlink(linkpath)

        if len(names) > 1:
            raise SFTPError(FX_BAD_MESSAGE, 'Too many names returned')

        return self.decode(names[0].filename, isinstance(path, str))

    @asyncio.coroutine
    def symlink(self, oldpath, newpath):
        """Create a remote symbolic link

           This method creates a symbolic link. The argument order here
           matches the standard Python :meth:`os.symlink` call. The
           argument order sent on the wire is automatically adapted
           depending on the version information sent by the server, as
           a number of servers (OpenSSH in particular) did not follow
           the SFTP standard when implementing this call.

           :param oldpath:
               The path the link should point to
           :param newpath:
               The path of where to create the remote symbolic link
           :type oldpath: str or bytes
           :type newpath: str or bytes

           :raises: :exc:`SFTPError` if the server returns an error

        """

        oldpath = self.compose_path(oldpath)
        newpath = self.encode(newpath)
        yield from self._handler.symlink(oldpath, newpath)

    @asyncio.coroutine
    def link(self, oldpath, newpath):
        """Create a remote hard link

           This method creates a hard link to the remote file specified
           by oldpath at the location specified by newpath.

           This method may not be supported by all SFTP servers.

           :param oldpath:
               The path of the remote file the hard link should point to
           :param newpath:
               The path of where to create the remote hard link
           :type oldpath: str or bytes
           :type newpath: str or bytes

           :raises: :exc:`SFTPError` if the server doesn't support this
                    extension or returns an error

        """

        oldpath = self.compose_path(oldpath)
        newpath = self.compose_path(newpath)
        yield from self._handler.link(oldpath, newpath)

    def exit(self):
        """Exit the SFTP client session

           This method exits the SFTP client session, closing the
           corresponding channel opened on the server.

        """

        self._handler.exit()

    @asyncio.coroutine
    def wait_closed(self):
        """Wait for this SFTP client session to close"""

        yield from self._handler.wait_closed()


class SFTPServerHandler(SFTPHandler):
    """An SFTP server session handler"""

    _extensions = [(b'posix-rename@openssh.com', b'1'),
                   (b'statvfs@openssh.com', b'2'),
                   (b'fstatvfs@openssh.com', b'2'),
                   (b'hardlink@openssh.com', b'1'),
                   (b'fsync@openssh.com', b'1')]

    def __init__(self, sftp_factory, conn, reader, writer):
        super().__init__(conn, reader, writer)

        self._server = sftp_factory(conn)
        self._version = None
        self._nonstandard_symlink = False
        self._next_handle = 0
        self._file_handles = {}
        self._dir_handles = {}

    @asyncio.coroutine
    def _cleanup(self, exc):
        """Clean up this SFTP server session"""

        if self._server: # pragma: no branch
            for file_obj in self._file_handles.values():
                result = self._server.close(file_obj)

                if asyncio.iscoroutine(result):
                    result = yield from result

            result = self._server.exit()

            if asyncio.iscoroutine(result):
                result = yield from result

            self._server = None
            self._file_handles = []
            self._dir_handles = []

        yield from super()._cleanup(exc)

    def _get_next_handle(self):
        """Get the next available unique file handle number"""

        while True:
            handle = self._next_handle.to_bytes(4, 'big')
            self._next_handle = (self._next_handle + 1) & 0xffffffff

            if (handle not in self._file_handles and
                    handle not in self._dir_handles):
                return handle

    @asyncio.coroutine
    def _process_packet(self, pkttype, pktid, packet):
        """Process incoming SFTP requests"""

        # pylint: disable=broad-except
        try:
            if pkttype == FXP_EXTENDED:
                pkttype = packet.get_string()

            handler = self._packet_handlers.get(pkttype)
            if not handler:
                raise SFTPError(FX_OP_UNSUPPORTED,
                                'Unsupported request type: %s' % pkttype)

            return_type = self._return_types.get(pkttype, FXP_STATUS)
            result = yield from handler(self, packet)

            if return_type == FXP_STATUS:
                result = UInt32(FX_OK) + String('') + String('')
            elif return_type in (FXP_HANDLE, FXP_DATA):
                result = String(result)
            elif return_type == FXP_NAME:
                result = (UInt32(len(result)) +
                          b''.join(name.encode() for name in result))
            else:
                if isinstance(result, os.stat_result):
                    result = SFTPAttrs.from_local(result)
                elif isinstance(result, os.statvfs_result):
                    result = SFTPVFSAttrs.from_local(result)

                result = result.encode()
        except PacketDecodeError as exc:
            return_type = FXP_STATUS
            result = (UInt32(FX_BAD_MESSAGE) + String(str(exc)) +
                      String(DEFAULT_LANG))
        except SFTPError as exc:
            return_type = FXP_STATUS
            result = UInt32(exc.code) + String(exc.reason) + String(exc.lang)
        except NotImplementedError as exc:
            name = handler.__name__[9:]
            return_type = FXP_STATUS
            result = (UInt32(FX_OP_UNSUPPORTED) +
                      String('Operation not supported: %s' % name) +
                      String(DEFAULT_LANG))
        except OSError as exc:
            return_type = FXP_STATUS

            if exc.errno == errno.ENOENT:
                code = FX_NO_SUCH_FILE
            elif exc.errno == errno.EACCES:
                code = FX_PERMISSION_DENIED
            else:
                code = FX_FAILURE

            result = (UInt32(code) + String(exc.strerror) +
                      String(DEFAULT_LANG))
        except Exception as exc: # pragma: no cover
            return_type = FXP_STATUS
            result = (UInt32(FX_FAILURE) +
                      String('Uncaught exception: %s' % str(exc)) +
                      String(DEFAULT_LANG))

        self.send_packet(Byte(return_type), UInt32(pktid), result)

    @asyncio.coroutine
    def _process_open(self, packet):
        """Process an incoming SFTP open request"""

        path = packet.get_string()
        pflags = packet.get_uint32()
        attrs = SFTPAttrs.decode(packet)
        packet.check_end()

        result = self._server.open(path, pflags, attrs)

        if asyncio.iscoroutine(result):
            result = yield from result

        handle = self._get_next_handle()
        self._file_handles[handle] = result
        return handle

    @asyncio.coroutine
    def _process_close(self, packet):
        """Process an incoming SFTP close request"""

        handle = packet.get_string()
        packet.check_end()

        file_obj = self._file_handles.pop(handle, None)
        if file_obj:
            result = self._server.close(file_obj)

            if asyncio.iscoroutine(result):
                yield from result

            return

        if self._dir_handles.pop(handle, None) is not None:
            return

        raise SFTPError(FX_FAILURE, 'Invalid file handle')

    @asyncio.coroutine
    def _process_read(self, packet):
        """Process an incoming SFTP read request"""

        handle = packet.get_string()
        offset = packet.get_uint64()
        length = packet.get_uint32()
        packet.check_end()

        file_obj = self._file_handles.get(handle)

        if file_obj:
            result = self._server.read(file_obj, offset, length)

            if asyncio.iscoroutine(result):
                result = yield from result

            if result:
                return result
            else:
                raise SFTPError(FX_EOF, '')
        else:
            raise SFTPError(FX_FAILURE, 'Invalid file handle')

    @asyncio.coroutine
    def _process_write(self, packet):
        """Process an incoming SFTP write request"""

        handle = packet.get_string()
        offset = packet.get_uint64()
        data = packet.get_string()
        packet.check_end()

        file_obj = self._file_handles.get(handle)

        if file_obj:
            result = self._server.write(file_obj, offset, data)

            if asyncio.iscoroutine(result):
                result = yield from result

            return result
        else:
            raise SFTPError(FX_FAILURE, 'Invalid file handle')

    @asyncio.coroutine
    def _process_lstat(self, packet):
        """Process an incoming SFTP lstat request"""

        path = packet.get_string()
        packet.check_end()

        result = self._server.lstat(path)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_fstat(self, packet):
        """Process an incoming SFTP fstat request"""

        handle = packet.get_string()
        packet.check_end()

        file_obj = self._file_handles.get(handle)

        if file_obj:
            result = self._server.fstat(file_obj)

            if asyncio.iscoroutine(result):
                result = yield from result

            return result
        else:
            raise SFTPError(FX_FAILURE, 'Invalid file handle')

    @asyncio.coroutine
    def _process_setstat(self, packet):
        """Process an incoming SFTP setstat request"""

        path = packet.get_string()
        attrs = SFTPAttrs.decode(packet)
        packet.check_end()

        result = self._server.setstat(path, attrs)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_fsetstat(self, packet):
        """Process an incoming SFTP fsetstat request"""

        handle = packet.get_string()
        attrs = SFTPAttrs.decode(packet)
        packet.check_end()

        file_obj = self._file_handles.get(handle)

        if file_obj:
            result = self._server.fsetstat(file_obj, attrs)

            if asyncio.iscoroutine(result):
                result = yield from result

            return result
        else:
            raise SFTPError(FX_FAILURE, 'Invalid file handle')

    @asyncio.coroutine
    def _process_opendir(self, packet):
        """Process an incoming SFTP opendir request"""

        path = packet.get_string()
        packet.check_end()

        listdir_result = self._server.listdir(path)

        if asyncio.iscoroutine(listdir_result):
            listdir_result = yield from listdir_result

        for i, name in enumerate(listdir_result):
            # pylint: disable=no-member

            if isinstance(name, bytes):
                name = SFTPName(name)
                listdir_result[i] = name

                # pylint: disable=attribute-defined-outside-init

                filename = os.path.join(path, name.filename)
                attr_result = self._server.lstat(filename)

                if asyncio.iscoroutine(attr_result):
                    attr_result = yield from attr_result

                if isinstance(attr_result, os.stat_result):
                    attr_result = SFTPAttrs.from_local(attr_result)

                name.attrs = attr_result

            if not name.longname:
                longname_result = self._server.format_longname(name)

                if asyncio.iscoroutine(longname_result):
                    yield from longname_result

        handle = self._get_next_handle()
        self._dir_handles[handle] = listdir_result
        return handle

    @asyncio.coroutine
    def _process_readdir(self, packet):
        """Process an incoming SFTP readdir request"""

        handle = packet.get_string()
        packet.check_end()

        names = self._dir_handles.get(handle)
        if names:
            self._dir_handles[handle] = []
            return names
        else:
            raise SFTPError(FX_EOF, '')

    @asyncio.coroutine
    def _process_remove(self, packet):
        """Process an incoming SFTP remove request"""

        path = packet.get_string()
        packet.check_end()

        result = self._server.remove(path)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_mkdir(self, packet):
        """Process an incoming SFTP mkdir request"""

        path = packet.get_string()
        attrs = SFTPAttrs.decode(packet)
        packet.check_end()

        result = self._server.mkdir(path, attrs)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_rmdir(self, packet):
        """Process an incoming SFTP rmdir request"""

        path = packet.get_string()
        packet.check_end()

        result = self._server.rmdir(path)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_realpath(self, packet):
        """Process an incoming SFTP realpath request"""

        path = packet.get_string()
        packet.check_end()

        result = self._server.realpath(path)

        if asyncio.iscoroutine(result):
            result = yield from result

        return [SFTPName(result)]

    @asyncio.coroutine
    def _process_stat(self, packet):
        """Process an incoming SFTP stat request"""

        path = packet.get_string()
        packet.check_end()

        result = self._server.stat(path)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_rename(self, packet):
        """Process an incoming SFTP rename request"""

        oldpath = packet.get_string()
        newpath = packet.get_string()
        packet.check_end()

        result = self._server.rename(oldpath, newpath)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_readlink(self, packet):
        """Process an incoming SFTP readlink request"""

        path = packet.get_string()
        packet.check_end()

        result = self._server.readlink(path)

        if asyncio.iscoroutine(result):
            result = yield from result

        return [SFTPName(result)]

    @asyncio.coroutine
    def _process_symlink(self, packet):
        """Process an incoming SFTP symlink request"""

        if self._nonstandard_symlink:
            oldpath = packet.get_string()
            newpath = packet.get_string()
        else:
            newpath = packet.get_string()
            oldpath = packet.get_string()

        packet.check_end()

        result = self._server.symlink(oldpath, newpath)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_posix_rename(self, packet):
        """Process an incoming SFTP POSIX rename request"""

        oldpath = packet.get_string()
        newpath = packet.get_string()
        packet.check_end()

        result = self._server.posix_rename(oldpath, newpath)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_statvfs(self, packet):
        """Process an incoming SFTP statvfs request"""

        path = packet.get_string()
        packet.check_end()

        result = self._server.statvfs(path)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_fstatvfs(self, packet):
        """Process an incoming SFTP fstatvfs request"""

        handle = packet.get_string()
        packet.check_end()

        file_obj = self._file_handles.get(handle)

        if file_obj:
            result = self._server.fstatvfs(file_obj)

            if asyncio.iscoroutine(result):
                result = yield from result

            return result
        else:
            raise SFTPError(FX_FAILURE, 'Invalid file handle')

    @asyncio.coroutine
    def _process_link(self, packet):
        """Process an incoming SFTP hard link request"""

        oldpath = packet.get_string()
        newpath = packet.get_string()
        packet.check_end()

        result = self._server.link(oldpath, newpath)

        if asyncio.iscoroutine(result):
            result = yield from result

        return result

    @asyncio.coroutine
    def _process_fsync(self, packet):
        """Process an incoming SFTP fsync request"""

        handle = packet.get_string()
        packet.check_end()

        file_obj = self._file_handles.get(handle)

        if file_obj:
            result = self._server.fsync(file_obj)

            if asyncio.iscoroutine(result):
                result = yield from result

            return result
        else:
            raise SFTPError(FX_FAILURE, 'Invalid file handle')

    _packet_handlers = {
        FXP_OPEN:                     _process_open,
        FXP_CLOSE:                    _process_close,
        FXP_READ:                     _process_read,
        FXP_WRITE:                    _process_write,
        FXP_LSTAT:                    _process_lstat,
        FXP_FSTAT:                    _process_fstat,
        FXP_SETSTAT:                  _process_setstat,
        FXP_FSETSTAT:                 _process_fsetstat,
        FXP_OPENDIR:                  _process_opendir,
        FXP_READDIR:                  _process_readdir,
        FXP_REMOVE:                   _process_remove,
        FXP_MKDIR:                    _process_mkdir,
        FXP_RMDIR:                    _process_rmdir,
        FXP_REALPATH:                 _process_realpath,
        FXP_STAT:                     _process_stat,
        FXP_RENAME:                   _process_rename,
        FXP_READLINK:                 _process_readlink,
        FXP_SYMLINK:                  _process_symlink,
        b'posix-rename@openssh.com':  _process_posix_rename,
        b'statvfs@openssh.com':       _process_statvfs,
        b'fstatvfs@openssh.com':      _process_fstatvfs,
        b'hardlink@openssh.com':      _process_link,
        b'fsync@openssh.com':         _process_fsync
    }

    @asyncio.coroutine
    def start(self):
        """Start a new SFTP server"""

        try:
            packet = yield from self.recv_packet()

            pkttype = packet.get_byte()
            version = packet.get_uint32()
        except PacketDecodeError as exc:
            yield from self._cleanup(SFTPError(FX_BAD_MESSAGE, str(exc)))
            return
        except SFTPError as exc:
            yield from self._cleanup(exc)
            return

        if pkttype != FXP_INIT:
            yield from self._cleanup(SFTPError(FX_BAD_MESSAGE,
                                               'Expected init message'))
            return

        version = min(version, _SFTP_VERSION)
        extensions = (String(name) + String(data)
                      for name, data in self._extensions)

        try:
            self.send_packet(Byte(FXP_VERSION), UInt32(version), *extensions)
        except SFTPError as exc:
            yield from self._cleanup(exc)
            return

        if version == 3:
            # Check if the server has a buggy SYMLINK implementation

            client_version = self._reader.get_extra_info('client_version', '')
            if any(name in client_version
                   for name in self._nonstandard_symlink_impls):
                self._nonstandard_symlink = True

        yield from self.recv_packets()


class SFTPServer:
    """SFTP server

       Applications should subclass this when implementing an SFTP
       server. The methods listed below should be implemented to
       provide the desired application behavior.

           .. note:: Any method can optionally be defined as a
                     coroutine if that method needs to perform
                     blocking opertions to determine its result.

       The ``conn`` object provided here refers to the
       :class:`SSHServerConnection` instance this SFTP server is
       associated with. It can be queried to determine which user
       the client authenticated as or to request key and certificate
       options or permissions which should be applied to this session.

       If the ``chroot`` argument is specified when this object is
       created, the default :meth:`map_path` and :meth:`reverse_map_path`
       methods will enforce a virtual root directory starting in that
       location, limiting access to only files within that directory
       tree. This will also affect path names returned by the
       :meth:`realpath` and :meth:`readlink` methods.

    """

    # The default implementation of a number of these methods don't need self
    # pylint: disable=no-self-use

    def __init__(self, conn, chroot=None):
        # pylint: disable=unused-argument

        if chroot:
            self._chroot = os.fsencode(os.path.realpath(chroot))
        else:
            self._chroot = None

    def format_longname(self, name):
        """Format the long name associated with an SFTP name

           This method fills in the ``longname`` field of a
           :class:`SFTPName` object. By default, it generates
           something similar to UNIX "ls -l" output. The ``filename``
           and ``attrs`` fields of the :class:`SFTPName` should
           already be filled in before this method is called.

           :param name:
               The :class:`SFTPName` instance to format the long name for
           :type name: :class:`SFTPName`

        """

        if name.attrs.permissions is not None:
            mode = stat.filemode(name.attrs.permissions)
        else:
            mode = ''

        nlink = str(name.attrs.nlink) if name.attrs.nlink else ''

        user = _get_user_name(name.attrs.uid)
        group = _get_group_name(name.attrs.gid)

        size = str(name.attrs.size) if name.attrs.size is not None else ''

        if name.attrs.mtime is not None:
            now = time.time()
            mtime = time.localtime(name.attrs.mtime)
            modtime = time.strftime('%b ', mtime)

            try:
                modtime += time.strftime('%e', mtime)
            except ValueError:
                modtime += time.strftime('%d', mtime)

            if now - 365*24*60*60/2 < name.attrs.mtime <= now:
                modtime += time.strftime(' %H:%M', mtime)
            else:
                modtime += time.strftime('  %Y', mtime)
        else:
            modtime = ''

        detail = '{:10s} {:>4s} {:8s} {:8s} {:>8s} {:12s} '.format(
            mode, nlink, user, group, size, modtime)

        name.longname = detail.encode('utf-8') + name.filename

    def map_path(self, path):
        """Map the path requested by the client to a local path

           This method can be overridden to provide a custom mapping
           from path names requested by the client to paths in the local
           filesystem. By default, it will enforce a virtual "chroot"
           if one was specified when this server was created. Otherwise,
           path names are left unchanged, with relative paths being
           interpreted based on the working directory of the currently
           running process.

           :param bytes path:
               The path name to map

           :returns: bytes containing he local path name to operate on

        """

        if self._chroot:
            normpath = os.path.normpath(os.path.join(b'/', path))
            return os.path.join(self._chroot, normpath[1:])
        else:
            return path

    def reverse_map_path(self, path):
        """Reverse map a local path into the path reported to the client

           This method can be overridden to provide a custom reverse
           mapping for the mapping provided by :meth:`map_path`. By
           default, it hides the portion of the local path associated
           with the virtual "chroot" if one was specified.

           :param bytes path:
               The local path name to reverse map

           :returns: bytes containing the path name to report to the client

        """

        if self._chroot:
            if path == self._chroot:
                return b'/'
            elif path.startswith(self._chroot + b'/'):
                return path[len(self._chroot):]
            else:
                raise SFTPError(FX_NO_SUCH_FILE, 'File not found')
        else:
            return path

    def open(self, path, pflags, attrs):
        """Open a file to serve to a remote client

           This method returns a file object which can be used to read
           and write data and get and set file attributes.

           The possible open mode flags and their meanings are:

             ========== ======================================================
             Mode       Description
             ========== ======================================================
             FXF_READ   Open the file for reading. If neither FXF_READ nor
                        FXF_WRITE are set, this is the default.
             FXF_WRITE  Open the file for writing. If both this and FXF_READ
                        are set, open the file for both reading and writing.
             FXF_APPEND Force writes to append data to the end of the file
                        regardless of seek position.
             FXF_CREAT  Create the file if it doesn't exist. Without this,
                        attempts to open a non-existent file will fail.
             FXF_TRUNC  Truncate the file to zero length if it already exists.
             FXF_EXCL   Return an error when trying to open a file which
                        already exists.
             ========== ======================================================

           The attrs argument is used to set initial attributes of the
           file if it needs to be created. Otherwise, this argument is
           ignored.

           :param bytes path:
               The name of the file to open
           :param int pflags:
               The access mode to use for the file (see above)
           :param attrs:
               File attributes to use if the file needs to be created
           :type attrs: :class:`SFTPAttrs`

           :returns: A file object to use to access the file

           :raises: :exc:`SFTPError` to return an error to the client

        """

        if pflags & FXF_EXCL:
            mode = 'xb'
        elif pflags & FXF_APPEND:
            mode = 'ab'
        elif pflags & FXF_WRITE and not pflags & FXF_READ:
            mode = 'wb'
        else:
            mode = 'rb'

        if pflags & FXF_READ and pflags & FXF_WRITE:
            mode += '+'
            flags = os.O_RDWR
        elif pflags & FXF_WRITE:
            flags = os.O_WRONLY
        else:
            flags = os.O_RDONLY

        if pflags & FXF_APPEND:
            flags |= os.O_APPEND

        if pflags & FXF_CREAT:
            flags |= os.O_CREAT

        if pflags & FXF_TRUNC:
            flags |= os.O_TRUNC

        if pflags & FXF_EXCL:
            flags |= os.O_EXCL

        flags |= getattr(os, 'O_BINARY', 0)

        perms = 0o666 if attrs.permissions is None else attrs.permissions
        return open(self.map_path(path), mode, buffering=0,
                    opener=lambda path, _: os.open(path, flags, perms))

    def close(self, file_obj):
        """Close an open file or directory

           :param file file_obj:
               The file or directory object to close

           :raises: :exc:`SFTPError` to return an error to the client

        """

        file_obj.close()

    def read(self, file_obj, offset, size):
        """Read data from an open file

           :param file file_obj:
               The file to read from
           :param int offset:
               The offset from the beginning of the file to begin reading
           :param int size:
               The number of bytes to read

           :returns: bytes read from the file

           :raises: :exc:`SFTPError` to return an error to the client

        """

        file_obj.seek(offset)
        return file_obj.read(size)

    def write(self, file_obj, offset, data):
        """Write data to an open file

           :param file file_obj:
               The file to write to
           :param int offset:
               The offset from the beginning of the file to begin writing
           :param bytes data:
               The data to write to the file

           :returns: number of bytes written

           :raises: :exc:`SFTPError` to return an error to the client

        """

        file_obj.seek(offset)
        return file_obj.write(data)

    def lstat(self, path):
        """Get attributes of a file, directory, or symlink

           This method queries the attributes of a file, directory,
           or symlink. Unlike :meth:`stat`, this method should
           return the attributes of a symlink itself rather than
           the target of that link.

           :param bytes path:
               The path of the file, directory, or link to get attributes for

           :returns: An :class:`SFTPAttrs` or an os.stat_result containing
                     the file attributes

           :raises: :exc:`SFTPError` to return an error to the client

        """

        return os.lstat(self.map_path(path))

    def fstat(self, file_obj):
        """Get attributes of an open file

           :param file file_obj:
               The file to get attributes for

           :returns: An :class:`SFTPAttrs` or an os.stat_result containing
                     the file attributes

           :raises: :exc:`SFTPError` to return an error to the client

        """

        file_obj.flush()
        return os.fstat(file_obj.fileno())

    def setstat(self, path, attrs):
        """Set attributes of a file or directory

           This method sets attributes of a file or directory. If
           the path provided is a symbolic link, the attributes
           should be set on the target of the link. A subset of the
           fields in ``attrs`` can be initialized and only those
           attributes should be changed.

           :param bytes path:
               The path of the remote file or directory to set attributes for
           :param attrs:
               File attributes to set
           :type attrs: :class:`SFTPAttrs`

           :raises: :exc:`SFTPError` to return an error to the client

        """

        _setstat(self.map_path(path), attrs)

    def fsetstat(self, file_obj, attrs):
        """Set attributes of an open file

           :param attrs:
               File attributes to set on the file
           :type attrs: :class:`SFTPAttrs`

           :raises: :exc:`SFTPError` to return an error to the client

        """

        file_obj.flush()
        _setstat(file_obj.fileno(), attrs)

    def listdir(self, path):
        """List the contents of a directory

           :param bytes path:
               The path of the directory to open

           :returns: A list of names of files in the directory

           :raises: :exc:`SFTPError` to return an error to the client

        """

        return [b'.', b'..'] + os.listdir(self.map_path(path))

    def remove(self, path):
        """Remove a file or symbolic link

           :param bytes path:
               The path of the file or link to remove

           :raises: :exc:`SFTPError` to return an error to the client

        """

        return os.remove(self.map_path(path))

    def mkdir(self, path, attrs):
        """Create a directory with the specified attributes

           :param bytes path:
               The path of where the new directory should be created
           :param attrs:
               The file attributes to use when creating the directory
           :type attrs: :class:`SFTPAttrs`

           :raises: :exc:`SFTPError` to return an error to the client

        """

        mode = 0o777 if attrs.permissions is None else attrs.permissions
        return os.mkdir(self.map_path(path), mode)

    def rmdir(self, path):
        """Remove a directory

           :param bytes path:
               The path of the directory to remove

           :raises: :exc:`SFTPError` to return an error to the client

        """

        return os.rmdir(self.map_path(path))

    def realpath(self, path):
        """Return the canonical version of a path

           :param bytes path:
               The path of the directory to canonicalize

           :returns: bytes containing the canonical path

           :raises: :exc:`SFTPError` to return an error to the client

        """

        return self.reverse_map_path(os.path.realpath(self.map_path(path)))

    def stat(self, path):
        """Get attributes of a file or directory, following symlinks

           This method queries the attributes of a file or directory.
           If the path provided is a symbolic link, the returned
           attributes should correspond to the target of the link.

           :param bytes path:
               The path of the remote file or directory to get attributes for

           :returns: An :class:`SFTPAttrs` or an os.stat_result containing
                     the file attributes

           :raises: :exc:`SFTPError` to return an error to the client

        """

        return os.stat(self.map_path(path))

    def rename(self, oldpath, newpath):
        """Rename a file, directory, or link

           This method renames a file, directory, or link.

           .. note:: This is a request for the standard SFTP version
                     of rename which will not overwrite the new path
                     if it already exists. The :meth:`posix_rename`
                     method will be called if the client requests the
                     POSIX behavior where an existing instance of the
                     new path is removed before the rename.

           :param bytes oldpath:
               The path of the file, directory, or link to rename
           :param bytes newpath:
               The new name for this file, directory, or link

           :raises: :exc:`SFTPError` to return an error to the client

        """

        oldpath = self.map_path(oldpath)
        newpath = self.map_path(newpath)

        if os.path.exists(newpath):
            raise SFTPError(FX_FAILURE, 'File already exists')

        return os.rename(oldpath, newpath)

    def readlink(self, path):
        """Return the target of a symbolic link

           :param bytes path:
               The path of the symbolic link to follow

           :returns: bytes containing the target path of the link

           :raises: :exc:`SFTPError` to return an error to the client

        """

        target = os.readlink(self.map_path(path))

        if os.path.isabs(target):
            return self.reverse_map_path(target)
        else:
            return target

    def symlink(self, oldpath, newpath):
        """Create a symbolic link

           :param bytes oldpath:
               The path the link should point to
           :param bytes newpath:
               The path of where to create the symbolic link

           :raises: :exc:`SFTPError` to return an error to the client

        """

        if posixpath.isabs(oldpath):
            oldpath = self.map_path(oldpath)
        else:
            newdir = posixpath.dirname(newpath)
            abspath1 = self.map_path(posixpath.join(newdir, oldpath))

            mapped_newdir = self.map_path(newdir)
            abspath2 = os.path.join(mapped_newdir, oldpath)

            # Make sure the symlink doesn't point outside the chroot
            if os.path.realpath(abspath1) != os.path.realpath(abspath2):
                oldpath = os.path.relpath(abspath1, start=mapped_newdir)

        newpath = self.map_path(newpath)

        return os.symlink(oldpath, newpath)

    def posix_rename(self, oldpath, newpath):
        """Rename a file, directory, or link with POSIX semantics

           This method renames a file, directory, or link, removing
           the prior instance of new path if it previously existed.

           :param bytes oldpath:
               The path of the file, directory, or link to rename
           :param bytes newpath:
               The new name for this file, directory, or link

           :raises: :exc:`SFTPError` to return an error to the client

        """

        return os.rename(self.map_path(oldpath), self.map_path(newpath))

    def statvfs(self, path):
        """Get attributes of the file system containing a file

           :param bytes path:
               The path of the file system to get attributes for

           :returns: An :class:`SFTPVFSAttrs` or an os.statvfs_result
                     containing the file system attributes

           :raises: :exc:`SFTPError` to return an error to the client

        """

        return os.statvfs(self.map_path(path))

    def fstatvfs(self, file_obj):
        """Return attributes of the file system containing an open file

           :param file file_obj:
               The open file to get file system attributes for

           :returns: An :class:`SFTPVFSAttrs` or an os.statvfs_result
                     containing the file system attributes

           :raises: :exc:`SFTPError` to return an error to the client

        """

        return os.statvfs(file_obj.fileno())

    def link(self, oldpath, newpath):
        """Create a hard link

           :param bytes oldpath:
               The path of the file the hard link should point to
           :param bytes newpath:
               The path of where to create the hard link

           :raises: :exc:`SFTPError` to return an error to the client

        """

        return os.link(self.map_path(oldpath), self.map_path(newpath))

    def fsync(self, file_obj):
        """Force file data to be written to disk

           :param file file_obj:
               The open file containing the data to flush to disk

           :raises: :exc:`SFTPError` to return an error to the client

        """

        os.fsync(file_obj.fileno())

    def exit(self):
        """Shut down this SFTP server"""

        pass
