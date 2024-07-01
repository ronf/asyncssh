# Copyright (c) 2015-2024 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Unit tests for AsyncSSH SFTP client and server"""

import asyncio
import errno
import functools
import os
from pathlib import Path
import posixpath
import shutil
import stat
import sys
import time
import unittest
from unittest.mock import patch

import asyncssh

from asyncssh import SFTPError, SFTPNoSuchFile, SFTPPermissionDenied
from asyncssh import SFTPFailure, SFTPBadMessage, SFTPNoConnection
from asyncssh import SFTPConnectionLost, SFTPOpUnsupported, SFTPInvalidHandle
from asyncssh import SFTPNoSuchPath, SFTPFileAlreadyExists, SFTPWriteProtect
from asyncssh import SFTPNoMedia, SFTPNoSpaceOnFilesystem, SFTPQuotaExceeded
from asyncssh import SFTPUnknownPrincipal, SFTPLockConflict, SFTPDirNotEmpty
from asyncssh import SFTPNotADirectory, SFTPInvalidFilename, SFTPLinkLoop
from asyncssh import SFTPCannotDelete, SFTPInvalidParameter
from asyncssh import SFTPFileIsADirectory, SFTPByteRangeLockConflict
from asyncssh import SFTPByteRangeLockRefused, SFTPDeletePending
from asyncssh import SFTPFileCorrupt, SFTPOwnerInvalid, SFTPGroupInvalid
from asyncssh import SFTPNoMatchingByteRangeLock
from asyncssh import SFTPAttrs, SFTPVFSAttrs, SFTPName, SFTPServer
from asyncssh import SEEK_CUR, SEEK_END
from asyncssh import FXP_INIT, FXP_VERSION, FXP_OPEN, FXP_READ
from asyncssh import FXP_WRITE, FXP_STATUS, FXP_HANDLE, FXP_DATA
from asyncssh import FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC
from asyncssh import FXF_CREATE_NEW, FXF_CREATE_TRUNCATE, FXF_OPEN_EXISTING
from asyncssh import FXF_OPEN_OR_CREATE, FXF_TRUNCATE_EXISTING
from asyncssh import FXF_APPEND_DATA, FXF_BLOCK_READ
from asyncssh import ACE4_READ_DATA, ACE4_WRITE_DATA, ACE4_APPEND_DATA
from asyncssh import FXR_OVERWRITE
from asyncssh import FXRP_STAT_IF_EXISTS, FXRP_STAT_ALWAYS
from asyncssh import FILEXFER_ATTR_UIDGID, FILEXFER_ATTR_OWNERGROUP
from asyncssh import FILEXFER_TYPE_REGULAR, FILEXFER_TYPE_DIRECTORY
from asyncssh import FILEXFER_TYPE_SYMLINK, FILEXFER_TYPE_SPECIAL
from asyncssh import FILEXFER_TYPE_UNKNOWN, FILEXFER_TYPE_SOCKET
from asyncssh import FILEXFER_TYPE_CHAR_DEVICE, FILEXFER_TYPE_BLOCK_DEVICE
from asyncssh import FILEXFER_TYPE_FIFO
from asyncssh import FILEXFER_ATTR_BITS_READONLY, FILEXFER_ATTR_KNOWN_TEXT
from asyncssh import FX_OK, scp

from asyncssh.packet import SSHPacket, String, UInt32
from asyncssh.sftp import LocalFile, SFTPHandler, SFTPServerHandler

from .server import ServerTestCase
from .util import asynctest


def _getpwuid_error(uid):
    """Simulate not being able to resolve user name"""

    # pylint: disable=unused-argument

    raise KeyError


def _getgrgid_error(gid):
    """Simulate not being able to resolve group name"""

    # pylint: disable=unused-argument

    raise KeyError


def tuple_to_nsec(sec, nsec):
    """Convert seconds and remainder to nanoseconds since epoch"""

    return sec * 1_000_000_000 + (nsec or 0)


def lookup_user(uid):
    """Return the user name associated with a uid"""

    try:
        # pylint: disable=import-outside-toplevel
        import pwd

        return pwd.getpwuid(uid).pw_name
    except ImportError: # pragma: no cover
        return ''


def lookup_group(gid):
    """Return the group name associated with a gid"""

    try:
        # pylint: disable=import-outside-toplevel
        import grp

        return grp.getgrgid(gid).gr_name
    except ImportError: # pragma: no cover
        return ''


def remove(files):
    """Remove files and directories"""

    for f in files.split():
        try:
            if os.path.isdir(f) and not os.path.islink(f):
                shutil.rmtree(f)
            else:
                os.remove(f)
        except OSError:
            pass


def sftp_test(func):
    """Decorator for running SFTP tests"""

    @asynctest
    @functools.wraps(func)
    async def sftp_wrapper(self):
        """Run a test after opening an SFTP client"""

        async with self.connect() as conn:
            async with conn.start_sftp_client() as sftp:
                await func(self, sftp)

    return sftp_wrapper


def sftp_test_v4(func):
    """Decorator for running SFTPv4 tests"""

    @asynctest
    @functools.wraps(func)
    async def sftp_wrapper(self):
        """Run a test after opening an SFTP client"""

        async with self.connect() as conn:
            async with conn.start_sftp_client(sftp_version=4) as sftp:
                await func(self, sftp)

    return sftp_wrapper


def sftp_test_v5(func):
    """Decorator for running SFTPv5 tests"""

    @asynctest
    @functools.wraps(func)
    async def sftp_wrapper(self):
        """Run a test after opening an SFTP client"""

        async with self.connect() as conn:
            async with conn.start_sftp_client(sftp_version=5) as sftp:
                await func(self, sftp)

    return sftp_wrapper


def sftp_test_v6(func):
    """Decorator for running SFTPv6 tests"""

    @asynctest
    @functools.wraps(func)
    async def sftp_wrapper(self):
        """Run a test after opening an SFTP client"""

        async with self.connect() as conn:
            async with conn.start_sftp_client(sftp_version=6) as sftp:
                await func(self, sftp)

    return sftp_wrapper


class _ResetFileHandleServerHandler(SFTPServerHandler):
    """Reset file handle counter on each request to test handle-in-use check"""

    async def recv_packet(self):
        """Reset next handle counter to test handle-in-use check"""

        self._next_handle = 0
        return await super().recv_packet()


class _IncompleteMessageServerHandler(SFTPServerHandler):
    """Close the SFTP session in the middle of sending a message"""

    async def run(self):
        """Close the session after sending an incomplete message"""

        await self.recv_packet()
        self._writer.write(UInt32(1))
        self._writer.close()


class _WriteCloseServerHandler(SFTPServerHandler):
    """Close the SFTP session in the middle of a write request"""

    async def _process_packet(self, pkttype, pktid, packet):
        """Close the session when a file close request is received"""

        if pkttype == FXP_WRITE:
            await self._cleanup(None)
        else:
            await super()._process_packet(pkttype, pktid, packet)


class _ReorderReadServerHandler(SFTPServerHandler):
    """Reorder first two read requests"""

    _request = 'delay'

    async def _process_packet(self, pkttype, pktid, packet):
        """Close the session when a file close request is received"""

        if pkttype == FXP_READ:
            if self._request == 'delay':
                self._request = pkttype, pktid, packet
            elif self._request:
                await super()._process_packet(pkttype, pktid, packet)

                pkttype, pktid, packet = self._request
                await super()._process_packet(pkttype, pktid, packet)

                self._request = None
            else:
                await super()._process_packet(pkttype, pktid, packet)
        else:
            await super()._process_packet(pkttype, pktid, packet)


class _CheckPropSFTPServer(SFTPServer):
    """Return an FTP server which checks channel properties"""

    def listdir(self, _path):
        """List the contents of a directory"""

        if self.channel.get_connection() == self.connection: # pragma: no branch
            return [SFTPName(k.encode()) for k in self.env.keys()]


class _ChrootSFTPServer(SFTPServer):
    """Return an FTP server with a changed root"""

    def __init__(self, chan):
        os.mkdir('chroot')
        super().__init__(chan, 'chroot')

    def exit(self):
        """Clean up the changed root directory"""

        remove('chroot')

    def stat(self, path):
        """Get attributes of a file or directory, following symlinks"""

        return SFTPAttrs.from_local(super().stat(path))


class _OpenErrorSFTPServer(SFTPServer):
    """Return an error on file open"""

    async def open56(self, path, desired_access, flags, attrs):
        """Return an error when opening a file"""

        err = getattr(errno, path.decode('ascii'))
        raise OSError(err, os.strerror(err))


class _IOErrorSFTPServer(SFTPServer):
    """Return an I/O error during file writing"""

    async def read(self, file_obj, offset, size):
        """Return an error for reads past 64 KB in a file"""

        if offset >= 65536:
            raise SFTPFailure('I/O error')
        else:
            return super().read(file_obj, offset, size)

    async def write(self, file_obj, offset, data):
        """Return an error for writes past 64 KB in a file"""

        if offset >= 65536:
            raise SFTPFailure('I/O error')
        else:
            super().write(file_obj, offset, data)


class _SmallBlockSizeSFTPServer(SFTPServer):
    """Limit reads to a small block size"""

    async def read(self, file_obj, offset, size):
        """Limit reads to return no more than 4 KB at a time"""

        return super().read(file_obj, offset, min(size, 4096))


class _TruncateSFTPServer(SFTPServer):
    """Truncate a file when it is accessed, simulating a simultaneous writer"""

    async def read(self, file_obj, offset, size):
        """Truncate a file to 32 KB when a read is done"""

        os.truncate('src', 32768)

        return super().read(file_obj, offset, size)


class _NotImplSFTPServer(SFTPServer):
    """Return an error that a request is not implemented"""

    async def symlink(self, oldpath, newpath):
        """Return that symlinks aren't implemented"""

        raise NotImplementedError


class _FileTypeSFTPServer(SFTPServer):
    """Return a list of files of each possible file type"""

    _file_types = ((FILEXFER_TYPE_REGULAR,      stat.S_IFREG),
                   (FILEXFER_TYPE_DIRECTORY,    stat.S_IFDIR),
                   (FILEXFER_TYPE_SYMLINK,      stat.S_IFLNK),
                   (FILEXFER_TYPE_SPECIAL,      0xf000),
                   (FILEXFER_TYPE_UNKNOWN,      0),
                   (FILEXFER_TYPE_SOCKET,       stat.S_IFSOCK),
                   (FILEXFER_TYPE_CHAR_DEVICE,  stat.S_IFCHR),
                   (FILEXFER_TYPE_BLOCK_DEVICE, stat.S_IFBLK),
                   (FILEXFER_TYPE_FIFO,         stat.S_IFIFO))

    def listdir(self, _path):
        """List the contents of a directory"""

        return [SFTPName(str(filetype).encode('ascii'),
                         attrs=SFTPAttrs(permissions=mode))
                for filetype, mode in self._file_types]


class _LongnameSFTPServer(SFTPServer):
    """Return a fixed set of files in response to a listdir request"""

    def listdir(self, _path):
        """List the contents of a directory"""

        # pylint: disable=no-self-use

        return list((b'.',
                     b'..',
                     SFTPName(b'.file'),
                     SFTPName(b'file1'),
                     SFTPName(b'file2', b'', SFTPAttrs(permissions=0, nlink=1,
                                                       uid=0, gid=0,
                                                       size=0, mtime=0)),
                     SFTPName(b'file3', b'', SFTPAttrs(mtime=time.time())),
                     SFTPName(b'file4', 56*b' ' + b'file4')))

    def lstat(self, path):
        """Get attributes of a file, directory, or symlink"""

        return SFTPAttrs.from_local(super().lstat(path))


class _LargeDirSFTPServer(SFTPServer):
    """Return a really large listdir result"""

    async def listdir(self, path):
        """Return a really large listdir result"""

        # pylint: disable=unused-argument

        return 100000 * [SFTPName(b'a', '', SFTPAttrs())]


class _StatVFSSFTPServer(SFTPServer):
    """Return a fixed set of attributes in response to a statvfs request"""

    expected_statvfs = SFTPVFSAttrs(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)

    def statvfs(self, path):
        """Get attributes of the file system containing a file"""

        # pylint: disable=unused-argument

        return self.expected_statvfs

    def fstatvfs(self, file_obj):
        """Return attributes of the file system containing an open file"""

        # pylint: disable=unused-argument

        return self.expected_statvfs


class _ChownSFTPServer(SFTPServer):
    """Simulate file ownership changes"""

    _ownership = {}

    def setstat(self, path, attrs):
        """Get attributes of a file or directory, following symlinks"""

        self._ownership[self.map_path(path)] = \
            (attrs.uid, attrs.gid, attrs.owner, attrs.group)

    def stat(self, path):
        """Get attributes of a file or directory, following symlinks"""

        path = self.map_path(path)
        attrs = SFTPAttrs.from_local(os.stat(path))

        if path in self._ownership: # pragma: no branch
            attrs.uid, attrs.gid, attrs.owner, attrs.group = \
                self._ownership[path]

        return attrs


class _SymlinkSFTPServer(SFTPServer):
    """Implement symlink with non-standard argument order"""

    def symlink(self, oldpath, newpath):
        """Create a symbolic link"""

        # pylint: disable=arguments-out-of-order
        return super().symlink(newpath, oldpath)


class _SFTPAttrsSFTPServer(SFTPServer):
    """Implement stat which returns SFTPAttrs and raises SFTPError"""

    async def stat(self, path):
        """Get attributes of a file or directory, following symlinks"""

        try:
            return SFTPAttrs.from_local(super().stat(path))
        except OSError as exc:
            if exc.errno == errno.EACCES:
                raise SFTPPermissionDenied(exc.strerror) from None
            else:
                raise SFTPError(99, exc.strerror) from None

    async def lstat(self, path):
        """Get attributes of a local file, directory, or symlink"""

        return SFTPAttrs.from_local(super().lstat(path))

    async def fstat(self, file_obj):
        """Get attributes of an open file"""

        return SFTPAttrs.from_local(super().fstat(file_obj))

    async def scandir(self, path):
        """Return names and attributes of the files in a local directory"""

        async for name in super().scandir(path):
            yield name


class _AsyncSFTPServer(SFTPServer):
    """Implement all SFTP callbacks as async methods"""

    # pylint: disable=useless-super-delegation

    async def format_longname(self, name):
        """Format the long name associated with an SFTP name"""

        return super().format_longname(name)

    async def open(self, path, pflags, attrs):
        """Open a file to serve to a remote client"""

        return super().open(path, pflags, attrs)

    async def close(self, file_obj):
        """Close an open file or directory"""

        super().close(file_obj)

    async def read(self, file_obj, offset, size):
        """Read data from an open file"""

        return super().read(file_obj, offset, size)

    async def write(self, file_obj, offset, data):
        """Write data to an open file"""

        return super().write(file_obj, offset, data)

    async def lstat(self, path):
        """Get attributes of a file, directory, or symlink"""

        return super().lstat(path)

    async def fstat(self, file_obj):
        """Get attributes of an open file"""

        return super().fstat(file_obj)

    async def setstat(self, path, attrs):
        """Set attributes of a file or directory, following symlinks"""

        super().setstat(path, attrs)

    async def lsetstat(self, path, attrs):
        """Set attributes of a file, directory, or symlink"""

        super().lsetstat(path, attrs)

    async def fsetstat(self, file_obj, attrs):
        """Set attributes of an open file"""

        super().fsetstat(file_obj, attrs)

    def scandir(self, path):
        """Scan the contents of a directory"""

        return super().scandir(path)

    async def remove(self, path):
        """Remove a file or symbolic link"""

        super().remove(path)

    async def mkdir(self, path, attrs):
        """Create a directory with the specified attributes"""

        super().mkdir(path, attrs)

    async def rmdir(self, path):
        """Remove a directory"""

        super().rmdir(path)

    async def realpath(self, path):
        """Return the canonical version of a path"""

        return super().realpath(path)

    async def stat(self, path):
        """Get attributes of a file or directory, following symlinks"""

        return super().stat(path)

    async def rename(self, oldpath, newpath):
        """Rename a file, directory, or link"""

        super().rename(oldpath, newpath)

    async def readlink(self, path):
        """Return the target of a symbolic link"""

        return super().readlink(path)

    async def symlink(self, oldpath, newpath):
        """Create a symbolic link"""

        super().symlink(oldpath, newpath)

    async def posix_rename(self, oldpath, newpath):
        """Rename a file, directory, or link with POSIX semantics"""

        super().posix_rename(oldpath, newpath)

    async def statvfs(self, path):
        """Get attributes of the file system containing a file"""

        return super().statvfs(path)

    async def fstatvfs(self, file_obj):
        """Return attributes of the file system containing an open file"""

        return super().fstatvfs(file_obj)

    async def link(self, oldpath, newpath):
        """Create a hard link"""

        super().link(oldpath, newpath)

    async def lock(self, file_obj, offset, length, flags):
        """Acquire a byte range lock on an open file"""

        super().lock(file_obj, offset, length, flags)

    async def unlock(self, file_obj, offset, length):
        """Release a byte range lock on an open file"""

        super().unlock(file_obj, offset, length)

    async def fsync(self, file_obj):
        """Force file data to be written to disk"""

        super().fsync(file_obj)


class _CheckSFTP(ServerTestCase):
    """Utility functions for AsyncSSH SFTP unit tests"""

    @classmethod
    def setUpClass(cls):
        """Check if symlink is available on this platform"""

        super().setUpClass()

        try:
            os.symlink('file', 'link')
            os.remove('link')
            cls._symlink_supported = True
        except OSError: # pragma: no cover
            cls._symlink_supported = False

    def _create_file(self, name, data=(), mode=None, utime=None):
        """Create a test file"""

        if data == ():
            data = str(id(self))

        binary = 'b' if isinstance(data, bytes) else ''

        with open(name, 'w' + binary) as f:
            f.write(data)

        if mode is not None:
            os.chmod(name, mode)

        if utime is not None:
            os.utime(name, utime)

    def _check_attr(self, name1, name2, follow_symlinks, check_atime):
        """Check if attributes on two files are equal"""

        statfunc = os.stat if follow_symlinks else os.lstat

        attrs1 = statfunc(name1)
        attrs2 = statfunc(name2)

        self.assertEqual(stat.S_IMODE(attrs1.st_mode),
                         stat.S_IMODE(attrs2.st_mode))
        self.assertEqual(int(attrs1.st_mtime), int(attrs2.st_mtime))

        if check_atime:
            self.assertEqual(int(attrs1.st_atime), int(attrs2.st_atime))

    def _check_file(self, name1, name2, preserve=False, follow_symlinks=False,
                    check_atime=True):
        """Check if two files are equal"""

        if preserve:
            self._check_attr(name1, name2, follow_symlinks, check_atime)

        with open(name1, 'rb') as file1:
            with open(name2, 'rb') as file2:
                self.assertEqual(file1.read(), file2.read())

    def _check_stat(self, sftp_stat, local_stat):
        """Check if file attributes are equal"""

        self.assertEqual(sftp_stat.size, local_stat.st_size)
        self.assertEqual(sftp_stat.uid, local_stat.st_uid)
        self.assertEqual(sftp_stat.gid, local_stat.st_gid)
        self.assertEqual(sftp_stat.permissions, local_stat.st_mode)
        self.assertEqual(sftp_stat.atime, int(local_stat.st_atime))
        self.assertEqual(sftp_stat.mtime, int(local_stat.st_mtime))

    def _check_stat_v4(self, sftp_stat, local_stat):
        """Check if file attributes are equal"""

        self.assertEqual(sftp_stat.size, local_stat.st_size)

        if sys.platform != 'win32': # pragma: no branch
            self.assertEqual(sftp_stat.owner, lookup_user(local_stat.st_uid))
            self.assertEqual(sftp_stat.group, lookup_group(local_stat.st_gid))

        self.assertEqual(sftp_stat.permissions,
                         stat.S_IMODE(local_stat.st_mode))
        self.assertEqual(tuple_to_nsec(sftp_stat.atime, sftp_stat.atime_ns),
                         local_stat.st_atime_ns)
        self.assertEqual(tuple_to_nsec(sftp_stat.mtime, sftp_stat.mtime_ns),
                         local_stat.st_mtime_ns)

    def _check_link(self, link, target):
        """Check if a symlink points to the right target"""

        self.assertEqual(os.readlink(link), target)


class _TestSFTP(_CheckSFTP):
    """Unit tests for AsyncSSH SFTP client and server"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server for the tests to use"""

        return await cls.create_server(sftp_factory=True, sftp_version=6)

    @sftp_test
    async def _dummy_sftp_client(self, sftp):
        """Test starting a new SFTPv3 client session and immediately exiting"""

        self.assertEqual(sftp.version, 3)

    @sftp_test_v5
    async def _dummy_sftp_client_v5(self, sftp):
        """Test starting a new SFTPv5 client session and immediately exiting"""

        self.assertEqual(sftp.version, 5)

    @sftp_test_v6
    async def _dummy_sftp_client_v6(self, sftp):
        """Test starting a new SFTPv6 client session and immediately exiting"""

        self.assertEqual(sftp.version, 6)

    @sftp_test
    async def test_copy(self, sftp):
        """Test copying a file over SFTP"""

        for method in ('get', 'put', 'copy'):
            for src in ('src', b'src', Path('src')):
                with self.subTest(method=method, src=type(src)):
                    try:
                        self._create_file('src')
                        await getattr(sftp, method)(src, 'dst')
                        self._check_file('src', 'dst')
                    finally:
                        remove('src dst')

    @sftp_test
    async def test_copy_progress(self, sftp):
        """Test copying a file over SFTP with progress reporting"""

        def _report_progress(_srcpath, _dstpath, bytes_copied, _total_bytes):
            """Monitor progress of copy"""

            reports.append(bytes_copied)

        for method in ('get', 'put', 'copy'):
            for size in (0, 100000):
                with self.subTest(method=method, size=size):
                    reports = []

                    try:
                        self._create_file('src', size * 'a')
                        await getattr(sftp, method)(
                            'src', 'dst', block_size=8192,
                            progress_handler=_report_progress)
                        self._check_file('src', 'dst')

                        self.assertEqual(len(reports), (size // 8192) + 1)
                        self.assertEqual(reports[-1], size)
                    finally:
                        remove('src dst')

    @sftp_test
    async def test_copy_preserve(self, sftp):
        """Test copying a file with preserved attributes over SFTP"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src', mode=0o666, utime=(1, 2))
                    await getattr(sftp, method)('src', 'dst', preserve=True)
                    self._check_file('src', 'dst', preserve=True)
                finally:
                    remove('src dst')

    @unittest.skipIf(sys.platform == 'win32', 'skip lsetstat tests on Windows')
    @sftp_test
    async def test_copy_preserve_link(self, sftp):
        """Test copying a symlink with preserved attributes over SFTP"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    os.symlink('file', 'link1')
                    os.utime('link1', times=(1, 2), follow_symlinks=False)
                    await getattr(sftp, method)(
                        'link1', 'link2', preserve=True, follow_symlinks=False)
                    self.assertEqual(os.lstat('link2').st_mtime, 2)
                finally:
                    remove('link1 link2')

    @unittest.skipIf(sys.platform == 'win32', 'skip lsetstat tests on Windows')
    def test_copy_preserve_link_unsupported(self):
        """Test preserving symlink attributes over SFTP without lsetstat"""

        @sftp_test
        async def _lsetstat_unsupported(self, sftp):
            """Try copying link attributes without lsetstat"""

            try:
                os.symlink('file', 'link1')
                os.utime('link1', times=(1, 2), follow_symlinks=False)
                await sftp.put('link1', 'link2', preserve=True,
                               follow_symlinks=False)
                self.assertNotEqual(int(os.lstat('link2').st_mtime), 2)
            finally:
                remove('link1 link2')

        with patch('asyncssh.sftp.SFTPServerHandler._extensions', []):
            # pylint: disable=no-value-for-parameter
            _lsetstat_unsupported(self)

    @sftp_test
    async def test_copy_recurse(self, sftp):
        """Test recursively copying a directory over SFTP"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    os.mkdir('src')
                    self._create_file('src/file1')

                    if self._symlink_supported: # pragma: no branch
                        os.symlink('file1', 'src/file2')

                    await getattr(sftp, method)('src', 'dst', recurse=True)

                    self._check_file('src/file1', 'dst/file1')

                    if self._symlink_supported: # pragma: no branch
                        self._check_link('dst/file2', 'file1')
                finally:
                    remove('src dst')

    @sftp_test
    async def test_copy_recurse_existing(self, sftp):
        """Test recursively copying over SFTP where target dir exists"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    os.mkdir('src')
                    os.mkdir('dst')
                    os.mkdir('dst/src')
                    self._create_file('src/file1')

                    if self._symlink_supported: # pragma: no branch
                        os.symlink('file1', 'src/file2')

                    await getattr(sftp, method)('src', 'dst', recurse=True)

                    self._check_file('src/file1', 'dst/src/file1')

                    if self._symlink_supported: # pragma: no branch
                        self._check_link('dst/src/file2', 'file1')
                finally:
                    remove('src dst')

    @sftp_test
    async def test_copy_follow_symlinks(self, sftp):
        """Test copying a file over SFTP while following symlinks"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src')
                    os.symlink('src', 'link')
                    await getattr(sftp, method)('link', 'dst',
                                                follow_symlinks=True)
                    self._check_file('src', 'dst')
                finally:
                    remove('src dst link')

    @sftp_test
    async def test_copy_recurse_follow_symlinks(self, sftp):
        """Test recursively copying over SFTP while following symlinks"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    os.mkdir('src')
                    self._create_file('src/file1')
                    os.symlink('file1', 'src/file2')
                    await getattr(sftp, method)('src', 'dst', recurse=True,
                                                follow_symlinks=True)
                    self._check_file('src/file1', 'dst/file2')
                finally:
                    remove('src dst')

    @sftp_test
    async def test_copy_invalid_name(self, sftp):
        """Test copying a file with an invalid name over SFTP"""

        for method in ('get', 'put', 'copy', 'mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                with self.assertRaises((OSError, SFTPNoSuchFile,
                                        SFTPFailure, UnicodeDecodeError)):
                    await getattr(sftp, method)(b'\xff')

    @sftp_test
    async def test_copy_directory_no_recurse(self, sftp):
        """Test copying a directory over SFTP without recurse option"""

        for method in ('get', 'put', 'copy', 'mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    os.mkdir('dir')
                    with self.assertRaises(SFTPFailure):
                        await getattr(sftp, method)('dir')
                finally:
                    remove('dir')

    @sftp_test_v6
    async def test_copy_directory_no_recurse_v6(self, sftp):
        """Test copying a directory over SFTPv6 without recurse option"""

        for method in ('get', 'put', 'copy', 'mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    os.mkdir('dir')
                    with self.assertRaises(SFTPFileIsADirectory):
                        await getattr(sftp, method)('dir')
                finally:
                    remove('dir')

    @sftp_test
    async def test_multiple_copy(self, sftp):
        """Test copying multiple files over SFTP"""

        for method in ('get', 'put', 'copy'):
            for seq in (list, tuple):
                with self.subTest(method=method):
                    try:
                        self._create_file('src1', 'xxx')
                        self._create_file('src2', 'yyy')
                        os.mkdir('dst')

                        await getattr(sftp, method)(seq(('src1', 'src2')),
                                                    'dst')

                        self._check_file('src1', 'dst/src1')
                        self._check_file('src2', 'dst/src2')
                    finally:
                        remove('src1 src2 dst')

    @sftp_test_v4
    async def test_multiple_copy_v4(self, sftp):
        """Test copying multiple files over SFTPv4"""

        for method in ('get', 'put', 'copy'):
            for seq in (list, tuple):
                with self.subTest(method=method):
                    try:
                        self._create_file('src1', 'xxx')
                        self._create_file('src2', 'yyy')
                        os.mkdir('dst')

                        await getattr(sftp, method)(seq(('src1', 'src2')),
                                                    'dst')

                        self._check_file('src1', 'dst/src1')
                        self._check_file('src2', 'dst/src2')
                    finally:
                        remove('src1 src2 dst')

    @sftp_test_v5
    async def test_multiple_copy_v5(self, sftp):
        """Test copying multiple files over SFTPv5"""

        for method in ('get', 'put', 'copy'):
            for seq in (list, tuple):
                with self.subTest(method=method):
                    try:
                        self._create_file('src1', 'xxx')
                        self._create_file('src2', 'yyy')
                        os.mkdir('dst')

                        await getattr(sftp, method)(seq(('src1', 'src2')),
                                                    'dst')

                        self._check_file('src1', 'dst/src1')
                        self._check_file('src2', 'dst/src2')
                    finally:
                        remove('src1 src2 dst')

    @sftp_test_v6
    async def test_multiple_copy_v6(self, sftp):
        """Test copying multiple files over SFTPv6"""

        for method in ('get', 'put', 'copy'):
            for seq in (list, tuple):
                with self.subTest(method=method):
                    try:
                        self._create_file('src1', 'xxx')
                        self._create_file('src2', 'yyy')
                        os.mkdir('dst')

                        await getattr(sftp, method)(seq(('src1', 'src2')),
                                                    'dst')

                        self._check_file('src1', 'dst/src1')
                        self._check_file('src2', 'dst/src2')
                    finally:
                        remove('src1 src2 dst')

    @sftp_test
    async def test_multiple_copy_glob(self, sftp):
        """Test copying multiple files via glob over SFTP"""

        for method in ('mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src1', 'xxx')
                    self._create_file('src2', 'yyy')
                    os.mkdir('dst')

                    await getattr(sftp, method)(['', 'src*'], 'dst')

                    self._check_file('src1', 'dst/src1')
                    self._check_file('src2', 'dst/src2')
                finally:
                    remove('src1 src2 dst')

    @sftp_test
    async def test_multiple_copy_bytes_path(self, sftp):
        """Test copying multiple files with byte string paths over SFTP"""

        for method in ('mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src1', 'xxx')
                    self._create_file('src2', 'yyy')
                    os.mkdir('dst')

                    await getattr(sftp, method)(b'src*', b'dst')

                    self._check_file('src1', 'dst/src1')
                    self._check_file('src2', 'dst/src2')
                finally:
                    remove('src1 src2 dst')

    @sftp_test
    async def test_multiple_copy_pathlib_path(self, sftp):
        """Test copying multiple files with pathlib paths over SFTP"""

        for method in ('mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src1', 'xxx')
                    self._create_file('src2', 'yyy')
                    os.mkdir('dst')

                    await getattr(sftp, method)(Path('src*'), Path('dst'))

                    self._check_file('src1', 'dst/src1')
                    self._check_file('src2', 'dst/src2')
                finally:
                    remove('src1 src2 dst')

    @sftp_test
    async def test_multiple_copy_target_not_dir(self, sftp):
        """Test copying multiple files over SFTP with non-directory target"""

        for method in ('mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src1')
                    self._create_file('src2')

                    with self.assertRaises(SFTPFailure):
                        await getattr(sftp, method)('src*', 'dst')
                finally:
                    remove('src')

    @sftp_test_v6
    async def test_multiple_copy_target_not_dir_v6(self, sftp):
        """Test copying multiple files over SFTP with non-directory target"""

        for method in ('mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src1')
                    self._create_file('src2')

                    with self.assertRaises(SFTPNotADirectory):
                        await getattr(sftp, method)('src*', 'dst')
                finally:
                    remove('src')

    @sftp_test
    async def test_multiple_copy_error_handler(self, sftp):
        """Test copying multiple files over SFTP with error handler"""

        def err_handler(exc):
            """Catch error for non-recursive copy of directory"""

            self.assertEqual(exc.reason, 'src2 is a directory')

        for method in ('mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src1')
                    os.mkdir('src2')
                    os.mkdir('dst')

                    await getattr(sftp, method)('src*', 'dst',
                                                error_handler=err_handler)

                    self._check_file('src1', 'dst/src1')
                finally:
                    remove('src1 src2 dst')

    @sftp_test
    async def test_glob(self, sftp):
        """Test a glob pattern match over SFTP"""

        glob_tests = (
            ('file*',                    ['file1', 'filedir']),
            ('./file*',                  ['./file1', './filedir']),
            (b'file*',                   [b'file1', b'filedir']),
            (['file*'],                  ['file1', 'filedir']),
            (['', 'file*'],              ['file1', 'filedir']),
            (['file*/*2'],               ['filedir/file2', 'filedir/filedir2']),
            (['file*/*[3-9]'],           ['filedir/file3']),
            (['**/file[12]'],            ['file1', 'filedir/file2']),
            (['**/file*/'],              ['filedir/', 'filedir/filedir2/']),
            (['filedir/**'],             ['filedir', 'filedir/file2',
                                          'filedir/file3', 'filedir/filedir2',
                                          'filedir/filedir2/file4',
                                          'filedir/filedir2/file5']),
            ('filedir/file2',            ['filedir/file2']),
            ('./filedir/file2',          ['./filedir/file2']),
            ('filedir/file*',            ['filedir/file2', 'filedir/file3',
                                          'filedir/filedir2']),
            ('./filedir/file*',          ['./filedir/file2', './filedir/file3',
                                          './filedir/filedir2']),
            ('./filedir/filedir2/file*', ['./filedir/filedir2/file4',
                                          './filedir/filedir2/file5']),
            ('filedir/filedir2/file*',   ['filedir/filedir2/file4',
                                          'filedir/filedir2/file5']),
            ('./filedir/*/file4',        ['./filedir/filedir2/file4']),
            ('filedir/*/file4',          ['filedir/filedir2/file4']),
            ('./*/filedir2/file4',       ['./filedir/filedir2/file4']),
            ('*/filedir2/file4',         ['filedir/filedir2/file4']),
            ('*/filedir2/file*4',        ['filedir/filedir2/file4']),
            ('./filedir/filedir*/file*', ['./filedir/filedir2/file4',
                                          './filedir/filedir2/file5']),
            ('filedir/filedir*/file*',   ['filedir/filedir2/file4',
                                          'filedir/filedir2/file5']),
            ('./**/filedir2/file4',      ['./filedir/filedir2/file4']),
            ('**/filedir2/file4',        ['filedir/filedir2/file4']),
            (['file1', '**/file1'],      ['file1']))

        try:
            os.mkdir('filedir')
            self._create_file('file1')
            self._create_file('filedir/file2')
            self._create_file('filedir/file3')
            os.mkdir('filedir/filedir2')
            self._create_file('filedir/filedir2/file4')
            self._create_file('filedir/filedir2/file5')

            for pattern, matches in glob_tests:
                with self.subTest(pattern=pattern):
                    self.assertEqual(sorted((await sftp.glob(pattern))),
                                     matches)

            self.assertEqual((await sftp.glob([b'fil*1', 'fil*dir'])),
                             [b'file1', 'filedir'])
        finally:
            remove('file1 filedir')

    @sftp_test
    async def test_glob_errors(self, sftp):
        """Test glob pattern match errors over SFTP"""

        _glob_errors = (
            'file*',
            'dir/file1/*',
            'dir*/file1/*',
            'dir/dir1/*')

        try:
            os.mkdir('dir')
            self._create_file('dir/file1')
            os.mkdir('dir/dir1')
            os.chmod('dir/dir1', 0)

            for pattern in _glob_errors:
                with self.subTest(pattern=pattern):
                    with self.assertRaises(SFTPNoSuchFile):
                        await sftp.glob(pattern)
        finally:
            os.chmod('dir/dir1', 0o700)
            remove('dir')

    @sftp_test_v4
    async def test_glob_error_v4(self, sftp):
        """Test a glob pattern match error over SFTP"""

        with self.assertRaises(SFTPNoSuchPath):
            await sftp.glob('file*')

    @sftp_test
    async def test_glob_error_handler(self, sftp):
        """Test a glob pattern match with error handler over SFTP"""

        def err_handler(exc):
            """Catch error for nonexistent file1"""

            self.assertEqual(exc.reason, 'No matches found')

        try:
            self._create_file('file2')

            self.assertEqual((await sftp.glob(['file1*', 'file2*'],
                                              error_handler=err_handler)),
                             ['file2'])
        finally:
            remove('file2')

    @sftp_test
    async def test_stat(self, sftp):
        """Test getting attributes on a file"""

        try:
            os.mkdir('dir')
            self._create_file('file')

            if self._symlink_supported: # pragma: no branch
                os.symlink('bad', 'badlink')
                os.symlink('dir', 'dirlink')
                os.symlink('file', 'filelink')

            self._check_stat((await sftp.stat('dir')), os.stat('dir'))
            self._check_stat((await sftp.stat('file')), os.stat('file'))

            if self._symlink_supported: # pragma: no branch
                self._check_stat((await sftp.stat('dirlink')),
                                 os.stat('dir'))
                self._check_stat((await sftp.stat('filelink')),
                                 os.stat('file'))

                with self.assertRaises(SFTPNoSuchFile):
                    await sftp.stat('badlink')

            self.assertTrue((await sftp.isdir('dir')))
            self.assertFalse((await sftp.isdir('file')))

            if self._symlink_supported: # pragma: no branch
                self.assertFalse((await sftp.isdir('badlink')))
                self.assertTrue((await sftp.isdir('dirlink')))
                self.assertFalse((await sftp.isdir('filelink')))

            self.assertFalse((await sftp.isfile('dir')))
            self.assertTrue((await sftp.isfile('file')))

            if self._symlink_supported: # pragma: no branch
                self.assertFalse((await sftp.isfile('badlink')))
                self.assertFalse((await sftp.isfile('dirlink')))
                self.assertTrue((await sftp.isfile('filelink')))

            self.assertFalse((await sftp.islink('dir')))
            self.assertFalse((await sftp.islink('file')))

            if self._symlink_supported: # pragma: no branch
                self.assertTrue((await sftp.islink('badlink')))
                self.assertTrue((await sftp.islink('dirlink')))
                self.assertTrue((await sftp.islink('filelink')))
        finally:
            remove('dir file badlink dirlink filelink')

    @sftp_test
    async def test_lstat(self, sftp):
        """Test getting attributes on a link"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            os.symlink('file', 'link')
            self._check_stat((await sftp.lstat('link')), os.lstat('link'))
        finally:
            remove('link')

    @sftp_test_v4
    async def test_lstat_v4(self, sftp):
        """Test getting attributes on a link with SFTPv4"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            os.symlink('file', 'link')
            self._check_stat_v4((await sftp.lstat('link')), os.lstat('link'))
        finally:
            remove('link')

    @sftp_test_v6
    async def test_lstat_v6(self, sftp):
        """Test getting attributes on a link with SFTPv6"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            os.symlink('file', 'link')
            self._check_stat_v4((await sftp.lstat('link')), os.lstat('link'))
        finally:
            remove('link')

    @sftp_test
    async def test_lstat_via_stat(self, sftp):
        """Test getting attributes on a link by disabling follow_symlinks"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            os.symlink('file', 'link')
            self._check_stat((await sftp.stat('link', follow_symlinks=False)),
                             os.lstat('link'))
        finally:
            remove('link')

    @sftp_test
    async def test_setstat(self, sftp):
        """Test setting attributes on a file"""

        try:
            self._create_file('file')
            await sftp.setstat('file', SFTPAttrs(permissions=0o666))
            self.assertEqual(stat.S_IMODE(os.stat('file').st_mode), 0o666)

            with self.assertRaises(ValueError):
                await sftp.setstat('file', SFTPAttrs(owner='root',
                                                     group='wheel'))
        finally:
            remove('file')

    @sftp_test_v4
    async def test_setstat_v4(self, sftp):
        """Test setting attributes on a file"""

        try:
            self._create_file('file')

            await sftp.setstat('file', SFTPAttrs(atime=1))

            stat_result = os.stat('file')
            self.assertEqual(stat_result.st_atime, 1)

            await sftp.setstat('file', SFTPAttrs(mtime=2))

            stat_result = os.stat('file')
            self.assertEqual(stat_result.st_mtime, 2)
        finally:
            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip uid/gid tests on Windows')
    @sftp_test_v6
    async def test_setstat_invalid_owner_group_v6(self, sftp):
        """Test setting invalid owner/group on a file"""

        try:
            self._create_file('file')

            with patch('pwd.getpwuid', _getpwuid_error):
                with self.assertRaises(SFTPOwnerInvalid):
                    await sftp.setstat('file', SFTPAttrs(owner='xxx',
                                                         group='0'))

            with patch('grp.getgrgid', _getgrgid_error):
                with self.assertRaises(SFTPGroupInvalid):
                    await sftp.setstat('file', SFTPAttrs(owner='0',
                                                         group='yyy'))
        finally:
            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip lsetstat tests on Windows')
    @sftp_test
    async def test_lsetstat(self, sftp):
        """Test setting attributes on a link"""

        try:
            os.symlink('file', 'link')

            await sftp.setstat('link', SFTPAttrs(atime=1, mtime=2),
                               follow_symlinks=False)

            stat_result = os.lstat('link')
            self.assertEqual(stat_result.st_atime, 1)
            self.assertEqual(stat_result.st_mtime, 2)
        finally:
            remove('link')

    @unittest.skipIf(sys.platform == 'win32', 'skip lsetstat tests on Windows')
    @sftp_test_v4
    async def test_lsetstat_v4(self, sftp):
        """Test setting attributes on a link"""

        try:
            os.symlink('file', 'link')

            await sftp.setstat('link', SFTPAttrs(atime=1),
                               follow_symlinks=False)

            self.assertEqual(os.lstat('link').st_atime, 1)

            await sftp.setstat('link', SFTPAttrs(mtime=2),
                               follow_symlinks=False)

            self.assertEqual(os.lstat('link').st_mtime, 2)
        finally:
            remove('link')

    @unittest.skipIf(sys.platform == 'win32', 'skip lsetstat tests on Windows')
    @sftp_test_v6
    async def test_lsetstat_v6(self, sftp):
        """Test setting attributes on a link"""

        try:
            os.symlink('file', 'link')

            await sftp.setstat('link', SFTPAttrs(atime=1),
                               follow_symlinks=False)

            self.assertEqual(os.lstat('link').st_atime, 1)

            await sftp.setstat('link', SFTPAttrs(mtime=2),
                               follow_symlinks=False)

            self.assertEqual(os.lstat('link').st_mtime, 2)
        finally:
            remove('link')

    @unittest.skipIf(sys.platform == 'win32', 'skip statvfs tests on Windows')
    @sftp_test
    async def test_statvfs(self, sftp):
        """Test getting attributes on a filesystem

           We can't compare the values returned by a live statvfs call since
           they can change at any time. See the separate _TestSFTStatPVFS
           class for a more complete test, but this is left in for code
           coverage purposes.

        """

        self.assertIsInstance((await sftp.statvfs('.')), SFTPVFSAttrs)

    @sftp_test
    async def test_truncate(self, sftp):
        """Test truncating a file"""

        try:
            self._create_file('file', '01234567890123456789')

            await sftp.truncate('file', 10)
            self.assertEqual((await sftp.getsize('file')), 10)

            with open('file') as localf:
                self.assertEqual(localf.read(), '0123456789')
        finally:
            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip chown tests on Windows')
    @sftp_test
    async def test_chown(self, sftp):
        """Test changing ownership of a file

           We can't change to a different user/group here if we're not
           root, so just change to the same user/group. See the separate
           _TestSFTPChown class for a more complete test, but this is
           left in for code coverage purposes.

        """

        try:
            self._create_file('file')
            stat_result = os.stat('file')

            await sftp.chown('file', stat_result.st_uid, stat_result.st_gid)

            new_stat_result = os.stat('file')
            self.assertEqual(new_stat_result.st_uid, stat_result.st_uid)
            self.assertEqual(new_stat_result.st_gid, stat_result.st_gid)
        finally:
            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip chown tests on Windows')
    @sftp_test_v4
    async def test_chown_v4(self, sftp):
        """Test changing ownership of a file

           We can't change to a different user/group here if we're not
           root, so just change to the same user/group. See the separate
           _TestSFTPChown class for a more complete test, but this is
           left in for code coverage purposes.

        """

        try:
            self._create_file('file')
            stat_result = os.stat('file')

            owner = lookup_user(stat_result.st_uid)
            group = lookup_group(stat_result.st_gid)

            await sftp.chown('file', owner, group)

            new_stat_result = os.stat('file')
            self.assertEqual(new_stat_result.st_uid, stat_result.st_uid)
            self.assertEqual(new_stat_result.st_gid, stat_result.st_gid)

            await sftp.chown('file', str(stat_result.st_uid), group)

            new_stat_result = os.stat('file')
            self.assertEqual(new_stat_result.st_uid, stat_result.st_uid)
            self.assertEqual(new_stat_result.st_gid, stat_result.st_gid)

            await sftp.chown('file', owner, str(stat_result.st_gid))

            new_stat_result = os.stat('file')
            self.assertEqual(new_stat_result.st_uid, stat_result.st_uid)
            self.assertEqual(new_stat_result.st_gid, stat_result.st_gid)

            await sftp.chown('file', str(stat_result.st_uid), group)

            new_stat_result = os.stat('file')
            self.assertEqual(new_stat_result.st_uid, stat_result.st_uid)
            self.assertEqual(new_stat_result.st_gid, stat_result.st_gid)

            await sftp.chown('file', owner, str(stat_result.st_gid))

            new_stat_result = os.stat('file')
            self.assertEqual(new_stat_result.st_uid, stat_result.st_uid)
            self.assertEqual(new_stat_result.st_gid, stat_result.st_gid)
        finally:
            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip chmod tests on Windows')
    @sftp_test
    async def test_chmod(self, sftp):
        """Test changing permissions on a file"""

        try:
            self._create_file('file')
            await sftp.chmod('file', 0o4321)
            self.assertEqual(stat.S_IMODE(os.stat('file').st_mode), 0o4321)
        finally:
            remove('file')

    @sftp_test
    async def test_utime(self, sftp):
        """Test changing access and modify times on a file"""

        try:
            self._create_file('file')

            await sftp.utime('file')
            await sftp.utime('file', (1, 2))

            stat_result = os.stat('file')
            self.assertEqual(stat_result.st_atime, 1)
            self.assertEqual(stat_result.st_mtime, 2)
            self.assertEqual((await sftp.getatime('file')), 1)
            self.assertEqual((await sftp.getmtime('file')), 2)
        finally:
            remove('file')

    @sftp_test_v4
    async def test_utime_v4(self, sftp):
        """Test changing access and modify times on a file with SFTPv4"""

        try:
            self._create_file('file')

            await sftp.utime('file')
            await sftp.utime('file', (1.0, 2.25))

            stat_result = os.stat('file')
            self.assertEqual(stat_result.st_atime, 1.0)
            self.assertEqual(stat_result.st_atime_ns, 1000000000)
            self.assertEqual(stat_result.st_mtime, 2.25)
            self.assertEqual(stat_result.st_mtime_ns, 2250000000)
            self.assertEqual((await sftp.getatime('file')), 1.0)
            self.assertEqual((await sftp.getatime_ns('file')), 1000000000)
            self.assertIsNotNone((await sftp.getcrtime('file')))
            self.assertIsNotNone((await sftp.getcrtime_ns('file')))
            self.assertEqual((await sftp.getmtime('file')), 2.25)
            self.assertEqual((await sftp.getmtime_ns('file')), 2250000000)

            await sftp.utime('file', ns=(3500000000, 4750000000))

            stat_result = os.stat('file')
            self.assertEqual(stat_result.st_atime, 3.5)
            self.assertEqual(stat_result.st_atime_ns, 3500000000)
            self.assertEqual(stat_result.st_mtime, 4.75)
            self.assertEqual(stat_result.st_mtime_ns, 4750000000)
            self.assertEqual((await sftp.getatime('file')), 3.5)
            self.assertEqual((await sftp.getatime_ns('file')), 3500000000)
            self.assertIsNotNone((await sftp.getcrtime('file')))
            self.assertIsNotNone((await sftp.getcrtime_ns('file')))
            self.assertEqual((await sftp.getmtime('file')), 4.75)
            self.assertEqual((await sftp.getmtime_ns('file')), 4750000000)
        finally:
            remove('file')

    @sftp_test
    async def test_exists(self, sftp):
        """Test checking whether a file exists"""

        try:
            self._create_file('file1')

            self.assertTrue((await sftp.exists('file1')))
            self.assertFalse((await sftp.exists('file2')))
        finally:
            remove('file1')

    @sftp_test
    async def test_lexists(self, sftp):
        """Test checking whether a link exists"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            os.symlink('file', 'link1')

            self.assertTrue((await sftp.lexists('link1')))
            self.assertFalse((await sftp.lexists('link2')))
        finally:
            remove('link1')

    @sftp_test
    async def test_remove(self, sftp):
        """Test removing a file"""

        try:
            self._create_file('file')
            await sftp.remove('file')

            with self.assertRaises(FileNotFoundError):
                os.stat('file')

            with self.assertRaises(SFTPNoSuchFile):
                await sftp.remove('file')
        finally:
            remove('file')

    @sftp_test
    async def test_unlink(self, sftp):
        """Test unlinking a file"""

        try:
            self._create_file('file')
            await sftp.unlink('file')

            with self.assertRaises(FileNotFoundError):
                os.stat('file')

            with self.assertRaises(SFTPNoSuchFile):
                await sftp.unlink('file')
        finally:
            remove('file')

    @sftp_test
    async def test_rename(self, sftp):
        """Test renaming a file"""

        try:
            self._create_file('file1', 'xxx')
            self._create_file('file2', 'yyy')

            with self.assertRaises(SFTPFailure):
                await sftp.rename('file1', 'file2')

            await sftp.rename('file1', 'file3')

            with open('file3') as localf:
                self.assertEqual(localf.read(), 'xxx')

            await sftp.rename('file2', 'file3', FXR_OVERWRITE)

            with open('file3') as localf:
                self.assertEqual(localf.read(), 'yyy')
        finally:
            remove('file1 file2 file3')

    @sftp_test_v6
    async def test_rename_v6(self, sftp):
        """Test renaming a file with SFTPv6"""

        try:
            self._create_file('file1', 'xxx')
            self._create_file('file2', 'yyy')

            with self.assertRaises(SFTPFileAlreadyExists):
                await sftp.rename('file1', 'file2')

            await sftp.rename('file1', 'file3')

            with open('file3') as localf:
                self.assertEqual(localf.read(), 'xxx')

            await sftp.rename('file2', 'file3', FXR_OVERWRITE)

            with open('file3') as localf:
                self.assertEqual(localf.read(), 'yyy')
        finally:
            remove('file1 file2 file3')

    @sftp_test
    async def test_posix_rename(self, sftp):
        """Test renaming a file that replaces a target file"""

        try:
            self._create_file('file1', 'xxx')
            self._create_file('file2', 'yyy')

            await sftp.posix_rename('file1', 'file2')

            with open('file2') as localf:
                self.assertEqual(localf.read(), 'xxx')
        finally:
            remove('file1 file2')

    @sftp_test_v6
    async def test_posix_rename_v6(self, sftp):
        """Test renaming a file that replaces a target file"""

        try:
            self._create_file('file1', 'xxx')
            self._create_file('file2', 'yyy')

            await sftp.posix_rename('file1', 'file2')

            with open('file2') as localf:
                self.assertEqual(localf.read(), 'xxx')
        finally:
            remove('file1 file2')

    @sftp_test
    async def test_listdir(self, sftp):
        """Test listing files in a directory"""

        try:
            os.mkdir('dir')
            self._create_file('dir/file1')
            self._create_file('dir/file2')
            self.assertEqual(sorted((await sftp.listdir('dir'))),
                             ['.', '..', 'file1', 'file2'])
        finally:
            remove('dir')

    @sftp_test_v4
    async def test_listdir_v4(self, sftp):
        """Test listing files in a directory with SFTPv4"""

        try:
            os.mkdir('dir')
            self._create_file('dir/file1')
            self._create_file('dir/file2')
            self.assertEqual(sorted((await sftp.listdir('dir'))),
                             ['.', '..', 'file1', 'file2'])
        finally:
            remove('dir')

    @sftp_test_v4
    async def test_listdir_error_v4(self, sftp):
        """Test error while listing contents of a directory"""

        orig_readdir = asyncssh.sftp.SFTPClientHandler.readdir

        async def _readdir_error(self, handle):
            """Return an error on an SFTP readdir request"""

            # pylint: disable=unused-argument

            return await orig_readdir(self, b'\xff\xff\xff\xff')

        try:
            os.mkdir('dir')

            with patch('asyncssh.sftp.SFTPClientHandler.readdir',
                       _readdir_error):
                with self.assertRaises(SFTPInvalidHandle):
                    await sftp.listdir('dir')
        finally:
            remove('dir')

    @sftp_test
    async def test_mkdir(self, sftp):
        """Test creating a directory"""

        try:
            await sftp.mkdir('dir')
            self.assertTrue(os.path.isdir('dir'))
        finally:
            remove('dir')

    @sftp_test
    async def test_rmdir(self, sftp):
        """Test removing a directory"""

        try:
            os.mkdir('dir')
            await sftp.rmdir('dir')

            with self.assertRaises(FileNotFoundError):
                os.stat('dir')
        finally:
            remove('dir')

    @sftp_test_v6
    async def test_rmdir_not_empty_v6(self, sftp):
        """Test rmdir on a non-empty directory"""

        try:
            os.mkdir('dir')
            self._create_file('dir/file')

            with self.assertRaises(SFTPDirNotEmpty):
                await sftp.rmdir('dir')
        finally:
            remove('dir')

    @sftp_test_v6
    async def test_open_file_dir_v6(self, sftp):
        """Test open on a directory"""

        try:
            os.mkdir('dir')

            with self.assertRaises((SFTPPermissionDenied,
                                    SFTPFileIsADirectory)):
                await sftp.open('dir')
        finally:
            remove('dir')

    @sftp_test
    async def test_rmtree(self, sftp):
        """Test removing a directory tree"""

        try:
            os.mkdir('dir')
            os.mkdir('dir/dir1')
            os.mkdir('dir/dir1/dir2')
            os.mkdir('dir/dir3')
            self._create_file('dir/file1')
            self._create_file('dir/file2')
            self._create_file('dir/dir1/file3')
            await sftp.rmtree('dir')

            with self.assertRaises(FileNotFoundError):
                os.stat('dir')
        finally:
            remove('dir')

    @sftp_test
    async def test_rmtree_non_existent(self, sftp):
        """Test passing a non-existent directory to rmtree"""

        with self.assertRaises(SFTPNoSuchFile):
            await sftp.rmtree('xxx')

    @sftp_test
    async def test_rmtree_ignore_errors(self, sftp):
        """Test ignoring errors in rmtree"""

        await sftp.rmtree('xxx', ignore_errors=True)

    @sftp_test
    async def test_rmtree_onerror(self, sftp):
        """Test onerror callback in rmtree"""

        def _error_handler(*args):
            errors.append(args)

        errors = []

        await sftp.rmtree('xxx', onerror=_error_handler)

        self.assertEqual(errors[0][0], sftp.scandir)
        self.assertEqual(errors[0][1], b'xxx')
        self.assertEqual(errors[0][2][0], SFTPNoSuchFile)

    @sftp_test
    async def test_rmtree_file(self, sftp):
        """Test passing a file to rmtree"""

        try:
            self._create_file('file')

            with self.assertRaises(SFTPNoSuchFile):
                await sftp.rmtree('file')
        finally:
            remove('file')

    @sftp_test
    async def test_rmtree_symlink(self, sftp):
        """Test passing a symlink to rmtree"""

        try:
            os.mkdir('dir')
            os.symlink('dir', 'link')

            with self.assertRaises(SFTPNoSuchFile):
                await sftp.rmtree('link')
        finally:
            remove('dir link')

    @sftp_test
    async def test_rmtree_symlink_onerror(self, sftp):
        """Test passing a symlink to rmtree with onerror callback"""

        def _error_handler(*args):
            errors.append(args)

        errors = []

        try:
            os.mkdir('dir')
            os.symlink('dir', 'link')

            await sftp.rmtree('link', onerror=_error_handler)

            self.assertEqual(errors[0][0], sftp.islink)
            self.assertEqual(errors[0][1], b'link')
            self.assertEqual(errors[0][2][0], SFTPNoSuchFile)
        finally:
            remove('dir link')

    @sftp_test
    async def test_rmtree_rmdir_failure(self, sftp):
        """Test rmdir failing in rmtree"""

        try:
            os.mkdir('dir')
            os.mkdir('dir/subdir')
            os.chmod('dir', 0o555)

            with self.assertRaises(SFTPPermissionDenied):
                await sftp.rmtree('dir')
        finally:
            os.chmod('dir', 0o755)
            remove('dir')

    @sftp_test
    async def test_rmtree_unlink_failure(self, sftp):
        """Test unlink failing in rmtree"""

        try:
            os.mkdir('dir')
            self._create_file('dir/file')
            os.chmod('dir', 0o555)

            with self.assertRaises(SFTPPermissionDenied):
                await sftp.rmtree('dir')
        finally:
            os.chmod('dir', 0o755)
            remove('dir')

    @sftp_test
    async def test_readlink(self, sftp):
        """Test reading a symlink"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            os.symlink('/file', 'link')
            self.assertEqual((await sftp.readlink('link')), '/file')
            self.assertEqual((await sftp.readlink(b'link')), b'/file')
        finally:
            remove('link')

    @sftp_test_v6
    async def test_readlink_v6(self, sftp):
        """Test reading a symlink with SFTPv6"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            os.symlink('/file', 'link')
            self.assertEqual((await sftp.readlink('link')), '/file')
            self.assertEqual((await sftp.readlink(b'link')), b'/file')
        finally:
            remove('link')

    @sftp_test
    async def test_readlink_decode_error(self, sftp):
        """Test unicode decode error while reading a symlink"""

        async def _readlink_error(self, path):
            """Return invalid unicode on an SFTP readlink request"""

            # pylint: disable=unused-argument

            return [SFTPName(b'\xff')], False

        with patch('asyncssh.sftp.SFTPClientHandler.readlink',
                   _readlink_error):
            with self.assertRaises(SFTPBadMessage):
                await sftp.readlink('link')

    @sftp_test
    async def test_symlink(self, sftp):
        """Test creating a symlink"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            await sftp.symlink('file', 'link')
            self._check_link('link', 'file')

            with self.assertRaises(SFTPFailure):
                await sftp.symlink('file', 'link')
        finally:
            remove('file link')

    @sftp_test_v4
    async def test_symlink_v4(self, sftp):
        """Test creating a symlink with SFTPv4"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            await sftp.symlink('file', 'link')
            self._check_link('link', 'file')

            with self.assertRaises(SFTPFileAlreadyExists):
                await sftp.symlink('file', 'link')
        finally:
            remove('file link')

    @sftp_test_v6
    async def test_symlink_v6(self, sftp):
        """Test creating a symlink with SFTPv6"""

        try:
            await sftp.symlink('file', 'link')
            self._check_link('link', 'file')

            with self.assertRaises(SFTPFileAlreadyExists):
                await sftp.symlink('file', 'link')
        finally:
            remove('file link')

    @asynctest
    async def test_symlink_encode_error(self):
        """Test creating a unicode symlink with no path encoding set"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        async with self.connect() as conn:
            async with conn.start_sftp_client(path_encoding=None) as sftp:
                with self.assertRaises(SFTPBadMessage):
                    await sftp.symlink('file', 'link')

    @asynctest
    async def test_nonstandard_symlink_client(self):
        """Test creating a symlink with opposite argument order"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            async with self.connect(client_version='OpenSSH') as conn:
                async with conn.start_sftp_client() as sftp:
                    await sftp.symlink('link', 'file')
                    self._check_link('link', 'file')
        finally:
            remove('file link')

    @sftp_test
    async def test_link(self, sftp):
        """Test creating a hard link"""

        try:
            self._create_file('file1')
            await sftp.link('file1', 'file2')
            self._check_file('file1', 'file2')
        finally:
            remove('file1 file2')

    @sftp_test_v6
    async def test_link_v6(self, sftp):
        """Test creating a hard link with SFTPv6"""

        try:
            self._create_file('file1')
            await sftp.link('file1', 'file2')
            self._check_file('file1', 'file2')
        finally:
            remove('file1 file2')

    @sftp_test
    async def test_open_read(self, sftp):
        """Test reading data from a file"""

        f = None

        try:
            self._create_file('file', 'xxx')

            f = await sftp.open('file')
            self.assertEqual((await f.read()), 'xxx')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_read_bytes(self, sftp):
        """Test reading bytes from a file"""

        f = None

        try:
            self._create_file('file', 'xxx')

            f = await sftp.open('file', 'rb')
            self.assertEqual((await f.read()), b'xxx')

            await f.seek(0)
            self.assertEqual([result async for result in
                              await f.read_parallel()], [(0, b'xxx')])
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_read_offset_size(self, sftp):
        """Test reading at a specific offset and size"""

        f = None

        try:
            self._create_file('file', 'xxxxyyyy')

            f = await sftp.open('file')
            self.assertEqual((await f.read(4, 2)), 'xxyy')
            self.assertEqual([result async for result in
                              await f.read_parallel(4, 2)], [(2, b'xxyy')])
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_read_no_blocksize(self, sftp):
        """Test reading with no block size set"""

        f = None

        try:
            self._create_file('file', 'xxxxyyyy')

            f = await sftp.open('file', block_size=None)
            self.assertEqual((await f.read(4, 2)), 'xxyy')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_read_parallel(self, sftp):
        """Test reading data from a file using parallel I/O"""

        f = None

        try:
            self._create_file('file', 40*1024*'\0')

            f = await sftp.open('file')
            self.assertEqual(len((await f.read(64*1024))), 40*1024)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    def test_open_read_out_of_order(self):
        """Test parallel read with out-of-order responses"""

        @sftp_test
        async def _test_read_out_of_order(self, sftp):
            """Test parallel read with out-of-order responses"""

            f = None

            try:
                random_data = os.urandom(4*1024*1024)
                self._create_file('file', random_data)

                async with sftp.open('file', 'rb') as f:
                    self.assertEqual(await f.read(), random_data)
            finally:
                remove('file')

        with patch('asyncssh.sftp.SFTPServerHandler',
                   _ReorderReadServerHandler):
            # pylint: disable=no-value-for-parameter
            _test_read_out_of_order(self)

    @sftp_test
    async def test_open_read_nonexistent(self, sftp):
        """Test reading data from a nonexistent file"""

        f = None

        try:
            with self.assertRaises(SFTPNoSuchFile):
                f = await sftp.open('file')
        finally:
            if f: # pragma: no cover
                await f.close()

    @unittest.skipIf(sys.platform == 'win32',
                     'skip permission tests on Windows')
    @sftp_test
    async def test_open_read_not_permitted(self, sftp):
        """Test reading data from a file with no read permission"""

        f = None

        try:
            self._create_file('file', mode=0)

            with self.assertRaises(SFTPPermissionDenied):
                f = await sftp.open('file')
        finally:
            if f: # pragma: no cover
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_write(self, sftp):
        """Test writing data to a file"""

        f = None

        try:
            f = await sftp.open('file', 'w')
            await f.write('xxx')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxx')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_write_bytes(self, sftp):
        """Test writing bytes to a file"""

        f = None

        try:
            f = await sftp.open('file', 'wb')
            await f.write(b'xxx')
            await f.close()

            with open('file', 'rb') as localf:
                self.assertEqual(localf.read(), b'xxx')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open_write_v6(self, sftp):
        """Test writing bytes to a file with SFTPv6 open"""

        f = None

        try:
            f = await sftp.open('file', 'wb')
            await f.write('xxx')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxx')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open56_write_v6(self, sftp):
        """Test writing bytes to a file with SFTPv6 open56"""

        f = None

        try:
            f = await sftp.open56('file', ACE4_WRITE_DATA, FXF_CREATE_TRUNCATE)
            await f.write('xxx')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxx')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_truncate(self, sftp):
        """Test truncating a file at open time"""

        f = None

        try:
            self._create_file('file', 'xxxyyy')

            f = await sftp.open('file', 'w')
            await f.write('zzz')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'zzz')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open_truncate_v6(self, sftp):
        """Test truncating a file at open time with SFTPv6 open"""

        f = None

        try:
            self._create_file('file', 'xxxyyy')

            f = await sftp.open('file', FXF_WRITE | FXF_TRUNC)
            await f.write('zzz')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'zzz')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open56_truncate_v6(self, sftp):
        """Test truncating a file at open time with SFTPv6 open56"""

        f = None

        try:
            self._create_file('file', 'xxxyyy')

            f = await sftp.open56('file', ACE4_WRITE_DATA,
                                  FXF_TRUNCATE_EXISTING)
            await f.write('zzz')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'zzz')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_append(self, sftp):
        """Test appending data to an existing file"""

        f = None

        try:
            self._create_file('file', 'xxx')

            f = await sftp.open('file', 'a+')
            await f.write('yyy')
            self.assertEqual((await f.read()), '')
            self.assertEqual([result async for result in
                              await f.read_parallel()], [])
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxxyyy')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open_append_v6(self, sftp):
        """Test appending data to an existing file with SFTPv6 open"""

        f = None

        try:
            self._create_file('file', 'xxx')

            f = await sftp.open('file', FXF_WRITE | FXF_APPEND)
            await f.write('yyy')
            self.assertEqual((await f.read()), '')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxxyyy')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open56_append_v6(self, sftp):
        """Test appending data to an existing file with SFTPv6 open56"""

        f = None

        try:
            self._create_file('file', 'xxx')

            f = await sftp.open56('file', ACE4_READ_DATA | ACE4_WRITE_DATA |
                                  ACE4_APPEND_DATA, FXF_OPEN_EXISTING |
                                  FXF_APPEND_DATA)
            await f.write('yyy')
            self.assertEqual((await f.read()), '')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxxyyy')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_exclusive_create(self, sftp):
        """Test creating a new file"""

        f = None

        try:
            f = await sftp.open('file', 'x')
            await f.write('xxx')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxx')

            with self.assertRaises(SFTPFailure):
                f = await sftp.open('file', 'x')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open_exclusive_create_v6(self, sftp):
        """Test creating a new file with SFTPv6 open"""

        f = None

        try:
            f = await sftp.open('file', 'x')
            await f.write('xxx')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxx')

            with self.assertRaises(SFTPFileAlreadyExists):
                f = await sftp.open('file', 'x')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open56_exclusive_create_v6(self, sftp):
        """Test creating a new file with SFTPv6 open56"""

        f = None

        try:
            f = await sftp.open56('file', ACE4_WRITE_DATA, FXF_CREATE_NEW)
            await f.write('xxx')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxx')

            with self.assertRaises(SFTPFileAlreadyExists):
                f = await sftp.open56('file', ACE4_WRITE_DATA, FXF_CREATE_NEW)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_exclusive_create_existing(self, sftp):
        """Test exclusive create of an existing file"""

        f = None

        try:
            self._create_file('file')

            with self.assertRaises(SFTPFailure):
                f = await sftp.open('file', 'x')
        finally:
            if f: # pragma: no cover
                await f.close()

            remove('file')

    @sftp_test_v4
    async def test_open_exclusive_create_existing_v4(self, sftp):
        """Test exclusive create of an existing file with SFTPv4"""

        f = None

        try:
            self._create_file('file')

            with self.assertRaises(SFTPFileAlreadyExists):
                f = await sftp.open('file', 'x')
        finally:
            if f: # pragma: no cover
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open56_exclusive_create_existing_v6(self, sftp):
        """Test exclusive create of an existing file with SFTPv6 open56"""

        f = None

        try:
            self._create_file('file')

            with self.assertRaises(SFTPFileAlreadyExists):
                f = await sftp.open56('file', ACE4_WRITE_DATA, FXF_CREATE_NEW)
        finally:
            if f: # pragma: no cover
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_overwrite(self, sftp):
        """Test overwriting part of an existing file"""

        f = None

        try:
            self._create_file('file', 'xxxyyy')

            f = await sftp.open('file', 'r+')
            await f.write('zzz')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'zzzyyy')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open56_overwrite_v6(self, sftp):
        """Test overwriting part of an existing file with SFTPv6 open56"""

        f = None

        try:
            self._create_file('file', 'xxxyyy')

            f = await sftp.open56('file', ACE4_WRITE_DATA, FXF_OPEN_EXISTING)
            await f.write('zzz')
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'zzzyyy')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_overwrite_offset_size(self, sftp):
        """Test writing data at a specific offset"""

        f = None

        try:
            self._create_file('file', 'xxxxyyyy')

            f = await sftp.open('file', 'r+')
            await f.write('zz', 3)
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxxzzyyy')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open_overwrite_offset_size_v6(self, sftp):
        """Test writing data at a specific offset with SFTPv6 open"""

        f = None

        try:
            self._create_file('file', 'xxxxyyyy')

            f = await sftp.open('file', FXF_WRITE | FXF_CREAT)
            await f.write('zz', 3)
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxxzzyyy')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_open56_overwrite_offset_size_v6(self, sftp):
        """Test writing data at a specific offset with SFTPv6 open56"""

        f = None

        try:
            self._create_file('file', 'xxxxyyyy')

            f = await sftp.open56('file', ACE4_WRITE_DATA, FXF_OPEN_OR_CREATE)
            await f.write('zz', 3)
            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxxzzyyy')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_open_overwrite_nonexistent(self, sftp):
        """Test overwriting a nonexistent file"""

        f = None

        try:
            with self.assertRaises(SFTPNoSuchFile):
                f = await sftp.open('file', 'r+')
        finally:
            if f: # pragma: no cover
                await f.close()

    @sftp_test_v6
    async def test_open_link_loop_v6(self, sftp):
        """Test opening a symlink which is a loop"""

        f = None

        try:
            os.symlink('link1', 'link2')
            os.symlink('link2', 'link1')

            with self.assertRaises((SFTPInvalidParameter, SFTPLinkLoop)):
                f = await sftp.open('link1')
        finally:
            if f: # pragma: no cover
                await f.close()

            remove('link1 link2')

    @sftp_test
    async def test_file_seek(self, sftp):
        """Test seeking within a file"""

        f = None

        try:
            f = await sftp.open('file', 'w+')
            await f.write('xxxxyyyy')
            await f.seek(3)
            await f.write('zz')

            await f.seek(-3, SEEK_CUR)
            self.assertEqual((await f.read(4)), 'xzzy')

            await f.seek(-4, SEEK_END)
            self.assertEqual((await f.read()), 'zyyy')
            self.assertEqual((await f.read()), '')
            self.assertEqual((await f.read(1)), '')

            with self.assertRaises(ValueError):
                await f.seek(0, -1)

            await f.close()

            f = await sftp.open('file', 'a+')
            await f.seek(-4, SEEK_CUR)
            self.assertEqual((await f.read()), 'zyyy')

            await f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxxzzyyy')
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_file_stat(self, sftp):
        """Test getting attributes on an open file"""

        f = None

        try:
            f = await sftp.open('file', 'w')
            self._check_stat((await f.stat()), os.stat('file'))
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v4
    async def test_file_stat_v4(self, sftp):
        """Test getting attributes on an open file with SFTPv4"""

        f = None

        try:
            f = await sftp.open('file', 'w')
            self._check_stat_v4((await f.stat()), os.stat('file'))
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_file_stat_v6(self, sftp):
        """Test getting attributes on an open file with SFTPv6"""

        f = None

        try:
            f = await sftp.open('file', 'w')
            self._check_stat_v4((await f.stat()), os.stat('file'))
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_file_setstat(self, sftp):
        """Test setting attributes on an open file"""

        f = None

        try:
            f = await sftp.open('file', 'w')
            await f.setstat(SFTPAttrs(permissions=0o666))

            self.assertEqual(stat.S_IMODE(os.stat('file').st_mode), 0o666)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_file_setstat_v6(self, sftp):
        """Test setting attributes on an open file with SFTPv6"""

        f = None

        try:
            f = await sftp.open('file', 'w')
            await f.setstat(SFTPAttrs(permissions=0o666))

            self.assertEqual(stat.S_IMODE(os.stat('file').st_mode), 0o666)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip chown tests on Windows')
    @sftp_test
    async def test_file_chown(self, sftp):
        """Test changing ownership of an open file

           We can't change to a different user/group here if we're not
           root, so just change to the same user/group. See the separate
           _TestSFTPChown class for a more complete test, but this is
           left in for code coverage purposes.

        """

        f = None

        try:
            f = await sftp.open('file', 'w')
            stat_result = os.stat('file')

            await f.chown(stat_result.st_uid, stat_result.st_gid)

            new_stat_result = os.stat('file')
            self.assertEqual(new_stat_result.st_uid, stat_result.st_uid)
            self.assertEqual(new_stat_result.st_gid, stat_result.st_gid)

            await f.chown(uid=stat_result.st_uid, gid=stat_result.st_gid)

            new_stat_result = os.stat('file')
            self.assertEqual(new_stat_result.st_uid, stat_result.st_uid)
            self.assertEqual(new_stat_result.st_gid, stat_result.st_gid)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip chown tests on Windows')
    @sftp_test_v4
    async def test_file_chown_v4(self, sftp):
        """Test changing ownership of an open file

           We can't change to a different user/group here if we're not
           root, so just change to the same user/group. See the separate
           _TestSFTPChown class for a more complete test, but this is
           left in for code coverage purposes.

        """

        f = None

        try:
            f = await sftp.open('file', 'w')
            stat_result = os.stat('file')

            owner = lookup_user(stat_result.st_uid)
            group = lookup_group(stat_result.st_gid)

            await f.chown(owner, group)

            new_stat_result = os.stat('file')
            self.assertEqual(new_stat_result.st_uid, stat_result.st_uid)
            self.assertEqual(new_stat_result.st_gid, stat_result.st_gid)

            await f.chown(owner=owner, group=group)

            new_stat_result = os.stat('file')
            self.assertEqual(new_stat_result.st_uid, stat_result.st_uid)
            self.assertEqual(new_stat_result.st_gid, stat_result.st_gid)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_file_truncate(self, sftp):
        """Test truncating an open file"""

        f = None

        try:
            self._create_file('file', '01234567890123456789')

            f = await sftp.open('file', 'a+')
            await f.truncate(10)
            self.assertEqual((await f.tell()), 10)
            self.assertEqual((await f.read(offset=0)), '0123456789')
            self.assertEqual((await f.tell()), 10)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_file_utime(self, sftp):
        """Test changing access and modify times on an open file"""

        f = None

        try:
            f = await sftp.open('file', 'w')
            await f.utime()
            await f.utime((1, 2))

            stat_result = os.stat('file')
            self.assertEqual(stat_result.st_atime, 1)
            self.assertEqual(stat_result.st_mtime, 2)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v4
    async def test_file_utime_v4(self, sftp):
        """Test changing access and modify times on an open file with SFTPv4"""

        f = None

        try:
            f = await sftp.open('file', 'w')
            await f.utime()
            await f.utime((1.0, 2.25))

            stat_result = os.stat('file')
            self.assertEqual(stat_result.st_atime, 1.0)
            self.assertEqual(stat_result.st_atime_ns, 1000000000)
            self.assertEqual(stat_result.st_mtime, 2.25)
            self.assertEqual(stat_result.st_mtime_ns, 2250000000)
            self.assertEqual((await sftp.getatime('file')), 1.0)
            self.assertEqual((await sftp.getatime_ns('file')), 1000000000)
            self.assertIsNotNone((await sftp.getcrtime('file')))
            self.assertIsNotNone((await sftp.getcrtime_ns('file')))
            self.assertEqual((await sftp.getmtime('file')), 2.25)
            self.assertEqual((await sftp.getmtime_ns('file')), 2250000000)

            await f.utime('file', ns=(3500000000, 4750000000))

            stat_result = os.stat('file')
            self.assertEqual(stat_result.st_atime, 3.5)
            self.assertEqual(stat_result.st_atime_ns, 3500000000)
            self.assertEqual(stat_result.st_mtime, 4.75)
            self.assertEqual(stat_result.st_mtime_ns, 4750000000)
            self.assertEqual((await sftp.getatime('file')), 3.5)
            self.assertEqual((await sftp.getatime_ns('file')), 3500000000)
            self.assertIsNotNone((await sftp.getcrtime('file')))
            self.assertIsNotNone((await sftp.getcrtime_ns('file')))
            self.assertEqual((await sftp.getmtime('file')), 4.75)
            self.assertEqual((await sftp.getmtime_ns('file')), 4750000000)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip statvfs tests on Windows')
    @sftp_test
    async def test_file_statvfs(self, sftp):
        """Test getting attributes on the filesystem containing an open file

           We can't compare the values returned by a live statvfs call since
           they can change at any time. See the separate _TestSFTStatPVFS
           class for a more complete test, but this is left in for code
           coverage purposes.

        """

        f = None

        try:
            f = await sftp.open('file', 'w')
            self.assertIsInstance((await f.statvfs()), SFTPVFSAttrs)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_file_lock(self, sftp):
        """Test file lock against earlier version SFTP server"""

        f = None

        try:
            f = await sftp.open('file', 'w')

            with self.assertRaises(SFTPOpUnsupported):
                await f.lock(0, 0, FXF_BLOCK_READ)

            with self.assertRaises(SFTPOpUnsupported):
                await f.unlock(0, 0)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_file_lock_v6(self, sftp):
        """Test file lock"""

        f = None

        try:
            f = await sftp.open('file', 'w')

            with self.assertRaises(SFTPOpUnsupported):
                await f.lock(0, 0, FXF_BLOCK_READ)

            with self.assertRaises(SFTPOpUnsupported):
                await f.unlock(0, 0)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_file_sync(self, sftp):
        """Test file sync"""

        f = None

        try:
            f = await sftp.open('file', 'w')
            self.assertIsNone((await f.fsync()))
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_exited_session(self, sftp):
        """Test use of SFTP session after exit"""

        sftp.exit()
        await sftp.wait_closed()

        f = None

        try:
            with self.assertRaises(SFTPNoConnection):
                f = await sftp.open('file')
        finally:
            if f: # pragma: no cover
                await f.close()

    @sftp_test
    async def test_cleanup_open_files(self, sftp):
        """Test cleanup of open file handles on exit"""

        try:
            await sftp.open('file', 'w')
        finally:
            sftp.exit()
            await sftp.wait_closed()

            remove('file')

    @sftp_test
    async def test_invalid_open_mode(self, sftp):
        """Test opening file with invalid mode"""

        with self.assertRaises(ValueError):
            await sftp.open('file', 'z')

    @sftp_test
    async def test_invalid_open56(self, sftp):
        """Test calling open56 on an earlier version SFTP server"""

        with self.assertRaises(SFTPOpUnsupported):
            await sftp.open56('file', ACE4_WRITE_DATA, FXF_OPEN_OR_CREATE)

    @sftp_test_v6
    async def test_invalid_access_flags_v6(self, sftp):
        """Test opening file with invalid access flags with SFTPv6"""

        with self.assertRaises(SFTPInvalidParameter):
            await sftp.open56('file', 0x80000000, FXF_OPEN_OR_CREATE)

    @sftp_test_v6
    async def test_invalid_open_flags_v6(self, sftp):
        """Test opening file with invalid open flags with SFTPv6"""

        with self.assertRaises(SFTPInvalidParameter):
            await sftp.open56('file', ACE4_WRITE_DATA, 0x80000000)

    @sftp_test
    async def test_invalid_handle(self, sftp):
        """Test sending requests associated with an invalid file handle"""

        async def _return_invalid_handle(self, path, pflags, attrs):
            """Return an invalid file handle"""

            # pylint: disable=unused-argument

            return UInt32(0xffffffff)

        with patch('asyncssh.sftp.SFTPClientHandler.open',
                   _return_invalid_handle):
            f = await sftp.open('file')

            with self.assertRaises(SFTPFailure):
                await f.read()

            with self.assertRaises(SFTPFailure):
                await f.read(1)

            with self.assertRaises(SFTPFailure):
                await f.write('')

            with self.assertRaises(SFTPFailure):
                await f.stat()

            with self.assertRaises(SFTPFailure):
                await f.setstat(SFTPAttrs())

            if sys.platform != 'win32': # pragma: no branch
                with self.assertRaises(SFTPFailure):
                    await f.statvfs()

            with self.assertRaises(SFTPFailure):
                await f.fsync()

            with self.assertRaises(SFTPFailure):
                await f.close()

    @sftp_test_v6
    async def test_invalid_handle_v6(self, sftp):
        """Test sending requests associated with an invalid file handle"""

        async def _return_invalid_handle(self, path, pflags, attrs):
            """Return an invalid file handle"""

            # pylint: disable=unused-argument

            return UInt32(0xffffffff)

        with patch('asyncssh.sftp.SFTPClientHandler.open',
                   _return_invalid_handle):
            f = await sftp.open('file')

            with self.assertRaises(SFTPInvalidHandle):
                await f.lock(0, 0, FXF_BLOCK_READ)

            with self.assertRaises(SFTPInvalidHandle):
                await f.unlock(0, 0)

    @sftp_test
    async def test_closed_file(self, sftp):
        """Test I/O operations on a closed file"""

        f = None

        try:
            self._create_file('file')

            async with sftp.open('file') as f:
                # Do an explicit close to test double-close
                await f.close()

            with self.assertRaises(ValueError):
                await f.read()

            with self.assertRaises(ValueError):
                await f.read_parallel()

            with self.assertRaises(ValueError):
                await f.write('')

            with self.assertRaises(ValueError):
                await f.seek(0)

            with self.assertRaises(ValueError):
                await f.tell()

            with self.assertRaises(ValueError):
                await f.stat()

            with self.assertRaises(ValueError):
                await f.setstat(SFTPAttrs())

            with self.assertRaises(ValueError):
                await f.statvfs()

            with self.assertRaises(ValueError):
                await f.truncate()

            with self.assertRaises(ValueError):
                await f.chown(0, 0)

            with self.assertRaises(ValueError):
                await f.chmod(0)

            with self.assertRaises(ValueError):
                await f.utime()

            with self.assertRaises(ValueError):
                await f.lock(0, 0, FXF_BLOCK_READ)

            with self.assertRaises(ValueError):
                await f.unlock(0, 0)

            with self.assertRaises(ValueError):
                await f.fsync()
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    def test_unexpected_client_close(self):
        """Test an unexpected connection close from client"""

        async def _unexpected_client_close(self):
            """Close the SSH connection before sending an init request"""

            self._writer.channel.get_connection().abort()

        with patch('asyncssh.sftp.SFTPClientHandler.start',
                   _unexpected_client_close):
            # pylint: disable=no-value-for-parameter
            self._dummy_sftp_client()

    def test_unexpected_server_close(self):
        """Test an unexpected connection close from server"""

        async def _unexpected_server_close(self):
            """Close the SSH connection before sending a version response"""

            packet = await SFTPHandler.recv_packet(self)
            self._writer.channel.get_connection().abort()
            return packet

        with patch('asyncssh.sftp.SFTPServerHandler.recv_packet',
                   _unexpected_server_close):
            with self.assertRaises(SFTPConnectionLost):
                # pylint: disable=no-value-for-parameter
                self._dummy_sftp_client()

    def test_incomplete_message(self):
        """Test session cleanup in the middle of a write request"""

        with patch('asyncssh.sftp.SFTPServerHandler',
                   _IncompleteMessageServerHandler):
            with self.assertRaises(SFTPConnectionLost):
                # pylint: disable=no-value-for-parameter
                self._dummy_sftp_client()

    def test_immediate_client_close(self):
        """Test closing SFTP channel immediately after opening"""

        async def _closing_start(self):
            """Immediately close the SFTP channel"""

            self.exit()

        with patch('asyncssh.sftp.SFTPClientHandler.start', _closing_start):
            # pylint: disable=no-value-for-parameter
            self._dummy_sftp_client()

    def test_no_init(self):
        """Test sending non-init request at start"""

        async def _no_init_start(self):
            """Send a non-init request at start"""

            self.send_packet(FXP_OPEN, 0, UInt32(0))

        with patch('asyncssh.sftp.SFTPClientHandler.start', _no_init_start):
            # pylint: disable=no-value-for-parameter
            self._dummy_sftp_client()

    def test_incomplete_init_request(self):
        """Test sending init with missing version"""

        async def _missing_version_start(self):
            """Send an init request with missing version"""

            self.send_packet(FXP_INIT, None)

        with patch('asyncssh.sftp.SFTPClientHandler.start',
                   _missing_version_start):
            # pylint: disable=no-value-for-parameter
            self._dummy_sftp_client()

    def test_incomplete_version_response(self):
        """Test sending an incomplete version response"""

        async def _incomplete_version_response(self):
            """Send an incomplete version response"""

            packet = await SFTPHandler.recv_packet(self)
            self.send_packet(FXP_VERSION, None)
            return packet

        with patch('asyncssh.sftp.SFTPServerHandler.recv_packet',
                   _incomplete_version_response):
            with self.assertRaises(SFTPBadMessage):
                # pylint: disable=no-value-for-parameter
                self._dummy_sftp_client()

    def test_nonstandard_version(self):
        """Test sending init with non-standard version"""

        with patch('asyncssh.sftp.MIN_SFTP_VERSION', 2):
            # pylint: disable=no-value-for-parameter
            self._dummy_sftp_client()

    def test_non_version_response(self):
        """Test sending a non-version message in response to init"""

        async def _non_version_response(self):
            """Send a non-version response to init"""

            packet = await SFTPHandler.recv_packet(self)
            self.send_packet(FXP_STATUS, None)
            return packet

        with patch('asyncssh.sftp.SFTPServerHandler.recv_packet',
                   _non_version_response):
            with self.assertRaises(SFTPBadMessage):
                # pylint: disable=no-value-for-parameter
                self._dummy_sftp_client()

    def test_unsupported_version_response(self):
        """Test sending an unsupported version in response to init"""

        async def _unsupported_version_response(self):
            """Send an unsupported version in response to init"""

            packet = await SFTPHandler.recv_packet(self)
            self.send_packet(FXP_VERSION, None, UInt32(99))
            return packet

        with patch('asyncssh.sftp.SFTPServerHandler.recv_packet',
                   _unsupported_version_response):
            with self.assertRaises(SFTPBadMessage):
                # pylint: disable=no-value-for-parameter
                self._dummy_sftp_client()

    def test_extension_in_init(self):
        """Test sending an extension in version 3 init request"""

        async def _init_extension_start(self):
            """Send an init request with missing version"""

            self.send_packet(FXP_INIT, None, UInt32(3), String(b'xxx'),
                             String(b'1'))

        with patch('asyncssh.sftp.SFTPClientHandler.start',
                   _init_extension_start):
            # pylint: disable=no-value-for-parameter
            self._dummy_sftp_client()

    def test_unknown_extension_response(self):
        """Test sending an unknown extension in version response"""

        with patch('asyncssh.sftp.SFTPServerHandler._extensions',
                   [(b'xxx', b'1')]):
            # pylint: disable=no-value-for-parameter
            self._dummy_sftp_client()

    def test_empty_extension_response_v5(self):
        """Test sending an empty extension list in SFTPv5 version response"""

        with patch('asyncssh.sftp.SFTPServerHandler._extensions', []):
            # pylint: disable=no-value-for-parameter
            self._dummy_sftp_client_v5()

    def test_attrib_extension_response_v6(self):
        """Test sending an attrib extension in version response"""

        with patch('asyncssh.sftp.SFTPServerHandler._attrib_extensions',
                   [b'xxx']):
            # pylint: disable=no-value-for-parameter
            self._dummy_sftp_client_v6()

    def test_close_after_init(self):
        """Test close immediately after init request at start"""

        async def _close_after_init_start(self):
            """Send a close immediately after init request at start"""

            self.send_packet(FXP_INIT, None, UInt32(3))
            await self._cleanup(None)

        with patch('asyncssh.sftp.SFTPClientHandler.start',
                   _close_after_init_start):
            # pylint: disable=no-value-for-parameter
            self._dummy_sftp_client()

    def test_file_handle_skip(self):
        """Test skipping over a file handle already in use"""

        @sftp_test
        async def _reset_file_handle(self, sftp):
            """Open multiple files, resetting next handle each time"""

            file1 = None
            file2 = None

            try:
                self._create_file('file1', 'xxx')
                self._create_file('file2', 'yyy')

                file1 = await sftp.open('file1')
                file2 = await sftp.open('file2')

                self.assertEqual((await file1.read()), 'xxx')
                self.assertEqual((await file2.read()), 'yyy')
            finally:
                if file1: # pragma: no branch
                    await file1.close()

                if file2: # pragma: no branch
                    await file2.close()

                remove('file1 file2')

        with patch('asyncssh.sftp.SFTPServerHandler',
                   _ResetFileHandleServerHandler):
            # pylint: disable=no-value-for-parameter
            _reset_file_handle(self)

    @sftp_test
    async def test_missing_request_pktid(self, sftp):
        """Test sending request without a packet ID"""

        async def _missing_pktid(self, filename, pflags, attrs):
            """Send a request without a packet ID"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_OPEN, None)

        with patch('asyncssh.sftp.SFTPClientHandler.open', _missing_pktid):
            await sftp.open('file')

    @sftp_test
    async def test_malformed_open_request(self, sftp):
        """Test sending malformed open request"""

        async def _malformed_open(self, filename, pflags, attrs):
            """Send a malformed open request"""

            # pylint: disable=unused-argument

            return await self._make_request(FXP_OPEN)

        with patch('asyncssh.sftp.SFTPClientHandler.open', _malformed_open):
            with self.assertRaises(SFTPBadMessage):
                await sftp.open('file')

    @sftp_test
    async def test_unknown_request(self, sftp):
        """Test sending unknown request type"""

        async def _unknown_request(self, filename, pflags, attrs):
            """Send a request with an unknown type"""

            # pylint: disable=unused-argument

            return await self._make_request(0xff)

        with patch('asyncssh.sftp.SFTPClientHandler.open', _unknown_request):
            with self.assertRaises(SFTPOpUnsupported):
                await sftp.open('file')

    @sftp_test
    async def test_unrecognized_response_pktid(self, sftp):
        """Test sending a response with an unrecognized packet ID"""

        async def _unrecognized_response_pktid(self, pkttype, pktid, packet):
            """Send a response with an unrecognized packet ID"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_HANDLE, 0xffffffff,
                             UInt32(0xffffffff), String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _unrecognized_response_pktid):
            with self.assertRaises(SFTPBadMessage):
                await sftp.open('file')

    @sftp_test
    async def test_bad_response_type(self, sftp):
        """Test sending a response with an incorrect response type"""

        async def _bad_response_type(self, pkttype, pktid, packet):
            """Send a response with an incorrect response type"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_DATA, pktid, UInt32(pktid), String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _bad_response_type):
            with self.assertRaises(SFTPBadMessage):
                await sftp.open('file')

    @sftp_test
    async def test_unexpected_ok_response(self, sftp):
        """Test sending an unexpected FX_OK response"""

        async def _unexpected_ok_response(self, pkttype, pktid, packet):
            """Send an unexpected FX_OK response"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_STATUS, pktid, UInt32(pktid), UInt32(FX_OK),
                             String(''), String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _unexpected_ok_response):
            with self.assertRaises(SFTPBadMessage):
                await sftp.open('file')

    @sftp_test
    async def test_malformed_ok_response(self, sftp):
        """Test sending an FX_OK response containing invalid Unicode"""

        async def _malformed_ok_response(self, pkttype, pktid, packet):
            """Send an FX_OK response containing invalid Unicode"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_STATUS, pktid, UInt32(pktid), UInt32(FX_OK),
                             String(b'\xff'), String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _malformed_ok_response):
            with self.assertRaises(SFTPBadMessage):
                await sftp.open('file')

    @sftp_test
    async def test_short_ok_response(self, sftp):
        """Test sending an FX_OK response without a reason and lang"""

        async def _short_ok_response(self, pkttype, pktid, packet):
            """Send an FX_OK response missing reason and lang"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_STATUS, pktid, UInt32(pktid), UInt32(FX_OK))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _short_ok_response):
            self.assertIsNone((await sftp.mkdir('dir')))

    @sftp_test
    async def test_malformed_realpath_response(self, sftp):
        """Test receiving malformed realpath response"""

        async def _malformed_realpath(self, path):
            """Return a malformed realpath response"""

            # pylint: disable=unused-argument

            return [SFTPName(''), SFTPName('')], False

        with patch('asyncssh.sftp.SFTPClientHandler.realpath',
                   _malformed_realpath):
            with self.assertRaises(SFTPBadMessage):
                await sftp.realpath('.')

    @sftp_test
    async def test_malformed_readlink_response(self, sftp):
        """Test receiving malformed readlink response"""

        async def _malformed_readlink(self, path):
            """Return a malformed readlink response"""

            # pylint: disable=unused-argument

            return [SFTPName(''), SFTPName('')], False

        with patch('asyncssh.sftp.SFTPClientHandler.readlink',
                   _malformed_readlink):
            with self.assertRaises(SFTPBadMessage):
                await sftp.readlink('.')

    def test_unsupported_extensions(self):
        """Test using extensions on a server that doesn't support them"""

        @sftp_test
        async def _unsupported_extensions(self, sftp):
            """Try using unsupported extensions"""

            f = None

            try:
                self._create_file('file1', 'xxx')
                self._create_file('file2', 'yyy')

                with self.assertRaises(SFTPOpUnsupported):
                    await sftp.statvfs('.')

                f = await sftp.open('file1')

                with self.assertRaises(SFTPOpUnsupported):
                    await f.statvfs()

                with self.assertRaises(SFTPOpUnsupported):
                    await sftp.posix_rename('file1', 'file2')

                with self.assertRaises(SFTPOpUnsupported):
                    await sftp.rename('file1', 'file2', flags=FXR_OVERWRITE)

                with self.assertRaises(SFTPOpUnsupported):
                    await sftp.link('file1', 'file2')

                with self.assertRaises(SFTPOpUnsupported):
                    await f.fsync()

                with self.assertRaises(SFTPOpUnsupported):
                    await sftp.setstat('file1', SFTPAttrs(),
                                       follow_symlinks=False)
            finally:
                if f: # pragma: no branch
                    await f.close()

                remove('file1')

        with patch('asyncssh.sftp.SFTPServerHandler._extensions', []):
            # pylint: disable=no-value-for-parameter
            _unsupported_extensions(self)

    def test_unsupported_extensions_v6(self):
        """Test using extensions on a server that doesn't support them"""

        @sftp_test_v6
        async def _unsupported_extensions_v6(self, sftp):
            """Try using unsupported extensions"""

            try:
                self._create_file('file1', 'xxx')
                self._create_file('file2', 'yyy')
                self._create_file('file3', 'zzz')

                await sftp.posix_rename('file1', 'file2')

                with open('file2') as localf:
                    self.assertEqual(localf.read(), 'xxx')

                await sftp.rename('file2', 'file3', FXR_OVERWRITE)

                with open('file3') as localf:
                    self.assertEqual(localf.read(), 'xxx')

                await sftp.link('file3', 'file4')

                with open('file4') as localf:
                    self.assertEqual(localf.read(), 'xxx')
            finally:
                remove('file1 file2 file3 file4')

        with patch('asyncssh.sftp.SFTPServerHandler._extensions', []):
            # pylint: disable=no-value-for-parameter
            _unsupported_extensions_v6(self)

    def test_write_close(self):
        """Test session cleanup in the middle of a write request"""

        @sftp_test
        async def _write_close(self, sftp):
            """Initiate write that triggers cleanup"""

            try:
                async with sftp.open('file', 'w') as f:
                    with self.assertRaises(SFTPConnectionLost):
                        await f.write('a')
            finally:
                sftp.exit()

                remove('file')

        with patch('asyncssh.sftp.SFTPServerHandler', _WriteCloseServerHandler):
            # pylint: disable=no-value-for-parameter
            _write_close(self)

    @sftp_test_v4
    async def test_write_protect_v4(self, sftp):
        """Test write protect error in SFTPv4"""

        def _write_error(self, file_obj, offset, data):
            """Return read-only FS error when writing to a file"""

            raise OSError(errno.EROFS, 'Read-only filesystem')

        try:
            with patch('asyncssh.sftp.SFTPServer.write', _write_error):
                with self.assertRaises(SFTPWriteProtect):
                    async with sftp.open('file', 'wb') as f:
                        await f.write(b'\0')
        finally:
            remove('file')

    @sftp_test_v4
    async def test_no_media_v4(self, sftp):
        """Test no media error in SFTPv4"""

        def _write_error(self, file_obj, offset, data):
            """Return read-only FS error when writing to a file"""

            raise SFTPNoMedia('No media in requested drive')

        try:
            with patch('asyncssh.sftp.SFTPServer.write', _write_error):
                with self.assertRaises(SFTPNoMedia):
                    async with sftp.open('file', 'wb') as f:
                        await f.write(b'\0')
        finally:
            remove('file')

    @sftp_test_v5
    async def test_no_space_v5(self, sftp):
        """Test no space on filesystem error in SFTPv5"""

        def _write_error(self, file_obj, offset, data):
            """Return no space error when writing to a file"""

            raise OSError(errno.ENOSPC, 'No space left on device')

        try:
            with patch('asyncssh.sftp.SFTPServer.write', _write_error):
                with self.assertRaises(SFTPNoSpaceOnFilesystem):
                    async with sftp.open('file', 'wb') as f:
                        await f.write(b'\0')
        finally:
            remove('file')

    @sftp_test_v5
    async def test_quota_exceeded_v5(self, sftp):
        """Test quota exceeded error in SFTPv5"""

        def _write_error(self, file_obj, offset, data):
            """Return quota exceeded error when writing to a file"""

            raise OSError(errno.EDQUOT, 'Disk quota exceeded')

        try:
            with patch('asyncssh.sftp.SFTPServer.write', _write_error):
                with self.assertRaises(SFTPQuotaExceeded):
                    async with sftp.open('file', 'wb') as f:
                        await f.write(b'\0')
        finally:
            remove('file')

    @sftp_test_v5
    async def test_unknown_principal_v5(self, sftp):
        """Test unknown principal error in SFTPv5"""

        def _open56_error(self, path, desired_access, flags, attrs):
            """Return unknown principal error when opening a file"""

            raise SFTPUnknownPrincipal('Unknown principal',
                unknown_names=(attrs.owner, attrs.group or b'\xff'))

        try:
            with patch('asyncssh.sftp.SFTPServer.open56', _open56_error):
                with self.assertRaises(SFTPUnknownPrincipal):
                    await sftp.open('file', 'wb', SFTPAttrs(owner='aaa',
                                                            group='bbb'))

                with self.assertRaises(SFTPBadMessage):
                    await sftp.open('file', 'wb', SFTPAttrs(owner=b'aaa',
                                                            group=''))
        finally:
            remove('file')

    @sftp_test_v5
    async def test_lock_conflict_v5(self, sftp):
        """Test lock conflict error in SFTPv5"""

        def _open56_error(self, path, desired_access, flags, attrs):
            """Return lock conflict error when opening a file"""

            raise SFTPLockConflict('Lock conflict')

        try:
            with patch('asyncssh.sftp.SFTPServer.open56', _open56_error):
                with self.assertRaises(SFTPLockConflict):
                    await sftp.open56('file', ACE4_WRITE_DATA, FXF_WRITE |
                                      FXF_CREATE_TRUNCATE)
        finally:
            remove('file')

    @sftp_test_v6
    async def test_cannot_delete_v6(self, sftp):
        """Test cannot delete error in SFTPv6"""

        def _remove_error(self, path):
            """Return cannot delete error when removing a file"""

            raise SFTPCannotDelete('Cannot delete file')

        with patch('asyncssh.sftp.SFTPServer.remove', _remove_error):
            with self.assertRaises(SFTPCannotDelete):
                await sftp.remove('file')

    @sftp_test_v6
    async def test_byte_range_lock_conflict_v6(self, sftp):
        """Test byte range lock conflict error in SFTPv6"""

        def _lock_error(self, file_obj, offset, length, flags):
            """Return byte range lock conflict error"""

            raise SFTPByteRangeLockConflict('Byte range lock conflict')

        f = None

        try:
            with patch('asyncssh.sftp.SFTPServer.lock', _lock_error):
                with self.assertRaises(SFTPByteRangeLockConflict):
                    async with sftp.open('file', 'wb') as f:
                        await f.lock(0, 0, FXF_BLOCK_READ)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_byte_range_lock_refused_v6(self, sftp):
        """Test byte range lock refused error in SFTPv6"""

        def _lock_error(self, file_obj, offset, length, flags):
            """Return byte range lock refused error"""

            raise SFTPByteRangeLockRefused('Byte range lock refused')

        f = None

        try:
            with patch('asyncssh.sftp.SFTPServer.lock', _lock_error):
                with self.assertRaises(SFTPByteRangeLockRefused):
                    async with sftp.open('file', 'wb') as f:
                        await f.lock(0, 0, FXF_BLOCK_READ)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test_v6
    async def test_delete_pending_v6(self, sftp):
        """Test delete pending error in SFTPv6"""

        def _remove_error(self, path):
            """Return delete pending error when removing a file"""

            raise SFTPDeletePending('Delete of file is pending')

        with patch('asyncssh.sftp.SFTPServer.remove', _remove_error):
            with self.assertRaises(SFTPDeletePending):
                await sftp.remove('file')

    @sftp_test_v6
    async def test_file_corrupt_v6(self, sftp):
        """Test file corrupt error in SFTPv6"""

        def _open56_error(self, path, desired_access, flags, attrs):
            """Return file corrupt  error when opening a file"""

            raise SFTPFileCorrupt('Filesystem is corrupt')

        with patch('asyncssh.sftp.SFTPServer.open56', _open56_error):
            with self.assertRaises(SFTPFileCorrupt):
                await sftp.open('file')

    @sftp_test_v6
    async def test_byte_range_unlock_mismatch_v6(self, sftp):
        """Test byte range unlock mismatch error in SFTPv6"""

        def _unlock_error(self, file_obj, offset, length):
            """Return byte range unlock mismatch error"""

            raise SFTPNoMatchingByteRangeLock('Byte range unlock mismatch')

        f = None

        try:
            with patch('asyncssh.sftp.SFTPServer.unlock', _unlock_error):
                with self.assertRaises(SFTPNoMatchingByteRangeLock):
                    async with sftp.open('file', 'wb') as f:
                        await f.unlock(0, 0)
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')

    @sftp_test
    async def test_log_formatting(self, sftp):
        """Exercise log formatting of SFTP objects"""

        asyncssh.set_sftp_log_level('DEBUG')

        with self.assertLogs(level='DEBUG'):
            await sftp.realpath('.')
            await sftp.stat('.')

            if sys.platform != 'win32': # pragma: no cover
                await sftp.statvfs('.')

        asyncssh.set_sftp_log_level('WARNING')

    @sftp_test
    async def test_makedirs_no_parent_perms(self, sftp):
        """Test creating a directory path without perms for a parent dir"""

        orig_mkdir = sftp.mkdir

        def _mkdir(path, *args, **kwargs):
            if path == b'/':
                raise SFTPPermissionDenied('')
            return orig_mkdir(path, *args, **kwargs)

        try:
            root = os.path.abspath(os.getcwd())
            with patch.object(sftp, 'mkdir', _mkdir):
                await sftp.makedirs(os.path.join(root, 'dir/dir1'))
                self.assertTrue(os.path.isdir(os.path.join(root, 'dir/dir1')))
        finally:
            remove('dir')

    @sftp_test
    async def test_makedirs_no_perms(self, sftp):
        """Test creating a directory path without perms for all parents"""

        root = os.path.abspath(os.getcwd())

        with patch.object(sftp, 'mkdir', side_effect=SFTPPermissionDenied('')):
            with self.assertRaises(SFTPPermissionDenied):
                await sftp.makedirs(os.path.join(root, 'dir/dir1'))


class _TestSFTPCallable(_CheckSFTP):
    """Unit tests for AsyncSSH SFTP factory being a callable"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server using a callable"""

        def sftp_factory(conn):
            """Return an SFTP server"""

            return SFTPServer(conn)

        return await cls.create_server(sftp_factory=sftp_factory)

    @sftp_test
    async def test_stat(self, sftp):
        """Test getting attributes on a file"""

        # pylint: disable=no-self-use

        await sftp.stat('.')


class _TestSFTPServerProperties(_CheckSFTP):
    """Unit test for checking SFTP server properties"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which checks channel properties"""

        return await cls.create_server(sftp_factory=_CheckPropSFTPServer)

    @asynctest
    async def test_properties(self):
        """Test SFTP server channel properties"""

        async with self.connect() as conn:
            async with conn.start_sftp_client(env={'A': 1, 'B': 2}) as sftp:
                files = await sftp.listdir()
                self.assertEqual(sorted(files), ['A', 'B'])


class _TestSFTPChroot(_CheckSFTP):
    """Unit test for SFTP server with changed root"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server with a changed root"""

        return await cls.create_server(sftp_factory=_ChrootSFTPServer,
                                       sftp_version=6)

    @sftp_test
    async def test_chroot_copy(self, sftp):
        """Test copying a file to an FTP server with a changed root"""

        try:
            self._create_file('src')
            await sftp.put('src', 'dst')
            self._check_file('src', 'chroot/dst')
        finally:
            remove('src chroot/dst')

    @sftp_test
    async def test_chroot_glob(self, sftp):
        """Test a glob pattern match over SFTP with a changed root"""

        try:
            self._create_file('chroot/file1')
            self._create_file('chroot/file2')
            self.assertEqual(sorted((await sftp.glob('/file*'))),
                             ['/file1', '/file2'])
        finally:
            remove('chroot/file1 chroot/file2')

    @sftp_test
    async def test_chroot_realpath(self, sftp):
        """Test canonicalizing a path on an SFTP server with a changed root"""

        self.assertEqual((await sftp.realpath('/dir/../file')), '/file')

        self._create_file('chroot/file1')

        name = await sftp.realpath('/dir/..', 'file1',
                                   check=FXRP_STAT_IF_EXISTS)

        self.assertEqual(name.attrs.type, FILEXFER_TYPE_REGULAR)

        name = await sftp.realpath('/dir/..', 'file2', FXRP_STAT_IF_EXISTS)

        self.assertEqual(name.attrs.type, FILEXFER_TYPE_UNKNOWN)

        with self.assertRaises(SFTPNoSuchFile):
            await sftp.realpath('/dir', '..', 'file2', check=FXRP_STAT_ALWAYS)

    @sftp_test_v6
    async def test_chroot_realpath_v6(self, sftp):
        """Test canonicalizing a path on an SFTP server with a changed root"""

        self.assertEqual((await sftp.realpath('/dir/../file')), '/file')

        self._create_file('chroot/file1')

        name = await sftp.realpath('/dir/..', 'file1', FXRP_STAT_IF_EXISTS)

        self.assertEqual(name.attrs.type, FILEXFER_TYPE_REGULAR)

        name = await sftp.realpath('/dir/..', 'file2',
                                   check=FXRP_STAT_IF_EXISTS)

        self.assertEqual(name.attrs.type, FILEXFER_TYPE_UNKNOWN)

        with self.assertRaises(SFTPNoSuchFile):
            await sftp.realpath('/dir', '..', 'file2', check=FXRP_STAT_ALWAYS)

        with self.assertRaises(SFTPInvalidParameter):
            await sftp.realpath('.', check=99)
    @sftp_test
    async def test_getcwd_and_chdir(self, sftp):
        """Test changing directory on an SFTP server with a changed root"""

        try:
            os.mkdir('chroot/dir')

            self.assertEqual((await sftp.getcwd()), '/')

            await sftp.chdir('dir')
            self.assertEqual((await sftp.getcwd()), '/dir')
        finally:
            remove('chroot/dir')

    @sftp_test
    async def test_chroot_readlink(self, sftp):
        """Test reading symlinks on an FTP server with a changed root"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            root = os.path.join(os.getcwd(), 'chroot')

            os.symlink(root, 'chroot/link1')
            os.symlink(os.path.join(root, 'file'), 'chroot/link2')
            os.symlink('/xxx', 'chroot/link3')

            self.assertEqual((await sftp.readlink('link1')), '/')
            self.assertEqual((await sftp.readlink('link2')), '/file')
            with self.assertRaises(SFTPNoSuchFile):
                await sftp.readlink('link3')
        finally:
            remove('chroot/link1 chroot/link2 chroot/link3')

    @sftp_test
    async def test_chroot_symlink(self, sftp):
        """Test setting a symlink on an SFTP server with a changed root"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            await sftp.symlink('/file', 'link1')
            await sftp.symlink('../../file', 'link2')

            self._check_link('chroot/link1', os.path.abspath('chroot/file'))
            self._check_link('chroot/link2', 'file')
        finally:
            remove('chroot/link1 chroot/link2')

    @sftp_test
    async def test_chroot_makedirs(self, sftp):
        """Test creating a directory path"""

        try:
            await sftp.makedirs('dir/dir1')
            self.assertTrue(os.path.isdir('chroot/dir'))
            self.assertTrue(os.path.isdir('chroot/dir/dir1'))

            await sftp.makedirs('dir/dir2')
            self.assertTrue(os.path.isdir('chroot/dir/dir2'))

            await sftp.makedirs('dir/dir2', exist_ok=True)
            self.assertTrue(os.path.isdir('chroot/dir/dir2'))

            with self.assertRaises(SFTPFailure):
                await sftp.makedirs('/dir/dir2')

            self._create_file('chroot/file')
            with self.assertRaises(SFTPFailure):
                await sftp.makedirs('file/dir')
        finally:
            remove('chroot/dir')

    @sftp_test_v6
    async def test_chroot_makedirs_v6(self, sftp):
        """Test creating a directory path with SFTPv6"""

        try:
            await sftp.makedirs('dir/dir1')
            self.assertTrue(os.path.isdir('chroot/dir'))
            self.assertTrue(os.path.isdir('chroot/dir/dir1'))

            await sftp.makedirs('dir/dir2')
            self.assertTrue(os.path.isdir('chroot/dir/dir2'))

            await sftp.makedirs('dir/dir2', exist_ok=True)
            self.assertTrue(os.path.isdir('chroot/dir/dir2'))

            with self.assertRaises(SFTPFileAlreadyExists):
                await sftp.makedirs('/dir/dir2')

            self._create_file('chroot/file')
            with self.assertRaises(SFTPNotADirectory):
                await sftp.makedirs('file/dir')
        finally:
            remove('chroot/dir')


class _TestSFTPReadEOFWithAttrs(_CheckSFTP):
    """Unit test for SFTP server read EOF flags with SFTPAttrs from fstat"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns SFTPAttrs on fstat"""

        return await cls.create_server(sftp_factory=_SFTPAttrsSFTPServer,
                                       sftp_version=6)

    @sftp_test_v6
    async def test_get(self, sftp):
        """Test copying a file over SFTP"""

        try:
            self._create_file('src')
            await sftp.get('src', 'dst')
            self._check_file('src', 'dst')
        finally:
            remove('src dst')


class _TestSFTPUnknownError(_CheckSFTP):
    """Unit test for SFTP server returning unknown error"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns unknown error"""

        return await cls.create_server(sftp_factory=_SFTPAttrsSFTPServer)

    @sftp_test
    async def test_stat_error(self, sftp):
        """Test error when getting attributes of a file on an SFTP server"""

        with self.assertRaises(SFTPError) as exc:
            await sftp.stat('file')

        self.assertEqual(exc.exception.code, 99)


class _TestSFTPOpenError(_CheckSFTP):
    """Unit test for SFTP server returning error on file open"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns file I/O errors"""

        return await cls.create_server(sftp_factory=_OpenErrorSFTPServer,
                                       sftp_version=6)

    @sftp_test_v6
    async def test_open_error_v6(self, sftp):
        """Test error when opening a file on an SFTP server"""

        with self.assertRaises(SFTPInvalidFilename):
            await sftp.open('ENAMETOOLONG')

        with self.assertRaises(SFTPInvalidParameter):
            await sftp.open('EINVAL')

        with self.assertRaises(SFTPFailure):
            await sftp.open('ENXIO')


class _TestSFTPIOError(_CheckSFTP):
    """Unit test for SFTP server returning file I/O error"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns file I/O errors"""

        return await cls.create_server(sftp_factory=_IOErrorSFTPServer)

    @sftp_test
    async def test_put_error(self, sftp):
        """Test error when putting a file to an SFTP server"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src', 4*1024*1024*'\0')

                    with self.assertRaises(SFTPFailure):
                        await getattr(sftp, method)('src', 'dst')
                finally:
                    remove('src dst')

    @sftp_test
    async def test_read_error(self, sftp):
        """Test error when reading a file on an SFTP server"""

        try:
            self._create_file('file', 4*1024*1024*'\0')

            async with sftp.open('file') as f:
                with self.assertRaises(SFTPFailure):
                    await f.read(4*1024*1024)

                with self.assertRaises(SFTPFailure):
                    async for _ in  await f.read_parallel(4*1024*1024):
                        pass
        finally:
            remove('file')

    @sftp_test
    async def test_write_error(self, sftp):
        """Test error when writing a file on an SFTP server"""

        try:
            with self.assertRaises(SFTPFailure):
                async with sftp.open('file', 'w') as f:
                    await f.write(4*1024*1024*'\0')
        finally:
            remove('file')


class _TestSFTPSmallBlockSize(_CheckSFTP):
    """Unit test for SFTP server returning file I/O error"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns file I/O errors"""

        return (await cls.create_server(
            sftp_factory=_SmallBlockSizeSFTPServer))

    @sftp_test
    async def test_read(self, sftp):
        """Test a large read on a server with a small block size"""

        try:
            data = os.urandom(65536)
            self._create_file('file', data)

            async with sftp.open('file', 'rb') as f:
                result = await f.read(32768, 16384)

            self.assertEqual(result, data[16384:49152])
        finally:
            remove('file')

    @sftp_test
    async def test_get(self, sftp):
        """Test getting a file from an SFTP server with a small block size"""

        try:
            data = os.urandom(65536)
            self._create_file('src', data)
            await sftp.get('src', 'dst')
            self._check_file('src', 'dst')
        finally:
            remove('src dst')


class _TestSFTPEOFDuringCopy(_CheckSFTP):
    """Unit test for SFTP server returning EOF during a file copy"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which truncates files when accessed"""

        return await cls.create_server(sftp_factory=_TruncateSFTPServer)

    @sftp_test
    async def test_get(self, sftp):
        """Test getting a file from an SFTP server truncated during the copy"""

        try:
            self._create_file('src', 65536*'\0')

            with self.assertRaises(SFTPFailure):
                await sftp.get('src', 'dst')
        finally:
            remove('src dst')


class _TestSFTPNotImplemented(_CheckSFTP):
    """Unit test for SFTP server returning not-implemented error"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns not-implemented errors"""

        return await cls.create_server(sftp_factory=_NotImplSFTPServer)

    @sftp_test
    async def test_symlink_error(self, sftp):
        """Test error when creating a symbolic link on an SFTP server"""

        with self.assertRaises(SFTPOpUnsupported):
            await sftp.symlink('file', 'link')


class _TestSFTPFileType(_CheckSFTP):
    """Unit test for SFTP server formatting directory listings"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns a fixed directory listing"""

        return await cls.create_server(sftp_factory=_FileTypeSFTPServer)

    @sftp_test
    async def test_filetype(self, sftp):
        """Test permission to filetype conversion in SFTP readdir call"""

        for file in await sftp.readdir('/'):
            self.assertEqual(file.filename, str(file.attrs.type))


class _TestSFTPLongname(_CheckSFTP):
    """Unit test for SFTP server formatting directory listings"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns a fixed directory listing"""

        return await cls.create_server(sftp_factory=_LongnameSFTPServer)

    @sftp_test
    async def test_longname(self, sftp):
        """Test long name formatting in SFTP readdir call"""

        for file in await sftp.readdir('/'):
            self.assertEqual(file.longname[56:], file.filename)

    @sftp_test
    async def test_glob_hidden(self, sftp):
        """Test a glob pattern match on hidden files"""

        self.assertEqual((await sftp.glob('/.*')), ['/.file'])

    @unittest.skipIf(sys.platform == 'win32', 'skip uid/gid tests on Windows')
    @sftp_test
    async def test_getpwuid_error(self, sftp):
        """Test long name formatting where user name can't be resolved"""

        with patch('pwd.getpwuid', _getpwuid_error):
            result = await sftp.readdir('/')

        self.assertEqual(result[3].longname[16:24], '        ')
        self.assertEqual(result[4].longname[16:24], '0       ')

    @unittest.skipIf(sys.platform == 'win32', 'skip uid/gid tests on Windows')
    @sftp_test
    async def test_getgrgid_error(self, sftp):
        """Test long name formatting where group name can't be resolved"""

        with patch('grp.getgrgid', _getgrgid_error):
            result = await sftp.readdir('/')

        self.assertEqual(result[3].longname[25:33], '        ')
        self.assertEqual(result[4].longname[25:33], '0       ')

    @sftp_test
    async def test_strftime_error(self, sftp):
        """Test long name formatting with strftime not supporting %e"""

        orig_strftime = time.strftime

        def strftime_error(fmt, t):
            """Simulate Windows srtftime that doesn't support %e"""

            if '%e' in fmt:
                raise ValueError
            else:
                return orig_strftime(fmt, t)

        with patch('time.strftime', strftime_error):
            result = await sftp.readdir('/')

        self.assertEqual(result[3].longname[51:55], '    ')
        self.assertIn(result[4].longname[51:55], ('1969', '1970'))


class _TestSFTPLargeListDir(_CheckSFTP):
    """Unit test for SFTP server returning large listdir result"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns file I/O errors"""

        return await cls.create_server(sftp_factory=_LargeDirSFTPServer)

    @sftp_test
    async def test_large_listdir(self, sftp):
        """Test large listdir result"""

        self.assertEqual(len((await sftp.readdir('/'))), 100000)


@unittest.skipIf(sys.platform == 'win32', 'skip statvfs tests on Windows')
class _TestSFTPStatVFS(_CheckSFTP):
    """Unit test for SFTP server filesystem attributes"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns fixed filesystem attrs"""

        return await cls.create_server(sftp_factory=_StatVFSSFTPServer)

    def _check_statvfs(self, sftp_statvfs):
        """Check if filesystem attributes are equal"""

        expected_statvfs = _StatVFSSFTPServer.expected_statvfs

        self.assertEqual(sftp_statvfs.bsize, expected_statvfs.bsize)
        self.assertEqual(sftp_statvfs.frsize, expected_statvfs.frsize)
        self.assertEqual(sftp_statvfs.blocks, expected_statvfs.blocks)
        self.assertEqual(sftp_statvfs.bfree, expected_statvfs.bfree)
        self.assertEqual(sftp_statvfs.bavail, expected_statvfs.bavail)
        self.assertEqual(sftp_statvfs.files, expected_statvfs.files)
        self.assertEqual(sftp_statvfs.ffree, expected_statvfs.ffree)
        self.assertEqual(sftp_statvfs.favail, expected_statvfs.favail)
        self.assertEqual(sftp_statvfs.fsid, expected_statvfs.fsid)
        self.assertEqual(sftp_statvfs.flags, expected_statvfs.flags)
        self.assertEqual(sftp_statvfs.namemax, expected_statvfs.namemax)

        self.assertEqual(repr(sftp_statvfs), repr(expected_statvfs))

    @sftp_test
    async def test_statvfs(self, sftp):
        """Test getting attributes on a filesystem"""

        self._check_statvfs((await sftp.statvfs('.')))

    @sftp_test
    async def test_file_statvfs(self, sftp):
        """Test getting attributes on the filesystem containing an open file"""

        f = None

        try:
            self._create_file('file')

            f = await sftp.open('file')
            self._check_statvfs((await f.statvfs()))
        finally:
            if f: # pragma: no branch
                await f.close()

            remove('file')


@unittest.skipIf(sys.platform == 'win32', 'skip chown tests on Windows')
class _TestSFTPChown(_CheckSFTP):
    """Unit test for SFTP server file ownership"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which simulates file ownership changes"""

        return await cls.create_server(sftp_factory=_ChownSFTPServer,
                                       sftp_version=6)

    @sftp_test
    async def test_chown(self, sftp):
        """Test changing ownership of a file"""

        try:
            self._create_file('file')
            await sftp.chown('file', 1, 2)
            attrs = await sftp.stat('file')
            self.assertEqual(attrs.uid, 1)
            self.assertEqual(attrs.gid, 2)
        finally:
            remove('file')

    @sftp_test_v4
    async def test_chown_v4(self, sftp):
        """Test changing ownership of a file with SFTPv4"""

        try:
            self._create_file('file')
            await sftp.chown('file', owner='root', group='wheel')
            attrs = await sftp.stat('file')
            self.assertEqual(attrs.owner, 'root')
            self.assertEqual(attrs.group, 'wheel')
        finally:
            remove('file')


class _TestSFTPAttrs(unittest.TestCase):
    """Unit test for SFTPAttrs object"""

    def test_attrs(self):
        """Test encoding and decoding of SFTP attributes"""

        for kwargs in ({'size': 1234},
                       {'uid': 1, 'gid': 2},
                       {'permissions': 0o7777},
                       {'atime': 1, 'mtime': 2},
                       {'extended': [(b'a1', b'v1'), (b'a2', b'v2')]}):
            attrs = SFTPAttrs(**kwargs)
            packet = SSHPacket(attrs.encode(3))
            self.assertEqual(repr(SFTPAttrs.decode(packet, 3)), repr(attrs))

        for kwargs in ({'type': FILEXFER_TYPE_REGULAR},
                       {'size': 1234},
                       {'owner': 'a', 'group': 'b'},
                       {'permissions': 0o7777},
                       {'atime': 1, 'atime_ns': 2},
                       {'crtime': 3, 'crtime_ns': 4},
                       {'mtime': 5, 'mtime_ns': 6},
                       {'atime': 7, 'crtime': 8, 'mtime': 9},
                       {'acl': b''}):
            attrs = SFTPAttrs(**kwargs)
            packet = SSHPacket(attrs.encode(4))
            self.assertEqual(repr(SFTPAttrs.decode(packet, 4)), repr(attrs))

            packet = SSHPacket(SFTPAttrs(uid=1, gid=2).encode(4))
            self.assertEqual(repr(SFTPAttrs.decode(packet, 4)),
                             repr(SFTPAttrs(owner='1', group='2')))

        for kwargs in ({'type': FILEXFER_TYPE_REGULAR},
                       {'size': 1234},
                       {'owner': 'a', 'group': 'b'},
                       {'permissions': 0o7777},
                       {'atime': 1, 'atime_ns': 2},
                       {'crtime': 3, 'crtime_ns': 4},
                       {'mtime': 5, 'mtime_ns': 6},
                       {'atime': 7, 'crtime': 8, 'mtime': 9},
                       {'acl': b''},
                       {'attrib_bits': FILEXFER_ATTR_BITS_READONLY,
                        'attrib_valid': FILEXFER_ATTR_BITS_READONLY}):
            attrs = SFTPAttrs(**kwargs)
            packet = SSHPacket(attrs.encode(5))
            self.assertEqual(repr(SFTPAttrs.decode(packet, 5)), repr(attrs))

        for kwargs in ({'type': FILEXFER_TYPE_REGULAR},
                       {'size': 1234, 'alloc_size': 5678},
                       {'owner': 'a', 'group': 'b'},
                       {'permissions': 0o7777},
                       {'atime': 1, 'atime_ns': 2},
                       {'crtime': 3, 'crtime_ns': 4},
                       {'mtime': 5, 'mtime_ns': 6},
                       {'ctime': 7, 'ctime_ns': 8},
                       {'atime': 7, 'crtime': 8, 'mtime': 9, 'ctime': 10},
                       {'acl': b''},
                       {'attrib_bits': FILEXFER_ATTR_BITS_READONLY,
                        'attrib_valid': FILEXFER_ATTR_BITS_READONLY},
                       {'text_hint': FILEXFER_ATTR_KNOWN_TEXT},
                       {'mime_type': 'application/octet-stream'},
                       {'untrans_name': b'\xff'},
                       {'extended': [(b'a1', b'v1'), (b'a2', b'v2')]}):
            attrs = SFTPAttrs(**kwargs)
            packet = SSHPacket(attrs.encode(6))
            self.assertEqual(repr(SFTPAttrs.decode(packet, 6)), repr(attrs))

    def test_illegal_attrs(self):
        """Test decoding illegal SFTP attributes value"""

        with self.assertRaises(SFTPBadMessage):
            SFTPAttrs.decode(SSHPacket(UInt32(FILEXFER_ATTR_OWNERGROUP)), 3)

        for version in range(4, 7):
            with self.assertRaises(SFTPBadMessage):
                SFTPAttrs.decode(SSHPacket(
                    UInt32(FILEXFER_ATTR_UIDGID)), version)

        with self.assertRaises(SFTPOwnerInvalid):
            SFTPAttrs.decode(SSHPacket(
                SFTPAttrs(owner=b'\xff', group='').encode(6)), 6)

        with self.assertRaises(SFTPGroupInvalid):
            SFTPAttrs.decode(SSHPacket(
                SFTPAttrs(owner='', group=b'\xff').encode(6)), 6)

        with self.assertRaises(SFTPBadMessage):
            SFTPAttrs.decode(SSHPacket(
                SFTPAttrs(mime_type=b'\xff').encode(6)), 6)


class _TestSFTPNonstandardSymlink(_CheckSFTP):
    """Unit tests for SFTP server with non-standard symlink order"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server for the tests to use"""

        return await cls.create_server(server_version='OpenSSH',
                                       sftp_factory=_SymlinkSFTPServer)

    @asynctest
    async def test_nonstandard_symlink_client(self):
        """Test creating a symlink with opposite argument order"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            async with self.connect(client_version='OpenSSH') as conn:
                async with conn.start_sftp_client() as sftp:
                    await sftp.symlink('link', 'file')
                    self._check_link('link', 'file')
        finally:
            remove('file link')


class _TestSFTPAsync(_TestSFTP):
    """Unit test for an async SFTPServer"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server with async callbacks"""

        return await cls.create_server(sftp_factory=_AsyncSFTPServer,
                                       sftp_version=6)

    @sftp_test
    async def test_async_realpath(self, sftp):
        """Test canonicalizing a path on an async SFTP server"""

        self.assertEqual((await sftp.realpath('dir/../file')),
                         posixpath.join((await sftp.getcwd()), 'file'))

    @sftp_test_v6
    async def test_async_realpath_v6(self, sftp):
        """Test canonicalizing a path on an async SFTPv6 server"""

        self._create_file('file1')

        self.assertEqual((await sftp.realpath('dir/../file')),
                         posixpath.join((await sftp.getcwd()), 'file'))

        name = await sftp.realpath('dir/../file1', check=FXRP_STAT_ALWAYS)
        self.assertEqual(name.attrs.type, FILEXFER_TYPE_REGULAR)


class _CheckSCP(_CheckSFTP):
    """Utility functions for AsyncSSH SCP unit tests"""

    @classmethod
    async def asyncSetUpClass(cls):
        """Set up SCP target host/port tuple"""

        await super().asyncSetUpClass()

        cls._scp_server = (cls._server_addr, cls._server_port)

    @classmethod
    async def start_server(cls):
        """Start an SFTP server with SCP enabled for the tests to use"""

        return await cls.create_server(sftp_factory=True, allow_scp=True)

    async def _check_scp(self, src, dst, data=(), **kwargs):
        """Check copying a file over SCP"""

        try:
            self._create_file('src', data)
            await scp(src, dst, **kwargs)
            self._check_file('src', 'dst')
        finally:
            remove('src dst')

    async def _check_progress(self, src, dst):
        """Check copying a file over SCP with progress reporting"""

        def _report_progress(_srcpath, _dstpath, bytes_copied, _total_bytes):
            """Monitor progress of copy"""

            reports.append(bytes_copied)

        for size in (0, 100000):
            with self.subTest(size=size):
                reports = []

                await self._check_scp(src, dst, size * 'a', block_size=8192,
                                      progress_handler=_report_progress)

                self.assertEqual(len(reports), (size // 8192) + 1)
                self.assertEqual(reports[-1], size)

    async def _check_cancel(self, src, dst):
        """Check cancelling a file transfer over SCP"""

        def _cancel(_srcpath, _dstpath, _bytes_copied, _total_bytes):
            """Cancel transfer"""

            task.cancel()

        try:
            self._create_file('src', 1024*8192 * 'a')

            coro = scp(src, dst, block_size=8192, progress_handler=_cancel)

            task = asyncio.create_task(coro)
            await task
        finally:
            remove('src dst')


class _TestSCP(_CheckSCP):
    """Unit tests for AsyncSSH SCP client and server"""

    @asynctest
    async def test_get(self):
        """Test getting a file over SCP"""

        for src in ('src', b'src', Path('src')):
            for dst in ('dst', b'dst', Path('dst')):
                with self.subTest(src=type(src), dst=type(dst)):
                    await self._check_scp((self._scp_server, src), dst)

    @asynctest
    async def test_get_progress(self):
        """Test getting a file over SCP with progress reporting"""

        await self._check_progress((self._scp_server, 'src'), 'dst')

    @asynctest
    async def test_get_cancel(self):
        """Test cancelling a get of a file over SCP"""

        await self._check_cancel((self._scp_server, 'src'), 'dst')

    @asynctest
    async def test_get_preserve(self):
        """Test getting a file with preserved attributes over SCP"""

        try:
            self._create_file('src', utime=(1, 2))
            await scp((self._scp_server, 'src'), 'dst', preserve=True)
            self._check_file('src', 'dst', preserve=True, check_atime=False)
        finally:
            remove('src dst')

    @asynctest
    async def test_get_recurse(self):
        """Test recursively getting a directory over SCP"""

        try:
            os.mkdir('src')
            self._create_file('src/file1')

            await scp((self._scp_server, 'src'), 'dst', recurse=True)

            self._check_file('src/file1', 'dst/file1')
        finally:
            remove('src dst')

    @asynctest
    async def test_get_error_handler(self):
        """Test getting multiple files over SCP with error handler"""

        def err_handler(exc):
            """Catch error for non-recursive copy of directory"""

            self.assertEqual(exc.reason, 'scp: Not a regular file: src2')

        try:
            self._create_file('src1')
            os.mkdir('src2')
            os.mkdir('dst')

            await scp((self._scp_server, 'src*'), 'dst',
                      error_handler=err_handler)

            self._check_file('src1', 'dst/src1')
        finally:
            remove('src1 src2 dst')

    @asynctest
    async def test_get_recurse_existing(self):
        """Test getting a directory over SCP where target dir exists"""

        try:
            os.mkdir('src')
            os.mkdir('dst')
            os.mkdir('dst/src')
            self._create_file('src/file1')

            await scp((self._scp_server, 'src'), 'dst', recurse=True)

            self._check_file('src/file1', 'dst/src/file1')
        finally:
            remove('src dst')

    @unittest.skipIf(sys.platform == 'win32',
                     'skip permission tests on Windows')
    @asynctest
    async def test_get_not_permitted(self):
        """Test getting a file with no read permissions over SCP"""

        try:
            self._create_file('src', mode=0)

            with self.assertRaises(SFTPFailure):
                await scp((self._scp_server, 'src'), 'dst')
        finally:
            remove('src dst')

    @asynctest
    async def test_get_directory_as_file(self):
        """Test getting a file which is actually a directory over SCP"""

        try:
            os.mkdir('src')

            with self.assertRaises(SFTPFailure):
                await scp((self._scp_server, 'src'), 'dst')
        finally:
            remove('src dst')

    @asynctest
    async def test_get_non_directory_in_path(self):
        """Test getting a file with a non-directory in path over SCP"""

        try:
            self._create_file('src')

            with self.assertRaises(SFTPFailure):
                await scp((self._scp_server, 'src/xxx'), 'dst')
        finally:
            remove('src dst')

    @asynctest
    async def test_get_recurse_not_directory(self):
        """Test getting a directory over SCP where target is not directory"""

        try:
            os.mkdir('src')
            self._create_file('dst')
            self._create_file('src/file1')

            with self.assertRaises(SFTPFailure):
                await scp((self._scp_server, 'src'), 'dst', recurse=True)
        finally:
            remove('src dst')

    @asynctest
    async def test_put(self):
        """Test putting a file over SCP"""

        for src in ('src', b'src', Path('src')):
            for dst in ('dst', b'dst', Path('dst')):
                with self.subTest(src=type(src), dst=type(dst)):
                    await self._check_scp(src, (self._scp_server, dst))

    @asynctest
    async def test_put_progress(self):
        """Test putting a file over SCP with progress reporting"""

        await self._check_progress('src', (self._scp_server, 'dst'))

    @asynctest
    async def test_put_cancel(self):
        """Test cancelling a put of a file over SCP"""

        await self._check_cancel('src', (self._scp_server, 'dst'))

    @asynctest
    async def test_put_preserve(self):
        """Test putting a file with preserved attributes over SCP"""

        try:
            self._create_file('src', utime=(1, 2))
            await scp('src', (self._scp_server, 'dst'), preserve=True)
            self._check_file('src', 'dst', preserve=True, check_atime=False)
        finally:
            remove('src dst')

    @asynctest
    async def test_put_recurse(self):
        """Test recursively putting a directory over SCP"""

        try:
            os.mkdir('src')
            self._create_file('src/file1')

            await scp('src', (self._scp_server, 'dst'), recurse=True)

            self._check_file('src/file1', 'dst/file1')
        finally:
            remove('src dst')

    @asynctest
    async def test_put_recurse_existing(self):
        """Test putting a directory over SCP where target dir exists"""

        try:
            os.mkdir('src')
            os.mkdir('dst')
            self._create_file('src/file1')

            await scp('src', (self._scp_server, 'dst'), recurse=True)

            self._check_file('src/file1', 'dst/src/file1')
        finally:
            remove('src dst')

    @asynctest
    async def test_put_must_be_dir(self):
        """Test putting multiple files to a non-directory over SCP"""

        try:
            self._create_file('src1')
            self._create_file('src2')
            self._create_file('dst')

            with self.assertRaises(SFTPFailure):
                await scp(['src1', 'src2'], (self._scp_server, 'dst'))
        finally:
            remove('src1 src2 dst')

    @asynctest
    async def test_put_non_directory_in_path(self):
        """Test putting a file with a non-directory in path over SCP"""

        try:
            self._create_file('src')

            with self.assertRaises(OSError):
                await scp('src/xxx', (self._scp_server, 'dst'))
        finally:
            remove('src')

    @asynctest
    async def test_put_recurse_not_directory(self):
        """Test putting a directory over SCP where target is not directory"""

        try:
            os.mkdir('src')
            self._create_file('dst')
            self._create_file('src/file1')

            with self.assertRaises(SFTPFailure):
                await scp('src', (self._scp_server, 'dst'), recurse=True)
        finally:
            remove('src dst')

    @asynctest
    async def test_put_read_error(self):
        """Test read errors when putting a file over SCP"""

        async def _read_error(self, size, offset):
            """Return an error for reads past 64 KB in a file"""

            if offset >= 65536:
                raise OSError(errno.EIO, 'I/O error')
            else:
                return await orig_read(self, size, offset)

        try:
            self._create_file('src', 128*1024*'\0')

            orig_read = LocalFile.read

            with patch('asyncssh.sftp.LocalFile.read', _read_error):
                with self.assertRaises(OSError):
                    await scp('src', (self._scp_server, 'dst'))
        finally:
            remove('src dst')

    @asynctest
    async def test_put_read_early_eof(self):
        """Test getting early EOF when putting a file over SCP"""

        async def _read_early_eof(self, size, offset):
            """Return an early EOF for reads past 64 KB in a file"""

            if offset >= 65536:
                return b''
            else:
                return await orig_read(self, size, offset)

        try:
            self._create_file('src', 128*1024*'\0')

            orig_read = LocalFile.read

            with patch('asyncssh.sftp.LocalFile.read', _read_early_eof):
                with self.assertRaises(SFTPFailure):
                    await scp('src', (self._scp_server, 'dst'))
        finally:
            remove('src dst')

    @asynctest
    async def test_put_name_too_long(self):
        """Test putting a file over SCP with too long a name"""

        try:
            self._create_file('src')

            with self.assertRaises(SFTPFailure):
                await scp('src', (self._scp_server, 256*'a'))
        finally:
            remove('src dst')

    @asynctest
    async def test_copy(self):
        """Test copying a file between remote hosts over SCP"""

        for src in ('src', b'src', Path('src')):
            for dst in ('dst', b'dst', Path('dst')):
                with self.subTest(src=type(src), dst=type(dst)):
                    await self._check_scp((self._scp_server, src),
                                          (self._scp_server, dst))

    @asynctest
    async def test_copy_progress(self):
        """Test copying a file over SCP with progress reporting"""

        await self._check_progress((self._scp_server, 'src'),
                                   (self._scp_server, 'dst'))

    @asynctest
    async def test_copy_cancel(self):
        """Test cancelling a copy of a file over SCP"""

        await self._check_cancel((self._scp_server, 'src'),
                                 (self._scp_server, 'dst'))

    @asynctest
    async def test_copy_preserve(self):
        """Test copying a file with preserved attributes between hosts"""

        try:
            self._create_file('src', utime=(1, 2))
            await scp((self._scp_server, 'src'), (self._scp_server, 'dst'),
                      preserve=True)
            self._check_file('src', 'dst', preserve=True, check_atime=False)
        finally:
            remove('src dst')

    @asynctest
    async def test_copy_recurse(self):
        """Test recursively copying a directory between hosts over SCP"""

        try:
            os.mkdir('src')
            self._create_file('src/file1')

            await scp((self._scp_server, 'src'), (self._scp_server, 'dst'),
                      recurse=True)

            self._check_file('src/file1', 'dst/file1')
        finally:
            remove('src dst')

    @asynctest
    async def test_copy_error_handler_source(self):
        """Test copying multiple files over SCP with error handler"""

        def err_handler(exc):
            """Catch error for non-recursive copy of directory"""

            self.assertEqual(exc.reason, 'scp: Not a regular file: src2')

        try:
            self._create_file('src1')
            os.mkdir('src2')
            os.mkdir('dst')

            await scp((self._scp_server, 'src*'), (self._scp_server, 'dst'),
                      error_handler=err_handler)

            self._check_file('src1', 'dst/src1')
        finally:
            remove('src1 src2 dst')

    @asynctest
    async def test_copy_error_handler_sink(self):
        """Test copying multiple files over SCP with error handler"""

        def err_handler(exc):
            """Catch error for non-recursive copy of directory"""

            if sys.platform == 'win32': # pragma: no cover
                self.assertEqual(exc.reason,
                                 'scp: Permission denied: dst\\src2')
            else:
                self.assertEqual(exc.reason, 'scp: Is a directory: dst/src2')

        try:
            self._create_file('src1')
            self._create_file('src2')
            os.mkdir('dst')
            os.mkdir('dst/src2')

            await scp((self._scp_server, 'src*'), (self._scp_server, 'dst'),
                      error_handler=err_handler)

            self._check_file('src1', 'dst/src1')
        finally:
            remove('src1 src2 dst')

    @asynctest
    async def test_copy_recurse_existing(self):
        """Test copying a directory over SCP where target dir exists"""

        try:
            os.mkdir('src')
            os.mkdir('dst')
            self._create_file('src/file1')

            await scp((self._scp_server, 'src'), (self._scp_server, 'dst'),
                      recurse=True)

            self._check_file('src/file1', 'dst/src/file1')
        finally:
            remove('src dst')

    @asynctest
    async def test_local_copy(self):
        """Test for error return when attempting to copy local files"""

        with self.assertRaises(ValueError):
            await scp('src', 'dst')

    @asynctest
    async def test_copy_multiple(self):
        """Test copying multiple files over SCP"""

        try:
            os.mkdir('src')
            self._create_file('src/file1')
            self._create_file('src/file2')
            await scp([(self._scp_server, 'src/file1'),
                       (self._scp_server, 'src/file2')], '.')
            self._check_file('src/file1', 'file1')
            self._check_file('src/file2', 'file2')
        finally:
            remove('src file1 file2')

    @asynctest
    async def test_copy_recurse_not_directory(self):
        """Test copying a directory over SCP where target is not directory"""

        try:
            os.mkdir('src')
            self._create_file('dst')
            self._create_file('src/file1')

            with self.assertRaises(SFTPFailure):
                await scp((self._scp_server, 'src'), (self._scp_server, 'dst'),
                          recurse=True)
        finally:
            remove('src dst')

    @asynctest
    async def test_source_string(self):
        """Test passing a string to SCP"""

        with self.assertRaises(OSError):
            await scp('\xff:xxx', '.')

    @asynctest
    async def test_source_bytes(self):
        """Test passing a byte string to SCP"""

        with self.assertRaises(OSError):
            await scp('\xff:xxx'.encode('utf-8'), '.')

    @asynctest
    async def test_source_open_connection(self):
        """Test passing an open SSHClientConnection to SCP as source"""

        try:
            async with self.connect() as conn:
                self._create_file('src')
                await scp((conn, 'src'), 'dst')
                self._check_file('src', 'dst')
        finally:
            remove('src dst')

    @asynctest
    async def test_destination_open_connection(self):
        """Test passing an open SSHClientConnection to SCP as destination"""

        try:
            async with self.connect() as conn:
                os.mkdir('src')
                self._create_file('src/file1')
                await scp('src/file1', conn)
                self._check_file('src/file1', 'file1')
        finally:
            remove('src file1')

    @asynctest
    async def test_missing_path(self):
        """Test running SCP with missing path"""

        async with self.connect() as conn:
            result = await conn.run('scp ')
            self.assertEqual(result.stderr, 'scp: the following arguments '
                             'are required: path\n')

    @asynctest
    async def test_missing_direction(self):
        """Test running SCP with missing direction argument"""

        async with self.connect() as conn:
            result = await conn.run('scp xxx')
            self.assertEqual(result.stderr, 'scp: one of the arguments -f -t '
                             'is required\n')

    @asynctest
    async def test_invalid_argument(self):
        """Test running SCP with invalid argument"""

        async with self.connect() as conn:
            result = await conn.run('scp -f -x src')
            self.assertEqual(result.stderr, 'scp: unrecognized arguments: -x\n')

    @asynctest
    async def test_invalid_c_argument(self):
        """Test running SCP with invalid argument to C request"""

        async with self.connect() as conn:
            result = await conn.run('scp -t dst', input='C\n')
            self.assertEqual(result.stdout,
                             '\0\x01scp: Invalid copy or dir request\n')

    @asynctest
    async def test_invalid_t_argument(self):
        """Test running SCP with invalid argument to C request"""

        async with self.connect() as conn:
            result = await conn.run('scp -t -p dst', input='T\n')
            self.assertEqual(result.stdout, '\0\x01scp: Invalid time request\n')


class _TestSCPAsync(_TestSCP):
    """Unit test for AsyncSSH SCP using an async SFTPServer"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server with async callbacks"""

        return await cls.create_server(sftp_factory=_AsyncSFTPServer,
                                       allow_scp=True)


class _TestSCPAttrs(_CheckSCP):
    """Unit test for SCP with SFTP server returning SFTPAttrs"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns SFTPAttrs from stat"""

        return await cls.create_server(sftp_factory=_SFTPAttrsSFTPServer,
                                       allow_scp=True)

    @asynctest
    async def test_get(self):
        """Test getting a file over SCP with stat returning SFTPAttrs"""

        try:
            self._create_file('src')
            await scp((self._scp_server, 'src*'), 'dst')
            self._check_file('src', 'dst')
        finally:
            remove('src dst')

    @asynctest
    async def test_put_recurse_not_directory(self):
        """Test putting a directory over SCP where target is not directory"""

        try:
            os.mkdir('src')
            self._create_file('dst')
            self._create_file('src/file1')

            with self.assertRaises(SFTPFailure):
                await scp('src', (self._scp_server, 'dst'), recurse=True)
        finally:
            remove('src dst')

    @asynctest
    async def test_put_not_permitted(self):
        """Test putting a file over SCP onto an unwritable target"""

        try:
            self._create_file('src')
            os.mkdir('dst')
            os.chmod('dst', 0)

            with self.assertRaises(SFTPFailure):
                await scp('src', (self._scp_server, 'dst/src'))
        finally:
            os.chmod('dst', 0o755)
            remove('src dst')


class _TestSCPIOError(_CheckSCP):
    """Unit test for SCP with SFTP server returning file I/O error"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns file I/O errors"""

        return await cls.create_server(sftp_factory=_IOErrorSFTPServer,
                                       allow_scp=True)

    @asynctest
    async def test_put_error(self):
        """Test error when putting a file over SCP"""

        try:
            self._create_file('src', 4*1024*1024*'\0')

            with self.assertRaises(SFTPFailure):
                await scp('src', (self._scp_server, 'dst'))
        finally:
            remove('src dst')

    @asynctest
    async def test_copy_error(self):
        """Test error when copying a file over SCP"""

        try:
            self._create_file('src', 4*1024*1024*'\0')

            with self.assertRaises(SFTPFailure):
                await scp((self._scp_server, 'src'),
                          (self._scp_server, 'dst'))
        finally:
            remove('src dst')


class _TestSCPErrors(_CheckSCP):
    """Unit test for SCP returning error on startup"""

    @classmethod
    async def start_server(cls):
        """Start an SFTP server which returns file I/O errors"""

        async def _handle_client(process):
            """Handle new client"""

            async with process:
                command = process.command

                if command.endswith('get_connection_lost'):
                    pass
                elif command.endswith('get_dir_no_recurse'):
                    await process.stdin.read(1)
                    process.stdout.write('D0755 0 src\n')
                elif command.endswith('get_early_eof'):
                    await process.stdin.read(1)
                    process.stdout.write('C0644 10 src\n')
                    await process.stdin.read(1)
                elif command.endswith('get_extra_e'):
                    await process.stdin.read(1)
                    process.stdout.write('E\n')
                    await process.stdin.read(1)
                elif command.endswith('get_t_without_preserve'):
                    await process.stdin.read(1)
                    process.stdout.write('T0 0 0 0\n')
                    await process.stdin.read(1)
                elif command.endswith('get_unknown_action'):
                    await process.stdin.read(1)
                    process.stdout.write('X\n')
                    await process.stdin.read(1)
                elif command.endswith('put_connection_lost'):
                    process.stdout.write('\0\0')
                elif command.endswith('put_startup_error'):
                    process.stdout.write('Error starting SCP\n')
                elif command.endswith('recv_early_eof'):
                    process.stdout.write('\0')
                    await process.stdin.readline()
                    try:
                        process.stdout.write('\0')
                    except BrokenPipeError:
                        pass
                else:
                    process.exit(255)

        return await cls.create_server(process_factory=_handle_client)

    @asynctest
    async def test_get_directory_without_recurse(self):
        """Test receiving directory when recurse wasn't requested"""

        try:
            with self.assertRaises((SFTPBadMessage, SFTPConnectionLost)):
                await scp((self._scp_server, 'get_dir_no_recurse'), 'dst')
        finally:
            remove('dst')

    @asynctest
    async def test_get_early_eof(self):
        """Test getting early EOF when getting a file over SCP"""

        try:
            with self.assertRaises(SFTPConnectionLost):
                await scp((self._scp_server, 'get_early_eof'), 'dst')
        finally:
            remove('dst')

    @asynctest
    async def test_get_t_without_preserve(self):
        """Test getting timestamps with requesting preserve"""

        try:
            await scp((self._scp_server, 'get_t_without_preserve'), 'dst')
        finally:
            remove('dst')

    @asynctest
    async def test_get_unknown_action(self):
        """Test getting unknown action from SCP server during get"""

        try:
            with self.assertRaises(SFTPBadMessage):
                await scp((self._scp_server, 'get_unknown_action'), 'dst')
        finally:
            remove('dst')

    @asynctest
    async def test_put_startup_error(self):
        """Test SCP server returning an error on startup"""

        try:
            self._create_file('src')

            with self.assertRaises(SFTPFailure) as exc:
                await scp('src', (self._scp_server, 'put_startup_error'))

            self.assertEqual(exc.exception.reason, 'Error starting SCP')
        finally:
            remove('src')

    @asynctest
    async def test_put_connection_lost(self):
        """Test SCP server abruptly closing connection on put"""

        try:
            self._create_file('src')

            with self.assertRaises(SFTPConnectionLost) as exc:
                await scp('src', (self._scp_server, 'put_connection_lost'))

            self.assertEqual(exc.exception.reason, 'Connection lost')
        finally:
            remove('src')

    @asynctest
    async def test_copy_connection_lost_source(self):
        """Test source abruptly closing connection during SCP copy"""

        with self.assertRaises(SFTPConnectionLost) as exc:
            await scp((self._scp_server, 'get_connection_lost'),
                      (self._scp_server, 'recv_early_eof'))

        self.assertEqual(exc.exception.reason, 'Connection lost')

    @asynctest
    async def test_copy_connection_lost_sink(self):
        """Test sink abruptly closing connection during SCP copy"""

        with self.assertRaises(SFTPConnectionLost) as exc:
            await scp((self._scp_server, 'get_early_eof'),
                      (self._scp_server, 'put_connection_lost'))

        self.assertEqual(exc.exception.reason, 'Connection lost')

    @asynctest
    async def test_copy_early_eof(self):
        """Test getting early EOF when copying a file over SCP"""

        with self.assertRaises(SFTPConnectionLost):
            await scp((self._scp_server, 'get_early_eof'),
                      (self._scp_server, 'recv_early_eof'))

    @asynctest
    async def test_copy_extra_e(self):
        """Test getting extra E when copying a file over SCP"""

        await scp((self._scp_server, 'get_extra_e'),
                  (self._scp_server, 'recv_early_eof'))

    @asynctest
    async def test_copy_unknown_action(self):
        """Test getting unknown action from SCP server during copy"""

        with self.assertRaises(SFTPBadMessage):
            await scp((self._scp_server, 'get_unknown_action'),
                      (self._scp_server, 'recv_early_eof'))

    @asynctest
    async def test_unknown(self):
        """Test unknown SCP server request for code coverage"""

        with self.assertRaises(SFTPConnectionLost):
            await scp('src', (self._scp_server, 'unknown'))
