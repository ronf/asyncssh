# Copyright (c) 2015-2018 by Ron Frederick <ronf@timeheart.net>.
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

from asyncssh import SFTPError, SFTPAttrs, SFTPVFSAttrs, SFTPName, SFTPServer
from asyncssh import SEEK_CUR, SEEK_END
from asyncssh import FXP_INIT, FXP_VERSION, FXP_OPEN, FXP_CLOSE
from asyncssh import FXP_STATUS, FXP_HANDLE, FXP_DATA, FILEXFER_ATTR_UNDEFINED
from asyncssh import FX_OK, FX_PERMISSION_DENIED, FX_FAILURE
from asyncssh import scp

from asyncssh.misc import python35
from asyncssh.packet import SSHPacket, String, UInt32
from asyncssh.sftp import LocalFile, SFTPHandler, SFTPServerHandler

from .server import ServerTestCase
from .util import asynctest


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
    def sftp_wrapper(self):
        """Run a test coroutine after opening an SFTP client"""

        with (yield from self.connect()) as conn:
            with (yield from conn.start_sftp_client()) as sftp:
                yield from asyncio.coroutine(func)(self, sftp)

            yield from sftp.wait_closed()

        yield from conn.wait_closed()

    return sftp_wrapper


class _ResetFileHandleServerHandler(SFTPServerHandler):
    """Reset file handle counter on each request to test handle-in-use check"""

    @asyncio.coroutine
    def recv_packet(self):
        """Reset next handle counter to test handle-in-use check"""

        self._next_handle = 0
        return (yield from super().recv_packet())


class _NonblockingCloseServerHandler(SFTPServerHandler):
    """Close the SFTP session without responding to a nonblocking close"""

    @asyncio.coroutine
    def _process_packet(self, pkttype, pktid, packet):
        """Close the session when a file close request is received"""

        if pkttype == FXP_CLOSE:
            yield from self._cleanup(None)
        else:
            yield from super()._process_packet(pkttype, pktid, packet)


class _ChrootSFTPServer(SFTPServer):
    """Return an FTP server with a changed root"""

    def __init__(self, conn):
        os.mkdir('chroot')
        super().__init__(conn, 'chroot')

    def exit(self):
        """Clean up the changed root directory"""

        remove('chroot')


class _IOErrorSFTPServer(SFTPServer):
    """Return an I/O error during file writing"""

    @asyncio.coroutine
    def write(self, file_obj, offset, data):
        """Return an error for writes past 64 KB in a file"""

        if offset >= 65536:
            raise SFTPError(FX_FAILURE, 'I/O error')
        else:
            super().write(file_obj, offset, data)


class _NotImplSFTPServer(SFTPServer):
    """Return an error that a request is not implemented"""

    @asyncio.coroutine
    def symlink(self, oldpath, newpath):
        """Return that symlinks aren't implemented"""

        raise NotImplementedError


class _LongnameSFTPServer(SFTPServer):
    """Return a fixed set of files in response to a listdir request"""

    def listdir(self, path):
        """List the contents of a directory"""

        return list((b'.',
                     b'..',
                     SFTPName(b'.file'),
                     SFTPName(b'file1'),
                     SFTPName(b'file2', '', SFTPAttrs(permissions=0, nlink=1,
                                                      uid=0, gid=0, size=0,
                                                      mtime=0)),
                     SFTPName(b'file3', '', SFTPAttrs(mtime=time.time())),
                     SFTPName(b'file4', 56*b' ' + b'file4')))

    def lstat(self, path):
        """Get attributes of a file, directory, or symlink"""

        return SFTPAttrs.from_local(super().lstat(path))


class _LargeDirSFTPServer(SFTPServer):
    """Return a really large listdir result"""

    @asyncio.coroutine
    def listdir(self, path):
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
        """Set attributes of a file or directory"""

        # pylint: disable=unused-argument

        self._ownership[self.map_path(path)] = (attrs.uid, attrs.gid)

    def stat(self, path):
        """Get attributes of a file or directory, following symlinks"""

        # pylint: disable=unused-argument

        path = self.map_path(path)
        attrs = SFTPAttrs.from_local(os.stat(path))

        if path in self._ownership: # pragma: no branch
            attrs.uid, attrs.gid = self._ownership[path]

        return attrs


class _SymlinkSFTPServer(SFTPServer):
    """Implement symlink with non-standard argument order"""

    def symlink(self, oldpath, newpath):
        """Create a symbolic link"""

        return super().symlink(newpath, oldpath)


class _SFTPAttrsSFTPServer(SFTPServer):
    """Implement stat which returns SFTPAttrs and raises SFTPError"""

    @asyncio.coroutine
    def stat(self, path):
        """Get attributes of a file or directory, following symlinks"""

        try:
            return SFTPAttrs.from_local(super().stat(path))
        except OSError as exc:
            if exc.errno == errno.EACCES:
                raise SFTPError(FX_PERMISSION_DENIED, exc.strerror)
            else:
                raise SFTPError(FX_FAILURE, exc.strerror)


class _AsyncSFTPServer(SFTPServer):
    """Implement all SFTP callbacks as coroutines"""

    @asyncio.coroutine
    def format_longname(self, name):
        """Format the long name associated with an SFTP name"""

        return super().format_longname(name)

    @asyncio.coroutine
    def open(self, path, pflags, attrs):
        """Open a file to serve to a remote client"""

        return super().open(path, pflags, attrs)

    @asyncio.coroutine
    def close(self, file_obj):
        """Close an open file or directory"""

        super().close(file_obj)

    @asyncio.coroutine
    def read(self, file_obj, offset, size):
        """Read data from an open file"""

        return super().read(file_obj, offset, size)

    @asyncio.coroutine
    def write(self, file_obj, offset, data):
        """Write data to an open file"""

        return super().write(file_obj, offset, data)

    @asyncio.coroutine
    def lstat(self, path):
        """Get attributes of a file, directory, or symlink"""

        return super().lstat(path)

    @asyncio.coroutine
    def fstat(self, file_obj):
        """Get attributes of an open file"""

        return super().fstat(file_obj)

    @asyncio.coroutine
    def setstat(self, path, attrs):
        """Set attributes of a file or directory"""

        super().setstat(path, attrs)

    @asyncio.coroutine
    def fsetstat(self, file_obj, attrs):
        """Set attributes of an open file"""

        super().fsetstat(file_obj, attrs)

    @asyncio.coroutine
    def listdir(self, path):
        """List the contents of a directory"""

        return super().listdir(path)

    @asyncio.coroutine
    def remove(self, path):
        """Remove a file or symbolic link"""

        super().remove(path)

    @asyncio.coroutine
    def mkdir(self, path, attrs):
        """Create a directory with the specified attributes"""

        super().mkdir(path, attrs)

    @asyncio.coroutine
    def rmdir(self, path):
        """Remove a directory"""

        super().rmdir(path)

    @asyncio.coroutine
    def realpath(self, path):
        """Return the canonical version of a path"""

        return super().realpath(path)

    @asyncio.coroutine
    def stat(self, path):
        """Get attributes of a file or directory, following symlinks"""

        return super().stat(path)

    @asyncio.coroutine
    def rename(self, oldpath, newpath):
        """Rename a file, directory, or link"""

        super().rename(oldpath, newpath)

    @asyncio.coroutine
    def readlink(self, path):
        """Return the target of a symbolic link"""

        return super().readlink(path)

    @asyncio.coroutine
    def symlink(self, oldpath, newpath):
        """Create a symbolic link"""

        super().symlink(oldpath, newpath)

    @asyncio.coroutine
    def posix_rename(self, oldpath, newpath):
        """Rename a file, directory, or link with POSIX semantics"""

        super().posix_rename(oldpath, newpath)

    @asyncio.coroutine
    def statvfs(self, path):
        """Get attributes of the file system containing a file"""

        return super().statvfs(path)

    @asyncio.coroutine
    def fstatvfs(self, file_obj):
        """Return attributes of the file system containing an open file"""

        return super().fstatvfs(file_obj)

    @asyncio.coroutine
    def link(self, oldpath, newpath):
        """Create a hard link"""

        super().link(oldpath, newpath)

    @asyncio.coroutine
    def fsync(self, file_obj):
        """Force file data to be written to disk"""

        super().fsync(file_obj)

    @asyncio.coroutine
    def exit(self):
        """Shut down this SFTP server"""

        super().exit()


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

        with open(name, 'w') as f:
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

        with open(name1) as file1:
            with open(name2) as file2:
                self.assertEqual(file1.read(), file2.read())

    def _check_stat(self, sftp_stat, local_stat):
        """Check if file attributes are equal"""

        self.assertEqual(sftp_stat.size, local_stat.st_size)
        self.assertEqual(sftp_stat.uid, local_stat.st_uid)
        self.assertEqual(sftp_stat.gid, local_stat.st_gid)
        self.assertEqual(sftp_stat.permissions, local_stat.st_mode)
        self.assertEqual(sftp_stat.atime, int(local_stat.st_atime))
        self.assertEqual(sftp_stat.mtime, int(local_stat.st_mtime))

    def _check_link(self, link, target):
        """Check if a symlink points to the right target"""

        self.assertEqual(os.readlink(link), target)


class _TestSFTP(_CheckSFTP):
    """Unit tests for AsyncSSH SFTP client and server"""

    # pylint: disable=too-many-public-methods

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server for the tests to use"""

        return (yield from cls.create_server(sftp_factory=True))

    @sftp_test
    def test_copy(self, sftp):
        """Test copying a file over SFTP"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src')
                    yield from getattr(sftp, method)('src', 'dst')
                    self._check_file('src', 'dst')
                finally:
                    remove('src dst')

    @sftp_test
    def test_copy_progress(self, sftp):
        """Test copying a file over SFTP with progress reporting"""

        def _report_progress(srcpath, dstpath, bytes_copied, total_bytes):
            """Monitor progress of copy"""

            # pylint: disable=unused-argument

            reports.append(bytes_copied)

        for method in ('get', 'put', 'copy'):
            reports = []

            with self.subTest(method=method):
                try:
                    self._create_file('src', 100000*'a')
                    yield from getattr(sftp, method)(
                        'src', 'dst', block_size=8192,
                        progress_handler=_report_progress)
                    self._check_file('src', 'dst')

                    self.assertEqual(len(reports), 13)
                    self.assertEqual(reports[-1], 100000)
                finally:
                    remove('src dst')

    @sftp_test
    def test_copy_preserve(self, sftp):
        """Test copying a file with preserved attributes over SFTP"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src', mode=0o666, utime=(1, 2))
                    yield from getattr(sftp, method)('src', 'dst',
                                                     preserve=True)
                    self._check_file('src', 'dst', preserve=True)
                finally:
                    remove('src dst')

    @sftp_test
    def test_copy_recurse(self, sftp):
        """Test recursively copying a directory over SFTP"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    os.mkdir('src')
                    self._create_file('src/file1')

                    if self._symlink_supported: # pragma: no branch
                        os.symlink('file1', 'src/file2')

                    yield from getattr(sftp, method)('src', 'dst',
                                                     recurse=True)

                    self._check_file('src/file1', 'dst/file1')

                    if self._symlink_supported: # pragma: no branch
                        self._check_link('dst/file2', 'file1')
                finally:
                    remove('src dst')

    @sftp_test
    def test_copy_recurse_existing(self, sftp):
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

                    yield from getattr(sftp, method)('src', 'dst',
                                                     recurse=True)

                    self._check_file('src/file1', 'dst/src/file1')

                    if self._symlink_supported: # pragma: no branch
                        self._check_link('dst/src/file2', 'file1')
                finally:
                    remove('src dst')

    @sftp_test
    def test_copy_follow_symlinks(self, sftp):
        """Test copying a file over SFTP while following symlinks"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src')
                    os.symlink('src', 'link')
                    yield from getattr(sftp, method)('link', 'dst',
                                                     follow_symlinks=True)
                    self._check_file('src', 'dst')
                finally:
                    remove('src dst link')

    @sftp_test
    def test_copy_invalid_name(self, sftp):
        """Test copying a file with an invalid name over SFTP"""

        for method in ('get', 'put', 'copy', 'mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                with self.assertRaises((FileNotFoundError, SFTPError,
                                        UnicodeDecodeError)):
                    yield from getattr(sftp, method)(b'\xff')

    @sftp_test
    def test_copy_directory_no_recurse(self, sftp):
        """Test copying a directory over SFTP without recurse option"""

        for method in ('get', 'put', 'copy', 'mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    os.mkdir('dir')
                    with self.assertRaises(SFTPError):
                        yield from getattr(sftp, method)('dir')
                finally:
                    remove('dir')

    @sftp_test
    def test_multiple_copy(self, sftp):
        """Test copying multiple files over SFTP"""

        for method in ('mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src1', 'xxx')
                    self._create_file('src2', 'yyy')
                    os.mkdir('dst')

                    yield from getattr(sftp, method)('src*', 'dst')

                    self._check_file('src1', 'dst/src1')
                    self._check_file('src2', 'dst/src2')
                finally:
                    remove('src1 src2 dst')

    @sftp_test
    def test_multiple_copy_bytes_path(self, sftp):
        """Test copying multiple files with byte string paths over SFTP"""

        for method in ('mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src1', 'xxx')
                    self._create_file('src2', 'yyy')
                    os.mkdir('dst')

                    yield from getattr(sftp, method)(b'src*', b'dst')

                    self._check_file('src1', 'dst/src1')
                    self._check_file('src2', 'dst/src2')
                finally:
                    remove('src1 src2 dst')

    @sftp_test
    def test_multiple_copy_pathlib_path(self, sftp):
        """Test copying multiple files with pathlib paths over SFTP"""

        for method in ('mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src1', 'xxx')
                    self._create_file('src2', 'yyy')
                    os.mkdir('dst')

                    yield from getattr(sftp, method)(Path('src*'), Path('dst'))

                    self._check_file('src1', 'dst/src1')
                    self._check_file('src2', 'dst/src2')
                finally:
                    remove('src1 src2 dst')

    @sftp_test
    def test_multiple_copy_target_not_dir(self, sftp):
        """Test copying multiple files over SFTP with non-directory target"""

        for method in ('mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src')

                    with self.assertRaises(SFTPError):
                        yield from getattr(sftp, method)('src', 'dst')
                finally:
                    remove('src')

    @sftp_test
    def test_multiple_copy_error_handler(self, sftp):
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

                    yield from getattr(sftp, method)('src*', 'dst',
                                                     error_handler=err_handler)

                    self._check_file('src1', 'dst/src1')
                finally:
                    remove('src1 src2 dst')

    @sftp_test
    def test_glob(self, sftp):
        """Test a glob pattern match over SFTP"""

        try:
            os.mkdir('filedir')
            self._create_file('file1')
            self._create_file('filedir/file2')
            self._create_file('filedir/file3')

            self.assertEqual(sorted((yield from sftp.glob('file*'))),
                             ['file1', 'filedir'])
            self.assertEqual(sorted((yield from sftp.glob('./file*'))),
                             ['./file1', './filedir'])
            self.assertEqual(sorted((yield from sftp.glob(b'file*'))),
                             [b'file1', b'filedir'])
            self.assertEqual(sorted((yield from sftp.glob(['file*']))),
                             ['file1', 'filedir'])
            self.assertEqual(sorted((yield from sftp.glob(['', 'file*']))),
                             ['file1', 'filedir'])
            self.assertEqual(sorted((yield from sftp.glob(['file*/*2']))),
                             ['filedir/file2'])
            self.assertEqual(sorted((yield from sftp.glob(['file*/*[3-9]']))),
                             ['filedir/file3'])
            self.assertEqual(sorted((yield from sftp.glob(['**/file[12]']))),
                             ['file1', 'filedir/file2'])
            self.assertEqual(sorted((yield from sftp.glob(['**/file*/']))),
                             ['filedir'])
            self.assertEqual((yield from sftp.glob([b'fil*1', 'fil*dir'])),
                             [b'file1', 'filedir'])
        finally:
            remove('file1 filedir')

    @sftp_test
    def test_glob_error(self, sftp):
        """Test a glob pattern match error over SFTP"""

        with self.assertRaises(SFTPError):
            yield from sftp.glob('file*')

    @sftp_test
    def test_glob_error_handler(self, sftp):
        """Test a glob pattern match with error handler over SFTP"""

        def err_handler(exc):
            """Catch error for nonexistent file1"""

            self.assertEqual(exc.reason, 'No matches found')

        try:
            self._create_file('file2')

            self.assertEqual((yield from sftp.glob(['file1*', 'file2*'],
                                                   error_handler=err_handler)),
                             ['file2'])
        finally:
            remove('file2')

    @sftp_test
    def test_stat(self, sftp):
        """Test getting attributes on a file"""

        try:
            os.mkdir('dir')
            self._create_file('file')

            if self._symlink_supported: # pragma: no branch
                os.symlink('bad', 'badlink')
                os.symlink('dir', 'dirlink')
                os.symlink('file', 'filelink')

            self._check_stat((yield from sftp.stat('dir')), os.stat('dir'))
            self._check_stat((yield from sftp.stat('file')), os.stat('file'))

            if self._symlink_supported: # pragma: no branch
                self._check_stat((yield from sftp.stat('dirlink')),
                                 os.stat('dir'))
                self._check_stat((yield from sftp.stat('filelink')),
                                 os.stat('file'))

                with self.assertRaises(SFTPError):
                    yield from sftp.stat('badlink') # pragma: no branch

            self.assertTrue((yield from sftp.isdir('dir')))
            self.assertFalse((yield from sftp.isdir('file')))

            if self._symlink_supported: # pragma: no branch
                self.assertFalse((yield from sftp.isdir('badlink')))
                self.assertTrue((yield from sftp.isdir('dirlink')))
                self.assertFalse((yield from sftp.isdir('filelink')))

            self.assertFalse((yield from sftp.isfile('dir')))
            self.assertTrue((yield from sftp.isfile('file')))

            if self._symlink_supported: # pragma: no branch
                self.assertFalse((yield from sftp.isfile('badlink')))
                self.assertFalse((yield from sftp.isfile('dirlink')))
                self.assertTrue((yield from sftp.isfile('filelink')))

            self.assertFalse((yield from sftp.islink('dir')))
            self.assertFalse((yield from sftp.islink('file')))

            if self._symlink_supported: # pragma: no branch
                self.assertTrue((yield from sftp.islink('badlink')))
                self.assertTrue((yield from sftp.islink('dirlink')))
                self.assertTrue((yield from sftp.islink('filelink')))
        finally:
            remove('dir file badlink dirlink filelink')

    @sftp_test
    def test_lstat(self, sftp):
        """Test getting attributes on a link"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            os.symlink('file', 'link')
            self._check_stat((yield from sftp.lstat('link')), os.lstat('link'))
        finally:
            remove('link')

    @sftp_test
    def test_setstat(self, sftp):
        """Test setting attributes on a file"""

        try:
            self._create_file('file')
            yield from sftp.setstat('file', SFTPAttrs(permissions=0o666))
            self.assertEqual(stat.S_IMODE(os.stat('file').st_mode), 0o666)
        finally:
            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip statvfs tests on Windows')
    @sftp_test
    def test_statvfs(self, sftp):
        """Test getting attributes on a filesystem

           We can't compare the values returned by a live statvfs call since
           they can change at any time. See the separate _TestSFTStatPVFS
           class for a more complete test, but this is left in for code
           coverage purposes.

        """

        self.assertIsInstance((yield from sftp.statvfs('.')), SFTPVFSAttrs)

    @unittest.skipIf(sys.platform == 'win32' and not python35,
                     'skip truncate tests on Windows before Python 3.5')
    @sftp_test
    def test_truncate(self, sftp):
        """Test truncating a file"""

        try:
            self._create_file('file', '01234567890123456789')

            yield from sftp.truncate('file', 10)
            self.assertEqual((yield from sftp.getsize('file')), 10)

            with open('file') as localf:
                self.assertEqual(localf.read(), '0123456789')
        finally:
            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip chown tests on Windows')
    @sftp_test
    def test_chown(self, sftp):
        """Test changing ownership of a file

           We can't change to a different user/group here if we're not
           root, so just change to the same user/group. See the separate
           _TestSFTPChown class for a more complete test, but this is
           left in for code coverage purposes.

        """

        try:
            self._create_file('file')
            attrs = os.stat('file')

            yield from sftp.chown('file', attrs.st_uid, attrs.st_gid)

            new_attrs = os.stat('file')
            self.assertEqual(new_attrs.st_uid, attrs.st_uid)
            self.assertEqual(new_attrs.st_gid, attrs.st_gid)
        finally:
            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip chmod tests on Windows')
    @sftp_test
    def test_chmod(self, sftp):
        """Test changing permissions on a file"""

        try:
            self._create_file('file')
            yield from sftp.chmod('file', 0o1234)
            self.assertEqual(stat.S_IMODE(os.stat('file').st_mode), 0o1234)
        finally:
            remove('file')

    @sftp_test
    def test_utime(self, sftp):
        """Test changing access and modify times on a file"""

        try:
            self._create_file('file')

            yield from sftp.utime('file')
            yield from sftp.utime('file', (1, 2))

            attrs = os.stat('file')
            self.assertEqual(attrs.st_atime, 1)
            self.assertEqual(attrs.st_mtime, 2)
            self.assertEqual((yield from sftp.getatime('file')), 1)
            self.assertEqual((yield from sftp.getmtime('file')), 2)
        finally:
            remove('file')

    @sftp_test
    def test_exists(self, sftp):
        """Test checking whether a file exists"""

        try:
            self._create_file('file1')

            self.assertTrue((yield from sftp.exists('file1')))
            self.assertFalse((yield from sftp.exists('file2')))

            with self.assertRaises(SFTPError):
                yield from sftp.exists(65536*'a')
        finally:
            remove('file1')

    @sftp_test
    def test_lexists(self, sftp):
        """Test checking whether a link exists"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            os.symlink('file', 'link1')

            self.assertTrue((yield from sftp.lexists('link1')))
            self.assertFalse((yield from sftp.lexists('link2')))
        finally:
            remove('link1')

    @sftp_test
    def test_remove(self, sftp):
        """Test removing a file"""

        try:
            self._create_file('file')
            yield from sftp.remove('file')

            with self.assertRaises(FileNotFoundError):
                os.stat('file') # pragma: no branch

            with self.assertRaises(SFTPError):
                yield from sftp.remove('file')
        finally:
            remove('file')

    @sftp_test
    def test_unlink(self, sftp):
        """Test unlinking a file"""

        try:
            self._create_file('file')
            yield from sftp.unlink('file')

            with self.assertRaises(FileNotFoundError):
                os.stat('file') # pragma: no branch

            with self.assertRaises(SFTPError):
                yield from sftp.unlink('file')
        finally:
            remove('file')

    @sftp_test
    def test_rename(self, sftp):
        """Test renaming a file"""

        try:
            self._create_file('file1')
            self._create_file('file2')

            with self.assertRaises(SFTPError):
                yield from sftp.rename('file1', 'file2') # pragma: no branch

            yield from sftp.rename('file1', 'file3')
            self.assertTrue(os.path.exists('file3'))
        finally:
            remove('file1 file2 file3')

    @sftp_test
    def test_posix_rename(self, sftp):
        """Test renaming a file that replaces a target file"""

        try:
            self._create_file('file1', 'xxx')
            self._create_file('file2', 'yyy')

            yield from sftp.posix_rename('file1', 'file2')

            with open('file2') as localf:
                self.assertEqual(localf.read(), 'xxx')
        finally:
            remove('file1 file2')

    @sftp_test
    def test_listdir(self, sftp):
        """Test listing files in a directory"""

        try:
            os.mkdir('dir')
            self._create_file('dir/file1')
            self._create_file('dir/file2')
            self.assertEqual(sorted((yield from sftp.listdir('dir'))),
                             ['.', '..', 'file1', 'file2'])
        finally:
            remove('dir')

    @sftp_test
    def test_listdir_error(self, sftp):
        """Test error while listing contents of a directory"""

        @asyncio.coroutine
        def _readdir_error(self, handle):
            """Return an error on an SFTP readdir request"""

            # pylint: disable=unused-argument

            raise SFTPError(FX_FAILURE, 'I/O error')

        try:
            os.mkdir('dir')

            with patch('asyncssh.sftp.SFTPClientHandler.readdir',
                       _readdir_error):
                with self.assertRaises(SFTPError):
                    yield from sftp.listdir('dir')
        finally:
            remove('dir')

    @sftp_test
    def test_mkdir(self, sftp):
        """Test creating a directory"""

        try:
            yield from sftp.mkdir('dir')
            self.assertTrue(os.path.isdir('dir'))
        finally:
            remove('dir')

    @sftp_test
    def test_rmdir(self, sftp):
        """Test removing a directory"""

        try:
            os.mkdir('dir')
            yield from sftp.rmdir('dir')

            with self.assertRaises(FileNotFoundError):
                os.stat('dir')
        finally:
            remove('dir')

    @sftp_test
    def test_readlink(self, sftp):
        """Test reading a symlink"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            os.symlink('/file', 'link')
            self.assertEqual((yield from sftp.readlink('link')), '/file')
            self.assertEqual((yield from sftp.readlink(b'link')), b'/file')
        finally:
            remove('link')

    @sftp_test
    def test_readlink_decode_error(self, sftp):
        """Test unicode decode error while reading a symlink"""

        @asyncio.coroutine
        def _readlink_error(self, path):
            """Return invalid unicode on an SFTP readlink request"""

            # pylint: disable=unused-argument

            return [SFTPName(b'\xff')]

        with patch('asyncssh.sftp.SFTPClientHandler.readlink',
                   _readlink_error):
            with self.assertRaises(SFTPError):
                yield from sftp.readlink('link')

    @sftp_test
    def test_symlink(self, sftp):
        """Test creating a symlink"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            yield from sftp.symlink('file', 'link')
            self._check_link('link', 'file')
        finally:
            remove('file link')

    @asynctest
    def test_symlink_encode_error(self):
        """Test creating a unicode symlink with no path encoding set"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        with (yield from self.connect()) as conn:
            sftp = yield from conn.start_sftp_client(path_encoding=None)
            with sftp:
                with self.assertRaises(SFTPError):
                    yield from sftp.symlink('file', 'link')

            yield from sftp.wait_closed()

        yield from conn.wait_closed()

    @asynctest
    def test_nonstandard_symlink_client(self):
        """Test creating a symlink with opposite argument order"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            with (yield from self.connect(client_version='OpenSSH')) as conn:
                with (yield from conn.start_sftp_client()) as sftp:
                    yield from sftp.symlink('link', 'file')
                    self._check_link('link', 'file') # pragma: no branch

                yield from sftp.wait_closed() # pragma: no branch

            yield from conn.wait_closed()
        finally:
            remove('file link')

    @sftp_test
    def test_link(self, sftp):
        """Test creating a hard link"""

        try:
            self._create_file('file1')
            yield from sftp.link('file1', 'file2')
            self._check_file('file1', 'file2')
        finally:
            remove('file1 file2')

    @sftp_test
    def test_open_read(self, sftp):
        """Test reading data from a file"""

        f = None

        try:
            self._create_file('file', 'xxx')

            f = yield from sftp.open('file')
            self.assertEqual((yield from f.read()), 'xxx')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_read_bytes(self, sftp):
        """Test reading bytes from a file"""

        f = None

        try:
            self._create_file('file', 'xxx')

            f = yield from sftp.open('file', 'rb')
            self.assertEqual((yield from f.read()), b'xxx')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_read_offset_size(self, sftp):
        """Test reading at a specific offset and size"""

        f = None

        try:
            self._create_file('file', 'xxxxyyyy')

            f = yield from sftp.open('file')
            self.assertEqual((yield from f.read(4, 2)), 'xxyy')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_read_nonexistent(self, sftp):
        """Test reading data from a nonexistent file"""

        f = None

        try:
            with self.assertRaises(SFTPError):
                f = yield from sftp.open('file')
        finally:
            if f: # pragma: no cover
                yield from f.close()

    @unittest.skipIf(sys.platform == 'win32',
                     'skip permission tests on Windows')
    @sftp_test
    def test_open_read_not_permitted(self, sftp):
        """Test reading data from a file with no read permission"""

        f = None

        try:
            self._create_file('file', mode=0)

            with self.assertRaises(SFTPError):
                f = yield from sftp.open('file')
        finally:
            if f: # pragma: no cover
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_write(self, sftp):
        """Test writing data to a file"""

        f = None

        try:
            f = yield from sftp.open('file', 'w')
            yield from f.write('xxx')
            yield from f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxx')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_write_bytes(self, sftp):
        """Test writing bytes to a file"""

        f = None

        try:
            f = yield from sftp.open('file', 'wb')
            yield from f.write(b'xxx')
            yield from f.close()

            with open('file', 'rb') as localf:
                self.assertEqual(localf.read(), b'xxx')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_truncate(self, sftp):
        """Test truncating a file at open time"""

        f = None

        try:
            self._create_file('file', 'xxxyyy')

            f = yield from sftp.open('file', 'w')
            yield from f.write('zzz')
            yield from f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'zzz')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_append(self, sftp):
        """Test appending data to an existing file"""

        f = None

        try:
            self._create_file('file', 'xxx')

            f = yield from sftp.open('file', 'a+')
            yield from f.write('yyy')
            self.assertEqual((yield from f.read()), '')
            yield from f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxxyyy')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_exclusive_create(self, sftp):
        """Test creating a new file"""

        f = None

        try:
            f = yield from sftp.open('file', 'x')
            yield from f.write('xxx')
            yield from f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxx') # pragma: no branch

            with self.assertRaises(SFTPError):
                f = yield from sftp.open('file', 'x')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_exclusive_create_existing(self, sftp):
        """Test exclusive create of an existing file"""

        f = None

        try:
            self._create_file('file')

            with self.assertRaises(SFTPError):
                f = yield from sftp.open('file', 'x')
        finally:
            if f: # pragma: no cover
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_overwrite(self, sftp):
        """Test overwriting part of an existing file"""

        f = None

        try:
            self._create_file('file', 'xxxyyy')

            f = yield from sftp.open('file', 'r+')
            yield from f.write('zzz')
            yield from f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'zzzyyy')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_overwrite_offset_size(self, sftp):
        """Test writing data at a specific offset"""

        f = None

        try:
            self._create_file('file', 'xxxxyyyy')

            f = yield from sftp.open('file', 'r+')
            yield from f.write('zz', 3)
            yield from f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxxzzyyy')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_open_overwrite_nonexistent(self, sftp):
        """Test overwriting a nonexistent file"""

        f = None

        try:
            with self.assertRaises(SFTPError):
                f = yield from sftp.open('file', 'r+')
        finally:
            if f: # pragma: no cover
                yield from f.close()

    @sftp_test
    def test_file_seek(self, sftp):
        """Test seeking within a file"""

        f = None

        try:
            f = yield from sftp.open('file', 'w+')
            yield from f.write('xxxxyyyy')
            yield from f.seek(3)
            yield from f.write('zz')

            yield from f.seek(-3, SEEK_CUR)
            self.assertEqual((yield from f.read(4)), 'xzzy')

            yield from f.seek(-4, SEEK_END)
            self.assertEqual((yield from f.read()), 'zyyy')
            self.assertEqual((yield from f.read()), '')
            self.assertEqual((yield from f.read(1)), '')

            with self.assertRaises(ValueError):
                yield from f.seek(0, -1)

            yield from f.close()

            with open('file') as localf:
                self.assertEqual(localf.read(), 'xxxzzyyy')
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_file_stat(self, sftp):
        """Test getting attributes on an open file"""

        f = None

        try:
            self._create_file('file')

            f = yield from sftp.open('file')
            self._check_stat((yield from f.stat()), os.stat('file'))
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_file_setstat(self, sftp):
        """Test setting attributes on an open file"""

        f = None

        try:
            self._create_file('file')
            attrs = SFTPAttrs(permissions=0o666)

            f = yield from sftp.open('file')
            yield from f.setstat(attrs)
            yield from f.close()

            self.assertEqual(stat.S_IMODE(os.stat('file').st_mode), 0o666)
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @unittest.skipIf(sys.platform == 'win32' and not python35,
                     'skip truncate tests on Windows before Python 3.5')
    @sftp_test
    def test_file_truncate(self, sftp):
        """Test truncating an open file"""

        f = None

        try:
            self._create_file('file', '01234567890123456789')

            f = yield from sftp.open('file', 'a+')
            yield from f.truncate(10)
            self.assertEqual((yield from f.tell()), 10)
            self.assertEqual((yield from f.read(offset=0)), '0123456789')
            self.assertEqual((yield from f.tell()), 10)
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_file_utime(self, sftp):
        """Test changing access and modify times on an open file"""

        f = None

        try:
            self._create_file('file')

            f = yield from sftp.open('file')
            yield from f.utime()
            yield from f.utime((1, 2))
            yield from f.close()

            attrs = os.stat('file')
            self.assertEqual(attrs.st_atime, 1)
            self.assertEqual(attrs.st_mtime, 2)
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @unittest.skipIf(sys.platform == 'win32', 'skip statvfs tests on Windows')
    @sftp_test
    def test_file_statvfs(self, sftp):
        """Test getting attributes on the filesystem containing an open file

           We can't compare the values returned by a live statvfs call since
           they can change at any time. See the separate _TestSFTStatPVFS
           class for a more complete test, but this is left in for code
           coverage purposes.

        """

        f = None

        try:
            self._create_file('file')

            f = yield from sftp.open('file')
            self.assertIsInstance((yield from f.statvfs()), SFTPVFSAttrs)
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_file_sync(self, sftp):
        """Test file sync"""

        f = None

        try:
            f = yield from sftp.open('file', 'w')
            self.assertIsNone((yield from f.fsync()))
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_exited_session(self, sftp):
        """Test use of SFTP session after exit"""

        sftp.exit()
        yield from sftp.wait_closed()

        f = None

        try:
            with self.assertRaises(SFTPError):
                f = yield from sftp.open('file')
        finally:
            if f: # pragma: no cover
                yield from f.close()

    @sftp_test
    def test_cleanup_open_files(self, sftp):
        """Test cleanup of open file handles on exit"""

        try:
            self._create_file('file')

            yield from sftp.open('file')
        finally:
            sftp.exit()
            yield from sftp.wait_closed()

            remove('file')

    @sftp_test
    def test_invalid_open_mode(self, sftp):
        """Test opening file with invalid mode"""

        with self.assertRaises(ValueError):
            yield from sftp.open('file', 'z')

    @sftp_test
    def test_invalid_handle(self, sftp):
        """Test sending requests associated with an invalid file handle"""

        @asyncio.coroutine
        def _return_invalid_handle(self, path, pflags, attrs):
            """Return an invalid file handle"""

            # pylint: disable=unused-argument

            return UInt32(0xffffffff)

        with patch('asyncssh.sftp.SFTPClientHandler.open',
                   _return_invalid_handle):
            f = yield from sftp.open('file')

            with self.assertRaises(SFTPError):
                yield from f.read()

            with self.assertRaises(SFTPError):
                yield from f.read(1)

            with self.assertRaises(SFTPError):
                yield from f.write('')

            with self.assertRaises(SFTPError):
                yield from f.stat()

            with self.assertRaises(SFTPError):
                yield from f.setstat(SFTPAttrs())

            with self.assertRaises(SFTPError):
                yield from f.statvfs()

            with self.assertRaises(SFTPError):
                yield from f.fsync()

            with self.assertRaises(SFTPError):
                yield from f.close()

    @sftp_test
    def test_closed_file(self, sftp):
        """Test I/O operations on a closed file"""

        f = None

        try:
            self._create_file('file')

            with (yield from sftp.open('file')) as f:
                # Do an explicit close to test double-close
                yield from f.close()

            with self.assertRaises(ValueError):
                yield from f.read() # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.write('') # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.seek(0) # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.tell() # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.stat() # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.setstat(SFTPAttrs()) # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.statvfs() # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.truncate() # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.chown(0, 0) # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.chmod(0) # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.utime() # pragma: no branch

            with self.assertRaises(ValueError):
                yield from f.fsync() # pragma: no branch
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')

    @sftp_test
    def test_exit_after_nonblocking_close(self, sftp):
        """Test exit before receiving reply to a non-blocking close"""

        # pylint: disable=no-self-use

        # We don't clean up this file, as it's still open when we exit
        with (yield from sftp.open('nonblocking_file', 'w')):
            pass

    def test_unexpected_client_close(self):
        """Test an unexpected connection close from client"""

        @asyncio.coroutine
        def _unexpected_client_close(self):
            """Close the SSH connection before sending an init request"""

            self._writer.channel.get_connection().abort()

        with patch('asyncssh.sftp.SFTPClientHandler.start',
                   _unexpected_client_close):
            sftp_test(lambda self, sftp: None)(self)

    def test_unexpected_server_close(self):
        """Test an unexpected connection close from server"""

        @asyncio.coroutine
        def _unexpected_server_close(self):
            """Close the SSH connection before sending a version response"""

            packet = yield from SFTPHandler.recv_packet(self)
            self._writer.channel.get_connection().abort()
            return packet

        with patch('asyncssh.sftp.SFTPServerHandler.recv_packet',
                   _unexpected_server_close):
            with self.assertRaises(SFTPError):
                sftp_test(lambda self, sftp: None)(self) # pragma: no branch

    def test_immediate_client_close(self):
        """Test closing SFTP channel immediately after opening"""

        @asyncio.coroutine
        def _closing_start(self):
            """Immediately close the SFTP channel"""

            self.exit()

        with patch('asyncssh.sftp.SFTPClientHandler.start', _closing_start):
            sftp_test(lambda self, sftp: None)(self)

    def test_no_init(self):
        """Test sending non-init request at start"""

        @asyncio.coroutine
        def _no_init_start(self):
            """Send a non-init request at start"""

            self.send_packet(FXP_OPEN, 0, UInt32(0))

        with patch('asyncssh.sftp.SFTPClientHandler.start', _no_init_start):
            sftp_test(lambda self, sftp: None)(self)

    def test_incomplete_init_request(self):
        """Test sending init with missing version"""

        @asyncio.coroutine
        def _missing_version_start(self):
            """Send an init request with missing version"""

            self.send_packet(FXP_INIT, None)

        with patch('asyncssh.sftp.SFTPClientHandler.start',
                   _missing_version_start):
            sftp_test(lambda self, sftp: None)(self)

    def test_incomplete_version_response(self):
        """Test sending an incomplete version response"""

        @asyncio.coroutine
        def _incomplete_version_response(self):
            """Send an incomplete version response"""

            packet = yield from SFTPHandler.recv_packet(self)
            self.send_packet(FXP_VERSION, None)
            return packet

        with patch('asyncssh.sftp.SFTPServerHandler.recv_packet',
                   _incomplete_version_response):
            with self.assertRaises(SFTPError):
                sftp_test(lambda self, sftp: None)(self) # pragma: no branch

    def test_nonstandard_version(self):
        """Test sending init with non-standard version"""

        # pylint: disable=no-self-use

        with patch('asyncssh.sftp._SFTP_VERSION', 4):
            sftp_test(lambda self, sftp: None)(self)

    def test_non_version_response(self):
        """Test sending a non-version message in response to init"""

        @asyncio.coroutine
        def _non_version_response(self):
            """Send a non-version response to init"""

            packet = yield from SFTPHandler.recv_packet(self)
            self.send_packet(FXP_STATUS, None)
            return packet

        with patch('asyncssh.sftp.SFTPServerHandler.recv_packet',
                   _non_version_response):
            with self.assertRaises(SFTPError):
                sftp_test(lambda self, sftp: None)(self) # pragma: no branch

    def test_unsupported_version_response(self):
        """Test sending an unsupported version in response to init"""

        @asyncio.coroutine
        def _unsupported_version_response(self):
            """Send an unsupported version in response to init"""

            packet = yield from SFTPHandler.recv_packet(self)
            self.send_packet(FXP_VERSION, None, UInt32(4))
            return packet

        with patch('asyncssh.sftp.SFTPServerHandler.recv_packet',
                   _unsupported_version_response):
            with self.assertRaises(SFTPError):
                sftp_test(lambda self, sftp: None)(self) # pragma: no branch

    def test_unknown_extension_request(self):
        """Test sending an unknown extension in init request"""

        with patch('asyncssh.sftp.SFTPClientHandler._extensions',
                   [(b'xxx', b'1')]):
            sftp_test(lambda self, sftp: None)(self)

    def test_unknown_extension_response(self):
        """Test sending an unknown extension in version response"""

        with patch('asyncssh.sftp.SFTPServerHandler._extensions',
                   [(b'xxx', b'1')]):
            sftp_test(lambda self, sftp: None)(self)

    def test_close_after_init(self):
        """Test close immediately after init request at start"""

        @asyncio.coroutine
        def _close_after_init_start(self):
            """Send a close immediately after init request at start"""

            self.send_packet(FXP_INIT, None, UInt32(3))
            yield from self._cleanup(None)

        with patch('asyncssh.sftp.SFTPClientHandler.start',
                   _close_after_init_start):
            sftp_test(lambda self, sftp: None)(self)

    def test_file_handle_skip(self):
        """Test skipping over a file handle already in use"""

        @asyncio.coroutine
        def _reset_file_handle(self, sftp):
            """Open multiple files, resetting next handle each time"""

            file1 = None
            file2 = None

            try:
                self._create_file('file1', 'xxx')
                self._create_file('file2', 'yyy')

                file1 = yield from sftp.open('file1')
                file2 = yield from sftp.open('file2')

                self.assertEqual((yield from file1.read()), 'xxx')
                self.assertEqual((yield from file2.read()), 'yyy')
            finally:
                if file1: # pragma: no branch
                    yield from file1.close()

                if file2: # pragma: no branch
                    yield from file2.close()

                remove('file1 file2')

        with patch('asyncssh.sftp.SFTPServerHandler',
                   _ResetFileHandleServerHandler):
            sftp_test(_reset_file_handle)(self)

    @sftp_test
    def test_missing_request_pktid(self, sftp):
        """Test sending request without a packet ID"""

        @asyncio.coroutine
        def _missing_pktid(self, filename, pflags, attrs):
            """Send a request without a packet ID"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_OPEN, None)

        with patch('asyncssh.sftp.SFTPClientHandler.open', _missing_pktid):
            yield from sftp.open('file')

    @sftp_test
    def test_malformed_open_request(self, sftp):
        """Test sending malformed open request"""

        @asyncio.coroutine
        def _malformed_open(self, filename, pflags, attrs):
            """Send a malformed open request"""

            # pylint: disable=unused-argument

            return (yield from self._make_request(FXP_OPEN))

        with patch('asyncssh.sftp.SFTPClientHandler.open', _malformed_open):
            with self.assertRaises(SFTPError):
                yield from sftp.open('file')

    @sftp_test
    def test_unknown_request(self, sftp):
        """Test sending unknown request type"""

        @asyncio.coroutine
        def _unknown_request(self, filename, pflags, attrs):
            """Send a request with an unknown type"""

            # pylint: disable=unused-argument

            return (yield from self._make_request(0xff))

        with patch('asyncssh.sftp.SFTPClientHandler.open', _unknown_request):
            with self.assertRaises(SFTPError):
                yield from sftp.open('file')

    @sftp_test
    def test_unrecognized_response_pktid(self, sftp):
        """Test sending a response with an unrecognized packet ID"""

        @asyncio.coroutine
        def _unrecognized_response_pktid(self, pkttype, pktid, packet):
            """Send a response with an unrecognized packet ID"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_HANDLE, 0xffffffff,
                             UInt32(0xffffffff), String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _unrecognized_response_pktid):
            with self.assertRaises(SFTPError):
                yield from sftp.open('file')

    @sftp_test
    def test_bad_response_type(self, sftp):
        """Test sending a response with an incorrect response type"""

        @asyncio.coroutine
        def _bad_response_type(self, pkttype, pktid, packet):
            """Send a response with an incorrect response type"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_DATA, pktid, UInt32(pktid), String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _bad_response_type):
            with self.assertRaises(SFTPError):
                yield from sftp.open('file')

    @sftp_test
    def test_unexpected_ok_response(self, sftp):
        """Test sending an unexpected FX_OK response"""

        @asyncio.coroutine
        def _unexpected_ok_response(self, pkttype, pktid, packet):
            """Send an unexpected FX_OK response"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_STATUS, pktid, UInt32(pktid), UInt32(FX_OK),
                             String(''), String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _unexpected_ok_response):
            with self.assertRaises(SFTPError):
                yield from sftp.open('file')

    @sftp_test
    def test_malformed_ok_response(self, sftp):
        """Test sending an FX_OK response containing invalid Unicode"""

        @asyncio.coroutine
        def _malformed_ok_response(self, pkttype, pktid, packet):
            """Send an FX_OK response containing invalid Unicode"""

            # pylint: disable=unused-argument

            self.send_packet(FXP_STATUS, pktid, UInt32(pktid), UInt32(FX_OK),
                             String(b'\xff'), String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _malformed_ok_response):
            with self.assertRaises(SFTPError):
                yield from sftp.open('file')

    @sftp_test
    def test_malformed_realpath_response(self, sftp):
        """Test receiving malformed realpath response"""

        @asyncio.coroutine
        def _malformed_realpath(self, path):
            """Return a malformed realpath response"""

            # pylint: disable=unused-argument

            return [SFTPName(''), SFTPName('')]

        with patch('asyncssh.sftp.SFTPClientHandler.realpath',
                   _malformed_realpath):
            with self.assertRaises(SFTPError):
                yield from sftp.realpath('.')

    @sftp_test
    def test_malformed_readlink_response(self, sftp):
        """Test receiving malformed readlink response"""

        @asyncio.coroutine
        def _malformed_readlink(self, path):
            """Return a malformed readlink response"""

            # pylint: disable=unused-argument

            return [SFTPName(''), SFTPName('')]

        with patch('asyncssh.sftp.SFTPClientHandler.readlink',
                   _malformed_readlink):
            with self.assertRaises(SFTPError):
                yield from sftp.readlink('.')

    def test_unsupported_extensions(self):
        """Test using extensions on a server that doesn't support them"""

        def _unsupported_extensions(self, sftp):
            """Try using unsupported extensions"""

            try:
                self._create_file('file1')

                with self.assertRaises(SFTPError):
                    yield from sftp.statvfs('.') # pragma: no branch

                f = yield from sftp.open('file1')

                with self.assertRaises(SFTPError):
                    yield from f.statvfs() # pragma: no branch

                with self.assertRaises(SFTPError):
                    yield from sftp.posix_rename('file1', # pragma: no branch
                                                 'file2')

                with self.assertRaises(SFTPError):
                    yield from sftp.link('file1', 'file2') # pragma: no branch

                with self.assertRaises(SFTPError):
                    yield from f.fsync()
            finally:
                if f: # pragma: no branch
                    yield from f.close()

                remove('file1')

        with patch('asyncssh.sftp.SFTPServerHandler._extensions', []):
            sftp_test(_unsupported_extensions)(self)

    def test_outstanding_nonblocking_close(self):
        """Test session cleanup with an outstanding non-blocking close"""

        @asyncio.coroutine
        def _nonblocking_close(self, sftp):
            """Initiate nonblocking close that triggers cleanup"""

            # pylint: disable=unused-argument

            try:
                with (yield from sftp.open('file', 'w')):
                    pass
            finally:
                sftp.exit()
                yield from sftp.wait_closed()

                remove('file')

        with patch('asyncssh.sftp.SFTPServerHandler',
                   _NonblockingCloseServerHandler):
            sftp_test(_nonblocking_close)(self)

    @sftp_test
    def test_log_formatting(self, sftp):
        """Exercise log formatting of SFTP objects"""

        asyncssh.set_sftp_log_level('DEBUG')

        with self.assertLogs(level='DEBUG'):
            yield from sftp.realpath('.')
            yield from sftp.stat('.')

            if sys.platform != 'win32': # pragma: no cover
                yield from sftp.statvfs('.')

        asyncssh.set_sftp_log_level('WARNING')


class _TestSFTPChroot(_CheckSFTP):
    """Unit test for SFTP server with changed root"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server with a changed root"""

        return (yield from cls.create_server(sftp_factory=_ChrootSFTPServer))

    @sftp_test
    def test_chroot_copy(self, sftp):
        """Test copying a file to an FTP server with a changed root"""

        try:
            self._create_file('src')
            yield from sftp.put('src', 'dst')
            self._check_file('src', 'chroot/dst')
        finally:
            remove('src chroot/dst')

    @sftp_test
    def test_chroot_glob(self, sftp):
        """Test a glob pattern match over SFTP with a changed root"""

        try:
            self._create_file('chroot/file1')
            self._create_file('chroot/file2')
            self.assertEqual(sorted((yield from sftp.glob('/file*'))),
                             ['/file1', '/file2'])
        finally:
            remove('chroot/file1 chroot/file2')

    @sftp_test
    def test_chroot_realpath(self, sftp):
        """Test canonicalizing a path on an SFTP server with a changed root"""

        self.assertEqual((yield from sftp.realpath('/dir/../file')), '/file')

    @sftp_test
    def test_getcwd_and_chdir(self, sftp):
        """Test changing directory on an SFTP server with a changed root"""

        try:
            os.mkdir('chroot/dir')

            self.assertEqual((yield from sftp.getcwd()), '/')

            yield from sftp.chdir('dir')
            self.assertEqual((yield from sftp.getcwd()), '/dir')
        finally:
            remove('chroot/dir')

    @sftp_test
    def test_chroot_readlink(self, sftp):
        """Test reading symlinks on an FTP server with a changed root"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            root = os.path.join(os.getcwd(), 'chroot')

            os.symlink(root, 'chroot/link1')
            os.symlink(os.path.join(root, 'file'), 'chroot/link2')
            os.symlink('/xxx', 'chroot/link3')

            self.assertEqual((yield from sftp.readlink('link1')), '/')
            self.assertEqual((yield from sftp.readlink('link2')), '/file')
            with self.assertRaises(SFTPError):
                yield from sftp.readlink('link3')
        finally:
            remove('chroot/link1 chroot/link2 chroot/link3')

    @sftp_test
    def test_chroot_symlink(self, sftp):
        """Test setting a symlink on an SFTP server with a changed root"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            yield from sftp.symlink('/file', 'link1')
            yield from sftp.symlink('../../file', 'link2')

            self._check_link('chroot/link1', os.path.abspath('chroot/file'))
            self._check_link('chroot/link2', 'file')
        finally:
            remove('chroot/link1 chroot/link2')


class _TestSFTPIOError(_CheckSFTP):
    """Unit test for SFTP server returning file I/O error"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server which returns file I/O errors"""

        return (yield from cls.create_server(sftp_factory=_IOErrorSFTPServer))

    @sftp_test
    def test_put_error(self, sftp):
        """Test error when putting a file to an SFTP server"""

        for method in ('put', 'copy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src', 4*1024*1024*'\0')

                    with self.assertRaises((FileNotFoundError, SFTPError)):
                        yield from getattr(sftp, method)('src', 'dst')
                finally:
                    remove('src dst')


class _TestSFTPNotImplemented(_CheckSFTP):
    """Unit test for SFTP server returning not-implemented error"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server which returns not-implemented errors"""

        return (yield from cls.create_server(sftp_factory=_NotImplSFTPServer))

    @sftp_test
    def test_symlink_error(self, sftp):
        """Test error when creating a symbolic link on an SFTP server"""

        with self.assertRaises(SFTPError):
            yield from sftp.symlink('file', 'link')


class _TestSFTPLongname(_CheckSFTP):
    """Unit test for SFTP server formatting directory listings"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server which returns a fixed directory listing"""

        return (yield from cls.create_server(sftp_factory=_LongnameSFTPServer))

    @sftp_test
    def test_longname(self, sftp):
        """Test long name formatting in SFTP opendir call"""

        for file in (yield from sftp.readdir('/')):
            self.assertEqual(file.longname[56:], file.filename)

    @sftp_test
    def test_glob_hidden(self, sftp):
        """Test a glob pattern match on hidden files"""

        self.assertEqual((yield from sftp.glob('/.*')), ['/.file'])

    @unittest.skipIf(sys.platform == 'win32', 'skip uid/gid tests on Windows')
    @sftp_test
    def test_getpwuid_error(self, sftp):
        """Test long name formatting where user name can't be resolved"""

        def getpwuid_error(uid):
            """Simulate not being able to resolve user name"""

            # pylint: disable=unused-argument

            raise KeyError

        with patch('pwd.getpwuid', getpwuid_error):
            result = yield from sftp.readdir('/')

        self.assertEqual(result[3].longname[16:24], '        ')
        self.assertEqual(result[4].longname[16:24], '0       ')

    @unittest.skipIf(sys.platform == 'win32', 'skip uid/gid tests on Windows')
    @sftp_test
    def test_getgrgid_error(self, sftp):
        """Test long name formatting where group name can't be resolved"""

        def getgrgid_error(gid):
            """Simulate not being able to resolve group name"""

            # pylint: disable=unused-argument

            raise KeyError

        with patch('grp.getgrgid', getgrgid_error):
            result = yield from sftp.readdir('/')

        self.assertEqual(result[3].longname[25:33], '        ')
        self.assertEqual(result[4].longname[25:33], '0       ')

    @sftp_test
    def test_strftime_error(self, sftp):
        """Test long name formatting with strftime not supporting %e"""

        orig_strftime = time.strftime

        def strftime_error(fmt, t):
            """Simulate Windows srtftime that doesn't support %e"""

            # pylint: disable=unused-argument

            if '%e' in fmt:
                raise ValueError
            else:
                return orig_strftime(fmt, t)

        with patch('time.strftime', strftime_error):
            result = yield from sftp.readdir('/')

        self.assertEqual(result[3].longname[51:55], '    ')
        self.assertIn(result[4].longname[51:55], ('1969', '1970'))


class _TestSFTPLargeListDir(_CheckSFTP):
    """Unit test for SFTP server returning large listdir result"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server which returns file I/O errors"""

        return (yield from cls.create_server(sftp_factory=_LargeDirSFTPServer))

    @sftp_test
    def test_large_listdir(self, sftp):
        """Test large listdir result"""

        self.assertEqual(len((yield from sftp.readdir('/'))), 100000)


@unittest.skipIf(sys.platform == 'win32', 'skip statvfs tests on Windows')
class _TestSFTPStatVFS(_CheckSFTP):
    """Unit test for SFTP server filesystem attributes"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server which returns fixed filesystem attrs"""

        return (yield from cls.create_server(sftp_factory=_StatVFSSFTPServer))

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
    def test_statvfs(self, sftp):
        """Test getting attributes on a filesystem"""

        self._check_statvfs((yield from sftp.statvfs('.')))

    @sftp_test
    def test_file_statvfs(self, sftp):
        """Test getting attributes on the filesystem containing an open file"""

        f = None

        try:
            self._create_file('file')

            f = yield from sftp.open('file')
            self._check_statvfs((yield from f.statvfs()))
        finally:
            if f: # pragma: no branch
                yield from f.close()

            remove('file')


@unittest.skipIf(sys.platform == 'win32', 'skip chown tests on Windows')
class _TestSFTPChown(_CheckSFTP):
    """Unit test for SFTP server file ownership"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server which simulates file ownership changes"""

        return (yield from cls.create_server(sftp_factory=_ChownSFTPServer))

    @sftp_test
    def test_chown(self, sftp):
        """Test changing ownership of a file"""

        try:
            self._create_file('file')
            yield from sftp.chown('file', 1, 2)
            attrs = yield from sftp.stat('file')
            self.assertEqual(attrs.uid, 1)
            self.assertEqual(attrs.gid, 2)
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
            packet = SSHPacket(attrs.encode())
            self.assertEqual(repr(SFTPAttrs.decode(packet)), repr(attrs))

    def test_illegal_attrs(self):
        """Test decoding illegal SFTP attributes value"""

        with self.assertRaises(SFTPError):
            SFTPAttrs.decode(SSHPacket(UInt32(FILEXFER_ATTR_UNDEFINED)))


class _TestSFTPNonstandardSymlink(_CheckSFTP):
    """Unit tests for SFTP server with non-standard symlink order"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server for the tests to use"""

        return (yield from cls.create_server(server_version='OpenSSH',
                                             sftp_factory=_SymlinkSFTPServer))

    @asynctest
    def test_nonstandard_symlink_client(self):
        """Test creating a symlink with opposite argument order"""

        if not self._symlink_supported: # pragma: no cover
            raise unittest.SkipTest('symlink not available')

        try:
            with (yield from self.connect(client_version='OpenSSH')) as conn:
                with (yield from conn.start_sftp_client()) as sftp:
                    yield from sftp.symlink('link', 'file')
                    self._check_link('link', 'file') # pragma: no branch

                yield from sftp.wait_closed() # pragma: no branch

            yield from conn.wait_closed()
        finally:
            remove('file link')


class _TestSFTPAsync(_TestSFTP):
    """Unit test for an async SFTPServer"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server with coroutine callbacks"""

        return (yield from cls.create_server(sftp_factory=_AsyncSFTPServer))

    @sftp_test
    def test_async_realpath(self, sftp):
        """Test canonicalizing a path on an async SFTP server"""

        self.assertEqual((yield from sftp.realpath('dir/../file')),
                         posixpath.join((yield from sftp.getcwd()), 'file'))


class _CheckSCP(_CheckSFTP):
    """Utility functions for AsyncSSH SCP unit tests"""

    @classmethod
    @asyncio.coroutine
    def asyncSetUpClass(cls):
        """Set up SCP target host/port tuple"""

        yield from super().asyncSetUpClass()

        cls._scp_server = (cls._server_addr, cls._server_port)

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server with SCP enabled for the tests to use"""

        return (yield from cls.create_server(sftp_factory=True, allow_scp=True))


class _TestSCP(_CheckSCP):
    """Unit tests for AsyncSSH SCP client and server"""

    @asynctest
    def test_get(self):
        """Test getting a file over SCP"""

        try:
            self._create_file('src')
            yield from scp((self._scp_server, 'src'), 'dst')
            self._check_file('src', 'dst')
        finally:
            remove('src dst')

    @asynctest
    def test_get_bytes_path(self):
        """Test getting a file with a byte string path over SCP"""

        try:
            self._create_file('src')
            yield from scp((self._scp_server, b'src'), b'dst')
            self._check_file('src', 'dst')
        finally:
            remove('src dst')

    @asynctest
    def test_get_progress(self):
        """Test getting a file over SCP with progress reporting"""

        def _report_progress(srcpath, dstpath, bytes_copied, total_bytes):
            """Monitor progress of copy"""

            # pylint: disable=unused-argument

            reports.append(bytes_copied)

        reports = []

        try:
            self._create_file('src', 100000*'a')
            yield from scp((self._scp_server, 'src'), 'dst', block_size=8192,
                           progress_handler=_report_progress)
            self._check_file('src', 'dst')

            self.assertEqual(len(reports), 13)
            self.assertEqual(reports[-1], 100000)
        finally:
            remove('src dst')

    @asynctest
    def test_get_preserve(self):
        """Test getting a file with preserved attributes over SCP"""

        try:
            self._create_file('src', utime=(1, 2))
            yield from scp((self._scp_server, 'src'), 'dst', preserve=True)
            self._check_file('src', 'dst', preserve=True, check_atime=False)
        finally:
            remove('src dst')

    @asynctest
    def test_get_recurse(self):
        """Test recursively getting a directory over SCP"""

        try:
            os.mkdir('src')
            self._create_file('src/file1')

            yield from scp((self._scp_server, 'src'), 'dst', recurse=True)

            self._check_file('src/file1', 'dst/file1')
        finally:
            remove('src dst')

    @asynctest
    def test_get_error_handler(self):
        """Test getting multiple files over SCP with error handler"""

        def err_handler(exc):
            """Catch error for non-recursive copy of directory"""

            self.assertEqual(exc.reason, 'scp: Not a regular file: src2')

        try:
            self._create_file('src1')
            os.mkdir('src2')
            os.mkdir('dst')

            yield from scp((self._scp_server, 'src*'), 'dst',
                           error_handler=err_handler)

            self._check_file('src1', 'dst/src1')
        finally:
            remove('src1 src2 dst')

    @asynctest
    def test_get_recurse_existing(self):
        """Test getting a directory over SCP where target dir exists"""

        try:
            os.mkdir('src')
            os.mkdir('dst')
            os.mkdir('dst/src')
            self._create_file('src/file1')

            yield from scp((self._scp_server, 'src'), 'dst', recurse=True)

            self._check_file('src/file1', 'dst/src/file1')
        finally:
            remove('src dst')

    @unittest.skipIf(sys.platform == 'win32',
                     'skip permission tests on Windows')
    @asynctest
    def test_get_not_permitted(self):
        """Test getting a file with no read permissions over SCP"""

        try:
            self._create_file('src', mode=0)

            with self.assertRaises(SFTPError):
                yield from scp((self._scp_server, 'src'), 'dst')
        finally:
            remove('src dst')

    @asynctest
    def test_get_directory_as_file(self):
        """Test getting a file which is actually a directory over SCP"""

        try:
            os.mkdir('src')

            with self.assertRaises(SFTPError):
                yield from scp((self._scp_server, 'src'), 'dst')
        finally:
            remove('src dst')

    @asynctest
    def test_get_non_directory_in_path(self):
        """Test getting a file with a non-directory in path over SCP"""

        try:
            self._create_file('src')

            with self.assertRaises(SFTPError):
                yield from scp((self._scp_server, 'src/xxx'), 'dst')
        finally:
            remove('src dst')

    @asynctest
    def test_get_recurse_not_directory(self):
        """Test getting a directory over SCP where target is not directory"""

        try:
            os.mkdir('src')
            self._create_file('dst')
            self._create_file('src/file1')

            with self.assertRaises(SFTPError):
                yield from scp((self._scp_server, 'src'), 'dst', recurse=True)
        finally:
            remove('src dst')

    @asynctest
    def test_put(self):
        """Test putting a file over SCP"""

        try:
            self._create_file('src')
            yield from scp('src', (self._scp_server, 'dst'))
            self._check_file('src', 'dst')
        finally:
            remove('src dst')

    @asynctest
    def test_put_bytes_path(self):
        """Test putting a file with a byte string path over SCP"""

        try:
            self._create_file('src')
            yield from scp(b'src', (self._scp_server, b'dst'))
            self._check_file('src', 'dst')
        finally:
            remove('src dst')

    @asynctest
    def test_put_progress(self):
        """Test putting a file over SCP with progress reporting"""

        def _report_progress(srcpath, dstpath, bytes_copied, total_bytes):
            """Monitor progress of copy"""

            # pylint: disable=unused-argument

            reports.append(bytes_copied)

        reports = []

        try:
            self._create_file('src', 100000*'a')
            yield from scp('src', (self._scp_server, 'dst'), block_size=8192,
                           progress_handler=_report_progress)
            self._check_file('src', 'dst')

            self.assertEqual(len(reports), 13)
            self.assertEqual(reports[-1], 100000)
        finally:
            remove('src dst')

    @asynctest
    def test_put_preserve(self):
        """Test putting a file with preserved attributes over SCP"""

        try:
            self._create_file('src', utime=(1, 2))
            yield from scp('src', (self._scp_server, 'dst'), preserve=True)
            self._check_file('src', 'dst', preserve=True, check_atime=False)
        finally:
            remove('src dst')

    @asynctest
    def test_put_recurse(self):
        """Test recursively putting a directory over SCP"""

        try:
            os.mkdir('src')
            self._create_file('src/file1')

            yield from scp('src', (self._scp_server, 'dst'), recurse=True)

            self._check_file('src/file1', 'dst/file1')
        finally:
            remove('src dst')

    @asynctest
    def test_put_recurse_existing(self):
        """Test putting a directory over SCP where target dir exists"""

        try:
            os.mkdir('src')
            os.mkdir('dst')
            self._create_file('src/file1')

            yield from scp('src', (self._scp_server, 'dst'), recurse=True)

            self._check_file('src/file1', 'dst/src/file1')
        finally:
            remove('src dst')

    @asynctest
    def test_put_must_be_dir(self):
        """Test putting multiple files to a non-directory over SCP"""

        try:
            self._create_file('src1')
            self._create_file('src2')
            self._create_file('dst')

            with self.assertRaises(SFTPError):
                yield from scp(['src1', 'src2'], (self._scp_server, 'dst'))
        finally:
            remove('src1 src2 dst')

    @asynctest
    def test_put_non_directory_in_path(self):
        """Test putting a file with a non-directory in path over SCP"""

        try:
            self._create_file('src')

            with self.assertRaises(OSError):
                yield from scp('src/xxx', (self._scp_server, 'dst'))
        finally:
            remove('src')

    @asynctest
    def test_put_recurse_not_directory(self):
        """Test putting a directory over SCP where target is not directory"""

        try:
            os.mkdir('src')
            self._create_file('dst')
            self._create_file('src/file1')

            with self.assertRaises(SFTPError):
                yield from scp('src', (self._scp_server, 'dst'), recurse=True)
        finally:
            remove('src dst')

    @asynctest
    def test_put_read_error(self):
        """Test read errors when putting a file over SCP"""

        @asyncio.coroutine
        def _read_error(self, size, offset):
            """Return an error for reads past 64 KB in a file"""

            if offset >= 65536:
                raise OSError(errno.EIO, 'I/O error')
            else:
                return (yield from orig_read(self, size, offset))

        try:
            self._create_file('src', 128*1024*'\0')

            orig_read = LocalFile.read

            with patch('asyncssh.sftp.LocalFile.read', _read_error):
                with self.assertRaises(OSError):
                    yield from scp('src', (self._scp_server, 'dst'))
        finally:
            remove('src dst')

    @asynctest
    def test_put_read_early_eof(self):
        """Test getting early EOF when putting a file over SCP"""

        @asyncio.coroutine
        def _read_early_eof(self, size, offset):
            """Return an early EOF for reads past 64 KB in a file"""

            if offset >= 65536:
                return b''
            else:
                return (yield from orig_read(self, size, offset))

        try:
            self._create_file('src', 128*1024*'\0')

            orig_read = LocalFile.read

            with patch('asyncssh.sftp.LocalFile.read', _read_early_eof):
                with self.assertRaises(SFTPError):
                    yield from scp('src', (self._scp_server, 'dst'))
        finally:
            remove('src dst')

    @asynctest
    def test_put_name_too_long(self):
        """Test putting a file over SCP with too long a name"""

        try:
            self._create_file('src')

            with self.assertRaises(SFTPError):
                yield from scp('src', (self._scp_server, 65536*'a'))
        finally:
            remove('src dst')

    @asynctest
    def test_copy(self):
        """Test copying a file between remote hosts over SCP"""

        try:
            self._create_file('src')
            yield from scp((self._scp_server, 'src'), (self._scp_server, 'dst'))
            self._check_file('src', 'dst')
        finally:
            remove('src dst')

    @asynctest
    def test_copy_progress(self):
        """Test copying a file over SCP with progress reporting"""

        def _report_progress(srcpath, dstpath, bytes_copied, total_bytes):
            """Monitor progress of copy"""

            # pylint: disable=unused-argument

            reports.append(bytes_copied)

        reports = []

        try:
            self._create_file('src', 100000*'a')
            yield from scp((self._scp_server, 'src'),
                           (self._scp_server, 'dst'), block_size=8192,
                           progress_handler=_report_progress)
            self._check_file('src', 'dst')

            self.assertEqual(len(reports), 13)
            self.assertEqual(reports[-1], 100000)
        finally:
            remove('src dst')

    @asynctest
    def test_copy_preserve(self):
        """Test copying a file with preserved attributes between hosts"""

        try:
            self._create_file('src', utime=(1, 2))
            yield from scp((self._scp_server, 'src'), (self._scp_server, 'dst'),
                           preserve=True)
            self._check_file('src', 'dst', preserve=True, check_atime=False)
        finally:
            remove('src dst')

    @asynctest
    def test_copy_recurse(self):
        """Test recursively copying a directory between hosts over SCP"""

        try:
            os.mkdir('src')
            self._create_file('src/file1')

            yield from scp((self._scp_server, 'src'), (self._scp_server, 'dst'),
                           recurse=True)

            self._check_file('src/file1', 'dst/file1')
        finally:
            remove('src dst')

    @asynctest
    def test_copy_error_handler_source(self):
        """Test copying multiple files over SCP with error handler"""

        def err_handler(exc):
            """Catch error for non-recursive copy of directory"""

            self.assertEqual(exc.reason, 'scp: Not a regular file: src2')

        try:
            self._create_file('src1')
            os.mkdir('src2')
            os.mkdir('dst')

            yield from scp((self._scp_server, 'src*'),
                           (self._scp_server, 'dst'),
                           error_handler=err_handler)

            self._check_file('src1', 'dst/src1')
        finally:
            remove('src1 src2 dst')

    @asynctest
    def test_copy_error_handler_sink(self):
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

            yield from scp((self._scp_server, 'src*'),
                           (self._scp_server, 'dst'),
                           error_handler=err_handler)

            self._check_file('src1', 'dst/src1')
        finally:
            remove('src1 src2 dst')

    @asynctest
    def test_copy_recurse_existing(self):
        """Test copying a directory over SCP where target dir exists"""

        try:
            os.mkdir('src')
            os.mkdir('dst')
            self._create_file('src/file1')

            yield from scp((self._scp_server, 'src'), (self._scp_server, 'dst'),
                           recurse=True)

            self._check_file('src/file1', 'dst/src/file1')
        finally:
            remove('src dst')

    @asynctest
    def test_local_copy(self):
        """Test for error return when attempting to copy local files"""

        with self.assertRaises(ValueError):
            yield from scp('src', 'dst')

    @asynctest
    def test_copy_multiple(self):
        """Test copying multiple files over SCP"""

        try:
            os.mkdir('src')
            self._create_file('src/file1')
            self._create_file('src/file2')
            yield from scp([(self._scp_server, 'src/file1'),
                            (self._scp_server, 'src/file2')], '.')
            self._check_file('src/file1', 'file1')
            self._check_file('src/file2', 'file2')
        finally:
            remove('src file1 file2')

    @asynctest
    def test_copy_recurse_not_directory(self):
        """Test copying a directory over SCP where target is not directory"""

        try:
            os.mkdir('src')
            self._create_file('dst')
            self._create_file('src/file1')

            with self.assertRaises(SFTPError):
                yield from scp((self._scp_server, 'src'),
                               (self._scp_server, 'dst'), recurse=True)
        finally:
            remove('src dst')

    @asynctest
    def test_source_string(self):
        """Test passing a string to SCP"""

        with self.assertRaises(OSError):
            yield from scp('0.0.0.1:xxx', '.')

    @unittest.skipUnless(python35, 'skip host as bytes before Python 3.5')
    @asynctest
    def test_source_bytes(self):
        """Test passing a byte string to SCP"""

        with self.assertRaises(OSError):
            yield from scp(b'0.0.0.1:xxx', '.')

    @asynctest
    def test_source_open_connection(self):
        """Test passing an open SSHClientConnection to SCP as source"""

        try:
            with (yield from self.connect()) as conn:
                self._create_file('src')
                yield from scp((conn, 'src'), 'dst')
                self._check_file('src', 'dst')
        finally:
            remove('src dst')

    @asynctest
    def test_destination_open_connection(self):
        """Test passing an open SSHClientConnection to SCP as destination"""

        try:
            with (yield from self.connect()) as conn:
                os.mkdir('src')
                self._create_file('src/file1')
                yield from scp('src/file1', conn)
                self._check_file('src/file1', 'file1')
        finally:
            remove('src file1')

    @asynctest
    def test_missing_path(self):
        """Test running SCP with missing path"""

        with (yield from self.connect()) as conn:
            result = yield from conn.run('scp ')
            self.assertEqual(result.stderr, 'scp: the following arguments '
                             'are required: path\n')

    @asynctest
    def test_missing_direction(self):
        """Test running SCP with missing direction argument"""

        with (yield from self.connect()) as conn:
            result = yield from conn.run('scp xxx')
            self.assertEqual(result.stderr, 'scp: one of the arguments -f -t '
                             'is required\n')

    @asynctest
    def test_invalid_argument(self):
        """Test running SCP with invalid argument"""

        with (yield from self.connect()) as conn:
            result = yield from conn.run('scp -f -x src')
            self.assertEqual(result.stderr, 'scp: unrecognized arguments: -x\n')

    @asynctest
    def test_invalid_c_argument(self):
        """Test running SCP with invalid argument to C request"""

        with (yield from self.connect()) as conn:
            result = yield from conn.run('scp -t dst', input='C\n')
            self.assertEqual(result.stdout,
                             '\0\x01scp: Invalid copy or dir request\n')

    @asynctest
    def test_invalid_t_argument(self):
        """Test running SCP with invalid argument to C request"""

        with (yield from self.connect()) as conn:
            result = yield from conn.run('scp -t -p dst', input='T\n')
            self.assertEqual(result.stdout, '\0\x01scp: Invalid time request\n')


class _TestSCPAsync(_TestSCP):
    """Unit test for AsyncSSH SCP using an async SFTPServer"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server with coroutine callbacks"""

        return (yield from cls.create_server(sftp_factory=_AsyncSFTPServer,
                                             allow_scp=True))


class _TestSCPAttrs(_CheckSCP):
    """Unit test for SCP with SFTP server returning SFTPAttrs"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server which returns SFTPAttrs from stat"""

        return (yield from cls.create_server(sftp_factory=_SFTPAttrsSFTPServer,
                                             allow_scp=True))

    @asynctest
    def test_get(self):
        """Test getting a file over SCP with stat returning SFTPAttrs"""

        try:
            self._create_file('src')
            yield from scp((self._scp_server, 'src'), 'dst')
            self._check_file('src', 'dst')
        finally:
            remove('src dst')

    @asynctest
    def test_put_recurse_not_directory(self):
        """Test putting a directory over SCP where target is not directory"""

        try:
            os.mkdir('src')
            self._create_file('dst')
            self._create_file('src/file1')

            with self.assertRaises(SFTPError):
                yield from scp('src', (self._scp_server, 'dst'), recurse=True)
        finally:
            remove('src dst')

    @asynctest
    def test_put_not_permitted(self):
        """Test putting a file over SCP onto an unwritable target"""

        try:
            self._create_file('src')
            os.mkdir('dst')
            os.chmod('dst', 0)

            with self.assertRaises(SFTPError):
                yield from scp('src', (self._scp_server, 'dst/src'))
        finally:
            os.chmod('dst', 0o755)
            remove('src dst')

    @asynctest
    def test_put_name_too_long(self):
        """Test putting a file over SCP with too long a name"""

        try:
            self._create_file('src')

            with self.assertRaises(SFTPError):
                yield from scp('src', (self._scp_server, 65536*'a'))
        finally:
            remove('src dst')


class _TestSCPIOError(_CheckSCP):
    """Unit test for SCP with SFTP server returning file I/O error"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server which returns file I/O errors"""

        return (yield from cls.create_server(sftp_factory=_IOErrorSFTPServer,
                                             allow_scp=True))

    @asynctest
    def test_put_error(self):
        """Test error when putting a file over SCP"""

        try:
            self._create_file('src', 4*1024*1024*'\0')

            with self.assertRaises(SFTPError):
                yield from scp('src', (self._scp_server, 'dst'))
        finally:
            remove('src dst')

    @asynctest
    def test_copy_error(self):
        """Test error when copying a file over SCP"""

        try:
            self._create_file('src', 4*1024*1024*'\0')

            with self.assertRaises(SFTPError):
                yield from scp((self._scp_server, 'src'),
                               (self._scp_server, 'dst'))
        finally:
            remove('src dst')


class _TestSCPErrors(_CheckSCP):
    """Unit test for SCP returning error on startup"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server which returns file I/O errors"""

        @asyncio.coroutine
        def _handle_client(process):
            """Handle new client"""

            with process:
                command = process.command

                if command.endswith('get_connection_lost'):
                    pass
                elif command.endswith('get_dir_no_recurse'):
                    yield from process.stdin.read(1)
                    process.stdout.write('D0755 0 src\n')
                elif command.endswith('get_early_eof'):
                    yield from process.stdin.read(1)
                    process.stdout.write('C0644 10 src\n')
                    yield from process.stdin.read(1)
                elif command.endswith('get_extra_e'):
                    yield from process.stdin.read(1)
                    process.stdout.write('E\n')
                    yield from process.stdin.read(1)
                elif command.endswith('get_t_without_preserve'):
                    yield from process.stdin.read(1)
                    process.stdout.write('T0 0 0 0\n')
                    yield from process.stdin.read(1)
                elif command.endswith('get_unknown_action'):
                    yield from process.stdin.read(1)
                    process.stdout.write('X\n')
                    yield from process.stdin.read(1)
                elif command.endswith('put_connection_lost'):
                    process.stdout.write('\0\0')
                elif command.endswith('put_startup_error'):
                    process.stdout.write('Error starting SCP\n')
                elif command.endswith('recv_early_eof'):
                    process.stdout.write('\0')
                    yield from process.stdin.readline()
                    try:
                        process.stdout.write('\0')
                    except BrokenPipeError:
                        pass
                else:
                    process.exit(255)

        return (yield from cls.create_server(process_factory=_handle_client))

    @asynctest
    def test_get_directory_without_recurse(self):
        """Test receiving directory when recurse wasn't requested"""

        try:
            with self.assertRaises(SFTPError):
                yield from scp((self._scp_server, 'get_dir_no_recurse'), 'dst')
        finally:
            remove('dst')

    @asynctest
    def test_get_early_eof(self):
        """Test getting early EOF when getting a file over SCP"""

        try:
            with self.assertRaises(SFTPError):
                yield from scp((self._scp_server, 'get_early_eof'), 'dst')
        finally:
            remove('dst')

    @asynctest
    def test_get_t_without_preserve(self):
        """Test getting timestamps with requesting preserve"""

        try:
            yield from scp((self._scp_server, 'get_t_without_preserve'), 'dst')
        finally:
            remove('dst')

    @asynctest
    def test_get_unknown_action(self):
        """Test getting unknown action from SCP server during get"""

        try:
            with self.assertRaises(SFTPError):
                yield from scp((self._scp_server, 'get_unknown_action'), 'dst')
        finally:
            remove('dst')

    @asynctest
    def test_put_startup_error(self):
        """Test SCP server returning an error on startup"""

        try:
            self._create_file('src')

            with self.assertRaises(SFTPError) as exc:
                yield from scp('src', (self._scp_server, 'put_startup_error'))

            self.assertEqual(exc.exception.reason, 'Error starting SCP')
        finally:
            remove('src')

    @asynctest
    def test_put_connection_lost(self):
        """Test SCP server abruptly closing connection on put"""

        try:
            self._create_file('src')

            with self.assertRaises(SFTPError) as exc:
                yield from scp('src', (self._scp_server, 'put_connection_lost'))

            self.assertEqual(exc.exception.reason, 'Connection lost')
        finally:
            remove('src')

    @asynctest
    def test_copy_connection_lost_source(self):
        """Test source abruptly closing connection during SCP copy"""

        with self.assertRaises(SFTPError) as exc:
            yield from scp((self._scp_server, 'get_connection_lost'),
                           (self._scp_server, 'recv_early_eof'))

        self.assertEqual(exc.exception.reason, 'Connection lost')

    @asynctest
    def test_copy_connection_lost_sink(self):
        """Test sink abruptly closing connection during SCP copy"""

        with self.assertRaises(SFTPError) as exc:
            yield from scp((self._scp_server, 'get_early_eof'),
                           (self._scp_server, 'put_connection_lost'))

        self.assertEqual(exc.exception.reason, 'Connection lost')

    @asynctest
    def test_copy_early_eof(self):
        """Test getting early EOF when copying a file over SCP"""

        with self.assertRaises(SFTPError):
            yield from scp((self._scp_server, 'get_early_eof'),
                           (self._scp_server, 'recv_early_eof'))

    @asynctest
    def test_copy_extra_e(self):
        """Test getting extra E when copying a file over SCP"""

        yield from scp((self._scp_server, 'get_extra_e'),
                       (self._scp_server, 'recv_early_eof'))

    @asynctest
    def test_copy_unknown_action(self):
        """Test getting unknown action from SCP server during copy"""

        with self.assertRaises(SFTPError):
            yield from scp((self._scp_server, 'get_unknown_action'),
                           (self._scp_server, 'recv_early_eof'))

    @asynctest
    def test_unknown(self):
        """Test unknown SCP server request for code coverage"""

        with self.assertRaises(SFTPError):
            yield from scp('src', (self._scp_server, 'unknown'))
