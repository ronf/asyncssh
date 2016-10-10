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

"""Unit tests for AsyncSSH SFTP client and server"""

import asyncio
import functools
import os
import stat
import time
import unittest

from unittest.mock import patch

from asyncssh import SFTPError, SFTPAttrs, SFTPVFSAttrs, SFTPName, SFTPServer
from asyncssh import SEEK_CUR, SEEK_END
from asyncssh import FXP_INIT, FXP_VERSION, FXP_OPEN, FXP_CLOSE
from asyncssh import FXP_STATUS, FXP_HANDLE, FXP_DATA
from asyncssh import FILEXFER_ATTR_UNDEFINED, FX_OK, FX_FAILURE

from asyncssh.packet import SSHPacket, Byte, String, UInt32
from asyncssh.sftp import SFTPHandler, SFTPServerHandler

from .server import ServerTestCase
from .util import asynctest, run


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

        run('rm -rf chroot')


class _IOErrorSFTPServer(SFTPServer):
    """Return an I/O error during file writing"""

    @asyncio.coroutine
    def write(self, file_obj, offset, data):
        """Return an error for writes past 64 KB in a file"""

        if offset >= 65536:
            raise SFTPError(FX_FAILURE, 'I/O error')
        else:
            yield from super().write(file_obj, offset, data)


class _NotImplSFTPServer(SFTPServer):
    """Return an error that a request is not implemented"""

    @asyncio.coroutine
    def symlink(self, old_path, new_path):
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


class _StatVFSSFTPServer(SFTPServer):
    """Return a fixed set of attributes in response to a statvfs request"""

    expected_statvfs = SFTPVFSAttrs.from_local(os.statvfs('.'))

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

    def symlink(self, newpath, oldpath):
        """Create a symbolic link"""

        return super().symlink(oldpath, newpath)


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

    def _create_file(self, name, data=(), mode=None, utime=None):
        """Create a test file"""

        if data is ():
            data = str(id(self))

        with open(name, 'w') as f:
            f.write(data)

        if mode is not None:
            os.chmod(name, mode)

        if utime is not None:
            os.utime(name, utime)

    def _check_attr(self, name1, name2, follow_symlinks=False):
        """Check if attributes on two files are equal"""

        statfunc = os.stat if follow_symlinks else os.lstat

        attrs1 = statfunc(name1)
        attrs2 = statfunc(name2)

        self.assertEqual(stat.S_IMODE(attrs1.st_mode),
                         stat.S_IMODE(attrs2.st_mode))
        self.assertEqual(int(attrs1.st_atime), int(attrs2.st_atime))
        self.assertEqual(int(attrs1.st_mtime), int(attrs2.st_mtime))

    def _check_file(self, name1, name2, preserve=False, follow_symlinks=False):
        """Check if two files are equal"""

        if preserve:
            self._check_attr(name1, name2, follow_symlinks)

        with open(name1, 'r') as file1:
            with open(name2, 'r') as file2:
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
                    run('rm -f src dst')

    @sftp_test
    def test_copy_preserve(self, sftp):
        """Test copying a file with preserved attributes over SFTP"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src', mode=0o400, utime=(1, 2))
                    yield from getattr(sftp, method)('src', 'dst',
                                                     preserve=True)
                    self._check_file('src', 'dst', preserve=True)
                finally:
                    run('rm -rf src dst')

    @sftp_test
    def test_copy_recurse(self, sftp):
        """Test recursively copying a directory over SFTP"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    os.mkdir('src')
                    self._create_file('src/file1')
                    os.symlink('file1', 'src/file2')
                    yield from getattr(sftp, method)('src', 'dst',
                                                     recurse=True)
                    self._check_file('src/file1', 'dst/file1')
                    self._check_link('dst/file2', 'file1')
                finally:
                    run('rm -rf src dst')

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
                    os.symlink('file1', 'src/file2')
                    yield from getattr(sftp, method)('src', 'dst',
                                                     recurse=True)
                    self._check_file('src/file1', 'dst/src/file1')
                    self._check_link('dst/src/file2', 'file1')
                finally:
                    run('rm -rf src dst')

    @sftp_test
    def test_copy_follow_symlinks(self, sftp):
        """Test copying a file over SFTP while following symlinks"""

        for method in ('get', 'put', 'copy'):
            with self.subTest(method=method):
                try:
                    self._create_file('src')
                    os.symlink('src', 'link')
                    yield from getattr(sftp, method)('link', 'dst',
                                                     follow_symlinks=True)
                    self._check_file('src', 'dst')
                finally:
                    run('rm -f src dst link')

    @sftp_test
    def test_copy_invalid_name(self, sftp):
        """Test copying a file with an invalid name over SFTP"""

        for method in ('get', 'put', 'copy', 'mget', 'mput', 'mcopy'):
            with self.subTest(method=method):
                with self.assertRaises((FileNotFoundError, SFTPError)):
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
                    run('rm -rf dir')

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
                    run('rm -rf src1 src2 dst')

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
                    run('rm -rf src1 src2 dst')

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
                    run('rm -f src')

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
                    run('rm -rf src1 src2 dst')

    @sftp_test
    def test_glob(self, sftp):
        """Test a glob pattern match over SFTP"""

        try:
            os.mkdir('filedir')
            self._create_file('file1')
            self._create_file('filedir/file2')

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
            self.assertEqual(sorted((yield from sftp.glob(['file*/*']))),
                             ['filedir/file2'])
        finally:
            run('rm -rf file1 filedir')

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

            self.assertEqual((yield from sftp.glob(['file1', 'file2'],
                                                   error_handler=err_handler)),
                             ['file2'])
        finally:
            run('rm -f file2')

    @sftp_test
    def test_stat(self, sftp):
        """Test getting attributes on a file"""

        try:
            os.mkdir('dir')
            self._create_file('file')

            os.symlink('bad', 'badlink')
            os.symlink('dir', 'dirlink')
            os.symlink('file', 'filelink')

            self._check_stat((yield from sftp.stat('dir')), os.stat('dir'))
            self._check_stat((yield from sftp.stat('file')), os.stat('file'))

            self._check_stat((yield from sftp.stat('dirlink')),
                             os.stat('dir'))
            self._check_stat((yield from sftp.stat('filelink')),
                             os.stat('file'))

            with self.assertRaises(SFTPError):
                yield from sftp.stat('badlink') # pragma: no branch

            self.assertTrue((yield from sftp.isdir('dir')))
            self.assertFalse((yield from sftp.isdir('file')))
            self.assertFalse((yield from sftp.isdir('badlink')))
            self.assertTrue((yield from sftp.isdir('dirlink')))
            self.assertFalse((yield from sftp.isdir('filelink')))

            self.assertFalse((yield from sftp.isfile('dir')))
            self.assertTrue((yield from sftp.isfile('file')))
            self.assertFalse((yield from sftp.isfile('badlink')))
            self.assertFalse((yield from sftp.isfile('dirlink')))
            self.assertTrue((yield from sftp.isfile('filelink')))

            self.assertFalse((yield from sftp.islink('dir')))
            self.assertFalse((yield from sftp.islink('file')))
            self.assertTrue((yield from sftp.islink('badlink')))
            self.assertTrue((yield from sftp.islink('dirlink')))
            self.assertTrue((yield from sftp.islink('filelink')))
        finally:
            run('rm -rf dir file badlink dirlink filelink')

    @sftp_test
    def test_lstat(self, sftp):
        """Test getting attributes on a link"""

        try:
            os.symlink('file', 'link')
            self._check_stat((yield from sftp.lstat('link')), os.lstat('link'))
        finally:
            run('rm -f link')

    @sftp_test
    def test_setstat(self, sftp):
        """Test setting attributes on a file"""

        try:
            self._create_file('file')
            yield from sftp.setstat('file', SFTPAttrs(permissions=0o777))
            self.assertEqual(stat.S_IMODE(os.stat('file').st_mode), 0o777)
        finally:
            run('rm -f file')

    @sftp_test
    def test_statvfs(self, sftp):
        """Test getting attributes on a filesystem

           We can't compare the values returned by a live statvfs call since
           they can change at any time. See the separate _TestSFTStatPVFS
           class for a more complete test, but this is left in for code
           coverage purposes.

        """

        self.assertIsInstance((yield from sftp.statvfs('.')), SFTPVFSAttrs)

    @sftp_test
    def test_truncate(self, sftp):
        """Test truncating a file"""

        try:
            self._create_file('file', '01234567890123456789')

            yield from sftp.truncate('file', 10)
            self.assertEqual((yield from sftp.getsize('file')), 10)

            with open('file', 'r') as f:
                self.assertEqual(f.read(), '0123456789')
        finally:
            run('rm -f file')

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
            run('rm -f file')

    @sftp_test
    def test_chmod(self, sftp):
        """Test changing permissions on a file"""

        try:
            self._create_file('file')
            yield from sftp.chmod('file', 0o1234)
            self.assertEqual(stat.S_IMODE(os.stat('file').st_mode), 0o1234)
        finally:
            run('rm -f file')

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
            run('rm -f file')

    @sftp_test
    def test_exists(self, sftp):
        """Test checking whether a file exists"""

        try:
            self._create_file('file1')

            self.assertTrue((yield from sftp.exists('file1')))
            self.assertFalse((yield from sftp.exists('file2')))

            with self.assertRaises(SFTPError):
                yield from sftp.exists('file1/file2')
        finally:
            run('rm -f file1')

    @sftp_test
    def test_lexists(self, sftp):
        """Test checking whether a link exists"""

        try:
            os.symlink('file', 'link1')

            self.assertTrue((yield from sftp.lexists('link1')))
            self.assertFalse((yield from sftp.lexists('link2')))
        finally:
            run('rm -f link1')

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
            run('rm -f file')

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
            run('rm -f file')

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
            run('rm -f file1 file2 file3')

    @sftp_test
    def test_posix_rename(self, sftp):
        """Test renaming a file that replaces a target file"""

        try:
            self._create_file('file1', 'xxx')
            self._create_file('file2', 'yyy')

            yield from sftp.posix_rename('file1', 'file2')

            with open('file2') as f:
                self.assertEqual(f.read(), 'xxx')
        finally:
            run('rm -f file1 file2')

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
            run('rm -rf dir')

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
            run('rm -rf dir')

    @sftp_test
    def test_mkdir(self, sftp):
        """Test creating a directory"""

        try:
            yield from sftp.mkdir('dir')
            self.assertTrue(os.path.isdir('dir'))
        finally:
            run('rm -rf dir')

    @sftp_test
    def test_rmdir(self, sftp):
        """Test removing a directory"""

        try:
            os.mkdir('dir')
            yield from sftp.rmdir('dir')

            with self.assertRaises(FileNotFoundError):
                os.stat('dir')
        finally:
            run('rm -rf dir')

    @sftp_test
    def test_readlink(self, sftp):
        """Test reading a symlink"""

        try:
            os.symlink('/file', 'link')
            self.assertEqual((yield from sftp.readlink('link')), '/file')
        finally:
            run('rm -f link')

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

        try:
            yield from sftp.symlink('file', 'link')
            self._check_link('link', 'file')
        finally:
            run('rm -f file link')

    @asynctest
    def test_symlink_encode_error(self):
        """Test creating a unicode symlink with no path encoding set"""

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

        try:
            with (yield from self.connect(client_version='OpenSSH')) as conn:
                with (yield from conn.start_sftp_client()) as sftp:
                    yield from sftp.symlink('link', 'file')
                    self._check_link('link', 'file') # pragma: no branch

                yield from sftp.wait_closed() # pragma: no branch

            yield from conn.wait_closed()
        finally:
            run('rm -f file link')

    @sftp_test
    def test_link(self, sftp):
        """Test creating a hard link"""

        try:
            self._create_file('file1')
            yield from sftp.link('file1', 'file2')
            self._check_file('file1', 'file2')
        finally:
            run('rm -f file1 file2')

    @sftp_test
    def test_open_read(self, sftp):
        """Test reading data from a file"""

        try:
            self._create_file('file', 'xxx')

            with (yield from sftp.open('file', 'r')) as f:
                self.assertEqual((yield from f.read()), 'xxx')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_read_bytes(self, sftp):
        """Test reading bytes from a file"""

        try:
            self._create_file('file', 'xxx')

            with (yield from sftp.open('file', 'rb')) as f:
                self.assertEqual((yield from f.read()), b'xxx')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_read_offset_size(self, sftp):
        """Test reading at a specific offset and size"""

        try:
            self._create_file('file', 'xxxxyyyy')

            with (yield from sftp.open('file', 'r')) as f:
                self.assertEqual((yield from f.read(4, 2)), 'xxyy')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_read_nonexistent(self, sftp):
        """Test reading data from a nonexistent file"""

        with self.assertRaises(SFTPError):
            yield from sftp.open('file', 'r')

    @sftp_test
    def test_open_read_not_permitted(self, sftp):
        """Test reading data from a file with no read permission"""

        try:
            self._create_file('file', mode=0)

            with self.assertRaises(SFTPError):
                yield from sftp.open('file', 'r')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_write(self, sftp):
        """Test writing data to a file"""

        try:
            with (yield from sftp.open('file', 'w')) as f:
                yield from f.write('xxx') # pragma: no branch

            with open('file', 'r') as f:
                self.assertEqual(f.read(), 'xxx')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_write_bytes(self, sftp):
        """Test writing bytes to a file"""

        try:
            with (yield from sftp.open('file', 'wb')) as f:
                yield from f.write(b'xxx') # pragma: no branch

            with open('file', 'rb') as f:
                self.assertEqual(f.read(), b'xxx')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_truncate(self, sftp):
        """Test truncating a file at open time"""

        try:
            self._create_file('file', 'xxxyyy')

            with (yield from sftp.open('file', 'w')) as f:
                yield from f.write('zzz') # pragma: no branch

            with open('file', 'r') as f:
                self.assertEqual(f.read(), 'zzz')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_append(self, sftp):
        """Test appending data to an existing file"""

        try:
            self._create_file('file', 'xxx')

            with (yield from sftp.open('file', 'a+')) as f:
                yield from f.write('yyy')
                self.assertEqual((yield from f.read()), '') # pragma: no branch

            with open('file', 'r') as f:
                self.assertEqual(f.read(), 'xxxyyy')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_exclusive_create(self, sftp):
        """Test creating a new file"""

        try:
            with (yield from sftp.open('file', 'x')) as f:
                yield from f.write('xxx') # pragma: no branch

            with open('file', 'r') as f:
                self.assertEqual(f.read(), 'xxx') # pragma: no branch

            with self.assertRaises(SFTPError):
                yield from sftp.open('file', 'x')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_exclusive_create_existing(self, sftp):
        """Test exclusive create of an existing file"""

        try:
            self._create_file('file')

            with self.assertRaises(SFTPError):
                yield from sftp.open('file', 'x')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_overwrite(self, sftp):
        """Test overwriting part of an existing file"""

        try:
            self._create_file('file', 'xxxyyy')

            with (yield from sftp.open('file', 'r+')) as f:
                yield from f.write('zzz') # pragma: no branch

            with open('file', 'r') as f:
                self.assertEqual(f.read(), 'zzzyyy')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_overwrite_offset_size(self, sftp):
        """Test writing data at a specific offset"""

        try:
            self._create_file('file', 'xxxxyyyy')

            with (yield from sftp.open('file', 'r+')) as f:
                yield from f.write('zz', 3) # pragma: no branch

            with open('file', 'r') as f:
                self.assertEqual(f.read(), 'xxxzzyyy')
        finally:
            run('rm -f file')

    @sftp_test
    def test_open_overwrite_nonexistent(self, sftp):
        """Test overwriting a nonexistent file"""

        with self.assertRaises(SFTPError):
            yield from sftp.open('file', 'r+')

    @sftp_test
    def test_file_seek(self, sftp):
        """Test seeking within a file"""

        try:
            with (yield from sftp.open('file', 'w+')) as f:
                yield from f.write('xxxxyyyy')
                yield from f.seek(3)
                yield from f.write('zz') # pragma: no branch

                yield from f.seek(-3, SEEK_CUR)
                self.assertEqual((yield from f.read(4)), 'xzzy')

                yield from f.seek(-4, SEEK_END)
                self.assertEqual((yield from f.read()), 'zyyy')
                self.assertEqual((yield from f.read()), '')
                self.assertEqual((yield from f.read(1)), '')

                with self.assertRaises(ValueError):
                    yield from f.seek(0, -1) # pragma: no branch

            with open('file', 'r') as f:
                self.assertEqual(f.read(), 'xxxzzyyy')
        finally:
            run('rm -f file')

    @sftp_test
    def test_file_stat(self, sftp):
        """Test getting attributes on an open file"""

        try:
            self._create_file('file')

            with (yield from sftp.open('file')) as f:
                self._check_stat((yield from f.stat()), os.stat('file'))
        finally:
            run('rm -f file')

    @sftp_test
    def test_file_setstat(self, sftp):
        """Test setting attributes on an open file"""

        try:
            self._create_file('file')
            attrs = SFTPAttrs(permissions=0o777)

            with (yield from sftp.open('file')) as f:
                yield from f.setstat(attrs) # pragma: no branch

            self.assertEqual(stat.S_IMODE(os.stat('file').st_mode), 0o777)
        finally:
            run('rm -f file')

    @sftp_test
    def test_file_truncate(self, sftp):
        """Test truncating an open file"""

        try:
            self._create_file('file', '01234567890123456789')

            with (yield from sftp.open('file', 'a+')) as f:
                yield from f.truncate(10)
                self.assertEqual((yield from f.tell()), 10)
                self.assertEqual((yield from f.read(offset=0)), '0123456789')
                self.assertEqual((yield from f.tell()), 10)
        finally:
            run('rm -f file')

    @sftp_test
    def test_file_utime(self, sftp):
        """Test changing access and modify times on an open file"""

        try:
            self._create_file('file')

            with (yield from sftp.open('file')) as f:
                yield from f.utime()
                yield from f.utime((1, 2)) # pragma: no branch

            attrs = os.stat('file')
            self.assertEqual(attrs.st_atime, 1)
            self.assertEqual(attrs.st_mtime, 2)
        finally:
            run('rm -f file')

    @sftp_test
    def test_file_statvfs(self, sftp):
        """Test getting attributes on the filesystem containing an open file

           We can't compare the values returned by a live statvfs call since
           they can change at any time. See the separate _TestSFTStatPVFS
           class for a more complete test, but this is left in for code
           coverage purposes.

        """

        try:
            self._create_file('file')

            with (yield from sftp.open('file')) as f:
                self.assertIsInstance((yield from f.statvfs()), SFTPVFSAttrs)
        finally:
            run('rm -f file')

    @sftp_test
    def test_file_sync(self, sftp):
        """Test file sync"""

        try:
            self._create_file('file')

            with (yield from sftp.open('file')) as f:
                self.assertIsNone((yield from f.fsync()))
        finally:
            run('rm -f file')

    @sftp_test
    def test_exited_session(self, sftp):
        """Test use of SFTP session after exit"""

        sftp.exit()
        yield from sftp.wait_closed()

        with self.assertRaises(SFTPError):
            yield from sftp.open('file', 'r')

    @sftp_test
    def test_cleanup_open_files(self, sftp):
        """Test cleanup of open file handles on exit"""

        try:
            self._create_file('file')

            yield from sftp.open('file', 'r')
        finally:
            run('rm -f file')

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

        try:
            self._create_file('file')

            with (yield from sftp.open('file')) as f:
                # Do an explicit close to test double-close
                yield from f.close() # pragma: no branch

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

            yield from f.close()
        finally:
            run('rm -f file')

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

            self.send_packet(Byte(FXP_OPEN), UInt32(0))

        with patch('asyncssh.sftp.SFTPClientHandler.start', _no_init_start):
            sftp_test(lambda self, sftp: None)(self)

    def test_missing_version(self):
        """Test sending init with missing version"""

        @asyncio.coroutine
        def _missing_version_start(self):
            """Send an init request with missing version"""

            self.send_packet(Byte(FXP_INIT))

        with patch('asyncssh.sftp.SFTPClientHandler.start',
                   _missing_version_start):
            sftp_test(lambda self, sftp: None)(self)

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
            self.send_packet(Byte(FXP_STATUS))
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

            self.send_packet(Byte(FXP_VERSION), UInt32(4))

        with patch('asyncssh.sftp.SFTPServerHandler.recv_packet',
                   _unsupported_version_response):
            with self.assertRaises(SFTPError):
                sftp_test(lambda self, sftp: None)(self) # pragma: no branch

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

            self.send_packet(Byte(FXP_INIT), UInt32(3))
            yield from self._cleanup(None)

        with patch('asyncssh.sftp.SFTPClientHandler.start',
                   _close_after_init_start):
            sftp_test(lambda self, sftp: None)(self)

    def test_file_handle_skip(self):
        """Test skipping over a file handle already in use"""

        @asyncio.coroutine
        def _reset_file_handle(self, sftp):
            """Open multiple files, resetting next handle each time"""

            try:
                self._create_file('file1', 'xxx')
                self._create_file('file2', 'yyy')

                with (yield from sftp.open('file1', 'r')) as file1:
                    with (yield from sftp.open('file2', 'r')) as file2:
                        self.assertEqual((yield from file1.read()), 'xxx')
                        self.assertEqual((yield from file2.read()), 'yyy')
            finally:
                run('rm -f file1 file2')

        with patch('asyncssh.stream.SFTPServerHandler',
                   _ResetFileHandleServerHandler):
            sftp_test(_reset_file_handle)(self)

    @sftp_test
    def test_missing_request_pktid(self, sftp):
        """Test sending request without a packet ID"""

        @asyncio.coroutine
        def _missing_pktid(self, filename, pflags, attrs):
            """Send a request without a packet ID"""

            # pylint: disable=unused-argument

            self.send_packet(Byte(FXP_OPEN))

        with patch('asyncssh.sftp.SFTPClientHandler.open', _missing_pktid):
            yield from sftp.open('file', 'r')

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
                yield from sftp.open('file', 'r')

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
                yield from sftp.open('file', 'r')

    @sftp_test
    def test_unrecognized_response_pktid(self, sftp):
        """Test sending a response with an unrecognized packet ID"""

        @asyncio.coroutine
        def _unrecognized_response_pktid(self, pkttype, pktid, packet):
            """Send a response with an unrecognized packet ID"""

            # pylint: disable=unused-argument

            self.send_packet(Byte(FXP_HANDLE), UInt32(0xffffffff),
                             String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _unrecognized_response_pktid):
            with self.assertRaises(SFTPError):
                yield from sftp.open('file', 'r')

    @sftp_test
    def test_bad_response_type(self, sftp):
        """Test sending a response with an incorrect response type"""

        @asyncio.coroutine
        def _bad_response_type(self, pkttype, pktid, packet):
            """Send a response with an incorrect response type"""

            # pylint: disable=unused-argument

            self.send_packet(Byte(FXP_DATA), UInt32(pktid),
                             String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _bad_response_type):
            with self.assertRaises(SFTPError):
                yield from sftp.open('file', 'r')

    @sftp_test
    def test_unexpected_ok_response(self, sftp):
        """Test sending an unexpected FX_OK response"""

        @asyncio.coroutine
        def _unexpected_ok_response(self, pkttype, pktid, packet):
            """Send an unexpected FX_OK response"""

            # pylint: disable=unused-argument

            self.send_packet(Byte(FXP_STATUS), UInt32(pktid), UInt32(FX_OK),
                             String(''), String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _unexpected_ok_response):
            with self.assertRaises(SFTPError):
                yield from sftp.open('file', 'r')

    @sftp_test
    def test_malformed_ok_response(self, sftp):
        """Test sending an FX_OK response containing invalid Unicode"""

        @asyncio.coroutine
        def _malformed_ok_response(self, pkttype, pktid, packet):
            """Send an FX_OK response containing invalid Unicode"""

            # pylint: disable=unused-argument

            self.send_packet(Byte(FXP_STATUS), UInt32(pktid), UInt32(FX_OK),
                             String(b'\xff'), String(''))

        with patch('asyncssh.sftp.SFTPServerHandler._process_packet',
                   _malformed_ok_response):
            with self.assertRaises(SFTPError):
                yield from sftp.open('file', 'r')

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

                with (yield from sftp.open('file1')) as f:
                    with self.assertRaises(SFTPError):
                        yield from f.statvfs() # pragma: no branch

                with self.assertRaises(SFTPError):
                    yield from sftp.posix_rename('file1', # pragma: no branch
                                                 'file2')

                with self.assertRaises(SFTPError):
                    yield from sftp.link('file1', 'file2') # pragma: no branch

                with (yield from sftp.open('file1')) as f:
                    with self.assertRaises(SFTPError):
                        yield from f.fsync()
            finally:
                run('rm -f file1')

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
                run('rm -f file')

        with patch('asyncssh.stream.SFTPServerHandler',
                   _NonblockingCloseServerHandler):
            sftp_test(_nonblocking_close)(self)


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
            run('rm -f src chroot/dst')

    @sftp_test
    def test_chroot_glob(self, sftp):
        """Test a glob pattern match over SFTP with a changed root"""

        try:
            self._create_file('chroot/file1')
            self._create_file('chroot/file2')
            self.assertEqual(sorted((yield from sftp.glob('/file*'))),
                             ['/file1', '/file2'])
        finally:
            run('rm -f chroot/file1 chroot/file2')

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
            run('rm -rf chroot/dir')

    @sftp_test
    def test_chroot_readlink(self, sftp):
        """Test reading symlinks on an FTP server with a changed root"""

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
            run('rm -f link1 link2 link3')

    @sftp_test
    def test_chroot_symlink(self, sftp):
        """Test setting a symlink on an SFTP server with a changed root"""

        try:
            yield from sftp.symlink('/file', 'link1')
            yield from sftp.symlink('../../file', 'link2')

            self._check_link('chroot/link1', os.path.abspath('chroot/file'))
            self._check_link('chroot/link2', 'file')
        finally:
            run('rm -f chroot/link1 chroot/link2')


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
                    run('rm -f src chroot/dst')


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

        try:
            self._create_file('file')

            with (yield from sftp.open('file')) as f:
                self._check_statvfs((yield from f.statvfs()))
        finally:
            run('rm -f file')


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
            run('rm -f file')


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

    # pylint: disable=too-many-public-methods

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SFTP server for the tests to use"""

        return (yield from cls.create_server(server_version='OpenSSH',
                                             sftp_factory=_SymlinkSFTPServer))

    @asynctest
    def test_nonstandard_symlink_client(self):
        """Test creating a symlink with opposite argument order"""

        try:
            with (yield from self.connect(client_version='OpenSSH')) as conn:
                with (yield from conn.start_sftp_client()) as sftp:
                    yield from sftp.symlink('link', 'file')
                    self._check_link('link', 'file') # pragma: no branch

                yield from sftp.wait_closed() # pragma: no branch

            yield from conn.wait_closed()
        finally:
            run('rm -f file link')


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
                         os.path.join(os.getcwd(), 'file'))
