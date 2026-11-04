# Copyright (c) 2017-2024 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH logging API"""

import logging
import unittest

from unittest.mock import MagicMock

import asyncssh

from asyncssh.logging import SSHLogger, logger
from asyncssh.session import SSHClientSession
from asyncssh.sftp import SFTPServer

from .server import ServerTestCase
from .util import asynctest, echo


async def _handle_client(process):
    """Handle a new client request"""

    await echo(process.stdin, process.stdout, process.stderr)
    process.close()
    await process.wait_closed()


class _SFTPServer(SFTPServer):
    """Test SFTP server"""

    def stat(self, path):
        """Get attributes of a file or directory"""

        self.logger.info('stat called')

        return super().stat(path)


class _TestSSHLogger(unittest.TestCase):
    """Unit tests for log argument conversion"""

    def test_disabled_logging(self):
        """Disabled messages should not convert their arguments"""

        for level, disabled in ((logging.WARNING, False), (logging.INFO, True)):
            with self.subTest(level=level, disabled=disabled):
                parent = logging.Logger('test', level)
                parent.disabled = disabled
                ssh_logger = SSHLogger(parent)
                item = MagicMock()

                ssh_logger.info('Test %s', [item])

                self.assertEqual(item.mock_calls, [])

    def test_enabled_logging(self):
        """Enabled messages should retain argument conversion and context"""

        parent = logging.Logger('test', logging.INFO)
        ssh_logger = SSHLogger(parent, context='test context')
        item = MagicMock()
        item.__str__.return_value = 'item'

        with self.assertLogs(parent, level='INFO') as log:
            ssh_logger.info('Test %s %s %s', [b'bytes', item],
                            ('localhost', 22), b'line\n')

        self.assertEqual(len(item.mock_calls), 1)
        self.assertEqual(log.records[0].getMessage(),
                         '[test context] Test bytes,item localhost, port 22 '
                         'line\\n')


class _TestLogging(ServerTestCase):
    """Unit tests for AsyncSSH logging API"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(process_factory=_handle_client,
                                       sftp_factory=_SFTPServer)

    @asynctest
    async def test_logging(self):
        """Test AsyncSSH logging"""

        asyncssh.set_log_level('INFO')

        with self.assertLogs(level='INFO') as log:
            logger.info('Test')

        self.assertEqual(len(log.records), 1)
        self.assertEqual(log.records[0].msg, 'Test')

    @asynctest
    async def test_debug_levels(self):
        """Test log debug levels"""

        asyncssh.set_log_level('DEBUG')

        for debug_level in range(1, 4):
            with self.subTest(debug_level=debug_level):
                asyncssh.set_debug_level(debug_level)

                with self.assertLogs(level='DEBUG') as log:
                    logger.debug1('DEBUG')
                    logger.debug2('DEBUG')
                    logger.packet(None, b'', 'DEBUG')

                self.assertEqual(len(log.records), debug_level)

                for record in log.records:
                    self.assertEqual(record.msg, record.levelname)

    @asynctest
    async def test_packet_logging(self):
        """Test packet logging"""

        asyncssh.set_log_level('DEBUG')
        asyncssh.set_debug_level(3)

        with self.assertLogs(level='DEBUG') as log:
            logger.packet(0, bytes(range(0x10, 0x30)), 'CONTROL')

        self.assertEqual(log.records[0].msg, '[pktid=0] CONTROL\n' +
                         '  00000000: 10 11 12 13 14 15 16 17 18 ' +
                         '19 1a 1b 1c 1d 1e 1f  ................\n' +
                         '  00000010: 20 21 22 23 24 25 26 27 28 ' +
                         '29 2a 2b 2c 2d 2e 2f   !"#$%%&\'()*+,-./')

    @asynctest
    async def test_connection_log(self):
        """Test connection-level logger"""

        asyncssh.set_log_level('INFO')

        async with self.connect() as conn:
            with self.assertLogs(level='INFO') as log:
                conn.logger.info('Test')

        self.assertEqual(len(log.records), 1)
        self.assertRegex(log.records[0].msg, r'\[conn=\d+\] Test')

    @asynctest
    async def test_channel_log(self):
        """Test channel-level logger"""

        asyncssh.set_log_level('INFO')

        async with self.connect() as conn:
            for i in range(2):
                chan, _ = await conn.create_session(SSHClientSession)

                with self.assertLogs(level='INFO') as log:
                    chan.logger.info('Test')

                chan.write_eof()
                await chan.wait_closed()

                self.assertEqual(len(log.records), 1)
                self.assertRegex(log.records[0].msg,
                                 rf'\[conn=\d+, chan={i}\] Test')

    @asynctest
    async def test_stream_log(self):
        """Test stream-level logger"""

        asyncssh.set_log_level('INFO')

        async with self.connect() as conn:
            stdin, _, _ = await conn.open_session()

            with self.assertLogs(level='INFO') as log:
                stdin.logger.info('Test')

            stdin.write_eof()
            await stdin.channel.wait_closed()

        self.assertEqual(len(log.records), 1)
        self.assertRegex(log.records[0].msg, r'\[conn=\d+, chan=0\] Test')

    @asynctest
    async def test_process_log(self):
        """Test process-level logger"""

        asyncssh.set_log_level('INFO')

        async with self.connect() as conn:
            process = await conn.create_process()

            with self.assertLogs(level='INFO') as log:
                process.logger.info('Test')

            process.stdin.write_eof()
            await process.wait()

        asyncssh.set_log_level('WARNING')

        self.assertEqual(len(log.records), 1)
        self.assertRegex(log.records[0].msg, r'\[conn=\d+, chan=0\] Test')

    @asynctest
    async def test_sftp_log(self):
        """Test sftp-level logger"""

        asyncssh.set_sftp_log_level('INFO')

        async with self.connect() as conn:
            async with conn.start_sftp_client() as sftp:
                with self.assertLogs(level='INFO') as log:
                    sftp.logger.info('Test')

                await sftp.stat('.')

        asyncssh.set_sftp_log_level('WARNING')

        self.assertEqual(len(log.records), 1)
        self.assertEqual(log.records[0].name, 'asyncssh.sftp')
        self.assertRegex(log.records[0].msg, r'\[conn=\d+, chan=0\] Test')

    @asynctest
    async def test_invalid_debug_level(self):
        """Test invalid debug level"""

        with self.assertRaises(ValueError):
            asyncssh.set_debug_level(5)
