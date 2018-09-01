# Copyright (c) 2016 by Ron Frederick <ronf@timeheart.net>.
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

"""Unit tests for AsyncSSH SFTP client and server on Python 3.5 and later"""

import os
from unittest.mock import patch

from asyncssh import SFTPError, FXP_WRITE

from asyncssh.sftp import SFTPServerHandler

from tests.server import ServerTestCase
from tests.util import asynctest, asynctest35


class _WriteCloseServerHandler(SFTPServerHandler):
    """Close the SFTP session in the middle of a write request"""

    async def _process_packet(self, pkttype, pktid, packet):
        """Close the session when a file close request is received"""

        if pkttype == FXP_WRITE:
            await self._cleanup(None)
        else:
            await super()._process_packet(pkttype, pktid, packet)


class _TestSFTP(ServerTestCase):
    """Unit tests for AsyncSSH SFTP async context manager"""

    # pylint: disable=not-async-context-manager

    @classmethod
    async def start_server(cls):
        """Start an SFTP server for the tests to use"""

        return await cls.create_server(sftp_factory=True)

    @asynctest35
    async def test_sftp(self):
        """Test starting SFTP in Python 3.5 with async context manager"""

        async with self.connect() as conn:
            async with conn.start_sftp_client():
                pass

    @asynctest35
    async def test_sftp_await(self):
        """Test starting SFTP with await and async context manager"""

        async with self.connect() as conn:
            sftp = await conn.start_sftp_client()
            async with sftp:
                pass

    @asynctest
    def test_sftp_yield(self):
        """Test starting SFTP with yield from"""

        with (yield from self.connect()) as conn:
            with (yield from conn.start_sftp_client()):
                pass

    @asynctest35
    async def test_sftp_open(self):
        """Test opening SFTP file in Python 3.5 with async context manager"""

        async with self.connect() as conn:
            async with conn.start_sftp_client() as sftp:
                try:
                    async with sftp.open('file', 'w'):
                        pass
                finally:
                    os.unlink('file')

    @asynctest35
    async def test_sftp_open_await(self):
        """Test opening SFTP file with await and async context manager"""

        async with self.connect() as conn:
            sftp = await conn.start_sftp_client()
            async with sftp:
                try:
                    async with sftp.open('file', 'w'):
                        pass
                finally:
                    os.unlink('file')

    @asynctest
    def test_sftp_open_yield(self):
        """Test opening SFTP file with yield from"""

        with (yield from self.connect()) as conn:
            with (yield from conn.start_sftp_client()) as sftp:
                f = None

                try:
                    f = yield from sftp.open('file', 'w')
                finally:
                    if f: # pragma: no branch
                        yield from f.close()

                    os.unlink('file')

    @asynctest35
    async def test_write_close(self):
        """Test session cleanup in the middle of a write request"""

        with patch('asyncssh.sftp.SFTPServerHandler', _WriteCloseServerHandler):
            async with self.connect() as conn:
                async with conn.start_sftp_client() as sftp:
                    try:
                        async with sftp.open('file', 'w') as f:
                            with self.assertRaises(SFTPError):
                                await f.write('a')
                    finally:
                        os.unlink('file')
