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
import asyncssh

from .server import ServerTestCase
from .util import asynctest


class _TestSFTP(ServerTestCase):
    """Unit tests for AsyncSSH SFTP client and server"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server for the tests to use"""

        # Pass loop explicitly to get coverage on non-default event loops
        return (yield from asyncssh.listen(
            '', 0, loop=cls.loop, server_host_keys=['skey'],
            authorized_client_keys='authorized_keys', sftp_factory=True))

    @asyncio.coroutine
    def _start_sftp(self):
        """Open an SFTP client session"""

        conn = yield from asyncssh.connect(self._server_addr,
                                           self._server_port,
                                           known_hosts=None,
                                           client_keys=['ckey'])

        sftp = yield from conn.start_sftp_client()

        return conn, sftp

    @asynctest
    def test_sftp_connect(self):
        """Connect to SFTP server"""

        conn, sftp = yield from self._start_sftp()

        with conn:
            with sftp:
                pass

        yield from conn.wait_closed()
