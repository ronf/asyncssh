# Copyright (c) 2016-2018 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH stream API on Python 3.5 and later"""

from tests.server import Server, ServerTestCase
from tests.util import asynctest35, echo


class _StreamServer(Server):
    """Server for testing the AsyncSSH stream API in Python 3.5"""

    def session_requested(self):
        """Handle a request to create a new session"""

        return echo


class _TestStream(ServerTestCase):
    """Unit tests for AsyncSSH stream API"""

    # pylint: disable=not-async-context-manager

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(_StreamServer)

    @asynctest35
    async def test_async_iterator(self):
        """Test reading lines by using SSHReader as an async iterator"""

        async with self.connect() as conn:
            stdin, stdout, _ = await conn.open_session()

            data = ['Line 1\n', 'Line 2\n']

            stdin.writelines(data)
            stdin.write_eof()

            async for line in stdout:
                self.assertEqual(line, data.pop(0))

            self.assertEqual(data, [])
