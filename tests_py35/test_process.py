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

"""Unit tests for AsyncSSH process API on Python 3.5 and later"""

from tests.server import ServerTestCase
from tests.util import asynctest35, echo


class _TestStream(ServerTestCase):
    """Unit tests for AsyncSSH stream API"""

    # pylint: disable=not-async-context-manager

    @classmethod
    async def start_server(cls):
        """Start an SSH server for the tests to use"""

        return await cls.create_server(session_factory=echo)

    @asynctest35
    async def test_shell(self):
        """Test starting a remote shell"""

        data = str(id(self))

        async with self.connect() as conn:
            async with conn.create_process() as process:
                process.stdin.write(data)
                process.stdin.write_eof()

                result = await process.wait()

        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, data)
