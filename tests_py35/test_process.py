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
