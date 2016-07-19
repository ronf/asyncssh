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

"""Unit tests for AsyncSSH connection API on Python 3.5 and later"""

from tests.server import ServerTestCase
from tests.util import asynctest, asynctest35


class _TestConnection(ServerTestCase):
    """Unit tests for AsyncSSH connection async context manager"""

    # pylint: disable=not-async-context-manager

    @asynctest35
    async def test_connect(self):
        """Test connecting in Python 3.5 with async context manager"""

        async with self.connect():
            pass

    @asynctest35
    async def test_connect_await(self):
        """Test connecting with await and async context manager"""

        conn = await self.connect()
        async with conn:
            pass

    @asynctest
    def test_connect_yield(self):
        """Test connecting with yield from"""

        with (yield from self.connect()):
            pass
