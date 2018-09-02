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
