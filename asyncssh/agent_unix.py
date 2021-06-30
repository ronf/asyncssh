# Copyright (c) 2016-2019 by Ron Frederick <ronf@timeheart.net> and others.
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

"""SSH agent support code for UNIX"""

import asyncio
import errno
from asyncio.streams import StreamReader
from asyncio.streams import StreamWriter
from typing import Optional
from typing import Tuple


async def open_agent(agent_path: Optional[str]) -> Tuple[StreamReader, StreamWriter]:
    """Open a connection to ssh-agent"""

    if not agent_path:
        raise OSError(errno.ENOENT, 'Agent not found')

    return await asyncio.open_unix_connection(agent_path)
