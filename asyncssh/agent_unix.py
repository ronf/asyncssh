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

"""SSH agent support code for UNIX"""

import asyncio
import errno


@asyncio.coroutine
def open_agent(loop, agent_path):
    """Open a connection to ssh-agent"""

    if not loop:
        loop = asyncio.get_event_loop()

    if not agent_path:
        raise OSError(errno.ENOENT, 'Agent not found')

    return (yield from asyncio.open_unix_connection(agent_path, loop=loop))
