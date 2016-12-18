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

"""SSH agent support code for UNIX"""

import asyncio
import errno
import os


@asyncio.coroutine
def open_agent(loop, agent_path):
    """Open a connection to ssh-agent"""

    if not loop:
        loop = asyncio.get_event_loop()

    if not agent_path:
        agent_path = os.environ.get('SSH_AUTH_SOCK', None)

        if not agent_path:
            raise OSError(errno.ENOENT, 'Agent not found')

    return (yield from asyncio.open_unix_connection(agent_path, loop=loop))
