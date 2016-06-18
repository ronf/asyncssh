#!/usr/bin/env python3.5
#
# Copyright (c) 2013-2016 by Ron Frederick <ronf@timeheart.net>.
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

import asyncio, asyncssh, sys

def connection_requested(orig_host, orig_port):
    global conn

    if orig_host in ('127.0.0.1', '::1'):
        return conn.forward_connection('localhost', 80)
    else:
        raise asyncssh.ChannelOpenError(
            asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED,
            'Connections only allowed from localhost')

async def run_client():
    global conn

    async with asyncssh.connect('localhost') as conn:
        listener = await conn.create_server(connection_requested, '', 8080)
        await listener.wait_closed()

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))
