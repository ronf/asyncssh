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

async def handle_connection(reader, writer):
    while not reader.at_eof():
        data = await reader.read(8192)
        writer.write(data)

    writer.close()

def connection_requested(orig_host, orig_port):
    print('Connection received from %s, port %s' % (orig_host, orig_port))
    return handle_connection

async def run_client():
    async with asyncssh.connect('localhost') as conn:
        server = await conn.start_server(connection_requested, '', 8888,
                                         encoding='utf-8')
        await server.wait_closed()

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))
