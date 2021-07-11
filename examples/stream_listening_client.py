#!/usr/bin/env python3.6
#
# Copyright (c) 2013-2021 by Ron Frederick <ronf@timeheart.net> and others.
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
