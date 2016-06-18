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

class MySSHTCPSession(asyncssh.SSHTCPSession):
    def connection_made(self, chan):
        self._chan = chan

    def data_received(self, data, datatype):
        self._chan.write(data)

def connection_requested(orig_host, orig_port):
    print('Connection received from %s, port %s' % (orig_host, orig_port))
    return MySSHTCPSession()

async def run_client():
    async with asyncssh.connect('localhost') as conn:
        server = await conn.create_server(connection_requested, '', 8888,
                                          encoding='utf-8')

        if server:
            await server.wait_closed()
        else:
            print('Listener couldn''t be opened.', file=sys.stderr)

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))
