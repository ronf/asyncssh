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

class MySSHClientSession(asyncssh.SSHClientSession):
    def data_received(self, data, datatype):
        print(data, end='')

    def connection_lost(self, exc):
        if exc:
            print('SSH session error: ' + str(exc), file=sys.stderr)

class MySSHClient(asyncssh.SSHClient):
    def connection_made(self, conn):
        print('Connection made to %s.' % conn.get_extra_info('peername')[0])

    def auth_completed(self):
        print('Authentication successful.')

async def run_client():
    conn, client = await asyncssh.create_connection(MySSHClient, 'localhost')

    async with conn:
        chan, session = await conn.create_session(MySSHClientSession, 'ls abc')
        await chan.wait_closed()

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))
