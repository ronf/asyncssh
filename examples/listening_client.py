#!/usr/bin/env python3.4
#
# Copyright (c) 2013-2014 by Ron Frederick <ronf@timeheart.net>.
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

    def session_started(self):
        self._chan.write('Connection successful!\r\n')
        self._chan.close()

@asyncio.coroutine
def connection_requested(orig_host, orig_port):
    print('Connection received from %s, port %s' % (orig_host, orig_port))
    return MySSHTCPSession()

@asyncio.coroutine
def start_client():
    conn, _ = yield from asyncssh.create_connection(None, 'localhost')
    server = yield from conn.create_server(connection_requested, '', 8888,
                                           encoding='utf-8')
    yield from server.wait_closed()

loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(start_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))
