#!/usr/bin/env python3.4
#
# Copyright (c) 2013-2015 by Ron Frederick <ronf@timeheart.net>.
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
        if datatype == asyncssh.EXTENDED_DATA_STDERR:
            print(data, end='', file=sys.stderr)
        else:
            print(data, end='')

    def exit_status_received(self, status):
        if status:
            print('Program exited with status %d' % status, file=sys.stderr)
        else:
            print('Program exited successfully')

    def connection_lost(self, exc):
        if exc:
            print('SSH session error: ' + str(exc), file=sys.stderr)

@asyncio.coroutine
def run_client():
    with (yield from asyncssh.connect('localhost')) as conn:
        chan, session = yield from conn.create_session(MySSHClientSession, 'ls abc')
        yield from chan.wait_closed()

    yield from conn.wait_closed()

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))
