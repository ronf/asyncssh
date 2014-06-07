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

# To run this program, the file ssh_host_keys must exist with at least
# one SSH private key to use as a server host key in it
ssh_host_keys = asyncssh.read_private_key_list('ssh_host_keys')

# Authentication requires the directory authorized_keys to exist
# with files in it named <username>.pub containing the public client
# keys which are accepted for that user.

class MySSHServerSession(asyncssh.SSHServerSession):
    def connection_made(self, chan):
        self._chan = chan

    def shell_requested(self):
        return True

    def session_started(self):
        self._chan.write('Welcome to my SSH server, %s!\r\n' %
                             self._chan.get_extra_info('username'))
        self._chan.exit(0)

class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self._conn = conn

        print('SSH connection received from %s.' %
                  conn.get_extra_info('peername')[0])

    def connection_lost(self, exc):
        if exc:
            print('SSH connection error: ' + str(exc), file=sys.stderr)
        else:
            print('SSH connection closed.')

    def begin_auth(self, username):
        try:
            self._keys = \
                asyncssh.read_public_key_list('authorized_keys/%s.pub' %
                                                  username)
        except IOError:
            self._keys = []

        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return key in self._keys

    def session_requested(self):
        return MySSHServerSession()

@asyncio.coroutine
def start_server():
    yield from asyncssh.create_server(MySSHServer, 'localhost', 8022,
                                      server_host_keys=ssh_host_keys)

loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(start_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit('Error starting server: ' + str(exc))

loop.run_forever()
