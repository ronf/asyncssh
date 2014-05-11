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
host_keys = asyncssh.read_private_key_list('ssh_host_keys')

class MySSHServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        # No auth in this example
        return False

    def server_requested(self, listen_host, listen_port):
        return listen_port == 8080

@asyncio.coroutine
def start_server():
    yield from asyncssh.create_server(MySSHServer, '', 8022,
                                      server_host_keys=host_keys)

loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(start_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH server failed: ' + str(exc))

loop.run_forever()
