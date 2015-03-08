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

# To run this program, the file ``ssh_host_key`` must exist with an SSH
# private key in it to use as a server host key. An SSH host certificate
# can optionally be provided in the file ``ssh_host_key-cert.pub``.

class MySSHServerSession(asyncssh.SSHServerSession):
    def connection_made(self, chan):
        self._chan = chan

    def shell_requested(self):
        return True

    def session_started(self):
        term_type = self._chan.get_terminal_type()
        term_size = self._chan.get_terminal_size()
        self._chan.write('Terminal type: %s, size: %sx%s\r\n' %
                             (term_type, term_size[0], term_size[1]))
        self._chan.write('Try resizing your window!\r\n')

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        self._chan.write('New window size: %sx%s' % (width, height))

        if pixwidth and pixheight:
            self._chan.write(' (%sx%s pixels)' % (pixwidth, pixheight))

        self._chan.write('\r\n')

class MySSHServer(asyncssh.SSHServer):
    def connection_lost(self, exc):
        if exc:
            print('SSH connection error: ' + str(exc), file=sys.stderr)

    def begin_auth(self, username):
        # No auth in this example
        return False

    def session_requested(self):
        return MySSHServerSession()

@asyncio.coroutine
def start_server():
    yield from asyncssh.create_server(MySSHServer, '', 8022,
                                      server_host_keys=['ssh_host_key'])

loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(start_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit('Error starting server: ' + str(exc))

loop.run_forever()
