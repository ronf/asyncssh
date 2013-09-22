#!/usr/bin/env python3.2
#
# Copyright (c) 2013 by Ron Frederick <ronf@timeheart.net>.
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

import asyncore, sys
from asyncssh import SSHListener, SSHServer, SSHServerSession
from asyncssh import read_private_key_list

# To run this program, the file ssh_host_keys must exist with at least
# one SSH private key to use as a server host key in it
ssh_host_keys = read_private_key_list('ssh_host_keys')

class MySSHServerSession(SSHServerSession):
    def handle_pty_request(self, term, modes):
        self.send('Terminal type: %s\r\n' % term)
        return True

    def handle_window_change(self, width, height, pixwidth, pixheight):
        self.send('Window size: %sx%s' % (width, height))

        if pixwidth and pixheight:
            self.send(' (%sx%s pixels)' % (pixwidth, pixheight))

        self.send('\r\n')

    def handle_shell_request(self):
        return True

    def handle_open(self):
        self.send('Try resizing your window!\r\n')

class MySSHServer(SSHServer):
    def __init__(self, sock, addr):
        super().__init__(sock, ssh_host_keys)

    def begin_auth(self, username):
        # No auth in this example
        return False

    def handle_session(self):
        return MySSHServerSession(self)

listener = SSHListener(8022, MySSHServer)
asyncore.loop()
