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
    def handle_shell_request(self):
        return True

    def handle_open(self):
        env = self.get_environment()
        if env:
            keywidth = max(map(len, env.keys()))+1
            self.send('Environment:\r\n')
            for key, value in env.items():
                self.send('  %-*s %s\r\n' % (keywidth, key+':', value))
            self.exit(0)
        else:
            self.send_stderr('No environment sent.\r\n')
            self.exit(1)

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
