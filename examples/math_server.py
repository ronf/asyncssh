#!/usr/bin/env python3.4
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
        self._input = ''
        self._total = 0

    def handle_data(self, data, datatype):
        self._input += data

        lines = self._input.split('\n')
        for line in lines[:-1]:
            try:
                self._total += int(line)
            except ValueError:
                self.send('Invalid number: %s\r\n' % line)

        self._input = lines[-1]

    def handle_eof(self):
        self.send('Total = %s\r\n' % self._total)
        self.exit(0)

class MySSHServer(SSHServer):
    def begin_auth(self, username):
        # No auth in this example
        return False

    def handle_session(self):
        return MySSHServerSession(self)

listener = SSHListener(8022, MySSHServer, ssh_host_keys)
asyncore.loop()
