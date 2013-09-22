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
from asyncssh import read_private_key_list, read_public_key_list

# To run this program, the file ssh_host_keys must exist with at least
# one SSH private key to use as a server host key in it
ssh_host_keys = read_private_key_list('ssh_host_keys')

# Authentication requires the directory authorized_keys to exist
# with files in it named <username>.pub containing the public client
# keys which are accepted for that user.

class MySSHServerSession(SSHServerSession):
    def handle_shell_request(self):
        return True

    def handle_open(self):
        self.send('Welcome to my SSH server, %s!\r\n' %
                      self.conn.get_username())
        self.exit(0)

class MySSHServer(SSHServer):
    def __init__(self, sock, addr):
        super().__init__(sock, ssh_host_keys)

    def begin_auth(self, username):
        try:
            self._keys = read_public_key_list('authorized_keys/%s.pub' %
                                                  username)
        except IOError:
            self._keys = []

        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return key in self._keys

    def handle_session(self):
        return MySSHServerSession(self)

listener = SSHListener(8022, MySSHServer)
asyncore.loop()
