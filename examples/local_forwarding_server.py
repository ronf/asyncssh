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

import asyncore
from asyncssh import SSHListener, SSHServer
from asyncssh import ChannelOpenError, OPEN_ADMINISTRATIVELY_PROHIBITED
from asyncssh import read_private_key_list

# To run this program, the file ssh_host_keys must exist with at least
# one SSH private key to use as a server host key in it
ssh_host_keys = read_private_key_list('ssh_host_keys')

class MySSHServer(SSHServer):
    def begin_auth(self, username):
        # No auth in this example
        return False

    def handle_direct_connection(self, dest_host, dest_port,
                                 orig_host, orig_port):
        # Allow port forwarding, but only to port 80
        if dest_port == 80:
            return True
        else:
            raise ChannelOpenError(OPEN_ADMINISTRATIVELY_PROHIBITED,
                                   'Only port 80 is allowed')

listener = SSHListener(8022, MySSHServer, ssh_host_keys)
asyncore.loop()
