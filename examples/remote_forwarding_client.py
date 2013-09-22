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
from asyncssh import SSHClient

class MySSHClient(SSHClient):
    def handle_auth_complete(self):
        self.forward_remote_port('', 8080, 'localhost', 80)

    def handle_remote_port_forwarding(self, bind_addr, bind_port):
        print('Server listening on port %s...' % bind_port)

    def handle_remote_port_forwarding_error(self, bind_addr, bind_port):
        print('Server listen failed.')

    def handle_disconnect(self, code, reason, lang):
        print('SSH connection error: %s' % reason, file=sys.stderr)

client = MySSHClient('localhost')
asyncore.loop()
