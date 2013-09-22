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

import asyncore, socket, sys
from asyncssh import SSHClient

class MySSHClient(SSHClient):
    def handle_auth_complete(self):
        try:
            bind_port = self.forward_local_port('', 8080, 'www.google.com', 80)
            print('Listening on port %s...' % bind_port)
        except socket.error as exc:
            print('Local listen failed: %s' % exc.args[1])
            self.disconnect()

    def handle_disconnect(self, code, reason, lang):
        print('SSH connection error: %s' % reason, file=sys.stderr)

client = MySSHClient('localhost')
asyncore.loop()
