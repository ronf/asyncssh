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

import asyncore, sys
from asyncssh import SSHClient, SSHClientRemotePortForwarder

class MyPortForwarder(SSHClientRemotePortForwarder):
    def handle_open_error(self):
        print('Remote listen failed.', file=sys.stderr)
        self.conn.disconnect()

class MySSHClient(SSHClient):
    def handle_auth_complete(self):
        forwarder = MyPortForwarder(self, '', 8080, 'localhost', 80)

    def handle_disconnect(self, code, reason, lang):
        print('SSH connection error: %s' % reason, file=sys.stderr)

client = MySSHClient('localhost')
asyncore.loop()
