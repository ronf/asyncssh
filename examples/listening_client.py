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
from asyncssh import SSHClient, SSHClientListener, SSHTCPConnection

class MySSHTCPConnection(SSHTCPConnection):
    def handle_open(self):
        self.send('Connection successful!\r\n')
        self.close()

class MySSHClientListener(SSHClientListener):
    def handle_open_error(self):
        print('Server listen failed.', file=sys.stderr)
        self.conn.disconnect()

    def handle_connection(self, orig_host, orig_port):
        print('Connection received from %s, port %s' % (orig_host, orig_port))
        return MySSHTCPConnection(self.conn, encoding='utf-8')

class MySSHClient(SSHClient):
    def handle_auth_complete(self):
        listener = MySSHClientListener(self, '', 8888)

    def handle_disconnect(self, code, reason, lang):
        print('SSH connection error: %s' % reason, file=sys.stderr)

client = MySSHClient('localhost')
asyncore.loop()
