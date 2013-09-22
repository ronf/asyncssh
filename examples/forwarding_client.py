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
from asyncssh import SSHClient, SSHTCPConnection

class MySSHTCPConnection(SSHTCPConnection):
    def handle_open(self):
        self.send('Connection successful!\r\n')
        self.close()

class MySSHClient(SSHClient):
    def handle_auth_complete(self):
        self.listen('', 8888)

    def handle_listen(self, bind_addr, bind_port):
        print('Listener opened.')

    def handle_listen_error(self, bind_addr, bind_port):
        print('Listener open failed!', file=sys.stderr)
        self.disconnect()

    def handle_forwarded_connection(self, dest_host, dest_port,
                                    orig_host, orig_port):
        print('Connection received from %s, port %s' % (orig_host, orig_port))

        return MySSHTCPConnection(self, encoding='utf-8')

    def handle_disconnect(self, code, reason, lang):
        print('SSH connection error: %s' % reason, file=sys.stderr)

client = MySSHClient('localhost')
asyncore.loop()
