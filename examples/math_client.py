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
from asyncssh import SSHClient, SSHClientSession

class MySSHClientSession(SSHClientSession):
    def next_operation(self):
        if self.operations:
            operation = self.operations.pop(0)
            print('%s = ' % operation, end='')
            self.send(operation + '\n')
        else:
            self.send_eof()

    def handle_open(self):
        self.operations = ['2+2', '1*2*3*4', '2^32']
        self.next_operation()

    def handle_data(self, data, datatype):
        print(data, end='')

        if '\n' in data:
            self.next_operation()

    def handle_close(self):
        self.conn.disconnect()

class MySSHClient(SSHClient):
    def handle_auth_complete(self):
        session = MySSHClientSession(self)
        session.exec('bc')

    def handle_disconnect(self, code, reason, lang):
        print('SSH connection error: %s' % reason, file=sys.stderr)

client = MySSHClient('localhost')
asyncore.loop()
