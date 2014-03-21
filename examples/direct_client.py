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
from asyncssh import SSHClient, SSHTCPConnection

class MySSHTCPConnection(SSHTCPConnection):
    def handle_open(self):
        # By default, TCP connections send/recv bytes, not strings
        self.send(b'HEAD / HTTP/1.0\r\n\r\n')
        self.send_eof()

    def handle_open_error(self, code, reason, lang):
        print('Direct connection failed: %s' % reason, file=sys.stderr)
        self.conn.disconnect()

    def handle_data(self, data, datatype):
        # We use sys.stdout.buffer here because we're writing bytes
        sys.stdout.buffer.write(data)

    def handle_close(self):
        self.conn.disconnect()

class MySSHClient(SSHClient):
    def handle_auth_complete(self):
        connection = MySSHTCPConnection(self)
        connection.connect('www.google.com', 80)

    def handle_disconnect(self, code, reason, lang):
        print('SSH connection error: %s' % reason, file=sys.stderr)

client = MySSHClient('localhost')
asyncore.loop()
