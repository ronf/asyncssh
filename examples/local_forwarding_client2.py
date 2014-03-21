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
from asyncssh import SSHClient, SSHClientLocalPortForwarder

class MyPortForwarder(SSHClientLocalPortForwarder):
    def handle_open(self):
        print('Listening on port %s...' % self.listen_port)

    def handle_open_error(self, exc):
        print('Local listen failed: %s' % exc.args[1], file=sys.stderr)
        self.conn.disconnect()

    def accept_connection(self, orig_host, orig_port):
        if orig_host not in ('127.0.0.1', '::1'):
            print('Accepting connection from %s...' % orig_host)
            return True
        else:
            print('Rejecting connection from %s...' % orig_host)
            return False

class MySSHClient(SSHClient):
    def handle_auth_complete(self):
        forwarder = MyPortForwarder(self, '', 0, 'www.google.com', 80)

    def handle_disconnect(self, code, reason, lang):
        print('SSH connection error: %s' % reason, file=sys.stderr)

client = MySSHClient('localhost')
asyncore.loop()
