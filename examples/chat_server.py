#!/usr/bin/env python3.5
#
# Copyright (c) 2016-2017 by Ron Frederick <ronf@timeheart.net>.
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

# To run this program, the file ``ssh_host_key`` must exist with an SSH
# private key in it to use as a server host key. An SSH host certificate
# can optionally be provided in the file ``ssh_host_key-cert.pub``.
#
# The file ``ssh_user_ca`` must exist with a cert-authority entry of
# the certificate authority which can sign valid client certificates.

import asyncio, asyncssh, sys

class ChatClient:
    _clients = []

    def __init__(self, process):
        self._process = process

    @classmethod
    async def handle_client(cls, process):
        await cls(process).run()

    def write(self, msg):
        self._process.stdout.write(msg)

    def broadcast(self, msg):
        for client in self._clients:
            if client != self:
                client.write(msg)

    async def run(self):
        self.write('Welcome to chat!\n\n')

        self.write('Enter your name: ')
        name = (await self._process.stdin.readline()).rstrip('\n')

        self.write('\n%d other users are connected.\n\n' % len(self._clients))

        self._clients.append(self)
        self.broadcast('*** %s has entered chat ***\n' % name)

        try:
            async for line in self._process.stdin:
                self.broadcast('%s: %s' % (name, line))
        except asyncssh.BreakReceived:
            pass

        self.broadcast('*** %s has left chat ***\n' % name)
        self._clients.remove(self)

async def start_server():
    await asyncssh.listen('', 8022, server_host_keys=['ssh_host_key'],
                          authorized_client_keys='ssh_user_ca',
                          process_factory=ChatClient.handle_client)

loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(start_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit('Error starting server: ' + str(exc))

loop.run_forever()
