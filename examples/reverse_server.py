#!/usr/bin/env python3.8
#
# Copyright (c) 2013-2021 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

# To run this program, the file server_key must exist on the server,
# containing an SSH private key for the server to use to authenticate itself
# to the client. An SSH certificate can optionally be provided in the file
# server_key-cert.pub.
#
# The file trusted_client_host_keys must also exist on the server, containing
# a list of trusted client host keys or a @cert-authority entry with a public
# key trusted to sign client host keys if certificates are used. This file
# should be in "known_hosts" format.

import asyncio, asyncssh, sys

async def run_commands(conn: asyncssh.SSHClientConnection) -> None:
    """Run a series of commands on the client which connected to us"""

    commands = ('ls', 'sleep 30 && date', 'sleep 5 && cat /proc/cpuinfo')

    async with conn:
        tasks = [conn.run(cmd) for cmd in commands]

        for task in asyncio.as_completed(tasks):
            result = await task
            print('Command:', result.command)
            print('Return code:', result.returncode)
            print('Stdout:')
            print(result.stdout, end='')
            print('Stderr:')
            print(result.stderr, end='')
            print(75*'-')

async def start_reverse_server() -> None:
    """Accept inbound connections and then become an SSH client on them"""

    await asyncssh.listen_reverse(port=8022, client_keys=['server_key'],
                                  known_hosts='trusted_client_host_keys',
                                  acceptor=run_commands)

loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(start_reverse_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit('Error starting server: ' + str(exc))

loop.run_forever()
