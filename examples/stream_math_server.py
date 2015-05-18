#!/usr/bin/env python3.4
#
# Copyright (c) 2013-2015 by Ron Frederick <ronf@timeheart.net>.
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

@asyncio.coroutine
def handle_connection(stdin, stdout, stderr):
    total = 0

    try:
        while not stdin.at_eof():
            try:
                line = yield from stdin.readline()
            except (asyncssh.BreakReceived, asyncssh.SignalReceived):
                # Exit if the client sends a break or signal
                break
            except asyncssh.TerminalSizeChanged:
                # Ignore terminal size changes
                continue

            line = line.rstrip('\n')
            if line:
                try:
                    total += int(line)
                except ValueError:
                    stderr.write('Invalid number: %s\r\n' % line)

        stdout.write('Total = %s\r\n' % total)
        stdout.channel.exit(0)
    except BrokenPipeError:
        # The channel is already closed here, so we can't send an exit status
        stdout.close()

@asyncio.coroutine
def start_server():
    yield from asyncssh.listen('', 8022, server_host_keys=['ssh_host_key'],
                               authorized_client_keys='ssh_user_ca',
                               session_factory=handle_connection)

loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(start_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit('Error starting server: ' + str(exc))

loop.run_forever()
