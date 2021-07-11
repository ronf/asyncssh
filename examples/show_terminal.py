#!/usr/bin/env python3.6
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

# To run this program, the file ``ssh_host_key`` must exist with an SSH
# private key in it to use as a server host key. An SSH host certificate
# can optionally be provided in the file ``ssh_host_key-cert.pub``.
#
# The file ``ssh_user_ca`` must exist with a cert-authority entry of
# the certificate authority which can sign valid client certificates.

import asyncio, asyncssh, sys

async def handle_client(process: asyncssh.SSHServerProcess) -> None:
    width, height, pixwidth, pixheight = process.term_size

    process.stdout.write('Terminal type: %s, size: %sx%s' %
                         (process.term_type, width, height))
    if pixwidth and pixheight:
        process.stdout.write(' (%sx%s pixels)' % (pixwidth, pixheight))
    process.stdout.write('\nTry resizing your window!\n')

    while not process.stdin.at_eof():
        try:
            await process.stdin.read()
        except asyncssh.TerminalSizeChanged as exc:
            process.stdout.write('New window size: %sx%s' %
                                 (exc.width, exc.height))
            if exc.pixwidth and exc.pixheight:
                process.stdout.write(' (%sx%s pixels)' %
                                     (exc.pixwidth, exc.pixheight))
            process.stdout.write('\n')

async def start_server() -> None:
    await asyncssh.listen('', 8022, server_host_keys=['ssh_host_key'],
                          authorized_client_keys='ssh_user_ca',
                          process_factory=handle_client)

loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(start_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit('Error starting server: ' + str(exc))

loop.run_forever()
