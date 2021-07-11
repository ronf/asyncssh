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

# To run this program, the file client_host_key must exist on the client,
# containing an SSH private key for the client to use to authenticate
# itself as a host to the server. An SSH certificate can optionally be
# provided in the file client_host_key-cert.pub.
#
# The file trusted_server_keys must also exist on the client, containing a
# list of trusted server keys or a cert-authority entry with a public key
# trusted to sign server keys if certificates are used. This file should
# be in "authorized_keys" format.

import asyncio, asyncssh, sys
from asyncio.subprocess import PIPE

async def handle_request(process: asyncssh.SSHServerProcess) -> None:
    """Run a command on the client, piping I/O over an SSH session"""

    assert process.command is not None

    local_proc = await asyncio.create_subprocess_shell(
        process.command, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    await process.redirect(stdin=local_proc.stdin, stdout=local_proc.stdout,
                           stderr=local_proc.stderr)

    process.exit(await local_proc.wait())
    await process.wait_closed()

async def run_reverse_client() -> None:
    """Make an outbound connection and then become an SSH server on it"""

    conn = await asyncssh.connect_reverse(
        'localhost', 8022, server_host_keys=['client_host_key'],
        authorized_client_keys='trusted_server_keys',
        process_factory=handle_request, encoding=None)

    await conn.wait_closed()

try:
    asyncio.get_event_loop().run_until_complete(run_reverse_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('Reverse SSH connection failed: ' + str(exc))
