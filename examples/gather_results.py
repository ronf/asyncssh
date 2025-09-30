#!/usr/bin/env python3.7
#
# Copyright (c) 2016-2024 by Ron Frederick <ronf@timeheart.net> and others.
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

import asyncio, asyncssh

async def run_client(host, command: str) -> asyncssh.SSHCompletedProcess:
    async with asyncssh.connect(host) as conn:
        return await conn.run(command)

async def run_multiple_clients() -> None:
    # Put your lists of hosts here
    hosts = 5 * ['localhost']

    tasks = (run_client(host, 'ls abc') for host in hosts)
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result in enumerate(results):
        task = f'Task {i+1} to host {hosts[i]}'

        if isinstance(result, Exception):
            print(f'{task} failed: {result}')
        elif result.exit_status != 0:
            print(f'{task} exited with status {result.exit_status}:')
            print(result.stderr, end='')
        else:
            print(f'{task} succeeded:')
            print(result.stdout, end='')

        print(75*'-')

asyncio.run(run_multiple_clients())
