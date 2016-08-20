#!/usr/bin/env python3.5
#
# Copyright (c) 2016 by Ron Frederick <ronf@timeheart.net>.
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

import asyncio, asyncssh

async def run_client(host, command):
    async with asyncssh.connect(host) as conn:
        return await conn.run(command)

async def run_multiple_clients():
    # Put your lists of hosts here
    hosts = 5 * ['localhost']

    tasks = (run_client(host, 'ls abc') for host in hosts)
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, result in enumerate(results, 1):
        if isinstance(result, Exception):
            print('Task %d failed: %s' % (i, str(result)))
        elif result.exit_status != 0:
            print('Task %d exited with status %s:' % (i, result.exit_status))
            print(result.stderr, end='')
        else:
            print('Task %d succeeded:' % i)
            print(result.stdout, end='')

        print(75*'-')

asyncio.get_event_loop().run_until_complete(run_multiple_clients())
