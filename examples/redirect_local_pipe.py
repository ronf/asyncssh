#!/usr/bin/env python3.5
#
# Copyright (c) 2013-2016 by Ron Frederick <ronf@timeheart.net>.
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

import asyncio, asyncssh, subprocess, sys

async def run_client():
    async with asyncssh.connect('localhost') as conn:
        local_proc = subprocess.Popen(r'echo "1\n2\n3"', shell=True,
                                      stdout=subprocess.PIPE)
        remote_result = await conn.run('tail -r', stdin=local_proc.stdout)
        print(remote_result.stdout, end='')

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))
