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

import asyncio, asyncssh, sys

async def run_client():
    async with asyncssh.connect('localhost') as conn:
        reader, writer = await conn.open_connection('www.google.com', 80)

        # By default, TCP connections send and receive bytes
        writer.write(b'HEAD / HTTP/1.0\r\n\r\n')
        writer.write_eof()

        # We use sys.stdout.buffer here because we're writing bytes
        response = await reader.read()
        sys.stdout.buffer.write(response)

try:
    asyncio.get_event_loop().run_until_complete(run_client())
except (OSError, asyncssh.Error) as exc:
    sys.exit('SSH connection failed: ' + str(exc))
