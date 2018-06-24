# Copyright (c) 2018 by Ron Frederick <ronf@timeheart.net>.
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

"""Stub ssh-keysign module for unit tests"""

import asyncio

import asyncssh
from asyncssh.keysign import KEYSIGN_VERSION
from asyncssh.packet import Byte, String, SSHPacket


class SSHKeysignStub:
    """Stub class to replace process running ssh-keysign"""

    @asyncio.coroutine
    def communicate(self, request):
        """Process SSH key signing request"""

        # pylint: disable=no-self-use

        packet = SSHPacket(request)
        request = packet.get_string()
        packet.check_end()

        packet = SSHPacket(request)
        version = packet.get_byte()
        _ = packet.get_uint32()     # sock_fd
        data = packet.get_string()
        packet.check_end()

        if version == 0:
            return b'', b''
        elif version == 1:
            return b'', b'invalid request'
        else:
            skey = asyncssh.load_keypairs('skey')[0]
            sig = skey.sign(data)
            return String(Byte(KEYSIGN_VERSION) + String(sig)), b''


@asyncio.coroutine
def create_subprocess_exec_stub(*args, **kwargs):
    """Return a stub for a subprocess running the ssh-keysign executable"""

    # pylint: disable=unused-argument

    return SSHKeysignStub()
