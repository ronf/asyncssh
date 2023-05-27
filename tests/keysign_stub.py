# Copyright (c) 2018-2019 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Stub ssh-keysign module for unit tests"""

import asyncssh
from asyncssh.keysign import KEYSIGN_VERSION
from asyncssh.packet import Byte, String, SSHPacket


class SSHKeysignStub:
    """Stub class to replace process running ssh-keysign"""

    async def communicate(self, request):
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
            skey = asyncssh.load_keypairs('skey_ecdsa')[0]
            sig = skey.sign(data)
            return String(Byte(KEYSIGN_VERSION) + String(sig)), b''


async def create_subprocess_exec_stub(*_args, **_kwargs):
    """Return a stub for a subprocess running the ssh-keysign executable"""

    return SSHKeysignStub()
