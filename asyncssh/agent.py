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

"""SSH agent client"""

import asyncio
import os

from .misc import ChannelOpenError
from .packet import Byte, String, UInt32, PacketDecodeError, SSHPacket
from .public_key import SSHKeyPair


# pylint: disable=bad-whitespace

# Generic agent replies
SSH_AGENT_FAILURE              = 5

# Protocol 2 key operations
SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENT_IDENTITIES_ANSWER   = 12
SSH2_AGENTC_SIGN_REQUEST       = 13
SSH2_AGENT_SIGN_RESPONSE       = 14

# pylint: enable=bad-whitespace


class _SSHAgentKeyPair(SSHKeyPair):
    """Surrogate for a key managed by the SSH agent"""

    def __init__(self, agent, public_data, comment):
        self._agent = agent

        packet = SSHPacket(public_data)
        self.algorithm = packet.get_string()

        self.public_data = public_data
        self.comment = comment

    @asyncio.coroutine
    def sign(self, data):
        """Sign a block of data with this private key"""

        return (yield from self._agent.sign(self.public_data, data))


class SSHAgentClient:
    """SSH agent client"""

    def __init__(self, loop, agent_path):
        self._loop = loop
        self._agent_path = agent_path
        self._reader = None
        self._writer = None
        self._lock = asyncio.Lock()

    def _cleanup(self):
        """Clean up this SSH agent client"""

        if self._writer:
            self._writer.close()
            self._reader = None
            self._writer = None

    @asyncio.coroutine
    def connect(self):
        """Connect to the SSH agent"""

        if isinstance(self._agent_path, str):
            # pylint doesn't think open_unix_connection exists
            # pylint: disable=no-member
            self._reader, self._writer = \
                yield from asyncio.open_unix_connection(self._agent_path,
                                                        loop=self._loop)
        else:
            self._reader, self._writer = \
                yield from self._agent_path.open_agent_connection()

    @asyncio.coroutine
    def _make_request(self, msgtype, *args):
        """Send an SSH agent request"""

        with (yield from self._lock):
            try:
                if not self._writer:
                    yield from self.connect()

                payload = Byte(msgtype) + b''.join(args)
                self._writer.write(UInt32(len(payload)) + payload)

                resplen = yield from self._reader.readexactly(4)
                resplen = int.from_bytes(resplen, 'big')

                resp = yield from self._reader.readexactly(resplen)
                resp = SSHPacket(resp)

                resptype = resp.get_byte()

                return resptype, resp
            except (OSError, EOFError, PacketDecodeError) as exc:
                self._cleanup()
                raise ValueError(str(exc)) from None

    @asyncio.coroutine
    def get_keys(self):
        """Request the available client keys

           This method is a coroutine which returns a list of client keys
           available in the ssh-agent.

           :returns: A list of :class:`SSHKeyPair` objects

        """

        resptype, resp = \
            yield from self._make_request(SSH2_AGENTC_REQUEST_IDENTITIES)

        if resptype == SSH2_AGENT_IDENTITIES_ANSWER:
            result = []

            num_keys = resp.get_uint32()
            for _ in range(num_keys):
                key_blob = resp.get_string()
                comment = resp.get_string()

                result.append(_SSHAgentKeyPair(self, key_blob, comment))

            resp.check_end()
            return result
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    @asyncio.coroutine
    def sign(self, key_blob, data):
        """Sign a block of data with this private key"""

        resptype, resp = \
            yield from self._make_request(SSH2_AGENTC_SIGN_REQUEST,
                                          String(key_blob), String(data),
                                          UInt32(0))

        if resptype == SSH2_AGENT_SIGN_RESPONSE:
            sig = resp.get_string()
            resp.check_end()
            return sig
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unknown key passed to SSH agent')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    def close(self):
        """Close the SSH agent connection

           This method closes the connection to the ssh-agent. Any
           attempts to use this :class:``SSHAgentClient`` or the key
           pairs it previously returned will result in an error.

        """

        self._cleanup()


@asyncio.coroutine
def connect_agent(agent_path=None, *, loop=None):
    """Make a connection to the SSH agent

       This function attempts to connect to an ssh-agent process
       listening on a UNIX domain socket at ``agent_path``. If not
       provided, it will attempt to get the path from the ``SSH_AUTH_SOCK``
       environment variable.

       If the connection is successful, an ``SSHAgentClient`` object
       is returned that has methods on it you can use to query the
       ssh-agent. If no path is specified and the environment variable
       is not set or the connection to the agent fails, this function
       returns ``None``.

       :param agent_path: (optional)
           The path to use to contact the ssh-agent process, or the
           :class:`SSHServerConnection` to forward the agent request
           over.
       :param loop: (optional)
           The event loop to use when creating the connection. If not
           specified, the default event loop is used.
       :type agent_path: str or :class:`SSHServerConnection`

       :returns: An :class:`SSHAgentClient` or ``None``

    """

    if not loop:
        loop = asyncio.get_event_loop()

    if not agent_path:
        agent_path = os.environ.get('SSH_AUTH_SOCK', None)

        if not agent_path:
            return None

    agent = SSHAgentClient(loop, agent_path)

    try:
        yield from agent.connect()
        return agent
    except (OSError, ChannelOpenError):
        return None
