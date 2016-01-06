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
        """Return a signature of the specified data using this key"""

        return (yield from self._agent.sign(self.public_data, data))


class SSHAgentClient:
    """SSH agent client"""

    def __init__(self, loop):
        self._loop = loop
        self._transport = None
        self._inpbuf = b''
        self._msglen = 0
        self._recv_handler = self._recv_msghdr
        self._waiters = []
        self._exc = None

    def _cleanup(self, exc):
        """Clean up this SSH agent client"""

        if not exc:
            exc = BrokenPipeError('Agent connection closed')

        self._exc = exc

        if self._waiters:
            for waiter in self._waiters:
                if waiter and not waiter.done():
                    waiter.set_exception(exc)

            self._waiters = []

        if self._transport:
            self._transport.close()
            self._transport = None

    def _recv_msghdr(self):
        """Receive and parse an SSH agent message header"""

        if len(self._inpbuf) < 4:
            return False

        self._msglen = int.from_bytes(self._inpbuf[:4], 'big')
        self._inpbuf = self._inpbuf[4:]

        self._recv_handler = self._recv_msg
        return True

    def _recv_msg(self):
        """Receive the rest of an SSH agent message and process it"""

        if len(self._inpbuf) < self._msglen:
            return False

        msg = SSHPacket(self._inpbuf[:self._msglen])
        self._inpbuf = self._inpbuf[self._msglen:]

        if self._waiters:
            waiter = self._waiters.pop(0)

            try:
                msgtype = msg.get_byte()
            except PacketDecodeError as exc:
                self._cleanup(exc)
            else:
                waiter.set_result((msgtype, msg))
        else:
            self._cleanup(ValueError('Unexpected agent response'))

        self._recv_handler = self._recv_msghdr
        return True

    def connection_made(self, transport):
        """Handle a newly opened SSH agent connection"""

        self._transport = transport

    def connection_lost(self, exc):
        """Handle an SSH agent connection close"""

        self._cleanup(exc)

    def data_received(self, data):
        """Handle incoming data"""

        if data:
            self._inpbuf += data

            while self._inpbuf and self._recv_handler():
                pass

    def eof_received(self):
        """Handle an incoming end of file"""

        self.connection_lost(None)

    @asyncio.coroutine
    def _make_request(self, msgtype, *args):
        """Send an SSH agent request"""

        if self._exc:
            raise self._exc    # pylint: disable=raising-bad-type

        waiter = asyncio.Future(loop=self._loop)
        self._waiters.append(waiter)

        payload = Byte(msgtype) + b''.join(args)
        self._transport.write(UInt32(len(payload)) + payload)

        return (yield from waiter)

    @asyncio.coroutine
    def get_keys(self):
        """Request the available client keys

           This method returna a list of client keys available in the
           ssh-agent.

           :returns: A list of :class:`SSHKeyPair` objects

        """

        resp_type, resp = \
            yield from self._make_request(SSH2_AGENTC_REQUEST_IDENTITIES)

        if resp_type == SSH2_AGENT_IDENTITIES_ANSWER:
            try:
                result = []

                num_keys = resp.get_uint32()
                for _ in range(num_keys):
                    key_blob = resp.get_string()
                    comment = resp.get_string()

                    result.append(_SSHAgentKeyPair(self, key_blob, comment))

                resp.check_end()
                return result
            except PacketDecodeError as exc:
                raise ValueError(str(exc)) from None
        else:
            raise ValueError('Unknown SSH agent response: %d' % resp_type)

    @asyncio.coroutine
    def sign(self, key_blob, data):
        """Sign a block of data with this private key"""

        resp_type, resp = \
            yield from self._make_request(SSH2_AGENTC_SIGN_REQUEST,
                                          String(key_blob), String(data),
                                          UInt32(0))

        if resp_type == SSH2_AGENT_SIGN_RESPONSE:
            try:
                sig = resp.get_string()
                resp.check_end()
                return sig
            except PacketDecodeError as exc:
                raise ValueError(str(exc)) from None
        elif resp_type == SSH_AGENT_FAILURE:
            raise ValueError('Unknown key passed to SSH agent')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resp_type)

    def close(self):
        """Close the SSH agent connection

           This method closes the connection to the ssh-agent. Any
           attempts to use this :class:``SSHAgentClient`` or the key
           pairs it previously returned will result in an error.

        """

        self._cleanup(None)


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

       :param string agent_path: (optional)
           The path to use to contact the ssh-agent process.
       :param loop: (optional)
           The event loop to use when creating the connection. If not
           specified, the default event loop is used.

       :returns: An :class:`SSHAgentClient` or ``None``

    """

    if not loop:
        loop = asyncio.get_event_loop()

    if not agent_path:
        agent_path = os.environ.get('SSH_AUTH_SOCK', None)

        if not agent_path:
            return None

    def agent_factory():
        """Return an SSH agent client"""

        return SSHAgentClient(loop)

    try:
        _, agent = yield from loop.create_unix_connection(agent_factory,
                                                          agent_path)
    except OSError:
        agent = None

    return agent
