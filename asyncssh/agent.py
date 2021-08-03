# Copyright (c) 2016-2021 by Ron Frederick <ronf@timeheart.net> and others.
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

"""SSH agent client"""

import asyncio
import errno
import os
import sys

from .misc import async_context_manager, maybe_wait_closed
from .packet import Byte, String, UInt32, PacketDecodeError, SSHPacket
from .public_key import SSHKeyPair, load_default_keypairs, load_keypairs


try:
    if sys.platform == 'win32': # pragma: no cover
        from .agent_win32 import open_agent
    else:
        from .agent_unix import open_agent
except ImportError as _exc: # pragma: no cover
    async def open_agent(_agent_path, reason=str(_exc)):
        """Dummy function if we're unable to import agent support"""

        raise OSError(errno.ENOENT, 'Agent support unavailable: %s' % reason)


# Client request message numbers
SSH_AGENTC_REQUEST_IDENTITIES            = 11
SSH_AGENTC_SIGN_REQUEST                  = 13
SSH_AGENTC_ADD_IDENTITY                  = 17
SSH_AGENTC_REMOVE_IDENTITY               = 18
SSH_AGENTC_REMOVE_ALL_IDENTITIES         = 19
SSH_AGENTC_ADD_SMARTCARD_KEY             = 20
SSH_AGENTC_REMOVE_SMARTCARD_KEY          = 21
SSH_AGENTC_LOCK                          = 22
SSH_AGENTC_UNLOCK                        = 23
SSH_AGENTC_ADD_ID_CONSTRAINED            = 25
SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26
SSH_AGENTC_EXTENSION                     = 27

# Agent response message numbers
SSH_AGENT_FAILURE                        = 5
SSH_AGENT_SUCCESS                        = 6
SSH_AGENT_IDENTITIES_ANSWER              = 12
SSH_AGENT_SIGN_RESPONSE                  = 14
SSH_AGENT_EXTENSION_FAILURE              = 28

# SSH agent constraint numbers
SSH_AGENT_CONSTRAIN_LIFETIME             = 1
SSH_AGENT_CONSTRAIN_CONFIRM              = 2
SSH_AGENT_CONSTRAIN_EXTENSION            = 255

# SSH agent signature flags
SSH_AGENT_RSA_SHA2_256                   = 2
SSH_AGENT_RSA_SHA2_512                   = 4


class SSHAgentKeyPair(SSHKeyPair):
    """Surrogate for a key managed by the SSH agent"""

    _key_type = 'agent'

    def __init__(self, agent, algorithm, public_data, comment):
        is_cert = algorithm.endswith(b'-cert-v01@openssh.com')

        if is_cert:
            if algorithm.startswith(b'sk-'):
                sig_algorithm = algorithm[:-21] + b'@openssh.com'
            else:
                sig_algorithm = algorithm[:-21]
        else:
            sig_algorithm = algorithm

        # Neither Pageant nor the Win10 OpenSSH agent seems to support the
        # ssh-agent protocol flags used to request RSA SHA2 signatures yet
        if sig_algorithm == b'ssh-rsa' and sys.platform != 'win32':
            sig_algorithms = (b'rsa-sha2-256', b'rsa-sha2-512', b'ssh-rsa')
        else:
            sig_algorithms = (sig_algorithm,)

        if is_cert:
            host_key_algorithms = (algorithm,)
        else:
            host_key_algorithms = sig_algorithms

        super().__init__(algorithm, sig_algorithm, sig_algorithms,
                         host_key_algorithms, public_data, comment)

        self._agent = agent
        self._is_cert = is_cert
        self._flags = 0

    def set_certificate(self, cert):
        """Set certificate to use with this key"""

        super().set_certificate(cert)

        self._is_cert = True

    def set_sig_algorithm(self, sig_algorithm):
        """Set the signature algorithm to use when signing data"""

        super().set_sig_algorithm(sig_algorithm)

        if sig_algorithm == b'rsa-sha2-256':
            self._flags |= SSH_AGENT_RSA_SHA2_256
        elif sig_algorithm == b'rsa-sha2-512':
            self._flags |= SSH_AGENT_RSA_SHA2_512

    async def sign(self, data):
        """Sign a block of data with this private key"""

        return await self._agent.sign(self.key_public_data, data, self._flags)

    async def remove(self):
        """Remove this key pair from the agent"""

        await self._agent.remove_keys([self])


class SSHAgentClient:
    """SSH agent client"""

    def __init__(self, agent_path):
        self._agent_path = agent_path
        self._reader = None
        self._writer = None
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        """Allow SSHAgentClient to be used as an async context manager"""

        return self

    async def __aexit__(self, *exc_info):
        """Wait for connection close when used as an async context manager"""

        await self._cleanup()

    async def _cleanup(self):
        """Clean up this SSH agent client"""

        self.close()
        await self.wait_closed()

    @staticmethod
    def encode_constraints(lifetime, confirm):
        """Encode key constraints"""

        result = b''

        if lifetime:
            result += Byte(SSH_AGENT_CONSTRAIN_LIFETIME) + UInt32(lifetime)

        if confirm:
            result += Byte(SSH_AGENT_CONSTRAIN_CONFIRM)

        return result

    async def connect(self):
        """Connect to the SSH agent"""

        if hasattr(self._agent_path, 'open_agent_connection'):
            self._reader, self._writer = \
                await self._agent_path.open_agent_connection()
        else:
            self._reader, self._writer = await open_agent(self._agent_path)

    async def _make_request(self, msgtype, *args):
        """Send an SSH agent request"""

        async with self._lock:
            try:
                if not self._writer:
                    await self.connect()

                payload = Byte(msgtype) + b''.join(args)
                self._writer.write(UInt32(len(payload)) + payload)

                resplen = await self._reader.readexactly(4)
                resplen = int.from_bytes(resplen, 'big')

                resp = await self._reader.readexactly(resplen)
                resp = SSHPacket(resp)

                resptype = resp.get_byte()

                return resptype, resp
            except (OSError, EOFError, PacketDecodeError) as exc:
                await self._cleanup()
                raise ValueError(str(exc)) from None

    async def get_keys(self, identities=()):
        """Request the available client keys

           This method is a coroutine which returns a list of client keys
           available in the ssh-agent.

           :param identities: (optional)
               A list of allowed byte string identities to return. If empty,
               all identities on the SSH agent will be returned.

           :returns: A list of :class:`SSHKeyPair` objects

        """

        resptype, resp = \
            await self._make_request(SSH_AGENTC_REQUEST_IDENTITIES)

        if resptype == SSH_AGENT_IDENTITIES_ANSWER:
            result = []

            num_keys = resp.get_uint32()
            for _ in range(num_keys):
                key_blob = resp.get_string()
                comment = resp.get_string()

                if identities and key_blob not in identities:
                    continue

                packet = SSHPacket(key_blob)
                algorithm = packet.get_string()

                result.append(SSHAgentKeyPair(self, algorithm,
                                              key_blob, comment))

            resp.check_end()
            return result
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    async def sign(self, key_blob, data, flags=0):
        """Sign a block of data with the requested key"""

        resptype, resp = await self._make_request(SSH_AGENTC_SIGN_REQUEST,
                                                  String(key_blob),
                                                  String(data), UInt32(flags))

        if resptype == SSH_AGENT_SIGN_RESPONSE:
            sig = resp.get_string()
            resp.check_end()
            return sig
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unable to sign with requested key')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    async def add_keys(self, keylist=(), passphrase=None,
                       lifetime=None, confirm=False):
        """Add keys to the agent

           This method adds a list of local private keys and optional
           matching certificates to the agent.

           :param keylist: (optional)
               The list of keys to add. If not specified, an attempt will
               be made to load keys from the files
               :file:`.ssh/id_ed25519_sk`, :file:`.ssh/id_ecdsa_sk`,
               :file:`.ssh/id_ed448`, :file:`.ssh/id_ed25519`,
               :file:`.ssh/id_ecdsa`, :file:`.ssh/id_rsa` and
               :file:`.ssh/id_dsa` in the user's home directory with
               optional matching certificates loaded from the files
               :file:`.ssh/id_ed25519_sk-cert.pub`,
               :file:`.ssh/id_ecdsa_sk-cert.pub`,
               :file:`.ssh/id_ed448-cert.pub`,
               :file:`.ssh/id_ed25519-cert.pub`,
               :file:`.ssh/id_ecdsa-cert.pub`, :file:`.ssh/id_rsa-cert.pub`,
               and :file:`.ssh/id_dsa-cert.pub`. Failures when adding keys
               are ignored in this case, as the agent may not recognize
               some of these key types.
           :param passphrase: (optional)
               The passphrase to use to decrypt the keys.
           :param lifetime: (optional)
               The time in seconds after which the keys should be
               automatically deleted, or `None` to store these keys
               indefinitely (the default).
           :param confirm: (optional)
               Whether or not to require confirmation for each private
               key operation which uses these keys, defaulting to `False`.
           :type keylist: *see* :ref:`SpecifyingPrivateKeys`
           :type passphrase: `str`
           :type lifetime: `int` or `None`
           :type confirm: `bool`

           :raises: :exc:`ValueError` if the keys cannot be added

        """

        if keylist:
            keypairs = load_keypairs(keylist, passphrase)
            ignore_failures = False
        else:
            keypairs = load_default_keypairs(passphrase)
            ignore_failures = True

        base_constraints = self.encode_constraints(lifetime, confirm)

        provider = os.environ.get('SSH_SK_PROVIDER') or 'internal'

        sk_constraints = Byte(SSH_AGENT_CONSTRAIN_EXTENSION) + \
                         String('sk-provider@openssh.com') + \
                         String(provider)

        for keypair in keypairs:
            constraints = base_constraints

            if keypair.algorithm.startswith(b'sk-'):
                constraints += sk_constraints

            msgtype = SSH_AGENTC_ADD_ID_CONSTRAINED if constraints else \
                          SSH_AGENTC_ADD_IDENTITY

            comment = keypair.get_comment_bytes()

            resptype, resp = \
                await self._make_request(msgtype,
                                         keypair.get_agent_private_key(),
                                         String(comment or b''), constraints)

            if resptype == SSH_AGENT_SUCCESS:
                resp.check_end()
            elif resptype == SSH_AGENT_FAILURE:
                if not ignore_failures:
                    raise ValueError('Unable to add key')
            else:
                raise ValueError('Unknown SSH agent response: %d' % resptype)

    async def add_smartcard_keys(self, provider, pin=None,
                                 lifetime=None, confirm=False):
        """Store keys associated with a smart card in the agent

           :param provider:
               The name of the smart card provider
           :param pin: (optional)
               The PIN to use to unlock the smart card
           :param lifetime: (optional)
               The time in seconds after which the keys should be
               automatically deleted, or `None` to store these keys
               indefinitely (the default).
           :param confirm: (optional)
               Whether or not to require confirmation for each private
               key operation which uses these keys, defaulting to `False`.
           :type provider: `str`
           :type pin: `str` or `None`
           :type lifetime: `int` or `None`
           :type confirm: `bool`

           :raises: :exc:`ValueError` if the keys cannot be added

        """

        constraints = self.encode_constraints(lifetime, confirm)
        msgtype = SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED \
                      if constraints else SSH_AGENTC_ADD_SMARTCARD_KEY

        resptype, resp = await self._make_request(msgtype, String(provider),
                                                  String(pin or ''),
                                                  constraints)

        if resptype == SSH_AGENT_SUCCESS:
            resp.check_end()
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unable to add keys')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    async def remove_keys(self, keylist):
        """Remove a key stored in the agent

           :param keylist:
               The list of keys to remove.
           :type keylist: `list` of :class:`SSHKeyPair`

           :raises: :exc:`ValueError` if any keys are not found

        """

        for keypair in keylist:
            resptype, resp = \
                await self._make_request(SSH_AGENTC_REMOVE_IDENTITY,
                                         String(keypair.public_data))

            if resptype == SSH_AGENT_SUCCESS:
                resp.check_end()
            elif resptype == SSH_AGENT_FAILURE:
                raise ValueError('Key not found')
            else:
                raise ValueError('Unknown SSH agent response: %d' % resptype)

    async def remove_smartcard_keys(self, provider, pin=None):
        """Remove keys associated with a smart card stored in the agent

           :param provider:
               The name of the smart card provider
           :param pin: (optional)
               The PIN to use to unlock the smart card
           :type provider: `str`
           :type pin: `str` or `None`

           :raises: :exc:`ValueError` if the keys are not found

        """

        resptype, resp = \
            await self._make_request(SSH_AGENTC_REMOVE_SMARTCARD_KEY,
                                     String(provider), String(pin or ''))

        if resptype == SSH_AGENT_SUCCESS:
            resp.check_end()
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Keys not found')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    async def remove_all(self):
        """Remove all keys stored in the agent

           :raises: :exc:`ValueError` if the keys can't be removed

        """

        resptype, resp = \
            await self._make_request(SSH_AGENTC_REMOVE_ALL_IDENTITIES)

        if resptype == SSH_AGENT_SUCCESS:
            resp.check_end()
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unable to remove all keys')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    async def lock(self, passphrase):
        """Lock the agent using the specified passphrase

           .. note:: The lock and unlock actions don't appear to be
                     supported on the Windows 10 OpenSSH agent.

           :param passphrase:
               The passphrase required to later unlock the agent
           :type passphrase: `str`

           :raises: :exc:`ValueError` if the agent can't be locked

        """

        resptype, resp = await self._make_request(SSH_AGENTC_LOCK,
                                                  String(passphrase))

        if resptype == SSH_AGENT_SUCCESS:
            resp.check_end()
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unable to lock SSH agent')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    async def unlock(self, passphrase):
        """Unlock the agent using the specified passphrase

           .. note:: The lock and unlock actions don't appear to be
                     supported on the Windows 10 OpenSSH agent.

           :param passphrase:
               The passphrase to use to unlock the agent
           :type passphrase: `str`

           :raises: :exc:`ValueError` if the agent can't be unlocked

        """

        resptype, resp = await self._make_request(SSH_AGENTC_UNLOCK,
                                                  String(passphrase))

        if resptype == SSH_AGENT_SUCCESS:
            resp.check_end()
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unable to unlock SSH agent')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    async def query_extensions(self):
        """Return a list of extensions supported by the agent

           :returns: A list of strings of supported extension names

        """

        resptype, resp = await self._make_request(SSH_AGENTC_EXTENSION,
                                                  String('query'))

        if resptype == SSH_AGENT_SUCCESS:
            result = []

            while resp:
                exttype = resp.get_string()

                try:
                    exttype = exttype.decode('utf-8')
                except UnicodeDecodeError:
                    raise ValueError('Invalid extension type name') from None

                result.append(exttype)

            return result
        elif resptype == SSH_AGENT_FAILURE:
            return []
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    def close(self):
        """Close the SSH agent connection

           This method closes the connection to the ssh-agent. Any
           attempts to use this :class:`SSHAgentClient` or the key
           pairs it previously returned will result in an error.

        """

        if self._writer:
            self._writer.close()

    async def wait_closed(self):
        """Wait for this agent connection to close

           This method is a coroutine which can be called to block until
           the connection to the agent has finished closing.

        """

        if self._writer:
            await maybe_wait_closed(self._writer)

            self._reader = None
            self._writer = None


class SSHAgentListener:
    """Listener used to forward agent connections"""

    def __init__(self, tempdir, path, unix_listener):
        self._tempdir = tempdir
        self._path = path
        self._unix_listener = unix_listener

    def get_path(self):
        """Return the path being listened on"""

        return self._path

    def close(self):
        """Close the agent listener"""

        self._unix_listener.close()
        self._tempdir.cleanup()


@async_context_manager
async def connect_agent(agent_path=None):
    """Make a connection to the SSH agent

       This function attempts to connect to an ssh-agent process
       listening on a UNIX domain socket at `agent_path`. If not
       provided, it will attempt to get the path from the `SSH_AUTH_SOCK`
       environment variable.

       If the connection is successful, an :class:`SSHAgentClient` object
       is returned that has methods on it you can use to query the
       ssh-agent. If no path is specified and the environment variable
       is not set or the connection to the agent fails, an error is
       raised.

       :param agent_path: (optional)
           The path to use to contact the ssh-agent process, or the
           :class:`SSHServerConnection` to forward the agent request
           over.
       :type agent_path: `str` or :class:`SSHServerConnection`

       :returns: An :class:`SSHAgentClient`

       :raises: :exc:`OSError` or :exc:`ChannelOpenError` if the
                connection to the agent can't be opened

    """

    if not agent_path:
        agent_path = os.environ.get('SSH_AUTH_SOCK', None)

    agent = SSHAgentClient(agent_path)
    await agent.connect()

    return agent
