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
import errno
import os
import sys
import tempfile

import asyncssh

from .logging import logger


try:
    if sys.platform == 'win32': # pragma: no cover
        from .agent_win32 import open_agent
    else:
        from .agent_unix import open_agent
except ImportError as exc: # pragma: no cover
    def open_agent(loop, agent_path, reason=str(exc)):
        """Dummy function if we're unable to import agent support"""

        # pylint: disable=unused-argument

        raise OSError(errno.ENOENT, 'Agent support unavailable: %s' % reason)

from .listener import create_unix_forward_listener
from .misc import ChannelOpenError, load_default_keypairs
from .packet import Byte, String, UInt32, PacketDecodeError, SSHPacket
from .public_key import SSHKeyPair


# pylint: disable=bad-whitespace

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
SSH_AGENT_CONSTRAIN_EXTENSION            = 3

# SSH agent signature flags
SSH_AGENT_RSA_SHA2_256                   = 2
SSH_AGENT_RSA_SHA2_512                   = 4

# pylint: enable=bad-whitespace


class _X11AgentListener:
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


class SSHAgentKeyPair(SSHKeyPair):
    """Surrogate for a key managed by the SSH agent"""

    _key_type = 'agent'

    def __init__(self, agent, algorithm, public_data, comment):
        super().__init__(algorithm, comment)

        self._agent = agent
        self.public_data = public_data

        self._cert = algorithm.endswith(b'-cert-v01@openssh.com')
        self._flags = 0

        if self._cert:
            self.sig_algorithm = algorithm[:-21]
        else:
            self.sig_algorithm = algorithm

        if self.sig_algorithm == b'ssh-rsa':
            self.sig_algorithms = (b'rsa-sha2-256', b'rsa-sha2-512',
                                   b'ssh-rsa')
        else:
            self.sig_algorithms = (self.sig_algorithm,)

        if self._cert:
            self.host_key_algorithms = (algorithm,)
        else:
            self.host_key_algorithms = self.sig_algorithms

    def set_sig_algorithm(self, sig_algorithm):
        """Set the signature algorithm to use when signing data"""

        self.sig_algorithm = sig_algorithm

        if not self._cert:
            self.algorithm = sig_algorithm

        if sig_algorithm == b'rsa-sha2-256':
            self._flags |= SSH_AGENT_RSA_SHA2_256
        elif sig_algorithm == b'rsa-sha2-512':
            self._flags |= SSH_AGENT_RSA_SHA2_512

    @asyncio.coroutine
    def sign(self, data):
        """Sign a block of data with this private key"""

        return (yield from self._agent.sign(self.public_data,
                                            data, self._flags))

    @asyncio.coroutine
    def remove(self):
        """Remove this key pair from the agent"""

        yield from self._agent.remove_keys([self])


class SSHAgentClient:
    """SSH agent client"""

    def __init__(self, loop, agent_path):
        self._loop = loop
        self._agent_path = agent_path
        self._reader = None
        self._writer = None
        self._lock = asyncio.Lock(loop=loop)

    def _cleanup(self):
        """Clean up this SSH agent client"""

        if self._writer:
            self._writer.close()
            self._reader = None
            self._writer = None

    @staticmethod
    def encode_constraints(lifetime, confirm):
        """Encode key constraints"""

        result = b''

        if lifetime:
            result += Byte(SSH_AGENT_CONSTRAIN_LIFETIME) + UInt32(lifetime)

        if confirm:
            result += Byte(SSH_AGENT_CONSTRAIN_CONFIRM)

        return result

    @asyncio.coroutine
    def connect(self):
        """Connect to the SSH agent"""

        if isinstance(self._agent_path, asyncssh.SSHServerConnection):
            self._reader, self._writer = \
                yield from self._agent_path.open_agent_connection()
        else:
            self._reader, self._writer = \
                yield from open_agent(self._loop, self._agent_path)

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
            yield from self._make_request(SSH_AGENTC_REQUEST_IDENTITIES)

        if resptype == SSH_AGENT_IDENTITIES_ANSWER:
            result = []

            num_keys = resp.get_uint32()
            for _ in range(num_keys):
                key_blob = resp.get_string()
                comment = resp.get_string()

                packet = SSHPacket(key_blob)
                algorithm = packet.get_string()

                result.append(SSHAgentKeyPair(self, algorithm,
                                              key_blob, comment))

            resp.check_end()
            return result
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    @asyncio.coroutine
    def sign(self, key_blob, data, flags=0):
        """Sign a block of data with the requested key"""

        resptype, resp = \
            yield from self._make_request(SSH_AGENTC_SIGN_REQUEST,
                                          String(key_blob), String(data),
                                          UInt32(flags))

        if resptype == SSH_AGENT_SIGN_RESPONSE:
            sig = resp.get_string()
            resp.check_end()
            return sig
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unable to sign with requested key')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    @asyncio.coroutine
    def add_keys(self, keylist=(), passphrase=None,
                 lifetime=None, confirm=False):
        """Add keys to the agent

           This method adds a list of local private keys and optional
           matching certificates to the agent.

           :param keylist: (optional)
               The list of keys to add. If not specified, an attempt will
               be made to load keys from the files :file:`.ssh/id_ed25519`,
               :file:`.ssh/id_ecdsa`, :file:`.ssh/id_rsa` and
               :file:`.ssh/id_dsa` in the user's home directory with
               optional matching certificates loaded from the files
               :file:`.ssh/id_ed25519-cert.pub`,
               :file:`.ssh/id_ecdsa-cert.pub`, :file:`.ssh/id_rsa-cert.pub`,
               and :file:`.ssh/id_dsa-cert.pub`.
           :param str passphrase: (optional)
               The passphrase to use to decrypt the keys.
           :param lifetime: (optional)
               The time in seconds after which the keys should be
               automatically deleted, or ``None`` to store these keys
               indefinitely (the default).
           :param bool confirm: (optional)
               Whether or not to require confirmation for each private
               key operation which uses these keys, defaulting to ``False``.
           :type keylist: *see* :ref:`SpecifyingPrivateKeys`
           :type lifetime: `int` or ``None``

           :raises: :exc:`ValueError` if the keys cannot be added

        """

        if keylist:
            keypairs = asyncssh.load_keypairs(keylist, passphrase)
        else:
            keypairs = load_default_keypairs(passphrase)

        constraints = self.encode_constraints(lifetime, confirm)
        msgtype = SSH_AGENTC_ADD_ID_CONSTRAINED if constraints else \
                      SSH_AGENTC_ADD_IDENTITY

        for keypair in keypairs:
            comment = keypair.get_comment()
            resptype, resp = \
                yield from self._make_request(msgtype,
                                              keypair.get_agent_private_key(),
                                              String(comment or ''),
                                              constraints)

            if resptype == SSH_AGENT_SUCCESS:
                resp.check_end()
            elif resptype == SSH_AGENT_FAILURE:
                raise ValueError('Unable to add key')
            else:
                raise ValueError('Unknown SSH agent response: %d' % resptype)

    @asyncio.coroutine
    def add_smartcard_keys(self, provider, pin=None,
                           lifetime=None, confirm=False):
        """Store keys associated with a smart card in the agent

           :param str provider:
               The name of the smart card provider
           :param pin: (optional)
               The PIN to use to unlock the smart card
           :param lifetime: (optional)
               The time in seconds after which the keys should be
               automatically deleted, or ``None`` to store these keys
               indefinitely (the default).
           :param bool confirm: (optional)
               Whether or not to require confirmation for each private
               key operation which uses these keys, defaulting to ``False``.
           :type pin: `str` or ``None``
           :type lifetime: `int` or ``None``

           :raises: :exc:`ValueError` if the keys cannot be added

        """

        constraints = self.encode_constraints(lifetime, confirm)
        msgtype = SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED \
                      if constraints else SSH_AGENTC_ADD_SMARTCARD_KEY

        resptype, resp = \
            yield from self._make_request(msgtype, String(provider),
                                          String(pin or ''), constraints)

        if resptype == SSH_AGENT_SUCCESS:
            resp.check_end()
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unable to add keys')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    @asyncio.coroutine
    def remove_keys(self, keylist):
        """Remove a key stored in the agent

           :param keylist:
               The list of keys to remove.
           :type keylist: list of :class:`SSHKeyPair`

           :raises: :exc:`ValueError` if any keys are not found

        """

        for keypair in keylist:
            resptype, resp = \
                yield from self._make_request(SSH_AGENTC_REMOVE_IDENTITY,
                                              String(keypair.public_data))

            if resptype == SSH_AGENT_SUCCESS:
                resp.check_end()
            elif resptype == SSH_AGENT_FAILURE:
                raise ValueError('Key not found')
            else:
                raise ValueError('Unknown SSH agent response: %d' % resptype)

    @asyncio.coroutine
    def remove_smartcard_keys(self, provider, pin=None):
        """Remove keys associated with a smart card stored in the agent

           :param str provider:
               The name of the smart card provider
           :param pin: (optional)
               The PIN to use to unlock the smart card
           :type pin: `str` or ``None``

           :raises: :exc:`ValueError` if the keys are not found

        """

        resptype, resp = \
            yield from self._make_request(SSH_AGENTC_REMOVE_SMARTCARD_KEY,
                                          String(provider), String(pin or ''))

        if resptype == SSH_AGENT_SUCCESS:
            resp.check_end()
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Keys not found')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    @asyncio.coroutine
    def remove_all(self):
        """Remove all keys stored in the agent

           :raises: :exc:`ValueError` if the keys can't be removed

        """

        resptype, resp = \
            yield from self._make_request(SSH_AGENTC_REMOVE_ALL_IDENTITIES)

        if resptype == SSH_AGENT_SUCCESS:
            resp.check_end()
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unable to remove all keys')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    @asyncio.coroutine
    def lock(self, passphrase):
        """Lock the agent using the specified passphrase

           :param str passphrase:
               The passphrase required to later unlock the agent

           :raises: :exc:`ValueError` if the agent can't be locked

        """

        resptype, resp = yield from self._make_request(SSH_AGENTC_LOCK,
                                                       String(passphrase))

        if resptype == SSH_AGENT_SUCCESS:
            resp.check_end()
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unable to lock SSH agent')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    @asyncio.coroutine
    def unlock(self, passphrase):
        """Unlock the agent using the specified passphrase

           :param str passphrase:
               The passphrase to use to unlock the agent

           :raises: :exc:`ValueError` if the agent can't be unlocked

        """

        resptype, resp = yield from self._make_request(SSH_AGENTC_UNLOCK,
                                                       String(passphrase))

        if resptype == SSH_AGENT_SUCCESS:
            resp.check_end()
        elif resptype == SSH_AGENT_FAILURE:
            raise ValueError('Unable to unlock SSH agent')
        else:
            raise ValueError('Unknown SSH agent response: %d' % resptype)

    @asyncio.coroutine
    def query_extensions(self):
        """Return a list of extensions supported by the agent

           :returns: A list of strings of supported extension names

        """

        resptype, resp = yield from self._make_request(SSH_AGENTC_EXTENSION,
                                                       String('query'))

        if resptype == SSH_AGENT_SUCCESS:
            result = []

            while resp:
                exttype = resp.get_string()

                try:
                    exttype = exttype.decode('utf-8')
                except UnicodeDecodeError:
                    raise ValueError('Invalid extension type name')

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

    agent = SSHAgentClient(loop, agent_path)

    try:
        yield from agent.connect()
        return agent
    except (OSError, ChannelOpenError) as exc:
        logger.debug('Unable to contact agent: %s', exc)
        return None


@asyncio.coroutine
def create_agent_listener(conn, loop):
    """Create a listener for forwarding ssh-agent connections"""

    try:
        tempdir = tempfile.TemporaryDirectory(prefix='asyncssh-')
        path = os.path.join(tempdir.name, 'agent')
        unix_listener = yield from create_unix_forward_listener(
            conn, loop, conn.create_agent_connection, path)

        return _X11AgentListener(tempdir, path, unix_listener)
    except OSError:
        return None
