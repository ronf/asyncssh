# Copyright (c) 2016-2022 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH ssh-agent client"""

import asyncio
import functools
import os
from pathlib import Path
import signal
import subprocess
import unittest

import asyncssh

from asyncssh.agent import SSH_AGENT_SUCCESS, SSH_AGENT_FAILURE
from asyncssh.agent import SSH_AGENT_IDENTITIES_ANSWER
from asyncssh.crypto import ed25519_available
from asyncssh.packet import Byte, String, UInt32

from .sk_stub import sk_available, patch_sk
from .util import AsyncTestCase, asynctest, get_test_key, run, try_remove


def agent_test(func):
    """Decorator for running SSH agent tests"""

    @asynctest
    @functools.wraps(func)
    async def agent_wrapper(self):
        """Run a test after connecting to an SSH agent"""

        async with asyncssh.connect_agent() as agent:
            await agent.remove_all()
            await func(self, agent)

    return agent_wrapper


class _Agent:
    """Mock SSH agent for testing error cases"""

    def __init__(self, response):
        self._response = b'' if response is None else String(response)
        self._path = None
        self._server = None

    async def start(self, path):
        """Start a new mock SSH agent"""

        self._path = path

        # pylint doesn't think start_unix_server exists
        # pylint: disable=no-member
        self._server = \
            await asyncio.start_unix_server(self.process_request, path)

    async def process_request(self, reader, writer):
        """Process a request sent to the mock SSH agent"""

        await reader.readexactly(4)
        writer.write(self._response)
        writer.close()

    async def stop(self):
        """Shut down the mock SSH agent"""

        self._server.close()
        await self._server.wait_closed()

        try_remove(self._path)


class _TestAgent(AsyncTestCase):
    """Unit tests for AsyncSSH API"""

    _agent_pid = None
    _public_keys = {}

    @staticmethod
    def set_askpass(status):
        """Set return status for ssh-askpass"""

        with open('ssh-askpass', 'w') as f:
            f.write('#!/bin/sh\nexit %d\n' % status)
            os.chmod('ssh-askpass', 0o755)

    # Pylint doesn't like mixed case method names, but this was chosen to
    # match the convention used in the unittest module.

    # pylint: disable=invalid-name

    @classmethod
    async def asyncSetUpClass(cls):
        """Set up keys and an SSH server for the tests to use"""

        os.environ['DISPLAY'] = ' '
        os.environ['HOME'] = '.'
        os.environ['SSH_ASKPASS'] = os.path.join(os.getcwd(), 'ssh-askpass')

        try:
            output = run('ssh-agent -a agent 2>/dev/null')
        except subprocess.CalledProcessError: # pragma: no cover
            return

        cls._agent_pid = int(output.splitlines()[2].split()[3][:-1])
        os.environ['SSH_AUTH_SOCK'] = 'agent'

    @classmethod
    async def asyncTearDownClass(cls):
        """Shut down agents"""

        if cls._agent_pid: # pragma: no branch
            os.kill(cls._agent_pid, signal.SIGTERM)

    def setUp(self):
        """Skip unit tests if we couldn't start an agent"""

        if not self._agent_pid: # pragma: no cover
            self.skipTest('ssh-agent not available')

    # pylint: enable=invalid-name

    @agent_test
    async def test_connection(self, agent):
        """Test opening a connection to the agent"""

        self.assertIsNotNone(agent)

    @asynctest
    async def test_connection_failed(self):
        """Test failure in opening a connection to the agent"""

        with self.assertRaises(OSError):
            await asyncssh.connect_agent('xxx')

    @asynctest
    async def test_no_auth_sock(self):
        """Test failure when no auth sock is set"""

        del os.environ['SSH_AUTH_SOCK']

        with self.assertRaises(OSError):
            await asyncssh.connect_agent()

        os.environ['SSH_AUTH_SOCK'] = 'agent'

    @agent_test
    async def test_get_keys(self, agent):
        """Test getting keys from the agent"""

        keys = await agent.get_keys()
        self.assertEqual(len(keys), len(self._public_keys))

    @agent_test
    async def test_sign(self, agent):
        """Test signing a block of data using the agent"""

        algs = ['ssh-rsa', 'ecdsa-sha2-nistp256']

        if ed25519_available: # pragma: no branch
            algs.append('ssh-ed25519')

        for alg_name in algs:
            key = get_test_key(alg_name)
            pubkey = key.convert_to_public()
            cert = key.generate_user_certificate(key, 'name')

            await agent.add_keys([(key, cert)])
            agent_keys = await agent.get_keys()

            for agent_key in agent_keys:
                agent_key.set_sig_algorithm(agent_key.sig_algorithms[0])
                sig = await agent_key.sign_async(b'test')
                self.assertTrue(pubkey.verify(b'test', sig))

            await agent.remove_keys(agent_keys)

    @agent_test
    async def test_set_certificate(self, agent):
        """Test setting certificate on an existing keypair"""

        key = get_test_key('ssh-rsa')
        cert = key.generate_user_certificate(key, 'name')

        key2 = get_test_key('ssh-rsa', 1)
        cert2 = key.generate_user_certificate(key2, 'name')

        await agent.add_keys([key])
        agent_key = (await agent.get_keys())[0]

        agent_key.set_certificate(cert)
        self.assertEqual(agent_key.public_data, cert.public_data)

        with self.assertRaises(ValueError):
            asyncssh.load_keypairs([(agent_key, cert2)])

        agent_key = (await agent.get_keys())[0]
        agent_key = asyncssh.load_keypairs([(agent_key, cert)])[0]
        self.assertEqual(agent_key.public_data, cert.public_data)

        with self.assertRaises(ValueError):
            asyncssh.load_keypairs([(agent_key, cert2)])

    @agent_test
    async def test_reconnect(self, agent):
        """Test reconnecting to the agent after closing it"""

        key = get_test_key('ecdsa-sha2-nistp256')
        pubkey = key.convert_to_public()

        async with agent:
            await agent.add_keys([key])
            agent_keys = await agent.get_keys()

        for agent_key in agent_keys:
            sig = await agent_key.sign_async(b'test')
            self.assertTrue(pubkey.verify(b'test', sig))

    @agent_test
    async def test_add_remove_keys(self, agent):
        """Test adding and removing keys"""

        await agent.add_keys()
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

        key = get_test_key('ssh-rsa')
        await agent.add_keys([key])
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 1)

        await agent.remove_keys(agent_keys)
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

        await agent.add_keys([key])
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 1)

        await agent_keys[0].remove()
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

        await agent.add_keys([key], lifetime=1)
        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 1)
        await asyncio.sleep(2)

        agent_keys = await agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

    @agent_test
    async def test_add_nonlocal(self, agent):
        """Test failure when adding a non-local key to an agent"""

        key = get_test_key('ssh-rsa')

        async with agent:
            await agent.add_keys([key])
            agent_keys = await agent.get_keys()

            with self.assertRaises(asyncssh.KeyImportError):
                await agent.add_keys(agent_keys)

    @agent_test
    async def test_add_keys_failure(self, agent):
        """Test failure adding keys to the agent"""

        os.mkdir('.ssh', 0o700)
        key = get_test_key('ssh-rsa')
        key.write_private_key(Path('.ssh', 'id_rsa'))

        try:
            mock_agent = _Agent(Byte(SSH_AGENT_FAILURE))
            await mock_agent.start('mock_agent')

            async with asyncssh.connect_agent('mock_agent') as agent:
                async with agent:
                    await agent.add_keys()

                async with agent:
                    with self.assertRaises(ValueError):
                        await agent.add_keys([key])
        finally:
            await mock_agent.stop()
            os.remove(os.path.join('.ssh', 'id_rsa'))
            os.rmdir('.ssh')

    @unittest.skipUnless(sk_available, 'security key support not available')
    @patch_sk([2])
    @asynctest
    async def test_add_sk_keys(self):
        """Test adding U2F security keys"""

        key = get_test_key('sk-ecdsa-sha2-nistp256@openssh.com')
        cert = key.generate_user_certificate(key, 'test')

        mock_agent = _Agent(Byte(SSH_AGENT_SUCCESS))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            for keypair in asyncssh.load_keypairs([key, (key, cert)]):
                async with agent:
                    self.assertIsNone(await agent.add_keys([keypair]))

            async with agent:
                with self.assertRaises(asyncssh.KeyExportError):
                    await agent.add_keys([key.convert_to_public()])

        await mock_agent.stop()

    @unittest.skipUnless(sk_available, 'security key support not available')
    @patch_sk([2])
    @asynctest
    async def test_get_sk_keys(self):
        """Test getting U2F security keys"""

        key = get_test_key('sk-ecdsa-sha2-nistp256@openssh.com')
        cert = key.generate_user_certificate(key, 'test')

        mock_agent = _Agent(Byte(SSH_AGENT_IDENTITIES_ANSWER) + UInt32(2) +
                            String(key.public_data) + String('') +
                            String(cert.public_data) + String(''))

        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            await agent.get_keys()

        await mock_agent.stop()

    @asynctest
    async def test_add_remove_smartcard_keys(self):
        """Test adding and removing smart card keys"""

        mock_agent = _Agent(Byte(SSH_AGENT_SUCCESS))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            result = await agent.add_smartcard_keys('provider')
            self.assertIsNone(result)

        await mock_agent.stop()

        mock_agent = _Agent(Byte(SSH_AGENT_SUCCESS))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            result = await agent.remove_smartcard_keys('provider')
            self.assertIsNone(result)

        await mock_agent.stop()

    @agent_test
    async def test_confirm(self, agent):
        """Test confirmation of key"""

        key = get_test_key('ecdsa-sha2-nistp256')
        pubkey = key.convert_to_public()

        await agent.add_keys([key], confirm=True)
        agent_keys = await agent.get_keys()

        self.set_askpass(1)

        for agent_key in agent_keys:
            with self.assertRaises(ValueError):
                sig = await agent_key.sign_async(b'test')

        self.set_askpass(0)

        for agent_key in agent_keys:
            sig = await agent_key.sign_async(b'test')
            self.assertTrue(pubkey.verify(b'test', sig))

    @agent_test
    async def test_lock(self, agent):
        """Test lock and unlock"""

        key = get_test_key('ecdsa-sha2-nistp256')
        pubkey = key.convert_to_public()

        await agent.add_keys([key])
        agent_keys = await agent.get_keys()

        await agent.lock('passphrase')

        for agent_key in agent_keys:
            with self.assertRaises(ValueError):
                await agent_key.sign_async(b'test')

        await agent.unlock('passphrase')

        for agent_key in agent_keys:
            sig = await agent_key.sign_async(b'test')
            self.assertTrue(pubkey.verify(b'test', sig))

    @asynctest
    async def test_query_extensions(self):
        """Test query of supported extensions"""

        mock_agent = _Agent(Byte(SSH_AGENT_SUCCESS) + String('xxx'))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            extensions = await agent.query_extensions()
            self.assertEqual(extensions, ['xxx'])

        await mock_agent.stop()

        mock_agent = _Agent(Byte(SSH_AGENT_SUCCESS) + String(b'\xff'))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            with self.assertRaises(ValueError):
                await agent.query_extensions()

        await mock_agent.stop()

        mock_agent = _Agent(Byte(SSH_AGENT_FAILURE))
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            extensions = await agent.query_extensions()
            self.assertEqual(extensions, [])

        await mock_agent.stop()

        mock_agent = _Agent(b'\xff')
        await mock_agent.start('mock_agent')

        async with asyncssh.connect_agent('mock_agent') as agent:
            with self.assertRaises(ValueError):
                await agent.query_extensions()

        await mock_agent.stop()

    @agent_test
    async def test_unknown_key(self, agent):
        """Test failure when signing with an unknown key"""

        key = get_test_key('ssh-rsa')

        with self.assertRaises(ValueError):
            await agent.sign(key.public_data, b'test')

    @agent_test
    async def test_double_close(self, agent):
        """Test calling close more than once on the agent"""

        self.assertIsNotNone(agent)
        agent.close()

    @asynctest
    async def test_errors(self):
        """Test getting error responses from SSH agent"""

        key = get_test_key('ssh-rsa')
        keypair = asyncssh.load_keypairs(key)[0]

        for response in (None, b'', Byte(SSH_AGENT_FAILURE), b'\xff'):
            mock_agent = _Agent(response)
            await mock_agent.start('mock_agent')

            async with asyncssh.connect_agent('mock_agent') as agent:
                for request in (agent.get_keys(),
                                agent.sign(b'xxx', b'test'),
                                agent.add_keys([key]),
                                agent.add_smartcard_keys('xxx'),
                                agent.remove_keys([keypair]),
                                agent.remove_smartcard_keys('xxx'),
                                agent.remove_all(),
                                agent.lock('passphrase'),
                                agent.unlock('passphrase')):
                    async with agent:
                        with self.assertRaises(ValueError):
                            await request

            await mock_agent.stop()
