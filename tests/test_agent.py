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

"""Unit tests for AsyncSSH ssh-agent client"""

import asyncio
import functools
import os
import signal
import subprocess
import unittest

import asyncssh

from asyncssh.agent import SSH_AGENT_SUCCESS, SSH_AGENT_FAILURE
from asyncssh.packet import Byte, String

from .util import AsyncTestCase, asynctest, libnacl_available, run


def agent_test(func):
    """Decorator for running SSH agent tests"""

    @asynctest
    @functools.wraps(func)
    def agent_wrapper(self):
        """Run a test coroutine after connecting to an SSH agent"""

        agent = yield from asyncssh.connect_agent()
        yield from agent.remove_all()
        yield from asyncio.coroutine(func)(self, agent)
        agent.close()

    return agent_wrapper


class _Agent:
    """Mock SSH agent for testing error cases"""

    def __init__(self, response):
        self._response = response
        self._path = None
        self._server = None

    @asyncio.coroutine
    def start(self, path):
        """Start a new mock SSH agent"""

        self._path = path

        # pylint doesn't think start_unix_server exists
        # pylint: disable=no-member
        self._server = \
            yield from asyncio.start_unix_server(self.process_request, path)

    @asyncio.coroutine
    def process_request(self, _reader, writer):
        """Process a request sent to the mock SSH agent"""

        yield from _reader.readexactly(4)
        writer.write(self._response)
        writer.close()

    @asyncio.coroutine
    def stop(self):
        """Shut down the mock SSH agent"""

        self._server.close()
        yield from self._server.wait_closed()

        os.remove(self._path)


class _TestAPI(AsyncTestCase):
    """Unit tests for AsyncSSH API"""

    _agent_pid = None
    _public_keys = {}

    # Pylint doesn't like mixed case method names, but this was chosen to
    # match the convention used in the unittest module.

    # pylint: disable=invalid-name

    @staticmethod
    def set_askpass(status):
        """Set return status for ssh-askpass"""

        with open('ssh-askpass', 'w') as f:
            f.write('#!/bin/sh\nexit %d\n' % status)
            os.chmod('ssh-askpass', 0o755)

    @classmethod
    @asyncio.coroutine
    def asyncSetUpClass(cls):
        """Set up keys and an SSH server for the tests to use"""

        os.environ['DISPLAY'] = ''
        os.environ['HOME'] = '.'
        os.environ['SSH_ASKPASS'] = os.path.join(os.getcwd(), 'ssh-askpass')

        try:
            output = run('ssh-agent -a agent 2>/dev/null')
        except subprocess.CalledProcessError: # pragma: no cover
            raise unittest.SkipTest('ssh-agent not available')

        cls._agent_pid = int(output.splitlines()[2].split()[3][:-1])
        os.environ['SSH_AUTH_SOCK'] = 'agent'

    @classmethod
    @asyncio.coroutine
    def asyncTearDownClass(cls):
        """Shut down agents"""

        os.kill(cls._agent_pid, signal.SIGTERM)

    # pylint: enable=invalid-name

    @agent_test
    def test_connection(self, agent):
        """Test opening a connection to the agent"""

        self.assertIsNotNone(agent)

    @asynctest
    def test_connection_failed(self):
        """Test failure in opening a connection to the agent"""

        self.assertIsNone((yield from asyncssh.connect_agent('xxx')))

    @asynctest
    def test_no_auth_sock(self):
        """Test failure when no auth sock is set"""

        del os.environ['SSH_AUTH_SOCK']
        self.assertIsNone((yield from asyncssh.connect_agent()))
        os.environ['SSH_AUTH_SOCK'] = 'agent'

    @asynctest
    def test_explicit_loop(self):
        """Test passing the event loop explicitly"""

        loop = asyncio.get_event_loop()
        agent = yield from asyncssh.connect_agent(loop=loop)
        self.assertIsNotNone(agent)
        agent.close()

    @agent_test
    def test_get_keys(self, agent):
        """Test getting keys from the agent"""

        keys = yield from agent.get_keys()
        self.assertEqual(len(keys), len(self._public_keys))

    @agent_test
    def test_sign(self, agent):
        """Test signing a block of data using the agent"""

        algs = ['ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256']

        if libnacl_available: # pragma: no branch
            algs.append('ssh-ed25519')

        for alg_name in algs:
            key = asyncssh.generate_private_key(alg_name)
            pubkey = key.convert_to_public()
            cert = key.generate_user_certificate(key, 'name')

            yield from agent.add_keys([(key, cert)])
            agent_keys = yield from agent.get_keys()

            for agent_key in agent_keys:
                sig = yield from agent_key.sign(b'test')
                self.assertTrue(pubkey.verify(b'test', sig))

            yield from agent.remove_keys(agent_keys)

    @agent_test
    def test_reconnect(self, agent):
        """Test reconnecting to the agent after closing it"""

        key = asyncssh.generate_private_key('ssh-rsa')
        pubkey = key.convert_to_public()

        yield from agent.add_keys([key])
        agent_keys = yield from agent.get_keys()
        agent.close()

        for agent_key in agent_keys:
            sig = yield from agent_key.sign(b'test')
            self.assertTrue(pubkey.verify(b'test', sig))

    @agent_test
    def test_add_remove_keys(self, agent):
        """Test adding and removing keys"""

        yield from agent.add_keys()
        agent_keys = yield from agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

        key = asyncssh.generate_private_key('ssh-rsa')
        yield from agent.add_keys([key])
        agent_keys = yield from agent.get_keys()
        self.assertEqual(len(agent_keys), 1)

        yield from agent.remove_keys(agent_keys)
        agent_keys = yield from agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

        yield from agent.add_keys([key])
        agent_keys = yield from agent.get_keys()
        self.assertEqual(len(agent_keys), 1)

        yield from agent_keys[0].remove()
        agent_keys = yield from agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

        yield from agent.add_keys([key], lifetime=1)
        agent_keys = yield from agent.get_keys()
        self.assertEqual(len(agent_keys), 1)
        yield from asyncio.sleep(2)

        agent_keys = yield from agent.get_keys()
        self.assertEqual(len(agent_keys), 0)

    @asynctest
    def test_add_remove_smartcard_keys(self):
        """Test adding and removing smart card keys"""

        mock_agent = _Agent(String(Byte(SSH_AGENT_SUCCESS)))
        yield from mock_agent.start('mock_agent')
        agent = yield from asyncssh.connect_agent('mock_agent')

        result = yield from agent.add_smartcard_keys('provider')
        self.assertIsNone(result)

        agent.close()
        yield from mock_agent.stop()

        mock_agent = _Agent(String(Byte(SSH_AGENT_SUCCESS)))
        yield from mock_agent.start('mock_agent')
        agent = yield from asyncssh.connect_agent('mock_agent')

        result = yield from agent.remove_smartcard_keys('provider')
        self.assertIsNone(result)

        agent.close()
        yield from mock_agent.stop()

    @agent_test
    def test_confirm(self, agent):
        """Test confirmation of key"""

        key = asyncssh.generate_private_key('ssh-rsa')
        pubkey = key.convert_to_public()

        yield from agent.add_keys([key], confirm=True)
        agent_keys = yield from agent.get_keys()

        self.set_askpass(1)

        for agent_key in agent_keys:
            with self.assertRaises(ValueError):
                sig = yield from agent_key.sign(b'test')

        self.set_askpass(0)

        for agent_key in agent_keys:
            sig = yield from agent_key.sign(b'test')
            self.assertTrue(pubkey.verify(b'test', sig))

    @agent_test
    def test_lock(self, agent):
        """Test lock and unlock"""

        key = asyncssh.generate_private_key('ssh-rsa')
        pubkey = key.convert_to_public()

        yield from agent.add_keys([key])
        agent_keys = yield from agent.get_keys()

        yield from agent.lock('passphrase')

        for agent_key in agent_keys:
            with self.assertRaises(ValueError):
                yield from agent_key.sign(b'test')

        yield from agent.unlock('passphrase')

        for agent_key in agent_keys:
            sig = yield from agent_key.sign(b'test')
            self.assertTrue(pubkey.verify(b'test', sig))

    @asynctest
    def test_query_extensions(self):
        """Test query of supported extensions"""

        mock_agent = _Agent(String(Byte(SSH_AGENT_SUCCESS) + String('xxx')))
        yield from mock_agent.start('mock_agent')
        agent = yield from asyncssh.connect_agent('mock_agent')

        extensions = yield from agent.query_extensions()
        self.assertEqual(extensions, ['xxx'])

        agent.close()
        yield from mock_agent.stop()

        mock_agent = _Agent(String(Byte(SSH_AGENT_SUCCESS) + String(b'\xff')))
        yield from mock_agent.start('mock_agent')
        agent = yield from asyncssh.connect_agent('mock_agent')

        with self.assertRaises(ValueError):
            yield from agent.query_extensions()

        agent.close()
        yield from mock_agent.stop()

        mock_agent = _Agent(String(Byte(SSH_AGENT_FAILURE)))
        yield from mock_agent.start('mock_agent')
        agent = yield from asyncssh.connect_agent('mock_agent')

        extensions = yield from agent.query_extensions()
        self.assertEqual(extensions, [])

        agent.close()
        yield from mock_agent.stop()

        mock_agent = _Agent(String(b'\xff'))
        yield from mock_agent.start('mock_agent')
        agent = yield from asyncssh.connect_agent('mock_agent')

        with self.assertRaises(ValueError):
            yield from agent.query_extensions()

        agent.close()
        yield from mock_agent.stop()

    @agent_test
    def test_unknown_key(self, agent):
        """Test failure when signing with an unknown key"""

        with self.assertRaises(ValueError):
            yield from agent.sign(b'xxx', b'test')

    @agent_test
    def test_double_close(self, agent):
        """Test calling close more than once on the agent"""

        self.assertIsNotNone(agent)
        agent.close()

    @asynctest
    def test_errors(self):
        """Test getting error responses from SSH agent"""

        # pylint: disable=bad-whitespace

        key = asyncssh.generate_private_key('ssh-rsa')
        keypair = asyncssh.load_keypairs(key)[0]

        for response in (b'', String(b''),
                         String(Byte(SSH_AGENT_FAILURE)), String(b'\xff')):
            mock_agent = _Agent(response)
            yield from mock_agent.start('mock_agent')

            agent = yield from asyncssh.connect_agent('mock_agent')

            for request in (agent.get_keys(),
                            agent.sign(b'xxx', b'test'),
                            agent.add_keys([key]),
                            agent.add_smartcard_keys('xxx'),
                            agent.remove_keys([keypair]),
                            agent.remove_smartcard_keys('xxx'),
                            agent.remove_all(),
                            agent.lock('passphrase'),
                            agent.unlock('passphrase')):
                with self.assertRaises(ValueError):
                    yield from request

                agent.close()

            yield from mock_agent.stop()
