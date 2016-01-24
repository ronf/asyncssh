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
import os
import signal

import asyncssh

from .util import asynctest, run, AsyncTestCase


class _Agent:
    """Mock SSH agent for testing error cases"""

    def __init__(self, failmode):
        self._failmode = failmode
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
    def process_request(self, _, writer):
        """Process a request sent to the mock SSH agent"""

        if self._failmode == 'unexpected_response':
            writer.write(b'\x00\x00\x00\x01\xff')
        elif self._failmode == 'empty_response':
            writer.write(b'\x00\x00\x00\x00')

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
    _public_key = None

    # Pylint doesn't like mixed case method names, but this was chosen to
    # match the convention used in the unittest module.

    # pylint: disable=invalid-name

    @classmethod
    @asyncio.coroutine
    def asyncSetUpClass(cls):
        """Set up keys and an SSH server for the tests to use"""

        run('ssh-keygen -q -b 2048 -t rsa -N "" -f ckey')

        output = run('ssh-agent -a agent')
        cls._agent_pid = int(output.splitlines()[2].split()[3][:-1])

        os.environ['SSH_AUTH_SOCK'] = 'agent'
        run('ssh-add ckey')

        cls._public_key = asyncssh.read_public_key('ckey.pub')

    @classmethod
    @asyncio.coroutine
    def asyncTearDownClass(cls):
        """Shut down agents"""

        os.kill(cls._agent_pid, signal.SIGTERM)

    # pylint: enable=invalid-name

    @asyncio.coroutine
    def check_invalid_response(self, failmode='', request=''):
        """Test getting invalid responses from SSH agent"""

        mock_agent = _Agent(failmode)
        yield from mock_agent.start('bad_agent')

        agent = yield from asyncssh.connect_agent('bad_agent')

        with self.assertRaises(ValueError):
            if request == 'sign':
                yield from agent.sign(b'xxx', b'test')
            else:
                yield from agent.get_keys()

        agent.close()
        yield from mock_agent.stop()

    @asynctest
    def test_connection(self):
        """Test opening a connection to the agent"""

        agent = yield from asyncssh.connect_agent()
        self.assertIsNotNone(agent)
        agent.close()

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

    @asynctest
    def test_get_keys(self):
        """Test getting keys from the agent"""

        agent = yield from asyncssh.connect_agent()
        keys = yield from agent.get_keys()
        agent.close()

        self.assertEqual(len(keys), 1)

    @asynctest
    def test_sign(self):
        """Test signing a block of data using the agent"""

        agent = yield from asyncssh.connect_agent()
        keys = yield from agent.get_keys()
        sig = yield from keys[0].sign(b'test')
        self.assertTrue(self._public_key.verify(b'test', sig))
        agent.close()

    @asynctest
    def test_reconnect(self):
        """Test reconnecting to the agent after closing it"""

        agent = yield from asyncssh.connect_agent()
        keys = yield from agent.get_keys()
        agent.close()

        sig = yield from keys[0].sign(b'test')
        self.assertTrue(self._public_key.verify(b'test', sig))
        agent.close()

    @asynctest
    def test_unknown_key(self):
        """Test failure when signing with an unknown key"""

        agent = yield from asyncssh.connect_agent()

        with self.assertRaises(ValueError):
            yield from agent.sign(b'xxx', b'test')

        agent.close()

    @asynctest
    def test_double_close(self):
        """Test calling close more than once on the agent"""

        agent = yield from asyncssh.connect_agent()
        self.assertIsNotNone(agent)
        agent.close()
        agent.close()

    @asynctest
    def test_no_response(self):
        """Test getting no response from SSH agent"""

        yield from self.check_invalid_response()

    @asynctest
    def test_empty_response(self):
        """Test getting empty response from SSH agent"""

        yield from self.check_invalid_response('empty_response')

    @asynctest
    def test_unexpected_get_keys_response(self):
        """Test getting unexpected get_keys response from SSH agent"""

        yield from self.check_invalid_response('unexpected_response')

    @asynctest
    def test_unexpected_sign_response(self):
        """Test getting unexpected get_keys response from SSH agent"""

        yield from self.check_invalid_response('unexpected_response', 'sign')
