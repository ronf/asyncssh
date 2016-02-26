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

"""Unit tests for AsyncSSH connection API"""

import asyncio
import os

import asyncssh

from .server import ServerTestCase
from .util import asynctest


class _PWChangeClient(asyncssh.SSHClient):
    """Test client password change"""

    def password_change_requested(self, prompt, lang):
        """Change the client's password"""

        return 'oldpw', 'pw'


class _TestConnection(ServerTestCase):
    """Unit tests for AsyncSSH connection API"""

    @asyncio.coroutine
    def _connect_pwchange(self, username, password):
        """Open a connection to test password change"""

        conn, _ = yield from self.create_connection(_PWChangeClient,
                                                    username=username,
                                                    password=password,
                                                    client_keys=None)

        return conn

    @asynctest
    def test_no_auth(self):
        """Test connecting without authentication"""

        with (yield from self.connect(username='guest')) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_agent_auth(self):
        """Test connecting with ssh-agent authentication"""

        with (yield from self.connect(username='ckey')) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_agent_auth_failure(self):
        """Test failure connecting with ssh-agent authentication"""

        os.environ['HOME'] = 'xxx'

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(username='ckey', agent_path='xxx')

        os.environ['HOME'] = '.'

    @asynctest
    def test_agent_auth_unset(self):
        """Test connecting with no local keys and no ssh-agent configured"""

        os.environ['HOME'] = 'xxx'
        del os.environ['SSH_AUTH_SOCK']

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(username='ckey')

        os.environ['HOME'] = '.'
        os.environ['SSH_AUTH_SOCK'] = 'agent'

    @asynctest
    def test_public_key_auth(self):
        """Test connecting with public key authentication"""

        with (yield from self.connect(username='ckey',
                                      client_keys=['ckey'])) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_default_public_key_auth(self):
        """Test connecting with default public key authentication"""

        with (yield from self.connect(username='ckey',
                                      agent_path=None)) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_password_auth(self):
        """Test connecting with password authentication"""

        with (yield from self.connect(username='pw', password='pw',
                                      client_keys=None)) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_password_auth_failure(self):
        """Test _failure connecting with password authentication"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(username='pw', password='badpw',
                                    client_keys=None)

    @asynctest
    def test_password_change(self):
        """Test password change"""

        with (yield from self._connect_pwchange('pw', 'oldpw')) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_password_change_failure(self):
        """Test failure of password change"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self._connect_pwchange('nopwchange', 'oldpw')

    @asynctest
    def test_kbdint_auth(self):
        """Test connecting with keyboard-interactive authentication"""

        with (yield from self.connect(username='kbdint', password='kbdint',
                                      client_keys=None)) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_kbdint_auth_failure(self):
        """Test failure connecting with keyboard-interactive authentication"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(username='kbdint', password='badpw',
                                    client_keys=None)

    @asynctest
    def test_known_hosts_failure(self):
        """Test failure to match known hosts"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(known_hosts=([], [], []))

    @asynctest
    def test_debug(self):
        """Test sending of debug message"""

        with (yield from self.connect()) as conn:
            conn.send_debug('debug')

        yield from conn.wait_closed()
