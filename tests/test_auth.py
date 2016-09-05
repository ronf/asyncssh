# Copyright (c) 2015-2016 by Ron Frederick <ronf@timeheart.net>.
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

"""Unit tests for authentication"""

import asyncio

import asyncssh

from asyncssh.auth import MSG_USERAUTH_PK_OK, lookup_client_auth
from asyncssh.auth import get_server_auth_methods, lookup_server_auth
from asyncssh.constants import MSG_USERAUTH_REQUEST, MSG_USERAUTH_FAILURE
from asyncssh.constants import MSG_USERAUTH_SUCCESS
from asyncssh.misc import DisconnectError, PasswordChangeRequired
from asyncssh.packet import SSHPacket, Boolean, Byte, NameList, String
from asyncssh.public_key import SSHLocalKeyPair

from .util import asynctest, create_task, AsyncTestCase, ConnectionStub


class _AuthConnectionStub(ConnectionStub):
    """Connection stub class to test authentication"""

    @asyncio.coroutine
    def _run_task(self, coro):
        """Run an asynchronous task"""

        try:
            yield from coro
        except DisconnectError as exc:
            self.connection_lost(exc)

    def create_task(self, coro):
        """Create an asynchronous task"""

        return create_task(self._run_task(coro))

    def connection_lost(self, exc):
        """Handle the closing of a connection"""

        raise NotImplementedError

    def process_packet(self, data):
        """Process an incoming packet"""

        raise NotImplementedError

class _AuthClientStub(_AuthConnectionStub):
    """Stub class for client connection"""

    @classmethod
    def make_pair(cls, method, **kwargs):
        """Make a client and server connection pair to test authentication"""

        client_conn = cls(method, **kwargs)
        return client_conn, client_conn.get_peer()

    def __init__(self, method, public_key_auth=False, client_key=None,
                 client_cert=None, override_pk_ok=False, password_auth=False,
                 password=None, password_change=NotImplemented,
                 password_change_prompt=None, kbdint_auth=False,
                 kbdint_submethods=None, kbdint_challenge=None,
                 kbdint_response=None, success=False):
        super().__init__(_AuthServerStub(self, public_key_auth, override_pk_ok,
                                         password_auth, password_change_prompt,
                                         kbdint_auth, kbdint_challenge,
                                         success), False)

        self._client_key = client_key
        self._client_cert = client_cert

        self._password = password
        self._password_change = password_change
        self._password_changed = None

        self._kbdint_submethods = kbdint_submethods
        self._kbdint_response = kbdint_response

        self._auth_waiter = asyncio.Future()
        self._auth = lookup_client_auth(self, method)

        if self._auth is None:
            self.close()
            self._peer.close()
            raise ValueError('Invalid auth method')

    def connection_lost(self, exc):
        """Handle the closing of a connection"""

        self._auth_waiter.set_exception(exc)

    def process_packet(self, data):
        """Process an incoming packet"""

        packet = SSHPacket(data)
        pkttype = packet.get_byte()

        if pkttype == MSG_USERAUTH_FAILURE:
            _ = packet.get_namelist()
            partial_success = packet.get_boolean()
            packet.check_end()

            if partial_success: # pragma: no cover
                # Partial success not implemented yet
                self._auth.auth_succeeded()
            else:
                self._auth.auth_failed()

            self._auth_waiter.set_result((False, self._password_changed))
            self._auth = None
            self._auth_waiter = None
        elif pkttype == MSG_USERAUTH_SUCCESS:
            packet.check_end()

            self._auth.auth_succeeded()
            self._auth_waiter.set_result((True, self._password_changed))
            self._auth = None
            self._auth_waiter = None
        else:
            try:
                self._auth.process_packet(pkttype, packet)
            except DisconnectError as exc:
                self.connection_lost(exc)

    def get_auth_result(self):
        """Return the result of the authentication"""

        return (yield from self._auth_waiter)

    def try_next_auth(self):
        """Handle a request to move to another form of auth"""

        # Report that the current auth attempt failed
        self._auth_waiter.set_result((False, self._password_changed))
        self._auth = None
        self._auth_waiter = None

    @asyncio.coroutine
    def send_userauth_request(self, method, *args, key=None):
        """Send a user authentication request"""

        packet = b''.join((Byte(MSG_USERAUTH_REQUEST), String('user'),
                           String(b'service'), String(method)) + args)

        if key:
            packet += String(key.sign(String('') + packet))

        self.send_packet(packet)

    @asyncio.coroutine
    def public_key_auth_requested(self):
        """Return key to use for public key authentication"""

        if self._client_key:
            return SSHLocalKeyPair(self._client_key, self._client_cert)
        else:
            return None

    @asyncio.coroutine
    def password_auth_requested(self):
        """Return password to send for password authentication"""

        # pylint: disable=no-self-use

        return self._password

    @asyncio.coroutine
    def password_change_requested(self, prompt, lang):
        """Return old & new passwords for password change"""

        # pylint: disable=unused-argument

        if self._password_change is True:
            return 'password', 'new_password'
        else:
            return self._password_change

    def password_changed(self):
        """Handle a successful password change"""

        self._password_changed = True

    def password_change_failed(self):
        """Handle an unsuccessful password change"""

        self._password_changed = False

    @asyncio.coroutine
    def kbdint_auth_requested(self):
        """Return submethods to send for keyboard-interactive authentication"""

        return self._kbdint_submethods

    @asyncio.coroutine
    def kbdint_challenge_received(self, name, instruction, lang, prompts):
        """Return responses to keyboard-interactive challenge"""

        # pylint: disable=no-self-use,unused-argument

        if self._kbdint_response is True:
            return ('password',)
        else:
            return self._kbdint_response


class _AuthServerStub(_AuthConnectionStub):
    """Stub class for server connection"""

    def __init__(self, peer=None, public_key_auth=False, override_pk_ok=False,
                 password_auth=False, password_change_prompt=None,
                 kbdint_auth=False, kbdint_challenge=False, success=False):
        super().__init__(peer, True)

        self._public_key_auth = public_key_auth
        self._override_pk_ok = override_pk_ok

        self._password_auth = password_auth
        self._password_change_prompt = password_change_prompt

        self._kbdint_auth = kbdint_auth
        self._kbdint_challenge = kbdint_challenge

        self._success = success

        self._auth = None

    def connection_lost(self, exc):
        """Handle the closing of a connection"""

        self._peer.connection_lost(exc)

    def process_packet(self, data):
        """Process an incoming packet"""

        packet = SSHPacket(data)
        pkttype = packet.get_byte()

        if pkttype == MSG_USERAUTH_REQUEST:
            _ = packet.get_string()         # username
            _ = packet.get_string()         # service
            method = packet.get_string()

            if self._auth:
                self._auth.cancel()

            if self._override_pk_ok:
                self.send_packet(Byte(MSG_USERAUTH_PK_OK),
                                 String(''), String(''))
            else:
                self._auth = lookup_server_auth(self, 'user', method, packet)
        else:
            try:
                self._auth.process_packet(pkttype, packet)
            except DisconnectError as exc:
                self.connection_lost(exc)

    def send_userauth_failure(self, partial_success):
        """Send a user authentication failure response"""

        self._auth = None
        self.send_packet(Byte(MSG_USERAUTH_FAILURE), NameList([]),
                         Boolean(partial_success))

    def send_userauth_success(self):
        """Send a user authentication success response"""

        self._auth = None
        self.send_packet(Byte(MSG_USERAUTH_SUCCESS))

    def public_key_auth_supported(self):
        """Return whether or not public key authentication is supported"""

        return self._public_key_auth

    @asyncio.coroutine
    def validate_public_key(self, username, key_data, msg, signature):
        """Validate public key"""

        # pylint: disable=unused-argument

        return self._success

    def password_auth_supported(self):
        """Return whether or not password authentication is supported"""

        return self._password_auth

    @asyncio.coroutine
    def validate_password(self, username, password):
        """Validate password"""

        # pylint: disable=unused-argument

        if self._password_change_prompt:
            raise PasswordChangeRequired(self._password_change_prompt)
        else:
            return self._success

    @asyncio.coroutine
    def change_password(self, username, old_password, new_password):
        """Validate password"""

        # pylint: disable=unused-argument

        return self._success

    def kbdint_auth_supported(self):
        """Return whether or not keyboard-interactive authentication
           is supported"""

        return self._kbdint_auth

    @asyncio.coroutine
    def get_kbdint_challenge(self, username, lang, submethods):
        """Return a keyboard-interactive challenge"""

        # pylint: disable=unused-argument

        if self._kbdint_challenge is True:
            return '', '', '', (('Password:', False),)
        else:
            return self._kbdint_challenge

    @asyncio.coroutine
    def validate_kbdint_response(self, username, responses):
        """Validate keyboard-interactive responses"""

        # pylint: disable=unused-argument

        return self._success


class _TestAuth(AsyncTestCase):
    """Unit tests for auth module"""

    @asyncio.coroutine
    def check_auth(self, method, expected_result, **kwargs):
        """Unit test authentication"""

        client_conn, server_conn = _AuthClientStub.make_pair(method, **kwargs)

        try:
            self.assertEqual((yield from client_conn.get_auth_result()),
                             expected_result)
        finally:
            client_conn.close()
            server_conn.close()

    @asynctest
    def test_client_auth_methods(self):
        """Test client auth methods"""

        with self.subTest('Unknown client auth method'):
            with self.assertRaises(ValueError):
                _AuthClientStub.make_pair(b'xxx')

    @asynctest
    def test_server_auth_methods(self):
        """Test server auth methods"""

        with self.subTest('No auth methods'):
            server_conn = _AuthServerStub()
            self.assertEqual(get_server_auth_methods(server_conn), [])
            server_conn.close()

        with self.subTest('All auth methods'):
            server_conn = _AuthServerStub(public_key_auth=True,
                                          password_auth=True,
                                          kbdint_auth=True)
            self.assertEqual(get_server_auth_methods(server_conn),
                             [b'publickey', b'keyboard-interactive',
                              b'password'])
            server_conn.close()

        with self.subTest('Unknown auth method'):
            server_conn = _AuthServerStub()
            self.assertEqual(lookup_server_auth(server_conn, 'user', b'xxx',
                                                SSHPacket(b'')), None)
            server_conn.close()

    @asynctest
    def test_null_auth(self):
        """Unit test null authentication"""

        yield from self.check_auth(b'none', (False, None))

    @asynctest
    def test_publickey_auth(self):
        """Unit test public key authentication"""

        ckey = asyncssh.generate_private_key('ssh-rsa')
        cert = ckey.generate_user_certificate(ckey, 'name')

        with self.subTest('Public key auth not available'):
            yield from self.check_auth(b'publickey', (False, None))

        with self.subTest('Untrusted key'):
            yield from self.check_auth(b'publickey', (False, None),
                                       client_key=ckey)

        with self.subTest('Trusted key'):
            yield from self.check_auth(b'publickey', (True, None),
                                       client_key=ckey, success=True)

        with self.subTest('Trusted certificate'):
            yield from self.check_auth(b'publickey', (True, None),
                                       client_key=ckey, client_cert=cert,
                                       success=True)

        with self.subTest('Invalid PK_OK message'):
            with self.assertRaises(DisconnectError):
                yield from self.check_auth(b'publickey', (False, None),
                                           client_key=ckey,
                                           override_pk_ok=True)

    @asynctest
    def test_password_auth(self):
        """Unit test password authentication"""

        with self.subTest('Password auth not available'):
            yield from self.check_auth(b'password', (False, None))

        with self.subTest('Invalid password'):
            with self.assertRaises(DisconnectError):
                yield from self.check_auth(b'password', (False, None),
                                           password=b'\xff')

        with self.subTest('Incorrect password'):
            yield from self.check_auth(b'password', (False, None),
                                       password='password')

        with self.subTest('Correct password'):
            yield from self.check_auth(b'password', (True, None),
                                       password='password', success=True)

        with self.subTest('Password change not available'):
            yield from self.check_auth(b'password', (False, None),
                                       password='password',
                                       password_change_prompt='change')

        with self.subTest('Invalid password change prompt'):
            with self.assertRaises(DisconnectError):
                yield from self.check_auth(b'password', (False, False),
                                           password='password',
                                           password_change=True,
                                           password_change_prompt=b'\xff')

        with self.subTest('Password change failed'):
            yield from self.check_auth(b'password', (False, False),
                                       password='password',
                                       password_change=True,
                                       password_change_prompt='change')

        with self.subTest('Password change succeeded'):
            yield from self.check_auth(b'password', (True, True),
                                       password='password',
                                       password_change=True,
                                       password_change_prompt='change',
                                       success=True)

    @asynctest
    def test_kbdint_auth(self):
        """Unit test keyboard-interactive authentication"""

        with self.subTest('No submethods'):
            yield from self.check_auth(b'keyboard-interactive', (False, None))

        with self.subTest('Invalid submethods'):
            with self.assertRaises(DisconnectError):
                yield from self.check_auth(b'keyboard-interactive',
                                           (False, None),
                                           kbdint_submethods=b'\xff')

        with self.subTest('No challenge'):
            yield from self.check_auth(b'keyboard-interactive', (False, None),
                                       kbdint_submethods='')

        with self.subTest('Invalid challenge name'):
            with self.assertRaises(DisconnectError):
                yield from self.check_auth(b'keyboard-interactive',
                                           (False, None), kbdint_submethods='',
                                           kbdint_challenge=(b'\xff', '',
                                                             '', ()))

        with self.subTest('Invalid challenge prompt'):
            with self.assertRaises(DisconnectError):
                yield from self.check_auth(b'keyboard-interactive',
                                           (False, None), kbdint_submethods='',
                                           kbdint_challenge=('', '', '',
                                                             ((b'\xff',
                                                               False),)))

        with self.subTest('No response'):
            yield from self.check_auth(b'keyboard-interactive', (False, None),
                                       kbdint_submethods='',
                                       kbdint_challenge=True)

        with self.subTest('Invalid response'):
            with self.assertRaises(DisconnectError):
                yield from self.check_auth(b'keyboard-interactive',
                                           (False, None), kbdint_submethods='',
                                           kbdint_challenge=True,
                                           kbdint_response=(b'\xff',))

        with self.subTest('Incorrect response'):
            yield from self.check_auth(b'keyboard-interactive', (False, None),
                                       kbdint_submethods='',
                                       kbdint_challenge=True,
                                       kbdint_response=True)

        with self.subTest('Correct response'):
            yield from self.check_auth(b'keyboard-interactive', (True, None),
                                       kbdint_submethods='',
                                       kbdint_challenge=True,
                                       kbdint_response=True, success=True)
