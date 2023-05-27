# Copyright (c) 2015-2022 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for authentication"""

import asyncio
import unittest

import asyncssh

from asyncssh.auth import MSG_USERAUTH_PK_OK, lookup_client_auth
from asyncssh.auth import get_supported_server_auth_methods, lookup_server_auth
from asyncssh.auth import MSG_USERAUTH_GSSAPI_RESPONSE
from asyncssh.constants import MSG_USERAUTH_REQUEST, MSG_USERAUTH_FAILURE
from asyncssh.constants import MSG_USERAUTH_SUCCESS
from asyncssh.gss import GSSClient, GSSServer
from asyncssh.packet import SSHPacket, Boolean, Byte, NameList, String

from .util import asynctest, gss_available, patch_gss
from .util import AsyncTestCase, ConnectionStub, get_test_key


class _AuthConnectionStub(ConnectionStub):
    """Connection stub class to test authentication"""

    def connection_lost(self, exc):
        """Handle the closing of a connection"""

        raise NotImplementedError

    def process_packet(self, data):
        """Process an incoming packet"""

        raise NotImplementedError

    def _get_userauth_request_packet(self, method, args):
        """Get packet data for a user authentication request"""

        # pylint: disable=no-self-use

        return b''.join((Byte(MSG_USERAUTH_REQUEST), String('user'),
                         String('service'), String(method)) + args)

    def get_userauth_request_data(self, method, *args):
        """Get signature data for a user authentication request"""

        return String('') + self._get_userauth_request_packet(method, args)

    def send_userauth_packet(self, pkttype, *args, handler=None,
                             trivial=True):
        """Send a user authentication packet"""

        # pylint: disable=unused-argument

        self.send_packet(pkttype, *args, handler=handler)


class _AuthClientStub(_AuthConnectionStub):
    """Stub class for client connection"""

    @classmethod
    def make_pair(cls, method, **kwargs):
        """Make a client and server connection pair to test authentication"""

        client_conn = cls(method, **kwargs)
        return client_conn, client_conn.get_peer()

    def __init__(self, method, gss_host=None, override_gss_mech=False,
                 host_based_auth=False, client_host_key=None,
                 client_host_cert=None, public_key_auth=False, client_key=None,
                 client_cert=None, override_pk_ok=False, password_auth=False,
                 password=None, password_change=NotImplemented,
                 password_change_prompt=None, kbdint_auth=False,
                 kbdint_submethods=None, kbdint_challenge=None,
                 kbdint_response=None, success=False):
        super().__init__(_AuthServerStub(self, gss_host, override_gss_mech,
                                         host_based_auth, public_key_auth,
                                         override_pk_ok, password_auth,
                                         password_change_prompt, kbdint_auth,
                                         kbdint_challenge, success), False)

        self._gss = GSSClient(gss_host, False) if gss_host else None

        self._client_host_key = client_host_key
        self._client_host_cert = client_host_cert

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
            raise ValueError('Invalid auth method')

    def connection_lost(self, exc=None):
        """Handle the closing of a connection"""

        if exc:
            self._auth_waiter.set_exception(exc)

        self.close()

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
            self._auth.process_packet(pkttype, None, packet)

    async def get_auth_result(self):
        """Return the result of the authentication"""

        return await self._auth_waiter

    def try_next_auth(self):
        """Handle a request to move to another form of auth"""

        # Report that the current auth attempt failed
        self._auth_waiter.set_result((False, self._password_changed))
        self._auth = None
        self._auth_waiter = None

    async def send_userauth_request(self, method, *args, key=None,
                                    trivial=True):
        """Send a user authentication request"""

        packet = self._get_userauth_request_packet(method, args)

        if key:
            packet += String(key.sign(String('') + packet))

        self.send_userauth_packet(MSG_USERAUTH_REQUEST, packet[1:],
                                  trivial=trivial)

    def get_gss_context(self):
        """Return the GSS context associated with this connection"""

        return self._gss

    def gss_mic_auth_requested(self):
        """Return whether to allow GSS MIC authentication or not"""

        return bool(self._gss)

    async def host_based_auth_requested(self):
        """Return a host key pair, host, and user to authenticate with"""

        if self._client_host_key:
            keypair = asyncssh.load_keypairs((self._client_host_key,
                                              self._client_host_cert))[0]
        else:
            keypair = None

        return keypair, 'host', 'user'

    async def public_key_auth_requested(self):
        """Return key to use for public key authentication"""

        if self._client_key:
            return asyncssh.load_keypairs((self._client_key,
                                           self._client_cert))[0]
        else:
            return None

    async def password_auth_requested(self):
        """Return password to send for password authentication"""

        return self._password

    async def password_change_requested(self, _prompt, _lang):
        """Return old & new passwords for password change"""

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

    async def kbdint_auth_requested(self):
        """Return submethods to send for keyboard-interactive authentication"""

        return self._kbdint_submethods

    async def kbdint_challenge_received(self, _name, _instruction,
                                        _lang, _prompts):
        """Return responses to keyboard-interactive challenge"""

        if self._kbdint_response is True:
            return ('password',)
        else:
            return self._kbdint_response


class _AuthServerStub(_AuthConnectionStub):
    """Stub class for server connection"""

    def __init__(self, peer=None, gss_host=None, override_gss_mech=False,
                 host_based_auth=False, public_key_auth=False,
                 override_pk_ok=False, password_auth=False,
                 password_change_prompt=None, kbdint_auth=False,
                 kbdint_challenge=False, success=False):
        super().__init__(peer, True)

        self._gss = GSSServer(gss_host) if gss_host else None
        self._override_gss_mech = override_gss_mech

        self._host_based_auth = host_based_auth

        self._public_key_auth = public_key_auth
        self._override_pk_ok = override_pk_ok

        self._password_auth = password_auth
        self._password_change_prompt = password_change_prompt

        self._kbdint_auth = kbdint_auth
        self._kbdint_challenge = kbdint_challenge

        self._success = success

        self._auth = None

    def connection_lost(self, exc=None):
        """Handle the closing of a connection"""

        if self._peer:
            self._peer.connection_lost(exc)

        self.close()

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

            if self._override_gss_mech:
                self.send_userauth_packet(MSG_USERAUTH_GSSAPI_RESPONSE,
                                          String('mismatch'))
            elif self._override_pk_ok:
                self.send_userauth_packet(MSG_USERAUTH_PK_OK, String(''),
                                          String(''))
            else:
                self._auth = lookup_server_auth(self, 'user', method, packet)
        else:
            self._auth.process_packet(pkttype, None, packet)

    def send_userauth_failure(self, partial_success):
        """Send a user authentication failure response"""

        self._auth = None
        self.send_userauth_packet(MSG_USERAUTH_FAILURE, NameList([]),
                                  Boolean(partial_success))

    def send_userauth_success(self):
        """Send a user authentication success response"""

        self._auth = None
        self.send_userauth_packet(MSG_USERAUTH_SUCCESS)

    def get_gss_context(self):
        """Return the GSS context associated with this connection"""

        return self._gss

    def gss_kex_auth_supported(self):
        """Return whether or not GSS key exchange authentication is supported"""

        return bool(self._gss)

    def gss_mic_auth_supported(self):
        """Return whether or not GSS MIC authentication is supported"""

        return bool(self._gss)

    async def validate_gss_principal(self, _username, _user_principal,
                                     _host_principal):
        """Validate the GSS principal name for the specified user"""

        return self._success

    def host_based_auth_supported(self):
        """Return whether or not host-based authentication is supported"""

        return self._host_based_auth

    async def validate_host_based_auth(self, _username, _key_data, _client_host,
                                       _client_username, _msg, _signature):
        """Validate host based authentication for the specified host and user"""

        return self._success

    def public_key_auth_supported(self):
        """Return whether or not public key authentication is supported"""

        return self._public_key_auth

    async def validate_public_key(self, _username, _key_data, _msg, _signature):
        """Validate public key"""

        return self._success

    def password_auth_supported(self):
        """Return whether or not password authentication is supported"""

        return self._password_auth

    async def validate_password(self, _username, _password):
        """Validate password"""

        if self._password_change_prompt:
            raise asyncssh.PasswordChangeRequired(self._password_change_prompt)
        else:
            return self._success

    async def change_password(self, _username, _old_password, _new_password):
        """Validate password"""

        return self._success

    def kbdint_auth_supported(self):
        """Return whether or not keyboard-interactive authentication
           is supported"""

        return self._kbdint_auth

    async def get_kbdint_challenge(self, _username, _lang, _submethods):
        """Return a keyboard-interactive challenge"""

        if self._kbdint_challenge is True:
            return '', '', '', (('Password:', False),)
        else:
            return self._kbdint_challenge

    async def validate_kbdint_response(self, _username, _responses):
        """Validate keyboard-interactive responses"""

        return self._success


@patch_gss
class _TestAuth(AsyncTestCase):
    """Unit tests for auth module"""

    async def check_auth(self, method, expected_result, **kwargs):
        """Unit test authentication"""

        client_conn, server_conn = _AuthClientStub.make_pair(method, **kwargs)

        try:
            self.assertEqual((await client_conn.get_auth_result()),
                             expected_result)
        finally:
            client_conn.close()
            server_conn.close()

    @asynctest
    async def test_client_auth_methods(self):
        """Test client auth methods"""

        with self.subTest('Unknown client auth method'):
            with self.assertRaises(ValueError):
                _AuthClientStub.make_pair(b'xxx')

    @asynctest
    async def test_server_auth_methods(self):
        """Test server auth methods"""

        with self.subTest('No auth methods'):
            server_conn = _AuthServerStub()
            self.assertEqual(
                get_supported_server_auth_methods(server_conn), [])
            server_conn.close()

        with self.subTest('All auth methods'):
            gss_host = '1' if gss_available else None
            server_conn = _AuthServerStub(
                gss_host=gss_host, host_based_auth=True, public_key_auth=True,
                password_auth=True, kbdint_auth=True)

            if gss_available: # pragma: no branch
                self.assertEqual(
                    get_supported_server_auth_methods(server_conn),
                    [b'gssapi-keyex', b'gssapi-with-mic', b'hostbased',
                     b'publickey', b'keyboard-interactive', b'password'])
            else: # pragma: no cover
                self.assertEqual(
                    get_supported_server_auth_methods(server_conn),
                    [b'hostbased', b'publickey',
                     b'keyboard-interactive', b'password'])

            server_conn.close()

        with self.subTest('Unknown auth method'):
            server_conn = _AuthServerStub()
            self.assertEqual(lookup_server_auth(server_conn, 'user', b'xxx',
                                                SSHPacket(b'')), None)
            server_conn.close()

    @asynctest
    async def test_null_auth(self):
        """Unit test null authentication"""

        await self.check_auth(b'none', (False, None))

    @unittest.skipUnless(gss_available, 'GSS not available')
    @asynctest
    async def test_gss_auth(self):
        """Unit test GSS authentication"""

        with self.subTest('GSS with MIC auth not available'):
            await self.check_auth(b'gssapi-with-mic', (False, None))

        for steps in range(4):
            with self.subTest('GSS with MIC auth available'):
                await self.check_auth(b'gssapi-with-mic', (True, None),
                                      gss_host=str(steps), success=True)

            gss_host = str(steps) + ',step_error'

            with self.subTest('GSS with MIC error', steps=steps):
                await self.check_auth(b'gssapi-with-mic', (False, None),
                                      gss_host=gss_host)

            with self.subTest('GSS with MIC error with token', steps=steps):
                await self.check_auth(b'gssapi-with-mic', (False, None),
                                      gss_host=gss_host + ',errtok')

        with self.subTest('GSS with MIC without integrity'):
            await self.check_auth(b'gssapi-with-mic', (True, None),
                                  gss_host='1,no_client_integrity,' +
                                  'no_server_integrity', success=True)

        with self.subTest('GSS client integrity mismatch'):
            await self.check_auth(b'gssapi-with-mic', (False, None),
                                  gss_host='1,no_client_integrity')

        with self.subTest('GSS server integrity mismatch'):
            await self.check_auth(b'gssapi-with-mic', (False, None),
                                  gss_host='1,no_server_integrity')

        with self.subTest('GSS mechanism unknown'):
            await self.check_auth(b'gssapi-with-mic', (False, None),
                                  gss_host='1,unknown_mech')

        with self.subTest('GSS mechanism mismatch'):
            with self.assertRaises(asyncssh.ProtocolError):
                await self.check_auth(b'gssapi-with-mic', (False, None),
                                      gss_host='1', override_gss_mech=True)

    @asynctest
    async def test_hostbased_auth(self):
        """Unit test host-based authentication"""

        hkey = get_test_key('ecdsa-sha2-nistp256')
        cert = hkey.generate_host_certificate(hkey, 'host')

        with self.subTest('Host-based auth not available'):
            await self.check_auth(b'hostbased', (False, None))

        with self.subTest('Untrusted key'):
            await self.check_auth(b'hostbased', (False, None),
                                  client_host_key=hkey, host_based_auth=True)

        with self.subTest('Trusted key'):
            await self.check_auth(b'hostbased', (True, None),
                                  client_host_key=hkey,
                                  host_based_auth=True, success=True)

        with self.subTest('Trusted certificate'):
            await self.check_auth(b'hostbased', (True, None),
                                  client_host_key=hkey, client_host_cert=cert,
                                  host_based_auth=True, success=True)

    @asynctest
    async def test_publickey_auth(self):
        """Unit test public key authentication"""

        ckey = get_test_key('ecdsa-sha2-nistp256')
        cert = ckey.generate_user_certificate(ckey, 'name')

        with self.subTest('Public key auth not available'):
            await self.check_auth(b'publickey', (False, None))

        with self.subTest('Untrusted key'):
            await self.check_auth(b'publickey', (False, None), client_key=ckey,
                                  public_key_auth=True)

        with self.subTest('Trusted key'):
            await self.check_auth(b'publickey', (True, None), client_key=ckey,
                                  public_key_auth=True, success=True)

        with self.subTest('Trusted certificate'):
            await self.check_auth(b'publickey', (True, None), client_key=ckey,
                                  client_cert=cert, public_key_auth=True,
                                  success=True)

        with self.subTest('Invalid PK_OK message'):
            with self.assertRaises(asyncssh.ProtocolError):
                await self.check_auth(b'publickey', (False, None),
                                      client_key=ckey, public_key_auth=True,
                                      override_pk_ok=True)

    @asynctest
    async def test_password_auth(self):
        """Unit test password authentication"""

        with self.subTest('Password auth not available'):
            await self.check_auth(b'password', (False, None))

        with self.subTest('Invalid password'):
            with self.assertRaises(asyncssh.ProtocolError):
                await self.check_auth(b'password', (False, None),
                                      password_auth=True, password=b'\xff')

        with self.subTest('Incorrect password'):
            await self.check_auth(b'password', (False, None),
                                  password_auth=True, password='password')

        with self.subTest('Correct password'):
            await self.check_auth(b'password', (True, None),
                                  password_auth=True, password='password',
                                  success=True)

        with self.subTest('Password change not available'):
            await self.check_auth(b'password', (False, None),
                                  password_auth=True, password='password',
                                  password_change_prompt='change')

        with self.subTest('Invalid password change prompt'):
            with self.assertRaises(asyncssh.ProtocolError):
                await self.check_auth(b'password', (False, False),
                                      password_auth=True, password='password',
                                      password_change=True,
                                      password_change_prompt=b'\xff')

        with self.subTest('Password change failed'):
            await self.check_auth(b'password', (False, False),
                                  password_auth=True, password='password',
                                  password_change=True,
                                  password_change_prompt='change')

        with self.subTest('Password change succeeded'):
            await self.check_auth(b'password', (True, True),
                                  password_auth=True, password='password',
                                  password_change=True,
                                  password_change_prompt='change', success=True)

    @asynctest
    async def test_kbdint_auth(self):
        """Unit test keyboard-interactive authentication"""

        with self.subTest('Kbdint auth not available'):
            await self.check_auth(b'keyboard-interactive', (False, None))

        with self.subTest('No submethods'):
            await self.check_auth(b'keyboard-interactive', (False, None),
                                  kbdint_auth=True)

        with self.subTest('Invalid submethods'):
            with self.assertRaises(asyncssh.ProtocolError):
                await self.check_auth(b'keyboard-interactive', (False, None),
                                      kbdint_auth=True,
                                      kbdint_submethods=b'\xff')

        with self.subTest('No challenge'):
            await self.check_auth(b'keyboard-interactive', (False, None),
                                  kbdint_auth=True, kbdint_submethods='')

        with self.subTest('Invalid challenge name'):
            with self.assertRaises(asyncssh.ProtocolError):
                await self.check_auth(b'keyboard-interactive', (False, None),
                                      kbdint_auth=True, kbdint_submethods='',
                                      kbdint_challenge=(b'\xff', '', '', ()))

        with self.subTest('Invalid challenge prompt'):
            with self.assertRaises(asyncssh.ProtocolError):
                await self.check_auth(b'keyboard-interactive', (False, None),
                                      kbdint_auth=True, kbdint_submethods='',
                                      kbdint_challenge=('', '', '',
                                                        ((b'\xff', False),)))

        with self.subTest('No response'):
            await self.check_auth(b'keyboard-interactive', (False, None),
                                  kbdint_auth=True, kbdint_submethods='',
                                  kbdint_challenge=True)

        with self.subTest('Invalid response'):
            with self.assertRaises(asyncssh.ProtocolError):
                await self.check_auth(b'keyboard-interactive', (False, None),
                                      kbdint_auth=True, kbdint_submethods='',
                                      kbdint_challenge=True,
                                      kbdint_response=(b'\xff',))

        with self.subTest('Incorrect response'):
            await self.check_auth(b'keyboard-interactive', (False, None),
                                  kbdint_auth=True, kbdint_submethods='',
                                  kbdint_challenge=True, kbdint_response=True)

        with self.subTest('Correct response'):
            await self.check_auth(b'keyboard-interactive', (True, None),
                                  kbdint_auth=True, kbdint_submethods='',
                                  kbdint_challenge=True, kbdint_response=True,
                                  success=True)
