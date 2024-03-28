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

"""Unit tests for AsyncSSH connection authentication"""

import asyncio
import os
import unittest

from unittest.mock import patch

from cryptography.exceptions import UnsupportedAlgorithm

import asyncssh
from asyncssh.misc import async_context_manager, write_file
from asyncssh.packet import String
from asyncssh.public_key import CERT_TYPE_USER, CERT_TYPE_HOST

from .keysign_stub import create_subprocess_exec_stub
from .server import Server, ServerTestCase
from .util import asynctest, gss_available, patch_getnameinfo, patch_gss
from .util import make_certificate, nc_available, x509_available


class _FailValidateHostSSHServerConnection(asyncssh.SSHServerConnection):
    """Test error in validating host key signature"""

    async def validate_host_based_auth(self, username, key_data, client_host,
                                       client_username, msg, signature):
        """Validate host based authentication for the specified host and user"""

        return await super().validate_host_based_auth(username, key_data,
                                                      client_host,
                                                      client_username,
                                                      msg + b'\xff', signature)


class _AsyncGSSServer(asyncssh.SSHServer):
    """Server for testing async GSS authentication"""

    # pylint: disable=useless-super-delegation

    async def validate_gss_principal(self, username, user_principal,
                                     host_principal):
        """Return whether password is valid for this user"""

        return super().validate_gss_principal(username, user_principal,
                                              host_principal)


class _NullServer(Server):
    """Server for testing disabled auth"""

    async def begin_auth(self, username):
        """Handle client authentication request"""

        return False


class _HostBasedServer(Server):
    """Server for testing host-based authentication"""

    def __init__(self, host_key=None, ca_key=None):
        super().__init__()

        self._host_key = \
            asyncssh.read_public_key(host_key) if host_key else None
        self._ca_key = \
            asyncssh.read_public_key(ca_key) if ca_key else None

    def host_based_auth_supported(self):
        """Return whether or not host based authentication is supported"""

        return True

    def validate_host_public_key(self, client_host, client_addr,
                                 client_port, key):
        """Return whether key is an authorized key for this host"""

        # pylint: disable=unused-argument

        return key == self._host_key

    def validate_host_ca_key(self, client_host, client_addr, client_port, key):
        """Return whether key is an authorized CA key for this host"""

        # pylint: disable=unused-argument

        return key == self._ca_key

    def validate_host_based_user(self, username, client_host, client_username):
        """Return whether remote host and user is authorized for this user"""

        # pylint: disable=unused-argument

        return client_username == 'user'


class _AsyncHostBasedServer(Server):
    """Server for testing async host-based authentication"""

    # pylint: disable=useless-super-delegation

    async def validate_host_based_user(self, username, client_host,
                                       client_username):
        """Return whether remote host and user is authorized for this user"""

        return super().validate_host_based_user(username, client_host,
                                                client_username)


class _InvalidUsernameClientConnection(asyncssh.connection.SSHClientConnection):
    """Test sending a client username with invalid Unicode to the server"""

    async def host_based_auth_requested(self):
        """Return a host key pair, host, and user to authenticate with"""

        keypair, host, _ = await super().host_based_auth_requested()

        return keypair, host, b'\xff'


class _PublicKeyClient(asyncssh.SSHClient):
    """Test client public key authentication"""

    def __init__(self, keylist, delay=0):
        self._keylist = keylist
        self._delay = delay

    async def public_key_auth_requested(self):
        """Return a public key to authenticate with"""

        if self._delay:
            await asyncio.sleep(self._delay)

        return self._keylist.pop(0) if self._keylist else None


class _AsyncPublicKeyClient(_PublicKeyClient):
    """Test async client public key authentication"""

    # pylint: disable=useless-super-delegation

    async def public_key_auth_requested(self):
        """Return a public key to authenticate with"""

        return await super().public_key_auth_requested()


class _PublicKeyServer(Server):
    """Server for testing public key authentication"""

    def __init__(self, client_keys=(), authorized_keys=None, delay=0):
        super().__init__()
        self._client_keys = client_keys
        self._authorized_keys = authorized_keys
        self._delay = delay

    def connection_made(self, conn):
        """Called when a connection is made"""

        super().connection_made(conn)
        conn.send_auth_banner('auth banner')

    async def begin_auth(self, username):
        """Handle client authentication request"""

        if self._authorized_keys:
            self._conn.set_authorized_keys(self._authorized_keys)
        else:
            self._client_keys = asyncssh.load_public_keys(self._client_keys)

        if self._delay:
            await asyncio.sleep(self._delay)

        return True

    def public_key_auth_supported(self):
        """Return whether or not public key authentication is supported"""

        return True

    def validate_public_key(self, username, key):
        """Return whether key is an authorized client key for this user"""

        return key in self._client_keys

    def validate_ca_key(self, username, key):
        """Return whether key is an authorized CA key for this user"""

        return key in self._client_keys


class _AsyncPublicKeyServer(_PublicKeyServer):
    """Server for testing async public key authentication"""

    # pylint: disable=useless-super-delegation

    async def begin_auth(self, username):
        """Handle client authentication request"""

        return await super().begin_auth(username)

    async def validate_public_key(self, username, key):
        """Return whether key is an authorized client key for this user"""

        return super().validate_public_key(username, key)

    async def validate_ca_key(self, username, key):
        """Return whether key is an authorized CA key for this user"""

        return super().validate_ca_key(username, key)


class _PasswordClient(asyncssh.SSHClient):
    """Test client password authentication"""

    def __init__(self, password, old_password, new_password):
        self._password = password
        self._old_password = old_password
        self._new_password = new_password

    def password_auth_requested(self):
        """Return a password to authenticate with"""

        if self._password:
            result = self._password
            self._password = None
            return result
        else:
            return None

    def password_change_requested(self, prompt, lang):
        """Change the client's password"""

        return self._old_password, self._new_password


class _AsyncPasswordClient(_PasswordClient):
    """Test async client password authentication"""

    # pylint: disable=useless-super-delegation

    async def password_auth_requested(self):
        """Return a password to authenticate with"""

        return super().password_auth_requested()

    async def password_change_requested(self, prompt, lang):
        """Change the client's password"""

        return super().password_change_requested(prompt, lang)


class _PasswordServer(Server):
    """Server for testing password authentication"""

    def password_auth_supported(self):
        """Enable password authentication"""

        return True

    def validate_password(self, username, password):
        """Accept password of pw, trigger password change on oldpw"""

        if password == 'oldpw':
            raise asyncssh.PasswordChangeRequired('Password change required')
        else:
            return password == 'pw'

    def change_password(self, username, old_password, new_password):
        """Only allow password change from password oldpw"""

        return old_password == 'oldpw'


class _AsyncPasswordServer(_PasswordServer):
    """Server for testing async password authentication"""

    # pylint: disable=useless-super-delegation

    async def validate_password(self, username, password):
        """Return whether password is valid for this user"""

        return super().validate_password(username, password)

    async def change_password(self, username, old_password, new_password):
        """Handle a request to change a user's password"""

        return super().change_password(username, old_password, new_password)


class _KbdintClient(asyncssh.SSHClient):
    """Test keyboard-interactive client auth"""

    def __init__(self, responses):
        self._responses = responses

    def kbdint_auth_requested(self):
        """Return the list of supported keyboard-interactive auth methods"""

        return '' if self._responses else None

    def kbdint_challenge_received(self, name, instructions, lang, prompts):
        """Return responses to a keyboard-interactive auth challenge"""

        # pylint: disable=unused-argument

        if not prompts:
            return []
        elif self._responses:
            result = self._responses
            self._responses = None
            return result
        else:
            return None


class _AsyncKbdintClient(_KbdintClient):
    """Test keyboard-interactive client auth"""

    # pylint: disable=useless-super-delegation

    async def kbdint_auth_requested(self):
        """Return the list of supported keyboard-interactive auth methods"""

        return super().kbdint_auth_requested()

    async def kbdint_challenge_received(self, name, instructions,
                                        lang, prompts):
        """Return responses to a keyboard-interactive auth challenge"""

        return super().kbdint_challenge_received(name, instructions,
                                                 lang, prompts)


class _KbdintServer(Server):
    """Server for testing keyboard-interactive authentication"""

    def __init__(self):
        super().__init__()
        self._kbdint_round = 0

    def kbdint_auth_supported(self):
        """Enable keyboard-interactive authentication"""

        return True

    def get_kbdint_challenge(self, username, lang, submethods):
        """Return an initial challenge with only instructions"""

        return '', 'instructions', '', []

    def validate_kbdint_response(self, username, responses):
        """Return a password challenge after the instructions"""

        if self._kbdint_round == 0:
            if username == 'none':
                result = ('', '', '', [])
            elif username == 'pw':
                result = ('', '', '', [('Password:', False)])
            elif username == 'pc':
                result = ('', '', '', [('Passcode:', False)])
            elif username == 'multi':
                result = ('', '', '', [('Prompt1:', True), ('Prompt2', True)])
            else:
                result = ('', '', '', [('Other Challenge:', False)])
        else:
            if responses in ([], ['kbdint'], ['1', '2']):
                result = True
            else:
                result = ('', '', '', [('Second Challenge:', True)])

        self._kbdint_round += 1
        return result


class _AsyncKbdintServer(_KbdintServer):
    """Server for testing async keyboard-interactive authentication"""

    # pylint: disable=useless-super-delegation

    async def get_kbdint_challenge(self, username, lang, submethods):
        """Return a keyboard-interactive auth challenge"""

        return super().get_kbdint_challenge(username, lang, submethods)

    async def validate_kbdint_response(self, username, responses):
        """Return whether the keyboard-interactive response is valid
           for this user"""

        return super().validate_kbdint_response(username, responses)


class _UnknownAuthClientConnection(asyncssh.connection.SSHClientConnection):
    """Test getting back an unknown auth method from the SSH server"""

    def try_next_auth(self):
        """Attempt client authentication using an unknown method"""

        self._auth_methods = [b'unknown'] + self._auth_methods
        super().try_next_auth()


class _TestNullAuth(ServerTestCase):
    """Unit tests for testing disabled authentication"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports disabled authentication"""

        return await cls.create_server(_NullServer)

    @asynctest
    async def test_get_server_auth_methods(self):
        """Test getting auth methods from the test server"""

        auth_methods = await asyncssh.get_server_auth_methods(
            self._server_addr, self._server_port)

        self.assertEqual(auth_methods, ['none'])

    @asynctest
    async def test_disabled_auth(self):
        """Test disabled authentication"""

        async with self.connect(username='user'):
            pass

    @asynctest
    async def test_disabled_trivial_auth(self):
        """Test disabling trivial auth with no authentication"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', disable_trivial_auth=True)


@unittest.skipUnless(gss_available, 'GSS not available')
@patch_gss
class _TestGSSAuth(ServerTestCase):
    """Unit tests for GSS authentication"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports GSS authentication"""

        return await cls.create_server(_AsyncGSSServer, gss_host='1')

    @asynctest
    async def test_get_server_auth_methods(self):
        """Test getting auth methods from the test server"""

        auth_methods = await asyncssh.get_server_auth_methods(
            self._server_addr, self._server_port)

        self.assertEqual(auth_methods, ['gssapi-with-mic'])

    @asynctest
    async def test_gss_kex_auth(self):
        """Test GSS key exchange authentication"""

        async with self.connect(kex_algs=['gss-gex-sha256'],
                                username='user', gss_host='1'):
            pass

    @asynctest
    async def test_gss_mic_auth(self):
        """Test GSS MIC authentication"""

        async with self.connect(kex_algs=['ecdh-sha2-nistp256'],
                                username='user', gss_host='1'):
            pass

    @asynctest
    async def test_gss_mic_auth_sign_error(self):
        """Test GSS MIC authentication signing failure"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(kex_algs=['ecdh-sha2-nistp256'],
                               username='user', gss_host='1,sign_error')

    @asynctest
    async def test_gss_mic_auth_verify_error(self):
        """Test GSS MIC authentication signature verification failure"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(kex_algs=['ecdh-sha2-nistp256'],
                               username='user', gss_host='1,verify_error')

    @asynctest
    async def test_gss_delegate(self):
        """Test GSS credential delegation"""

        async with self.connect(username='user', gss_host='1',
                                gss_delegate_creds=True):
            pass

    @asynctest
    async def test_gss_kex_disabled(self):
        """Test GSS key exchange being disabled"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', gss_host=(), gss_kex=False,
                               preferred_auth='gssapi-keyex')

    @asynctest
    async def test_gss_auth_disabled(self):
        """Test GSS authentication being disabled"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', gss_host=(), gss_auth=False)

    @asynctest
    async def test_gss_auth_unavailable(self):
        """Test GSS authentication being unavailable"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user1', gss_host=())

    @asynctest
    async def test_gss_client_error(self):
        """Test GSS client error"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(gss_host='1,init_error', username='user')

    @asynctest
    async def test_disabled_trivial_gss_kex_auth(self):
        """Test disabling trivial auth with GSS key exchange authentication"""

        async with self.connect(kex_algs=['gss-gex-sha256'],
                                username='user', gss_host='1',
                                disable_trivial_auth=True):
            pass

    @asynctest
    async def test_disabled_trivial_gss_mic_auth(self):
        """Test disabling trivial auth with GSS MIC authentication"""

        async with self.connect(kex_algs=['ecdh-sha2-nistp256'],
                                username='user', gss_host='1',
                                disable_trivial_auth=True):
            pass


@unittest.skipUnless(gss_available, 'GSS not available')
@patch_gss
class _TestGSSServerAuthDisabled(ServerTestCase):
    """Unit tests for with GSS key exchange and auth disabled on server"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server with GSS key exchange and auth disabled"""

        return await cls.create_server(gss_host='1', gss_kex=False,
                                       gss_auth=False)

    @asynctest
    async def test_gss_kex_unavailable(self):
        """Test GSS key exchange being unavailable"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', gss_host=(),
                               preferred_auth='gssapi-keyex')

    @asynctest
    async def test_gss_auth_unavailable(self):
        """Test GSS authentication being unavailable"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', gss_host=(),
                               preferred_auth='gssapi-with-mic')



@unittest.skipUnless(gss_available, 'GSS not available')
@patch_gss
class _TestGSSServerError(ServerTestCase):
    """Unit tests for GSS server error"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which raises an error on GSS authentication"""

        return await cls.create_server(gss_host='1,init_error')

    @asynctest
    async def test_gss_server_error(self):
        """Test GSS error on server"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user')


@unittest.skipUnless(gss_available, 'GSS not available')
@patch_gss
class _TestGSSFQDN(ServerTestCase):
    """Unit tests for GSS server error"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which raises an error on GSS authentication"""

        def mock_gethostname():
            """Return a non-fully-qualified hostname"""

            return 'host'

        def mock_getfqdn():
            """Confirm getfqdn is called on relative hostnames"""

            return '1'

        with patch('socket.gethostname', mock_gethostname):
            with patch('socket.getfqdn', mock_getfqdn):
                return await cls.create_server(gss_host=())

    @asynctest
    async def test_gss_fqdn_lookup(self):
        """Test GSS FQDN lookup"""

        async with self.connect(username='user', gss_host=()):
            pass


@patch_getnameinfo
class _TestHostBasedAuth(ServerTestCase):
    """Unit tests for host-based authentication"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports host-based authentication"""

        return await cls.create_server(
            _HostBasedServer, known_client_hosts='known_hosts')

    @asynctest
    async def test_get_server_auth_methods(self):
        """Test getting auth methods from the test server"""

        auth_methods = await asyncssh.get_server_auth_methods(
            self._server_addr, self._server_port, username='user')

        self.assertEqual(auth_methods, ['hostbased'])

    @unittest.skipUnless(nc_available, 'Netcat not available')
    @asynctest
    async def test_get_server_auth_methods_no_sockname(self):
        """Test getting auth methods from the test server"""

        proxy_command = ('nc', str(self._server_addr), str(self._server_port))

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', client_host_keys='skey',
                               proxy_command=proxy_command)

    @asynctest
    async def test_client_host_auth(self):
        """Test connecting with host-based authentication"""

        async with self.connect(username='user', client_host_keys='skey',
                                client_username='user'):
            pass

    @asynctest
    async def test_client_host_auth_disabled(self):
        """Test connecting with host-based authentication disabled"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', client_host_keys='skey',
                               client_username='user', host_based_auth=False)

    @asynctest
    async def test_client_host_key_bytes(self):
        """Test client host key passed in as bytes"""

        with open('skey', 'rb') as f:
            skey = f.read()

        async with self.connect(username='user', client_host_keys=[skey],
                                client_username='user'):
            pass

    @asynctest
    async def test_client_host_key_sshkey(self):
        """Test client host key passed in as an SSHKey"""

        skey = asyncssh.read_private_key('skey')

        async with self.connect(username='user', client_host_keys=[skey],
                                client_username='user'):
            pass

    @asynctest
    async def test_client_host_key_keypairs(self):
        """Test client host keys passed in as a list of SSHKeyPairs"""

        keys = asyncssh.load_keypairs('skey')

        async with self.connect(username='user', client_host_keys=keys,
                                client_username='user'):
            pass

    @asynctest
    async def test_client_host_signature_algs(self):
        """Test host based authentication with specific signature algorithms"""

        for alg in ('rsa-sha2-256', 'rsa-sha2-512'):
            async with self.connect(username='user', client_host_keys='skey',
                                    client_username='user',
                                    signature_algs=[alg]):
                pass

    @asynctest
    async def test_no_server_signature_algs(self):
        """Test a server which doesn't advertise signature algorithms"""

        def skip_ext_info(self):
            """Don't send extension information"""

            # pylint: disable=unused-argument

            return []

        with patch('asyncssh.connection.SSHConnection._get_extra_kex_algs',
                   skip_ext_info):
            try:
                async with self.connect(username='user',
                                        client_host_keys='skey',
                                        client_username='user'):
                    pass
            except UnsupportedAlgorithm: # pragma: no cover
                pass

    @asynctest
    async def test_untrusted_client_host_key(self):
        """Test untrusted client host key"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', client_host_keys='ckey',
                               client_username='user')

    @asynctest
    async def test_missing_cert(self):
        """Test missing client host certificate"""

        with self.assertRaises(OSError):
            await self.connect(username='user',
                               client_host_keys=[('skey', 'xxx')],
                               client_username='user')

    @asynctest
    async def test_invalid_client_host_signature(self):
        """Test invalid client host signature"""

        with patch('asyncssh.connection.SSHServerConnection',
                   _FailValidateHostSSHServerConnection):
            with self.assertRaises(asyncssh.PermissionDenied):
                await self.connect(username='user', client_host_keys='skey',
                                   client_username='user')

    @asynctest
    async def test_client_host_trailing_dot(self):
        """Test stripping of trailing dot from client host"""

        async with self.connect(username='user', client_host_keys='skey',
                                client_host='localhost.',
                                client_username='user'):
            pass

    @asynctest
    async def test_mismatched_client_host(self):
        """Test ignoring of mismatched client host due to canonicalization"""

        async with self.connect(username='user', client_host_keys='skey',
                                client_host='xxx', client_username='user'):
            pass

    @asynctest
    async def test_mismatched_client_username(self):
        """Test mismatched client username"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', client_host_keys='skey',
                               client_username='xxx')

    @asynctest
    async def test_invalid_client_username(self):
        """Test invalid client username"""

        with patch('asyncssh.connection.SSHClientConnection',
                   _InvalidUsernameClientConnection):
            with self.assertRaises(asyncssh.ProtocolError):
                await self.connect(username='user', client_host_keys='skey')

    @asynctest
    async def test_expired_cert(self):
        """Test expired certificate"""

        ckey = asyncssh.read_private_key('ckey')
        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_HOST, ckey, skey, ['localhost'],
                                valid_before=1)

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', client_host_keys=[(ckey, cert)],
                               client_username='user')

    @asynctest
    async def test_untrusted_ca(self):
        """Test untrusted CA"""

        ckey = asyncssh.read_private_key('ckey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_HOST, ckey, ckey, ['localhost'])

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', client_host_keys=[(ckey, cert)],
                               client_username='user')

    @asynctest
    async def test_disabled_trivial_client_host_auth(self):
        """Test disabling trivial auth with host-based authentication"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', client_host_keys='skey',
                               client_username='user',
                               disable_trivial_auth=True)


@patch_getnameinfo
class _TestCallbackHostBasedAuth(ServerTestCase):
    """Unit tests for host-based authentication using callback"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports host-based authentication"""

        def server_factory():
            """Return an SSHServer which can validate the client host key"""

            return _HostBasedServer(host_key='skey.pub', ca_key='skey.pub')

        return await cls.create_server(server_factory)

    @asynctest
    async def test_validate_client_host_callback(self):
        """Test using callback to validate client host key"""

        async with self.connect(username='user',
                                client_host_keys=[('skey', None)],
                                client_username='user'):
            pass

    @asynctest
    async def test_validate_client_host_ca_callback(self):
        """Test using callback to validate client host CA key"""

        async with self.connect(username='user', client_host_keys='skey',
                                client_username='user'):
            pass

    @asynctest
    async def test_untrusted_client_host_callback(self):
        """Test callback to validate client host key returning failure"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user',
                               client_host_keys=[('ckey', None)],
                               client_username='user')

    @asynctest
    async def test_untrusted_client_host_ca_callback(self):
        """Test callback to validate client host CA key returning failure"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', client_host_keys='ckey',
                               client_username='user')


@patch_getnameinfo
class _TestKeysignHostBasedAuth(ServerTestCase):
    """Unit tests for host-based authentication using ssh-keysign"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports host-based authentication"""

        return await cls.create_server(
            _HostBasedServer, known_client_hosts=(['skey_ecdsa.pub'], [], []))

    @async_context_manager
    async def _connect_keysign(self, client_host_keysign=True,
                               client_host_keys=None, keysign_dirs=('.',)):
        """Open a connection to test host-based auth using ssh-keysign"""

        with patch('asyncio.create_subprocess_exec',
                   create_subprocess_exec_stub):
            with patch('asyncssh.keysign._DEFAULT_KEYSIGN_DIRS', keysign_dirs):
                with patch('asyncssh.public_key._DEFAULT_HOST_KEY_DIRS', ['.']):
                    with patch('asyncssh.public_key._DEFAULT_HOST_KEY_FILES',
                               ['skey_ecdsa', 'xxx']):
                        return await self.connect(
                            username='user',
                            client_host_keysign=client_host_keysign,
                            client_host_keys=client_host_keys,
                            client_username='user')

    @asynctest
    async def test_keysign(self):
        """Test host-based authentication using ssh-keysign"""

        async with self._connect_keysign():
            pass

    @asynctest
    async def test_explciit_keysign(self):
        """Test ssh-keysign with an explicit path"""

        async with self._connect_keysign(client_host_keysign='.'):
            pass

    @asynctest
    async def test_keysign_explicit_host_keys(self):
        """Test ssh-keysign with explicit host public keys"""

        async with self._connect_keysign(client_host_keys='skey_ecdsa.pub'):
            pass

    @asynctest
    async def test_invalid_keysign_response(self):
        """Test invalid ssh-keysign response"""

        with patch('asyncssh.keysign.KEYSIGN_VERSION', 0):
            with self.assertRaises(asyncssh.PermissionDenied):
                await self._connect_keysign()

    @asynctest
    async def test_keysign_error(self):
        """Test ssh-keysign error response"""

        with patch('asyncssh.keysign.KEYSIGN_VERSION', 1):
            with self.assertRaises(asyncssh.PermissionDenied):
                await self._connect_keysign()

    @asynctest
    async def test_invalid_keysign_version(self):
        """Test invalid version in ssh-keysign request"""

        with patch('asyncssh.keysign.KEYSIGN_VERSION', 99):
            with self.assertRaises(asyncssh.PermissionDenied):
                await self._connect_keysign()

    @asynctest
    async def test_keysign_not_found(self):
        """Test ssh-keysign executable not being found"""

        with self.assertRaises(ValueError):
            await self._connect_keysign(keysign_dirs=())

    @asynctest
    async def test_explicit_keysign_not_found(self):
        """Test explicit ssh-keysign executable not being found"""

        with self.assertRaises(ValueError):
            await self._connect_keysign(client_host_keysign='xxx')

    @asynctest
    async def test_keysign_dir_not_present(self):
        """Test ssh-keysign executable not in a keysign dir"""

        with self.assertRaises(ValueError):
            await self._connect_keysign(keysign_dirs=('xxx',))


@patch_getnameinfo
class _TestHostBasedAsyncServerAuth(_TestHostBasedAuth):
    """Unit tests for host-based authentication with async server callbacks"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports async host-based auth"""

        return await cls.create_server(_AsyncHostBasedServer,
                                       known_client_hosts='known_hosts',
                                       trust_client_host=True)

    @asynctest
    async def test_mismatched_client_host(self):
        """Test mismatch of trusted client host"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='user', client_host_keys='skey',
                               client_host='xxx', client_username='user')


@patch_getnameinfo
class _TestLimitedHostBasedSignatureAlgs(ServerTestCase):
    """Unit tests for limited host key signature algorithms"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports host-based authentication"""

        return await cls.create_server(
            _HostBasedServer, known_client_hosts='known_hosts',
            signature_algs=['ssh-rsa', 'rsa-sha2-512'])

    @asynctest
    async def test_mismatched_host_signature_algs(self):
        """Test mismatched host key signature algorithms"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_host_keys='skey',
                               client_username='user',
                               signature_algs=['rsa-sha2-256'])

    @asynctest
    async def test_host_signature_alg_fallback(self):
        """Test fall back to default host key signature algorithm"""

        try:
            async with self.connect(username='ckey', client_host_keys='skey',
                                    client_username='user',
                                    signature_algs=['rsa-sha2-256', 'ssh-rsa']):
                pass
        except UnsupportedAlgorithm: # pragma: no cover
            pass


class _TestPublicKeyAuth(ServerTestCase):
    """Unit tests for public key authentication"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        return await cls.create_server(
            _PublicKeyServer, authorized_client_keys='authorized_keys')

    @async_context_manager
    async def _connect_publickey(self, keylist, test_async=False):
        """Open a connection to test public key auth"""

        def client_factory():
            """Return an SSHClient to use to do public key auth"""

            cls = _AsyncPublicKeyClient if test_async else _PublicKeyClient
            return cls(keylist)

        conn, _ = await self.create_connection(client_factory, username='ckey',
                                               client_keys=None)

        return conn

    @asynctest
    async def test_get_server_auth_methods(self):
        """Test getting auth methods from the test server"""

        auth_methods = await asyncssh.get_server_auth_methods(
            self._server_addr, self._server_port)

        self.assertEqual(auth_methods, ['publickey'])

    @asynctest
    async def test_encrypted_client_key(self):
        """Test public key auth with encrypted client key"""

        async with self.connect(username='ckey', client_keys='ckey_encrypted',
                                passphrase='passphrase'):
            pass

    @asynctest
    async def test_encrypted_client_key_callable(self):
        """Test public key auth with callable passphrase"""

        def _passphrase(filename):
            self.assertEqual(filename, 'ckey_encrypted')
            return 'passphrase'

        async with self.connect(username='ckey', client_keys='ckey_encrypted',
                                passphrase=_passphrase):
            pass

    @asynctest
    async def test_encrypted_client_key_awaitable(self):
        """Test public key auth with awaitable passphrase"""

        async def _passphrase(filename):
            self.assertEqual(filename, 'ckey_encrypted')
            return 'passphrase'

        async with self.connect(username='ckey', client_keys='ckey_encrypted',
                                passphrase=_passphrase):
            pass

    @asynctest
    async def test_encrypted_client_key_list_callable(self):
        """Test public key auth with callable passphrase"""

        def _passphrase(filename):
            self.assertEqual(filename, 'ckey_encrypted')
            return 'passphrase'

        async with self.connect(username='ckey',
                                client_keys=['ckey_encrypted'],
                                passphrase=_passphrase):
            pass

    @asynctest
    async def test_encrypted_client_key_list_awaitable(self):
        """Test public key auth with awaitable passphrase"""

        async def _passphrase(filename):
            self.assertEqual(filename, 'ckey_encrypted')
            return 'passphrase'

        async with self.connect(username='ckey',
                                client_keys=['ckey_encrypted'],
                                passphrase=_passphrase):
            pass

    @asynctest
    async def test_encrypted_client_key_bad_passphrase(self):
        """Test wrong passphrase for encrypted client key"""

        with self.assertRaises(asyncssh.KeyEncryptionError):
            await self.connect(username='ckey', client_keys='ckey_encrypted',
                               passphrase='xxx')

    @asynctest
    async def test_encrypted_client_key_missing_passphrase(self):
        """Test missing passphrase for encrypted client key"""

        with self.assertRaises(asyncssh.KeyImportError):
            await self.connect(username='ckey', client_keys='ckey_encrypted')

    @asynctest
    async def test_client_certs(self):
        """Test trusted client certificate via client_certs"""

        async with self.connect(username='ckey', client_keys='ckey',
                                client_certs='ckey-cert.pub'):
            pass

    @asynctest
    async def test_agent_auth(self):
        """Test connecting with ssh-agent authentication"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        async with self.connect(username='ckey'):
            pass

    @asynctest
    async def test_agent_identities(self):
        """Test connecting with ssh-agent auth with specific identities"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        ckey = asyncssh.read_private_key('ckey')
        ckey.write_private_key('ckey.pem', 'pkcs8-pem')

        ckey_cert = asyncssh.read_certificate('ckey-cert.pub')
        ckey_ecdsa = asyncssh.read_public_key('ckey_ecdsa.pub')

        for pubkey in ('ckey-cert.pub', 'ckey_ecdsa.pub', 'ckey.pem',
                       ckey_cert, ckey_ecdsa, ckey_ecdsa.public_data):
            async with self.connect(username='ckey', agent_identities=pubkey):
                pass

    @asynctest
    async def test_agent_identities_config(self):
        """Test connecting with ssh-agent auth and IdentitiesOnly config"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        write_file('ckey_err', b'')

        write_file('config', 'IdentitiesOnly True\n'
                   'IdentityFile ckey-cert.pub\n'
                   'IdentityFile ckey_ecdsa.pub\n'
                   'IdentityFile ckey_err\n', 'w')

        async with self.connect(username='ckey', config='config'):
            pass

    @asynctest
    async def test_agent_identities_config_default_keys(self):
        """Test connecting with ssh-agent auth and default IdentitiesOnly"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        write_file('config', 'IdentitiesOnly True\n', 'w')

        async with self.connect(username='ckey', config='config'):
            pass

    @asynctest
    async def test_agent_signature_algs(self):
        """Test ssh-agent keys with specific signature algorithms"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        for alg in ('rsa-sha2-256', 'rsa-sha2-512'):
            async with self.connect(username='ckey', signature_algs=[alg]):
                pass

    @asynctest
    async def test_agent_auth_failure(self):
        """Test failure connecting with ssh-agent authentication"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        with patch.dict(os.environ, HOME='xxx'):
            with self.assertRaises(asyncssh.PermissionDenied):
                await self.connect(username='ckey', agent_path='xxx',
                                   known_hosts='.ssh/known_hosts')

    @asynctest
    async def test_agent_auth_unset(self):
        """Test connecting with no local keys and no ssh-agent configured"""

        with patch.dict(os.environ, HOME='xxx', SSH_AUTH_SOCK=''):
            with self.assertRaises(asyncssh.PermissionDenied):
                await self.connect(username='ckey',
                                   known_hosts='.ssh/known_hosts')

    @asynctest
    async def test_public_key_auth(self):
        """Test connecting with public key authentication"""

        async with self.connect(username='ckey', client_keys='ckey'):
            pass

    @asynctest
    async def test_public_key_auth_disabled(self):
        """Test connecting with public key authentication disabled"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys='ckey',
                               public_key_auth=False)

    @asynctest
    async def test_public_key_auth_not_preferred(self):
        """Test public key authentication not being in preferred auth list"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys='ckey',
                               preferred_auth='password')

    @asynctest
    async def test_public_key_signature_algs(self):
        """Test public key authentication with specific signature algorithms"""

        for alg in ('rsa-sha2-256', 'rsa-sha2-512'):
            async with self.connect(username='ckey', agent_path=None,
                                    client_keys='ckey', signature_algs=[alg]):
                pass

    @asynctest
    async def test_no_server_signature_algs(self):
        """Test a server which doesn't advertise signature algorithms"""

        def skip_ext_info(self):
            """Don't send extension information"""

            # pylint: disable=unused-argument

            return []

        with patch('asyncssh.connection.SSHConnection._get_extra_kex_algs',
                   skip_ext_info):
            try:
                async with self.connect(username='ckey', client_keys='ckey',
                                        agent_path=None):
                    pass
            except UnsupportedAlgorithm: # pragma: no cover
                pass

    @asynctest
    async def test_default_public_key_auth(self):
        """Test connecting with default public key authentication"""

        async with self.connect(username='ckey', agent_path=None):
            pass

    @asynctest
    async def test_invalid_default_key(self):
        """Test connecting with invalid default client key"""

        key_path = os.path.join('.ssh', 'id_dsa')
        with open(key_path, 'w') as f:
            f.write('-----XXX-----')

        with self.assertRaises(asyncssh.KeyImportError):
            await self.connect(username='ckey', agent_path=None)

        os.remove(key_path)

    @asynctest
    async def test_client_key_bytes(self):
        """Test client key passed in as bytes"""

        with open('ckey', 'rb') as f:
            ckey = f.read()

        async with self.connect(username='ckey', client_keys=[ckey]):
            pass

    @asynctest
    async def test_client_key_sshkey(self):
        """Test client key passed in as an SSHKey"""

        ckey = asyncssh.read_private_key('ckey')

        async with self.connect(username='ckey', client_keys=[ckey]):
            pass

    @asynctest
    async def test_client_key_keypairs(self):
        """Test client keys passed in as a list of SSHKeyPairs"""

        keys = asyncssh.load_keypairs('ckey')

        async with self.connect(username='ckey', client_keys=keys):
            pass

    @asynctest
    async def test_client_key_agent_keypairs(self):
        """Test client keys passed in as a list of SSHAgentKeyPairs"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        async with asyncssh.connect_agent() as agent:
            for key in await agent.get_keys():
                async with self.connect(username='ckey', client_keys=[key]):
                    pass

    @asynctest
    async def test_keypair_with_replaced_cert(self):
        """Test connecting with a keypair with replaced cert"""

        ckey = asyncssh.load_keypairs(['ckey'])[0]

        async with self.connect(username='ckey',
                                client_keys=[(ckey, 'ckey-cert.pub')]):
            pass

    @asynctest
    async def test_agent_keypair_with_replaced_cert(self):
        """Test connecting with an agent key with replaced cert"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        async with asyncssh.connect_agent() as agent:
            ckey = (await agent.get_keys())[2]

            async with self.connect(username='ckey',
                                    client_keys=[(ckey, 'ckey-cert.pub')]):
                pass

    @asynctest
    async def test_untrusted_client_key(self):
        """Test untrusted client key"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys='skey',
                               agent_path=None)

    @asynctest
    async def test_missing_cert(self):
        """Test missing client certificate"""

        with self.assertRaises(OSError):
            await self.connect(username='ckey', client_keys=[('ckey', 'xxx')])

    @asynctest
    async def test_expired_cert(self):
        """Test expired certificate"""

        ckey = asyncssh.read_private_key('ckey')
        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, skey, ckey, ['ckey'],
                                valid_before=1)

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys=[(skey, cert)],
                               agent_path=None)

    @asynctest
    async def test_allowed_address(self):
        """Test allowed address in certificate"""

        ckey = asyncssh.read_private_key('ckey')
        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, skey, ckey, ['ckey'],
                                options={'source-address':
                                         String('0.0.0.0/0,::/0')})

        async with self.connect(username='ckey', client_keys=[(skey, cert)]):
            pass

    @asynctest
    async def test_disallowed_address(self):
        """Test disallowed address in certificate"""

        ckey = asyncssh.read_private_key('ckey')
        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, skey, ckey, ['ckey'],
                                options={'source-address': String('0.0.0.0')})

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys=[(skey, cert)],
                               agent_path=None)

    @asynctest
    async def test_untrusted_ca(self):
        """Test untrusted CA"""

        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, skey, skey, ['skey'])

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys=[(skey, cert)],
                               agent_path=None)

    @asynctest
    async def test_mismatched_ca(self):
        """Test mismatched CA"""

        ckey = asyncssh.read_private_key('ckey')
        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, skey, skey, ['skey'])

        with self.assertRaises(ValueError):
            await self.connect(username='ckey', client_keys=[(ckey, cert)])

    @asynctest
    async def test_callback(self):
        """Test connecting with public key authentication using callback"""

        async with self._connect_publickey(['ckey'], test_async=True):
            pass

    @asynctest
    async def test_callback_sshkeypair(self):
        """Test client key passed in as an SSHKeyPair by callback"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        async with asyncssh.connect_agent() as agent:
            keylist = await agent.get_keys()

            async with self._connect_publickey(keylist):
                pass

    @asynctest
    async def test_callback_untrusted_client_key(self):
        """Test failure connecting with public key authentication callback"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self._connect_publickey(['skey'])

    @asynctest
    async def test_unknown_auth(self):
        """Test server returning an unknown auth method before public key"""

        with patch('asyncssh.connection.SSHClientConnection',
                   _UnknownAuthClientConnection):
            async with self.connect(username='ckey', client_keys='ckey',
                                    agent_path=None):
                pass

    @asynctest
    async def test_disabled_trivial_public_key_auth(self):
        """Test disabling trivial auth with public key authentication"""

        async with self.connect(username='ckey', agent_path=None,
                                disable_trivial_auth=True):
            pass


class _TestPublicKeyAsyncServerAuth(_TestPublicKeyAuth):
    """Unit tests for public key authentication with async server callbacks"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports async public key auth"""

        def server_factory():
            """Return an SSH server which trusts specific client keys"""

            return _AsyncPublicKeyServer(client_keys=['ckey.pub',
                                                      'ckey_ecdsa.pub'])

        return await cls.create_server(server_factory)


class _TestLimitedPublicKeySignatureAlgs(ServerTestCase):
    """Unit tests for limited public key signature algorithms"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        return await cls.create_server(
            _PublicKeyServer, authorized_client_keys='authorized_keys',
            signature_algs=['ssh-rsa', 'rsa-sha2-512'])

    @asynctest
    async def test_mismatched_client_signature_algs(self):
        """Test mismatched client key signature algorithms"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys='ckey',
                               signature_algs=['rsa-sha2-256'])


class _TestSetAuthorizedKeys(ServerTestCase):
    """Unit tests for public key authentication with set_authorized_keys"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        def server_factory():
            """Return an SSH server which calls set_authorized_keys"""

            return _PublicKeyServer(authorized_keys='authorized_keys')

        return await cls.create_server(server_factory)

    @asynctest
    async def test_set_authorized_keys(self):
        """Test set_authorized_keys method on server"""

        async with self.connect(username='ckey', client_keys='ckey'):
            pass

    @asynctest
    async def test_cert_principals(self):
        """Test certificate principals check"""

        ckey = asyncssh.read_private_key('ckey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'])

        async with self.connect(username='ckey', client_keys=[(ckey, cert)]):
            pass


class _TestPreloadedAuthorizedKeys(ServerTestCase):
    """Unit tests for authentication with pre-loaded authorized keys"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        def server_factory():
            """Return an SSH server which calls set_authorized_keys"""

            authorized_keys = asyncssh.read_authorized_keys('authorized_keys')
            return _PublicKeyServer(authorized_keys=authorized_keys)

        return await cls.create_server(server_factory)

    @asynctest
    async def test_pre_loaded_authorized_keys(self):
        """Test pre-loaded authorized keys file"""

        async with self.connect(username='ckey', client_keys='ckey'):
            pass


class _TestPreloadedAuthorizedKeysFileList(ServerTestCase):
    """Unit tests with pre-loaded authorized keys file list"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        def server_factory():
            """Return an SSH server which calls set_authorized_keys"""

            authorized_keys = asyncssh.read_authorized_keys(['authorized_keys'])
            return _PublicKeyServer(authorized_keys=authorized_keys)

        return await cls.create_server(server_factory)

    @asynctest
    async def test_pre_loaded_authorized_keys(self):
        """Test pre-loaded authorized keys file list"""

        async with self.connect(username='ckey', client_keys='ckey'):
            pass


@unittest.skipUnless(x509_available, 'X.509 not available')
class _TestX509Auth(ServerTestCase):
    """Unit tests for X.509 certificate authentication"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        return await cls.create_server(
            _PublicKeyServer, authorized_client_keys='authorized_keys_x509')

    @asynctest
    async def test_x509_self(self):
        """Test connecting with X.509 self-signed certificate"""

        async with self.connect(username='ckey',
                                client_keys=['ckey_x509_self']):
            pass

    @asynctest
    async def test_x509_chain(self):
        """Test connecting with X.509 certificate chain"""

        async with self.connect(username='ckey',
                                client_keys=['ckey_x509_chain']):
            pass

    @asynctest
    async def test_keypair_with_x509_cert(self):
        """Test connecting with a keypair with replaced X.509 cert"""

        ckey = asyncssh.load_keypairs(['ckey'])[0]

        async with self.connect(username='ckey',
                                client_keys=[(ckey, 'ckey_x509_chain')]):
            pass

    @asynctest
    async def test_agent_keypair_with_x509_cert(self):
        """Test connecting with an agent key with replaced X.509 cert"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        async with asyncssh.connect_agent() as agent:
            ckey = (await agent.get_keys())[2]

            async with self.connect(username='ckey',
                                    client_keys=[(ckey, 'ckey_x509_chain')]):
                pass

    @asynctest
    async def test_x509_incomplete_chain(self):
        """Test connecting with incomplete X.509 certificate chain"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey',
                               client_keys=[('ckey_x509_chain',
                                             'ckey_x509_partial.pem')])

    @asynctest
    async def test_x509_untrusted_cert(self):
        """Test connecting with untrusted X.509 certificate chain"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys=['skey_x509_chain'])

    @asynctest
    async def test_disabled_trivial_x509_auth(self):
        """Test disabling trivial auth with X.509 certificate authentication"""

        async with self.connect(username='ckey',
                                client_keys=['ckey_x509_self'],
                                disable_trivial_auth=True):
            pass


@unittest.skipUnless(x509_available, 'X.509 not available')
class _TestX509AuthDisabled(ServerTestCase):
    """Unit tests for disabled X.509 certificate authentication"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which doesn't support X.509 authentication"""

        return await cls.create_server(
            _PublicKeyServer, x509_trusted_certs=None,
            authorized_client_keys='authorized_keys')

    @asynctest
    async def test_failed_x509_auth(self):
        """Test connect failure with X.509 certificate"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys=['ckey_x509_self'],
                               signature_algs=['x509v3-ssh-rsa'])

    @asynctest
    async def test_non_x509(self):
        """Test connecting without an X.509 certificate"""

        async with self.connect(username='ckey', client_keys=['ckey']):
            pass


@unittest.skipUnless(x509_available, 'X.509 not available')
class _TestX509Subject(ServerTestCase):
    """Unit tests for X.509 certificate authentication by subject name"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        authorized_keys = asyncssh.import_authorized_keys(
            'x509v3-ssh-rsa subject=OU=name\n')

        return await cls.create_server(
            _PublicKeyServer, authorized_client_keys=authorized_keys,
            x509_trusted_certs=['ckey_x509_self.pub'])

    @asynctest
    async def test_x509_subject(self):
        """Test authenticating X.509 certificate by subject name"""

        async with self.connect(username='ckey',
                                client_keys=['ckey_x509_self']):
            pass


@unittest.skipUnless(x509_available, 'X.509 not available')
class _TestX509Untrusted(ServerTestCase):
    """Unit tests for X.509 authentication with no trusted certificates"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        return await cls.create_server(_PublicKeyServer,
                                       authorized_client_keys=None)

    @asynctest
    async def test_x509_untrusted(self):
        """Test untrusted X.509 self-signed certificate"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys=['ckey_x509_self'])


@unittest.skipUnless(x509_available, 'X.509 not available')
class _TestX509Disabled(ServerTestCase):
    """Unit tests for X.509 authentication with server support disabled"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server with X.509 authentication disabled"""

        return await cls.create_server(_PublicKeyServer, x509_purposes=None)

    @asynctest
    async def test_x509_disabled(self):
        """Test X.509 client certificate with server support disabled"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='ckey', client_keys='skey_x509_self')


class _TestPasswordAuth(ServerTestCase):
    """Unit tests for password authentication"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports password authentication"""

        return await cls.create_server(_PasswordServer)

    @asynctest
    async def test_get_server_auth_methods(self):
        """Test getting auth methods from the test server"""

        auth_methods = await asyncssh.get_server_auth_methods(
            self._server_addr, self._server_port, username='pw')

        self.assertEqual(auth_methods, ['keyboard-interactive', 'password'])

    @async_context_manager
    async def _connect_password(self, username, password, old_password='',
                                new_password='', disable_trivial_auth=False,
                                test_async=False):
        """Open a connection to test password authentication"""

        def client_factory():
            """Return an SSHClient to use to do password change"""

            cls = _AsyncPasswordClient if test_async else _PasswordClient
            return cls(password, old_password, new_password)

        conn, _ = await self.create_connection(
            client_factory, username=username, client_keys=None,
            disable_trivial_auth=disable_trivial_auth)

        return conn

    @asynctest
    async def test_password_auth(self):
        """Test connecting with password authentication"""

        async with self.connect(username='pw', password='pw', client_keys=None):
            pass

    @asynctest
    async def test_password_auth_callable(self):
        """Test connecting with a callable for password authentication"""

        async with self.connect(username='pw', password=lambda: 'pw',
                                client_keys=None):
            pass

    @asynctest
    async def test_password_auth_async_callable(self):
        """Test connecting with an async callable for password authentication"""

        async def get_password():
            return 'pw'

        async with self.connect(username='pw', password=get_password,
                                client_keys=None):
            pass

    @asynctest
    async def test_password_auth_awaitable(self):
        """Test connecting with an awaitable for password authentication"""

        async def get_password():
            return 'pw'

        async with self.connect(username='pw', password=get_password(),
                                client_keys=None):
            pass

    @asynctest
    async def test_password_auth_disabled(self):
        """Test connecting with password authentication disabled"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='pw', password='kbdint',
                               password_auth=False, preferred_auth='password')

    @asynctest
    async def test_password_auth_failure(self):
        """Test _failure connecting with password authentication"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='pw', password='badpw',
                               client_keys=None)

    @asynctest
    async def test_password_auth_callback(self):
        """Test connecting with password authentication callback"""

        async with self._connect_password('pw', 'pw', test_async=True):
            pass

    @asynctest
    async def test_password_auth_callback_failure(self):
        """Test failure connecting with password authentication callback"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self._connect_password('pw', 'badpw')

    @asynctest
    async def test_password_change(self):
        """Test password change"""

        async with self._connect_password('pw', 'oldpw', 'oldpw', 'pw',
                                          test_async=True):
            pass

    @asynctest
    async def test_password_change_failure(self):
        """Test failure of password change"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self._connect_password('pw', 'oldpw', 'badpw', 'pw')

    @asynctest
    async def test_disabled_trivial_password_auth(self):
        """Test disabling trivial auth with password authentication"""

        async with self.connect(username='pw', password='pw',
                                client_keys=None, disable_trivial_auth=True):
            pass

    @asynctest
    async def test_disabled_trivial_password_change(self):
        """Test disabling trivial aith with password change"""

        async with self._connect_password('pw', 'oldpw', 'oldpw', 'pw',
                                          disable_trivial_auth=True):
            pass


class _TestPasswordAsyncServerAuth(_TestPasswordAuth):
    """Unit tests for password authentication with async server callbacks"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports async password authentication"""

        return await cls.create_server(_AsyncPasswordServer)


class _TestKbdintAuth(ServerTestCase):
    """Unit tests for keyboard-interactive authentication"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports keyboard-interactive auth"""

        return await cls.create_server(_KbdintServer)

    @asynctest
    async def test_get_server_auth_methods(self):
        """Test getting auth methods from the test server"""

        auth_methods = await asyncssh.get_server_auth_methods(
            self._server_addr, self._server_port, username='none')

        self.assertEqual(auth_methods, ['keyboard-interactive'])

    @async_context_manager
    async def _connect_kbdint(self, username, responses, test_async=False):
        """Open a connection to test keyboard-interactive auth"""

        def client_factory():
            """Return an SSHClient to use to do keyboard-interactive auth"""

            cls = _AsyncKbdintClient if test_async else _KbdintClient
            return cls(responses)

        conn, _ = await self.create_connection(client_factory,
                                               username=username,
                                               client_keys=None)

        return conn

    @asynctest
    async def test_kbdint_auth_no_prompts(self):
        """Test keyboard-interactive authentication with no prompts"""

        async with self.connect(username='none', password='kbdint',
                                client_keys=None):
            pass

    @asynctest
    async def test_kbdint_auth_password(self):
        """Test keyboard-interactive authentication via password"""

        async with self.connect(username='pw', password='kbdint',
                                client_keys=None):
            pass

    @asynctest
    async def test_kbdint_auth_passcode(self):
        """Test keyboard-interactive authentication via passcode"""

        async with self.connect(username='pc', password='kbdint',
                                client_keys=None):
            pass

    @asynctest
    async def test_kbdint_auth_not_password(self):
        """Test keyboard-interactive authentication other than password"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='kbdint', password='kbdint',
                               client_keys=None)

    @asynctest
    async def test_kbdint_auth_multi_not_password(self):
        """Test keyboard-interactive authentication with multiple prompts"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='multi', password='kbdint',
                               client_keys=None)

    @asynctest
    async def test_kbdint_auth_disabled(self):
        """Test connecting with keyboard-interactive authentication disabled"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='pw', password='kbdint',
                               kbdint_auth=False)

    @asynctest
    async def test_kbdint_auth_failure(self):
        """Test failure connecting with keyboard-interactive authentication"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='kbdint', password='badpw',
                               client_keys=None)

    @asynctest
    async def test_kbdint_auth_callback(self):
        """Test keyboard-interactive auth callback"""

        async with self._connect_kbdint('kbdint', ['kbdint'], test_async=True):
            pass

    @asynctest
    async def test_kbdint_auth_callback_multi(self):
        """Test keyboard-interactive auth callback with multiple challenges"""

        async with self._connect_kbdint('multi', ['1', '2'], test_async=True):
            pass

    @asynctest
    async def test_kbdint_auth_callback_failure(self):
        """Test failure connecting with keyboard-interactive auth callback"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self._connect_kbdint('kbdint', ['badpw'])

    @asynctest
    async def test_disabled_trivial_kbdint_auth(self):
        """Test disabled trivial auth with keyboard-interactive auth"""

        async with self.connect(username='pw', password='kbdint',
                                client_keys=None, disable_trivial_auth=True):
            pass

    @asynctest
    async def test_disabled_trivial_kbdint_no_prompts(self):
        """Test disabled trivial with with no keyboard-interactive prompts"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self.connect(username='none', password='kbdint',
                               client_keys=None, disable_trivial_auth=True)


class _TestKbdintAsyncServerAuth(_TestKbdintAuth):
    """Unit tests for keyboard-interactive auth with async server callbacks"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports async kbd-int auth"""

        return await cls.create_server(_AsyncKbdintServer)


class _TestKbdintPasswordServerAuth(ServerTestCase):
    """Unit tests for keyboard-interactive auth with server password auth"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports server password auth"""

        return await cls.create_server(_PasswordServer)

    @async_context_manager
    async def _connect_kbdint(self, username, responses):
        """Open a connection to test keyboard-interactive auth"""

        def client_factory():
            """Return an SSHClient to use to do keyboard-interactive auth"""

            return _KbdintClient(responses)

        conn, _ = await self.create_connection(client_factory,
                                               username=username,
                                               client_keys=None)

        return conn

    @asynctest
    async def test_kbdint_password_auth(self):
        """Test keyboard-interactive server password authentication"""

        async with self._connect_kbdint('pw', ['pw']):
            pass

    @asynctest
    async def test_kbdint_password_auth_multiple_responses(self):
        """Test multiple responses to server password authentication"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self._connect_kbdint('pw', ['xxx', 'yyy'])

    @asynctest
    async def test_kbdint_password_change(self):
        """Test keyboard-interactive server password change"""

        with self.assertRaises(asyncssh.PermissionDenied):
            await self._connect_kbdint('pw', ['oldpw'])


class _TestClientLoginTimeout(ServerTestCase):
    """Unit test for client login timeout"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        def server_factory():
            """Return an SSHServer that delays before starting auth"""

            return _PublicKeyServer(delay=2)

        return await cls.create_server(
            server_factory, authorized_client_keys='authorized_keys')

    @asynctest
    async def test_client_login_timeout_exceeded(self):
        """Test client login timeout exceeded"""

        with self.assertRaises(asyncssh.ConnectionLost):
            await self.connect(username='ckey', client_keys='ckey',
                               login_timeout=1)

    @asynctest
    async def test_client_login_timeout_exceeded_string(self):
        """Test client login timeout exceeded with string value"""

        with self.assertRaises(asyncssh.ConnectionLost):
            await self.connect(username='ckey', client_keys='ckey',
                               login_timeout='0m1s')

    @asynctest
    async def test_invalid_client_login_timeout(self):
        """Test invalid client login timeout"""

        with self.assertRaises(ValueError):
            await self.connect(login_timeout=-1)


class _TestServerLoginTimeoutExceeded(ServerTestCase):
    """Unit test for server login timeout"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server with a 1 second login timeout"""

        return await cls.create_server(
            _PublicKeyServer, authorized_client_keys='authorized_keys',
            login_timeout=1)

    @asynctest
    async def test_server_login_timeout_exceeded(self):
        """Test server_login timeout exceeded"""

        def client_factory():
            """Return an SSHClient that delays before providing a key"""

            return _PublicKeyClient(['ckey'], 2)

        with self.assertRaises(asyncssh.ConnectionLost):
            await self.create_connection(client_factory, username='ckey',
                                         client_keys=None)


class _TestServerLoginTimeoutDisabled(ServerTestCase):
    """Unit test for disabled server login timeout"""

    @classmethod
    async def start_server(cls):
        """Start an SSH server with no login timeout"""

        return await cls.create_server(
            _PublicKeyServer, authorized_client_keys='authorized_keys',
            login_timeout=None)

    @asynctest
    async def test_server_login_timeout_disabled(self):
        """Test with login timeout disabled"""

        async with self.connect(username='ckey', client_keys='ckey'):
            pass
