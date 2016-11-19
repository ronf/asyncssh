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

"""Unit tests for AsyncSSH connection authentication"""

import asyncio
import os

from unittest.mock import patch

import asyncssh
from asyncssh.packet import String
from asyncssh.public_key import CERT_TYPE_USER

from .server import Server, ServerTestCase
from .util import asynctest, make_certificate


class _PublicKeyClient(asyncssh.SSHClient):
    """Test client public key authentication"""

    def __init__(self, keylist, delay=0):
        self._keylist = keylist
        self._delay = delay

    @asyncio.coroutine
    def public_key_auth_requested(self):
        """Return a public key to authenticate with"""

        if self._delay:
            yield from asyncio.sleep(self._delay)

        return self._keylist.pop(0) if self._keylist else None


class _AsyncPublicKeyClient(_PublicKeyClient):
    """Test async client public key authentication"""

    @asyncio.coroutine
    def public_key_auth_requested(self):
        """Return a public key to authenticate with"""

        return super().public_key_auth_requested()


class _PublicKeyServer(Server):
    """Server for testing public key authentication"""

    def __init__(self, authorized_keys=None):
        super().__init__()
        self._client_keys = []
        self._authorized_keys = authorized_keys

    def connection_made(self, conn):
        """Called when a connection is made"""

        super().connection_made(conn)
        conn.send_auth_banner('auth banner')

    def begin_auth(self, username):
        """Handle client authentication request"""

        if self._authorized_keys:
            self._conn.set_authorized_keys(self._authorized_keys)
        else:
            self._client_keys = asyncssh.load_public_keys(['ckey_dsa.pub',
                                                           'ckey.pub'])

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

    @asyncio.coroutine
    def validate_public_key(self, username, key):
        """Return whether key is an authorized client key for this user"""

        return super().validate_public_key(username, key)

    @asyncio.coroutine
    def validate_ca_key(self, username, key):
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

    @asyncio.coroutine
    def password_auth_requested(self):
        """Return a password to authenticate with"""

        return super().password_auth_requested()

    @asyncio.coroutine
    def password_change_requested(self, prompt, lang):
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

    @asyncio.coroutine
    def validate_password(self, username, password):
        """Return whether password is valid for this user"""

        return super().validate_password(username, password)

    @asyncio.coroutine
    def change_password(self, username, old_password, new_password):
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

        if len(prompts) == 0:
            return []
        elif self._responses:
            result = self._responses
            self._responses = None
            return result
        else:
            return None


class _AsyncKbdintClient(_KbdintClient):
    """Test keyboard-interactive client auth"""

    @asyncio.coroutine
    def kbdint_auth_requested(self):
        """Return the list of supported keyboard-interactive auth methods"""

        return super().kbdint_auth_requested()

    @asyncio.coroutine
    def kbdint_challenge_received(self, name, instructions, lang, prompts):
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
            result = ('', '', '', [('Password:', False)])
        else:
            if len(responses) == 1 and responses[0] == 'kbdint':
                result = True
            else:
                result = ('', '', '', [('Other Challenge:', True)])

        self._kbdint_round += 1
        return result


class _AsyncKbdintServer(_KbdintServer):
    """Server for testing async keyboard-interactive authentication"""

    @asyncio.coroutine
    def get_kbdint_challenge(self, username, lang, submethods):
        """Return a keyboard-interactive auth challenge"""

        return super().get_kbdint_challenge(username, lang, submethods)

    @asyncio.coroutine
    def validate_kbdint_response(self, username, responses):
        """Return whether the keyboard-interactive response is valid
           for this user"""

        return super().validate_kbdint_response(username, responses)


class _UnknownAuthClientConnection(asyncssh.connection.SSHClientConnection):
    """Test getting back an unknown auth method from the SSH server"""

    def try_next_auth(self):
        """Attempt client authentication using an unknown method"""

        self._auth_methods = [b'unknown'] + self._auth_methods
        super().try_next_auth()


class _TestPublicKeyAuth(ServerTestCase):
    """Unit tests for public key authentication"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        return (yield from cls.create_server(
            _PublicKeyServer, authorized_client_keys='authorized_keys'))

    @asyncio.coroutine
    def _connect_publickey(self, keylist, async=False):
        """Open a connection to test public key auth"""

        def client_factory():
            """Return an SSHClient to use to do public key auth"""

            client_class = _AsyncPublicKeyClient if async else _PublicKeyClient
            return client_class(keylist)

        conn, _ = yield from self.create_connection(client_factory,
                                                    username='ckey',
                                                    client_keys=None)

        return conn

    @asynctest
    def test_agent_auth(self):
        """Test connecting with ssh-agent authentication"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        with (yield from self.connect(username='ckey')) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_agent_signature_algs(self):
        """Test ssh-agent keys with specific signature algorithms"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        for alg in ('ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512'):
            with (yield from self.connect(username='ckey',
                                          signature_algs=[alg])) as conn:
                pass

            yield from conn.wait_closed()

    @asynctest
    def test_agent_auth_failure(self):
        """Test failure connecting with ssh-agent authentication"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        with patch.dict(os.environ, HOME='xxx'):
            with self.assertRaises(asyncssh.DisconnectError):
                yield from self.connect(username='ckey', agent_path='xxx',
                                        known_hosts='.ssh/known_hosts')

    @asynctest
    def test_agent_auth_unset(self):
        """Test connecting with no local keys and no ssh-agent configured"""

        with patch.dict(os.environ, HOME='xxx', SSH_AUTH_SOCK=''):
            with self.assertRaises(asyncssh.DisconnectError):
                yield from self.connect(username='ckey',
                                        known_hosts='.ssh/known_hosts')

    @asynctest
    def test_public_key_auth(self):
        """Test connecting with public key authentication"""

        with (yield from self.connect(username='ckey',
                                      client_keys='ckey')) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_public_key_signature_algs(self):
        """Test public key authentication with specific signature algorithms"""

        for alg in ('ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512'):
            with (yield from self.connect(username='ckey', client_keys='ckey',
                                          signature_algs=[alg])) as conn:
                pass

            yield from conn.wait_closed()

    @asynctest
    def test_no_server_signature_algs(self):
        """Test a server which doesn't advertise signature algorithms"""

        def skip_ext_info(self):
            """Don't send extension information"""

            # pylint: disable=unused-argument

            return []

        with patch('asyncssh.connection.SSHConnection._get_ext_info_kex_alg',
                   skip_ext_info):
            with (yield from self.connect(username='ckey', client_keys='ckey',
                                          agent_path=None)) as conn:
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
    def test_client_key_bytes(self):
        """Test client key passed in as bytes"""

        with open('ckey', 'rb') as f:
            ckey = f.read()

        with (yield from self.connect(username='ckey',
                                      client_keys=[ckey])) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_client_key_sshkey(self):
        """Test client key passed in as an SSHKey"""

        ckey = asyncssh.read_private_key('ckey')

        with (yield from self.connect(username='ckey',
                                      client_keys=[ckey])) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_client_key_keypairs(self):
        """Test client keys passed in as a list of SSHKeyPairs"""

        keys = asyncssh.load_keypairs('ckey')

        with (yield from self.connect(username='ckey',
                                      client_keys=keys)) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_client_key_agent_keypairs(self):
        """Test client keys passed in as a list of SSHAgentKeyPairs"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        agent = yield from asyncssh.connect_agent()

        for key in (yield from agent.get_keys()):
            with (yield from self.connect(username='ckey',
                                          client_keys=[key])) as conn:
                pass

        yield from conn.wait_closed()

        agent.close()

    @asynctest
    def test_untrusted_client_key(self):
        """Test untrusted client key"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(username='ckey', client_keys='skey')

    @asynctest
    def test_missing_cert(self):
        """Test missing client certificate"""

        with self.assertRaises(OSError):
            yield from self.connect(username='ckey',
                                    client_keys=[('ckey', 'xxx')])

    @asynctest
    def test_expired_cert(self):
        """Test expired certificate"""

        ckey = asyncssh.read_private_key('ckey')
        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, skey, ckey, ['ckey'],
                                valid_before=1)

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(username='ckey',
                                    client_keys=[(skey, cert)])

    @asynctest
    def test_allowed_address(self):
        """Test allowed address in certificate"""

        ckey = asyncssh.read_private_key('ckey')
        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, skey, ckey, ['ckey'],
                                options={'source-address':
                                         String('0.0.0.0/0,::/0')})

        with (yield from self.connect(username='ckey',
                                      client_keys=[(skey, cert)])) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_disallowed_address(self):
        """Test disallowed address in certificate"""

        ckey = asyncssh.read_private_key('ckey')
        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, skey, ckey, ['ckey'],
                                options={'source-address': String('0.0.0.0')})

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(username='ckey',
                                    client_keys=[(skey, cert)])

    @asynctest
    def test_untrusted_ca(self):
        """Test untrusted CA"""

        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, skey, skey, ['skey'])

        with self.assertRaises(ValueError):
            yield from self.connect(username='ckey',
                                    client_keys=[('ckey', cert)])

    @asynctest
    def test_callback(self):
        """Test connecting with public key authentication using callback"""

        with (yield from self._connect_publickey(['ckey'],
                                                 async=True)) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_callback_sshkeypair(self):
        """Test client key passed in as an SSHKeyPair by callback"""

        if not self.agent_available(): # pragma: no cover
            self.skipTest('ssh-agent not available')

        agent = yield from asyncssh.connect_agent()
        keylist = yield from agent.get_keys()

        with (yield from self._connect_publickey(keylist)) as conn:
            pass

        yield from conn.wait_closed()

        agent.close()

    @asynctest
    def test_callback_untrusted_client_key(self):
        """Test failure connecting with public key authentication callback"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self._connect_publickey(['skey'])

    @asynctest
    def test_unknown_auth(self):
        """Test server returning an unknown auth method before public key"""

        with patch('asyncssh.connection.SSHClientConnection',
                   _UnknownAuthClientConnection):
            with (yield from self.connect(username='ckey', client_keys='ckey',
                                          agent_path=None)) as conn:
                pass

        yield from conn.wait_closed()


class _TestPublicKeyAsyncServerAuth(_TestPublicKeyAuth):
    """Unit tests for public key authentication with async server callbacks"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server which supports async public key auth"""

        return (yield from cls.create_server(_AsyncPublicKeyServer))


class _TestLimitedSignatureAlgs(ServerTestCase):
    """Unit tests for limited public key signature algorithms"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        return (yield from cls.create_server(
            _PublicKeyServer, authorized_client_keys='authorized_keys',
            signature_algs=['ssh-rsa', 'rsa-sha2-512']))

    @asynctest
    def test_mismatched_signature_algs(self):
        """Test mismatched signature algorithms"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(username='ckey', client_keys='ckey',
                                    signature_algs=['rsa-sha2-256'])

    @asynctest
    def test_signature_alg_fallback(self):
        """Test fall back to default signature algorithm"""

        with (yield from self.connect(username='ckey', client_keys='ckey',
                                      signature_algs=['rsa-sha2-256',
                                                      'ssh-rsa'])) as conn:
            pass

        yield from conn.wait_closed()


class _TestSetAuthorizedKeys(ServerTestCase):
    """Unit tests for public key authentication with set_authorized_keys"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        def server_factory():
            """Return an SSH server which calls set_authorized_keys"""

            return _PublicKeyServer(authorized_keys='authorized_keys')

        return (yield from cls.create_server(server_factory))

    @asynctest
    def test_set_authorized_keys(self):
        """Test set_authorized_keys method on server"""

        with (yield from self.connect(username='ckey',
                                      client_keys='ckey')) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_cert_principals(self):
        """Test certificate principals check"""

        ckey = asyncssh.read_private_key('ckey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'])

        with (yield from self.connect(username='ckey',
                                      client_keys=[(ckey, cert)])) as conn:
            pass

        yield from conn.wait_closed()


class _TestPreloadedAuthorizedKeys(ServerTestCase):
    """Unit tests for authentication with pre-loaded authorized keys"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server which supports public key authentication"""

        def server_factory():
            """Return an SSH server which calls set_authorized_keys"""

            authorized_keys = asyncssh.read_authorized_keys('authorized_keys')
            return _PublicKeyServer(authorized_keys=authorized_keys)

        return (yield from cls.create_server(server_factory))

    @asynctest
    def test_pre_loaded_authorized_keys(self):
        """Test set_authorized_keys with pre-loaded authorized keys"""

        with (yield from self.connect(username='ckey',
                                      client_keys='ckey')) as conn:
            pass

        yield from conn.wait_closed()


class _TestPasswordAuth(ServerTestCase):
    """Unit tests for password authentication"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server which supports password authentication"""

        return (yield from cls.create_server(_PasswordServer))

    @asyncio.coroutine
    def _connect_password(self, username, password, old_password='',
                          new_password='', async=False):
        """Open a connection to test password authentication"""

        def client_factory():
            """Return an SSHClient to use to do password change"""

            client_class = _AsyncPasswordClient if async else _PasswordClient
            return client_class(password, old_password, new_password)

        conn, _ = yield from self.create_connection(client_factory,
                                                    username=username,
                                                    client_keys=None)

        return conn

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
    def test_password_auth_callback(self):
        """Test connecting with password authentication callback"""

        with (yield from self._connect_password('pw', 'pw',
                                                async=True)) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_password_auth_callback_failure(self):
        """Test failure connecting with password authentication callback"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self._connect_password('pw', 'badpw')

    @asynctest
    def test_password_change(self):
        """Test password change"""

        with (yield from self._connect_password('pw', 'oldpw', 'oldpw',
                                                'pw', async=True)) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_password_change_failure(self):
        """Test failure of password change"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self._connect_password('pw', 'oldpw', 'badpw', 'pw')


class _TestPasswordAsyncServerAuth(_TestPasswordAuth):
    """Unit tests for password authentication with async server callbacks"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server which supports async password authentication"""

        return (yield from cls.create_server(_AsyncPasswordServer))


class _TestKbdintAuth(ServerTestCase):
    """Unit tests for keyboard-interactive authentication"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server which supports keyboard-interactive auth"""

        return (yield from cls.create_server(_KbdintServer))

    @asyncio.coroutine
    def _connect_kbdint(self, username, responses, async=False):
        """Open a connection to test keyboard-interactive auth"""

        def client_factory():
            """Return an SSHClient to use to do keyboard-interactive auth"""

            client_class = _AsyncKbdintClient if async else _KbdintClient
            return client_class(responses)

        conn, _ = yield from self.create_connection(client_factory,
                                                    username=username,
                                                    client_keys=None)

        return conn

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
    def test_kbdint_auth_callback(self):
        """Test keyboard-interactive auth callback"""

        with (yield from self._connect_kbdint('kbdint', ['kbdint'],
                                              async=True)) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_kbdint_auth_callback_faliure(self):
        """Test failure connection with keyboard-interactive auth callback"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self._connect_kbdint('kbdint', ['badpw'])


class _TestKbdintAsyncServerAuth(_TestKbdintAuth):
    """Unit tests for keyboard-interactive auth with async server callbacks"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server which supports async kbd-int auth"""

        return (yield from cls.create_server(_AsyncKbdintServer))


class _TestKbdintPasswordServerAuth(ServerTestCase):
    """Unit tests for keyboard-interactive auth with server password auth"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server which supports server password auth"""

        return (yield from cls.create_server(_PasswordServer))

    @asyncio.coroutine
    def _connect_kbdint(self, username, responses):
        """Open a connection to test keyboard-interactive auth"""

        def client_factory():
            """Return an SSHClient to use to do keyboard-interactive auth"""

            return _KbdintClient(responses)

        conn, _ = yield from self.create_connection(client_factory,
                                                    username=username,
                                                    client_keys=None)

        return conn

    @asynctest
    def test_kbdint_password_auth(self):
        """Test keyboard-interactive server password authentication"""

        with (yield from self._connect_kbdint('pw', ['pw'])) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_kbdint_password_auth_multiple_responses(self):
        """Test multiple responses to server password authentication"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self._connect_kbdint('pw', ['xxx', 'yyy'])

    @asynctest
    def test_kbdint_password_change(self):
        """Test keyboard-interactive server password change"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self._connect_kbdint('pw', ['oldpw'])


class _TestLoginTimeoutExceeded(ServerTestCase):
    """Unit test for login timeout"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server with a 1 second login timeout"""

        return (yield from cls.create_server(_PublicKeyServer,
                                             login_timeout=1))

    @asynctest
    def test_login_timeout_exceeded(self):
        """Test login timeout exceeded"""

        def client_factory():
            """Return an SSHClient that delays before providing a key"""

            return _PublicKeyClient(['ckey'], 2)

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.create_connection(client_factory, username='ckey',
                                              client_keys=None)


class _TestLoginTimeoutDisabled(ServerTestCase):
    """Unit test for disabled login timeout"""

    @classmethod
    @asyncio.coroutine
    def start_server(cls):
        """Start an SSH server with no login timeout"""

        return (yield from cls.create_server(_PublicKeyServer,
                                             login_timeout=None))

    @asynctest
    def test_login_timeout_disabled(self):
        """Test with login timeout disabled"""

        with (yield from self.connect(username='ckey',
                                      client_keys='ckey')) as conn:
            pass

        yield from conn.wait_closed()
