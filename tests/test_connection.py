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

from unittest.mock import patch

import asyncssh
from asyncssh.cipher import get_encryption_algs
from asyncssh.compression import get_compression_algs
from asyncssh.crypto.pyca.cipher import GCMShim
from asyncssh.kex import get_kex_algs
from asyncssh.mac import _MAC, get_mac_algs
from asyncssh.public_key import CERT_TYPE_USER

from .server import ServerTestCase
from .util import asynctest, make_certificate


class _SplitClientConnection(asyncssh.connection.SSHClientConnection):
    """Test SSH messages being split into multiple packets"""

    def data_received(self, data):
        """Handle incoming data on the connection"""

        l = len(data)
        super().data_received(data[:l//2])
        super().data_received(data[l//2:])


class _VersionedServerConnection(asyncssh.connection.SSHServerConnection):
    """Test alternate SSH server version lines"""

    def __init__(self, version, leading_text, newline, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._version = version
        self._leading_text = leading_text
        self._newline = newline

    @classmethod
    def create(cls, version=b'SSH-2.0-AsyncSSH_Test',
               leading_text=b'', newline=b'\r\n'):
        """Return a connection factory which sends modified version lines"""

        return (lambda *args, **kwargs: cls(version, leading_text,
                                            newline, *args, **kwargs))

    def _send_version(self):
        """Start the SSH handshake"""

        self._server_version = self._version
        self._extra.update(server_version=self._version.decode('ascii'))
        self._send(self._leading_text + self._version + self._newline)


class _FailingMAC(_MAC):
    """Test error in MAC validation"""

    def verify(self, data, sig):
        """Verify the signature of a message"""

        return super().verify(data + b'\xff', sig)


class _FailingGCMShim(GCMShim):
    """Test error in GCM tag verification"""

    def verify_and_decrypt(self, header, data, tag):
        """Verify the signature of and decrypt a block of data"""

        return super().verify_and_decrypt(header, data + b'\xff', tag)


class _InternalErrorClient(asyncssh.SSHClient):
    """Test of internal error exception handler"""

    def connection_made(self, conn):
        """Raise an error when a new connection is opened"""

        # pylint: disable=unused-argument

        raise RuntimeError('Exception handler test')


class _PublicKeyClient(asyncssh.SSHClient):
    """Test public key client auth"""

    def __init__(self, keylist):
        self._keylist = keylist

    def public_key_auth_requested(self):
        """Return a public key to authenticate with"""

        return self._keylist.pop(0) if self._keylist else None


class _PWChangeClient(asyncssh.SSHClient):
    """Test client password change"""

    def password_change_requested(self, prompt, lang):
        """Change the client's password"""

        return 'oldpw', 'pw'


class _TestConnection(ServerTestCase):
    """Unit tests for AsyncSSH connection API"""

    @asyncio.coroutine
    def _check_version(self, *args, **kwargs):
        """Check alternate SSH server version lines"""

        with patch('asyncssh.connection.SSHServerConnection',
                   _VersionedServerConnection.create(*args, **kwargs)):
            server = yield from self.start_server()

            sock = server.sockets[0]
            server_addr, server_port = sock.getsockname()[:2]

            try:
                with (yield from asyncssh.connect(server_addr, server_port,
                                                  loop=self.loop,
                                                  username='guest',
                                                  known_hosts=None)) as conn:
                    pass # pragma: no branch (false positive)

                yield from conn.wait_closed()
            finally:
                server.close()
                yield from server.wait_closed()

    @asyncio.coroutine
    def _connect_publickey(self, keylist):
        """Open a connection to test public key auth"""

        def client_factory():
            """Return an SSHClient to use to do public key auth"""

            return _PublicKeyClient(keylist)

        conn, _ = yield from self.create_connection(client_factory,
                                                    username='ckey',
                                                    client_keys=None)

        return conn

    @asyncio.coroutine
    def _connect_pwchange(self, username, password):
        """Open a connection to test password change"""

        conn, _ = yield from self.create_connection(_PWChangeClient,
                                                    username=username,
                                                    password=password,
                                                    client_keys=None)

        return conn

    @asynctest
    def test_connect_failure(self):
        """Test failure connecting"""

        with self.assertRaises(OSError):
            yield from asyncssh.connect('0.0.0.1')

    @asynctest
    def test_connect_failure_without_agent(self):
        """Test failure connecting with SSH agent disabled"""

        with self.assertRaises(OSError):
            yield from asyncssh.connect('0.0.0.1', agent_path=None)

    @asynctest
    def test_split_version(self):
        """Test version split across two packets"""

        with patch('asyncssh.connection.SSHClientConnection',
                   _SplitClientConnection):
            with (yield from self.connect()) as conn:
                pass

            yield from conn.wait_closed()

    @asynctest
    def test_version_1_99(self):
        """Test SSH server version 1.99"""

        yield from self._check_version(b'SSH-1.99-Test')

    @asynctest
    def test_text_before_version(self):
        """Test additional text before SSH server version"""

        yield from self._check_version(leading_text=b'Test\r\n')

    @asynctest
    def test_version_without_cr(self):
        """Test SSH server version with LF instead of CRLF"""

        yield from self._check_version(newline=b'\n')

    @asynctest
    def test_unknown_version(self):
        """Test unknown SSH server version"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self._check_version(b'SSH-1.0-Test')

    @asynctest
    def test_no_auth(self):
        """Test connecting without authentication"""

        with (yield from self.connect()) as conn:
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
                                      client_keys='ckey')) as conn:
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
    def test_public_key_auth_sshkeypair(self):
        """Test client keys passed in as a list of SSHKeyPairs"""

        agent = yield from asyncssh.connect_agent()
        keylist = yield from agent.get_keys()

        with (yield from self.connect(username='ckey',
                                      client_keys=keylist)) as conn:
            pass

        yield from conn.wait_closed()

        agent.close()

    @asynctest
    def test_public_key_auth_callback(self):
        """Test connecting with public key authentication using callback"""

        with (yield from self._connect_publickey(['ckey'])) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_public_key_auth_callback_sshkeypair(self):
        """Test client key passed in as an SSHKeyPair by callback"""

        agent = yield from asyncssh.connect_agent()
        keylist = yield from agent.get_keys()

        with (yield from self._connect_publickey(keylist)) as conn:
            pass

        yield from conn.wait_closed()

        agent.close()

    @asynctest
    def test_public_key_auth_bytes(self):
        """Test client key passed in as bytes"""

        with open('ckey', 'rb') as f:
            ckey = f.read()

        with (yield from self.connect(username='ckey',
                                      client_keys=[ckey])) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_public_key_auth_sshkey(self):
        """Test client key passed in as an SSHKey"""

        ckey = asyncssh.read_private_key('ckey')

        with (yield from self.connect(username='ckey',
                                      client_keys=[ckey])) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_public_key_auth_cert(self):
        """Test client key with certificate"""

        ckey = asyncssh.read_private_key('ckey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, ckey, ckey, ['ckey'])

        with (yield from self.connect(username='ckey',
                                      client_keys=[(ckey, cert)])) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_public_key_auth_missing_cert(self):
        """Test missing client key"""

        with self.assertRaises(OSError):
            yield from self.connect(username='ckey',
                                    client_keys=[('ckey', 'xxx')])

    @asynctest
    def test_public_key_auth_mismatched_cert(self):
        """Test client key with mismatched certificate"""

        skey = asyncssh.read_private_key('skey')

        cert = make_certificate('ssh-rsa-cert-v01@openssh.com',
                                CERT_TYPE_USER, skey, skey, ['skey'])

        with self.assertRaises(ValueError):
            yield from self.connect(username='ckey',
                                    client_keys=[('ckey', cert)])

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
    def test_known_hosts_bytes(self):
        """Test connecting with known hosts passed in as bytes"""

        with open('skey.pub', 'rb') as f:
            skey = f.read()

        with (yield from self.connect(known_hosts=([skey], [], []))) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_known_hosts_keylist_file(self):
        """Test connecting with known hosts passed as a keylist file"""

        with (yield from self.connect(known_hosts=('skey.pub',
                                                   [], []))) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_known_hosts_sshkeys(self):
        """Test connecting with known hosts passed in as SSHKeys"""

        keylist = asyncssh.read_public_key_list('skey.pub')

        with (yield from self.connect(known_hosts=(keylist, [], []))) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_known_hosts_failure(self):
        """Test failure to match known hosts"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(known_hosts=([], [], []))

    @asynctest
    def test_kex_algs(self):
        """Test connecting with different key exchange algorithms"""

        for kex in get_kex_algs():
            kex = kex.decode('ascii')

            with self.subTest(kex_alg=kex):
                with (yield from self.connect(kex_algs=[kex])) as conn:
                    pass

                yield from conn.wait_closed()

    @asynctest
    def test_empty_kex_algs(self):
        """Test connecting with an empty list of key exchange algorithms"""

        with self.assertRaises(ValueError):
            yield from self.connect(kex_algs=[])

    @asynctest
    def test_invalid_kex_alg(self):
        """Test connecting with invalid key exchange algorithm"""

        with self.assertRaises(ValueError):
            yield from self.connect(kex_algs=['xxx'])

    @asynctest
    def test_unsupported_kex_alg(self):
        """Test connecting with unsupported key exchange algorithm"""

        def unsupported_kex_alg():
            """Patched version of get_kex_algs to test unsupported algorithm"""

            return [b'fail'] + get_kex_algs()

        with patch('asyncssh.connection.get_kex_algs', unsupported_kex_alg):
            with self.assertRaises(asyncssh.DisconnectError):
                yield from self.connect(kex_algs=['fail'])

    @asynctest
    def test_encryption_algs(self):
        """Test connecting with different encryption algorithms"""

        for enc in get_encryption_algs():
            enc = enc.decode('ascii')
            with self.subTest(encryption_alg=enc):
                with (yield from self.connect(encryption_algs=[enc])) as conn:
                    pass

                yield from conn.wait_closed()

    @asynctest
    def test_empty_encryption_algs(self):
        """Test connecting with an empty list of encryption algorithms"""

        with self.assertRaises(ValueError):
            yield from self.connect(encryption_algs=[])

    @asynctest
    def test_invalid_encryption_alg(self):
        """Test connecting with invalid encryption algorithm"""

        with self.assertRaises(ValueError):
            yield from self.connect(encryption_algs=['xxx'])

    @asynctest
    def test_mac_algs(self):
        """Test connecting with different MAC algorithms"""

        for mac in get_mac_algs():
            mac = mac.decode('ascii')
            with self.subTest(mac_alg=mac):
                with (yield from self.connect(encryption_algs=['aes128-ctr'],
                                              mac_algs=[mac])) as conn:
                    pass

                yield from conn.wait_closed()

    @asynctest
    def test_mac_verify_error(self):
        """Test MAC validation failure"""

        with patch('asyncssh.mac._MAC', _FailingMAC):
            for mac in ('hmac-sha2-256-etm@openssh.com', 'hmac-sha2-256'):
                with self.subTest(mac_alg=mac):
                    with self.assertRaises(asyncssh.DisconnectError):
                        yield from self.connect(encryption_algs=['aes128-ctr'],
                                                mac_algs=[mac])

    @asynctest
    def test_gcm_verify_error(self):
        """Test GCM tag validation failure"""

        from asyncssh.cipher import _enc_ciphers

        with patch('asyncssh.crypto.pyca.cipher.GCMShim', _FailingGCMShim):
            with self.assertRaises(asyncssh.DisconnectError):
                yield from self.connect(
                    encryption_algs=['aes128-gcm@openssh.com'])

    @asynctest
    def test_empty_mac_algs(self):
        """Test connecting with an empty list of MAC algorithms"""

        with self.assertRaises(ValueError):
            yield from self.connect(mac_algs=[])

    @asynctest
    def test_invalid_mac_alg(self):
        """Test connecting with invalid MAC algorithm"""

        with self.assertRaises(ValueError):
            yield from self.connect(mac_algs=['xxx'])

    @asynctest
    def test_compression_algs(self):
        """Test connecting with different compression algorithms"""

        for cmp in get_compression_algs():
            cmp = cmp.decode('ascii')
            with self.subTest(cmp_alg=cmp):
                with (yield from self.connect(compression_algs=[cmp])) as conn:
                    pass

                yield from conn.wait_closed()

    @asynctest
    def test_no_compression(self):
        """Test connecting with compression disabled"""

        with (yield from self.connect(compression_algs=None)) as conn:
            pass

        yield from conn.wait_closed()

    @asynctest
    def test_invalid_cmp_alg(self):
        """Test connecting with invalid compression algorithm"""

        with self.assertRaises(ValueError):
            yield from self.connect(compression_algs=['xxx'])

    @asynctest
    def test_debug(self):
        """Test sending of debug message"""

        with (yield from self.connect()) as conn:
            conn.send_debug('debug')

        yield from conn.wait_closed()

    @asynctest
    def test_internal_error(self):
        """Test internal error in client callback"""

        with self.assertRaises(RuntimeError):
            yield from self.create_connection(_InternalErrorClient)

    @asynctest
    def test_server_internal_error(self):
        """Test internal error in server callback"""

        with self.assertRaises(asyncssh.DisconnectError):
            yield from self.connect(username='error')
