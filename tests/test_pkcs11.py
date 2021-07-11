# Copyright (c) 2020-2021 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH PKCS#11 security token support"""

import unittest

import asyncssh

from .pkcs11_stub import pkcs11_available
from .pkcs11_stub import get_pkcs11_public_keys, get_pkcs11_certs
from .pkcs11_stub import stub_pkcs11, unstub_pkcs11
from .server import ServerTestCase
from .util import asynctest


class _CheckPKCS11Auth(ServerTestCase):
    """Common code for testing security key authentication"""

    _certs_available = False

    _pkcs11_tokens = [
        ('Token 1', b'1234', [('ssh-rsa',             'RSA key'),
                              ('ecdsa-sha2-nistp256', 'EC key 1')]),
        ('Token 2', b'5678', [('ecdsa-sha2-nistp384', 'EC key 2'),
                              ('ssh-ed25519',         'ED key (unsupported)')])
    ]

    @classmethod
    async def start_server(cls):
        """Start an SSH server which supports security key authentication"""

        cls.addClassCleanup(unstub_pkcs11, *stub_pkcs11(cls._pkcs11_tokens))

        pubkeys = get_pkcs11_public_keys()
        certs = get_pkcs11_certs()
        cls._certs_available = bool(certs)

        for cert in certs:
            cert.append_certificate('auth_keys')

        for key in pubkeys:
            key.append_public_key('auth_keys')

        if pubkeys:
            ca_key = asyncssh.read_private_key('ckey')

            cert = ca_key.generate_user_certificate(pubkeys[0], 'name',
                                                    principals=['ckey'])

            with open('auth_keys', 'a') as auth_keys:
                auth_keys.write('cert-authority ')

            ca_key.append_public_key('auth_keys')
            cert.write_certificate('pkcs11_cert.pub')

        auth_keys = 'auth_keys' if cls._pkcs11_tokens else ()

        return await cls.create_server(authorized_client_keys=auth_keys,
                                       x509_trusted_certs=certs)


@unittest.skipUnless(pkcs11_available, 'pkcs11 support not available')
class _TestPKCS11TokenNotFound(_CheckPKCS11Auth):
    """Unit tests for PKCS#11 authentication with no token found"""

    _pkcs11_tokens = []

    @asynctest
    async def test_key_not_found(self):
        """Test PKCS#11 with no token found"""

        self.assertEqual(asyncssh.load_pkcs11_keys('xxx'), [])


@unittest.skipUnless(pkcs11_available, 'pkcs11 support not available')
class _TestPKCS11Auth(_CheckPKCS11Auth):
    """Unit tests for PKCS#11 authentication"""

    @asynctest
    async def test_load_keys(self):
        """Test loading keys and certs from PKCS#11 tokens"""

        keys = asyncssh.load_pkcs11_keys('xxx')
        self.assertEqual(len(keys), 6 if self._certs_available else 3)

    @asynctest
    async def test_load_keys_without_certs(self):
        """Test loading keys without certs from PKCS#11 tokens"""

        keys = asyncssh.load_pkcs11_keys('xxx', load_certs=False)
        self.assertEqual(len(keys), 3)

    @asynctest
    async def test_match_token_label(self):
        """Test matching on PKCS#11 token label"""

        keys = asyncssh.load_pkcs11_keys('xxx', token_label='Token 2')
        self.assertEqual(len(keys), 2 if self._certs_available else 1)

    @asynctest
    async def test_match_token_serial(self):
        """Test matching on PKCS#11 token serial number"""

        keys = asyncssh.load_pkcs11_keys('xxx', token_serial='1234')
        self.assertEqual(len(keys), 4 if self._certs_available else 2)

    @asynctest
    async def test_match_token_serial_bytes(self):
        """Test matching on PKCS#11 token serial number as bytes"""

        keys = asyncssh.load_pkcs11_keys('xxx', token_serial=b'1234')
        self.assertEqual(len(keys), 4 if self._certs_available else 2)

    @asynctest
    async def test_match_key_label(self):
        """Test matching on PKCS#11 key label"""

        keys = asyncssh.load_pkcs11_keys('xxx', key_label='EC key 2')
        self.assertEqual(len(keys), 2 if self._certs_available else 1)

    @asynctest
    async def test_match_key_id(self):
        """Test matching on PKCS#11 key id"""

        keys = asyncssh.load_pkcs11_keys('xxx', key_id='02')
        self.assertEqual(len(keys), 2 if self._certs_available else 1)

    @asynctest
    async def test_match_key_id_bytes(self):
        """Test matching on PKCS#11 key id as bytes"""

        keys = asyncssh.load_pkcs11_keys('xxx', key_id=b'\x02')
        self.assertEqual(len(keys), 2 if self._certs_available else 1)

    @asynctest
    async def test_pkcs11_auth(self):
        """Test authenticating with PKCS#11 token"""

        async with self.connect(username='ckey', pkcs11_provider='xxx'):
            pass

    @asynctest
    async def test_pkcs11_load_keys(self):
        """Test authenticating with explicitly loaded PKCS#11 keys"""

        for key in asyncssh.load_pkcs11_keys('xxx'):
            for sig_alg in key.sig_algorithms:
                sig_alg = sig_alg.decode('ascii')

                with self.subTest(key=key.get_comment(), sig_alg=sig_alg):
                    async with self.connect(
                            username='ckey', pkcs11_provider='xxx',
                            client_keys=[key], signature_algs=[sig_alg]):
                        pass

    @asynctest
    async def test_pkcs11_with_replaced_cert(self):
        """Test authenticating with a PKCS#11 with replaced cert"""

        ckey = asyncssh.load_pkcs11_keys('xxx')[1]

        async with self.connect(username='ckey', pkcs11_provider='xxx',
                                client_keys=[(ckey, 'pkcs11_cert.pub')]):
            pass
