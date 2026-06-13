# Copyright (c) 2026 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for SSHSIG creation and validation"""

import hashlib
import os

import asyncssh

from asyncssh.packet import String, UInt32

from .util import TempDirTestCase, get_test_key


class _TestSSHSIG(TempDirTestCase):
    """Unit tests for sshsig module"""

    @classmethod
    def setUpClass(cls):
        """Create public keys needed for test"""

        super().setUpClass()

        rsa_key = get_test_key('ssh-rsa', 0)
        ecdsa_key = get_test_key('ecdsa-sha2-nistp256', 0)
        missing_key = get_test_key('ssh-rsa', 1)
        ca_key = get_test_key('ecdsa-sha2-nistp256', 1)

        good_cert = ca_key.generate_user_certificate(rsa_key, 'id')

        bad_cert = ca_key.generate_user_certificate(ecdsa_key, 'id',
                                                    valid_before='-1d')

        cls._rsa_keypair = rsa_key
        cls._ecdsa_keypair = ecdsa_key
        cls._missing_keypair = missing_key
        cls._good_cert_keypair = (rsa_key, good_cert)
        cls._bad_cert_keypair = (ecdsa_key, bad_cert)

    @staticmethod
    def _build_signers(signers):
        """Build and import a list of allowed signers"""

        allowed_signers = '# Comment\n\n'

        for principals, options, keypair in signers:
            options = options + ' ' if options else ''

            if isinstance(keypair, tuple):
                pubkey = keypair[1].signing_key
            else:
                pubkey = keypair.convert_to_public()

            allowed_signers += (principals + ' ' + options +
                                pubkey.export_public_key().decode())

        return allowed_signers

    def _check_sshsig(self, keypair, hash_name='sha512', is_hashed=False,
                      raw=False, data_file=False, sig_file=False,
                      signers_type='file'):
        """Create and verify an SSHSIG signature"""

        data = os.urandom(256)

        if is_hashed:
            data = hashlib.new(hash_name).digest()
        elif data_file:
            with open('data', 'wb') as f:
                f.write(data)

            data = 'data'

        sig = asyncssh.create_sshsig(keypair, data, is_hashed=is_hashed,
                                     hash_name=hash_name, raw=raw)

        if sig_file:
            with open('sig', 'wb') as f:
                f.write(sig)

            sig = 'sig'

        options = 'cert-authority' if isinstance(keypair, tuple) else ''
        signers = self._build_signers([('*', options, keypair)])

        if signers_type == 'object':
            signers = asyncssh.import_allowed_signers(signers)
        else:
            with open('signers', 'w') as f:
                f.write(signers)

            signers = ['signers'] if signers_type == 'list' else 'signers'

        self.assertTrue(asyncssh.validate_sshsig(data, sig, 'principal',
                                                 signers, is_hashed=is_hashed))

    def test_allowed_signers_match(self):
        """Test matching against allowed signers"""

        tests = (
            ((('*', None, self._rsa_keypair),
              ('*', None, self._ecdsa_keypair),
              ('*', 'cert-authority', self._good_cert_keypair)),
             (('Match RSA key', self._rsa_keypair,
               'principal', 'file', True),
              ('Match ECDSA key', self._ecdsa_keypair,
               'principal', 'file', True),
              ('Match CA key', self._good_cert_keypair,
               'principal', 'file', True),
              ('No match', self._missing_keypair,
               'principal', 'file', False))),
            ((('principal*,!principal1', None, self._rsa_keypair),),
             (('Match principal', self._rsa_keypair,
               'principal', 'file', True),
              ('Exclude principal', self._rsa_keypair,
               'principal1', 'file', False))),
            ((('*', 'namespaces="file*,!file1"', self._rsa_keypair),),
             (('Match namespace', self._rsa_keypair,
               'principal', 'file', True),
              ('Exclude namespace', self._rsa_keypair,
               'principal', 'file1', False))),
            ((('*', 'valid-after=19700101Z,valid_before=29990101Z',
               self._rsa_keypair),),
             (('Match valid before/after', self._rsa_keypair,
               'principal', 'file', True),)),
            ((('*', 'valid-after=29990101Z', self._rsa_keypair),),
             (('Fail valid after', self._rsa_keypair,
               'principal', 'file', False),)),
            ((('*', 'valid-before=19700101Z', self._rsa_keypair),),
             (('Fail valid-before', self._rsa_keypair,
               'principal', 'file', False),))
        )

        for signers, matches in tests:
            allowed_signers = asyncssh.import_allowed_signers(
                self._build_signers(signers))

            for (msg, keypair, principal, namespace, match) in matches:
                with self.subTest(msg):
                    ca = isinstance(keypair, tuple)
                    pubkey = keypair[1].signing_key if ca else \
                             keypair.convert_to_public()
                    result = allowed_signers.validate(
                        pubkey, principal, namespace, ca)

                    self.assertEqual(result, match)

    def test_allowed_signers_errors(self):
        """Test various allowed signers key parsing errors"""

        tests = (
            ('No valid entries', '\n'),
            ('Missing key', '*\n'),
            ('Bad key', '* xxx\n'),
            ('Unbalanced quote', '* xxx"\n'),
            ('Unbalanced backslash', '* xxx\\\n'),
            ('Missing option name', '* =xxx\n')
        )

        for msg, data in tests:
            with self.subTest(msg):
                with self.assertRaises(ValueError):
                    asyncssh.import_allowed_signers(data)

    def test_sshsig_create_errors(self):
        """Test SSHSIG create errors"""

        tests = (
            ('Unsupported hash', {'hash_name': 'xxx'}),
            ('Empty namespace value', {'namespace': ''}),
            ('Incorrect hash size', {'is_hashed': True}),
            ('No signing key specified', {'key': []})
        )

        for msg, kwargs in tests:
            with self.subTest(msg):
                with self.assertRaises(ValueError):
                    if 'key' in kwargs:
                        asyncssh.create_sshsig(data=b'', **kwargs)
                    else:
                        asyncssh.create_sshsig(self._rsa_keypair,
                                               b'', **kwargs)

    def test_sshsig_signature_errors(self):
        """Test SSHSIG signature errors"""

        tests = (
            ('No signature header', b'xxx'),
            ('Incomplete signature header', b'-'),
            ('Bad signature header', b'-----BEGIN XXX-----\n'),
            ('Missing signature footer', b'-----BEGIN SSH SIGNATURE-----\n'),
            ('Bad base64 data', b'-----BEGIN SSH SIGNATURE-----\nXXX\n'
                                b'-----END SSH SIGNATURE-----\n'),
            ('Bad SSHSIG magic', b'XXXSIG'),
            ('Missing SSHSIG version', b'SSHSIG'),
            ('Bad SSHSIG version', b'SSHSIG' + UInt32(2)),
            ('Bad public key', b'SSHSIG' + UInt32(1) + String(b'xxx')),
            ('Bad namespace', b'SSHSIG' + UInt32(1) +
                 String(self._rsa_keypair.public_data) + String(b'\xff')),
            ('Bad signature', b'SSHSIG' + UInt32(1) +
                 String(self._rsa_keypair.public_data) + String('file') +
                 String(b'') + String(b'sha256') + String(b'')),
        )

        for msg, sig in tests:
            with self.subTest(msg):
                self.assertFalse(asyncssh.validate_sshsig(b'', sig, '', b''))

    def test_sshsig_validate_errors(self):
        """Test SSHSIG validate errors"""

        tests = (
            ('Mismatched principal', 'xxx', self._rsa_keypair),
            ('Mismatched CA principal', 'xxx', self._good_cert_keypair),
            ('Expired certificate', 'principal', self._bad_cert_keypair)
        )

        data = os.urandom(256)

        allowed_signers = self._build_signers(
            (('principal', None, self._rsa_keypair),
             ('principal', 'cert-authority', self._good_cert_keypair)))

        for msg, principal, keypair in tests:
            with self.subTest(msg):
                sig = asyncssh.create_sshsig(keypair, data)
                self.assertFalse(asyncssh.validate_sshsig(
                    data, sig, principal, allowed_signers.encode()))

    def test_sshsig(self):
        """Test creating and verifying SSHSIG signatures"""

        for hash_name in ('sha256', 'sha512'):
            self._check_sshsig(self._rsa_keypair, hash_name=hash_name)

        self._check_sshsig(self._ecdsa_keypair)
        self._check_sshsig(self._good_cert_keypair)
        self._check_sshsig(self._rsa_keypair, is_hashed=True)
        self._check_sshsig(self._rsa_keypair, raw=True)
        self._check_sshsig(self._rsa_keypair, data_file=True)
        self._check_sshsig(self._rsa_keypair, sig_file=True)
        self._check_sshsig(self._rsa_keypair, signers_type='list')
        self._check_sshsig(self._rsa_keypair, signers_type='object')
