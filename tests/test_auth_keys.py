# Copyright (c) 2015-2020 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for matching against authorized_keys file"""

import unittest

import asyncssh

from .util import TempDirTestCase, get_test_key, x509_available


class _TestAuthorizedKeys(TempDirTestCase):
    """Unit tests for auth_keys module"""

    keylist = []
    imported_keylist = []

    certlist = []
    imported_certlist = []

    @classmethod
    def setUpClass(cls):
        """Create public keys needed for test"""

        super().setUpClass()

        for i in range(3):
            key = get_test_key('ssh-rsa', i)
            cls.keylist.append(key.export_public_key().decode('ascii'))
            cls.imported_keylist.append(key.convert_to_public())

            if x509_available: # pragma: no branch
                subject = 'CN=cert%s' % i
                cert = key.generate_x509_user_certificate(key, subject)
                cls.certlist.append(cert.export_certificate().decode('ascii'))
                cls.imported_certlist.append(cert)

    def build_keys(self, keys, x509=False, from_file=False):
        """Build and import a list of authorized keys"""

        auth_keys = '# Comment line\n   # Comment line with whitespace\n\n'

        for options in keys:
            options = options + ' ' if options else ''
            keynum = 1 if 'cert-authority' in options else 0
            key_or_cert = (self.certlist if x509 else self.keylist)[keynum]

            auth_keys += '%s%s' % (options, key_or_cert)

        if from_file:
            with open('authorized_keys', 'w') as f:
                f.write(auth_keys)

            return asyncssh.read_authorized_keys('authorized_keys')
        else:
            return asyncssh.import_authorized_keys(auth_keys)

    def match_keys(self, tests, x509=False):
        """Match against authorized keys"""

        for keys, matches in tests:
            auth_keys = self.build_keys(keys, x509)
            for (msg, keynum, client_host, \
                    client_addr, cert_principals, match) in matches:
                with self.subTest(msg, x509=x509):
                    if x509:
                        result, trusted_cert = auth_keys.validate_x509(
                            self.imported_certlist[keynum], client_host,
                            client_addr)
                        if (trusted_cert and trusted_cert.subject !=
                                self.imported_certlist[keynum].subject):
                            result = None
                    else:
                        result = auth_keys.validate(
                            self.imported_keylist[keynum], client_host,
                            client_addr, cert_principals, keynum == 1)

                    self.assertEqual(result is not None, match)

    def test_matches(self):
        """Test authorized keys matching"""

        tests = (
            ((None, 'cert-authority'),
             (('Match key or cert', 0, '1.2.3.4', '1.2.3.4', None, True),
              ('Match CA key or cert', 1, '1.2.3.4', '1.2.3.4', None, True),
              ('No match', 2, '1.2.3.4', '1.2.3.4', None, False))),
            (('from="1.2.3.4"',),
             (('Match IP', 0, '1.2.3.4', '1.2.3.4', None, True),)),
            (('from="1.2.3.0/24,!1.2.3.5"',),
             (('Match subnet', 0, '1.2.3.4', '1.2.3.4', None, True),
              ('Exclude IP', 0, '1.2.3.5', '1.2.3.5', None, False))),
            (('from="localhost*"',),
             (('Match host name', 0, 'localhost', '127.0.0.1', None, True),)),
            (('from="1.2.3.*,!1.2.3.5*"',),
             (('Match host pattern', 0, '1.2.3.4', '1.2.3.4', None, True),
              ('Exclude host pattern', 0, '1.2.3.5', '1.2.3.5',
               None, False))),
            (('principals="cert*,!cert1"',),
             (('Match principal', 0, '1.2.3.4', '1.2.3.4',
               ['cert0'], True),)),
            (('cert-authority,principals="cert*,!cert1"',),
             (('Exclude principal', 1, '1.2.3.4', '1.2.3.4',
               ['cert1'], False),))
        )

        self.match_keys(tests)

        if x509_available: # pragma: no branch
            self.match_keys(tests, x509=True)

    def test_options(self):
        """Test authorized keys returned option values"""

        tests = (
            ('Command', 'command="ls abc"', {'command': 'ls abc'}),
            ('PermitOpen', 'permitopen="xxx:123"',
             {'permitopen': {('xxx', 123)}}),
            ('PermitOpen IPv6 address', 'permitopen="[fe80::1]:123"',
             {'permitopen': {('fe80::1', 123)}}),
            ('PermitOpen wildcard port', 'permitopen="xxx:*"',
             {'permitopen': {('xxx', None)}}),
            ('Unknown option', 'foo=abc,foo=def', {'foo': ['abc', 'def']}),
            ('Escaped value', 'environment="FOO=\\"xxx\\""',
             {'environment': {'FOO': '"xxx"'}})
        )

        for msg, options, expected in tests:
            with self.subTest(msg):
                auth_keys = self.build_keys([options])
                result = auth_keys.validate(self.imported_keylist[0],
                                            '1.2.3.4', None, False)
                self.assertEqual(result, expected)

    def test_file(self):
        """Test reading authorized keys from file"""

        self.build_keys([None], from_file=True)

    @unittest.skipUnless(x509_available, 'X.509 not available')
    def test_subject_match(self):
        """Test match on X.509 subject name"""

        auth_keys = asyncssh.import_authorized_keys(
            'x509v3-ssh-rsa subject=CN=cert0\n')
        result, _ = auth_keys.validate_x509(
            self.imported_certlist[0], '1.2.3.4', '1.2.3.4')
        self.assertIsNotNone(result)

    @unittest.skipUnless(x509_available, 'X.509 not available')
    def test_subject_option_match(self):
        """Test match on X.509 subject in options"""

        auth_keys = asyncssh.import_authorized_keys(
            'subject=CN=cert0 ' + self.certlist[0])
        result, _ = auth_keys.validate_x509(
            self.imported_certlist[0], '1.2.3.4', '1.2.3.4')
        self.assertIsNotNone(result)

    @unittest.skipUnless(x509_available, 'X.509 not available')
    def test_subject_option_mismatch(self):
        """Test failed match on X.509 subject in options"""

        auth_keys = asyncssh.import_authorized_keys(
            'subject=CN=cert1 ' + self.certlist[0])
        result, _ = auth_keys.validate_x509(
            self.imported_certlist[0], '1.2.3.4', '1.2.3.4')
        self.assertIsNone(result)

    @unittest.skipUnless(x509_available, 'X.509 not available')
    def test_cert_authority_with_subject(self):
        """Test error when cert-authority is used with subject"""

        with self.assertRaises(ValueError):
            asyncssh.import_authorized_keys(
                'cert-authority x509v3-sign-rsa subject=CN=cert0\n')

    @unittest.skipUnless(x509_available, 'X.509 not available')
    def test_non_root_ca(self):
        """Test error on non-root X.509 CA"""

        key = get_test_key('ssh-rsa')
        cert = key.generate_x509_user_certificate(key, 'CN=a', 'CN=b')
        data = 'cert-authority ' + cert.export_certificate().decode('ascii')

        with self.assertRaises(ValueError):
            asyncssh.import_authorized_keys(data)

    def test_errors(self):
        """Test various authorized key parsing errors"""

        tests = (
            ('Bad key', 'xxx\n'),
            ('Unbalanced quote', 'xxx"\n'),
            ('Unbalanced backslash', 'xxx\\\n'),
            ('Missing option name', '=xxx\n'),
            ('Environment missing equals', 'environment="FOO"\n'),
            ('Environment missing variable name', 'environment="=xxx"\n'),
            ('PermitOpen missing colon', 'permitopen="xxx"\n'),
            ('PermitOpen non-integer port', 'permitopen="xxx:yyy"\n')
        )

        for msg, data in tests:
            with self.subTest(msg):
                with self.assertRaises(ValueError):
                    asyncssh.import_authorized_keys(data)
