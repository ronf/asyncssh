# Copyright (c) 2015 by Ron Frederick <ronf@timeheart.net>.
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

"""Unit tests for matching against authorized_keys file"""

from unittest.mock import patch

import asyncssh

from .util import TempDirTestCase


class _TestAuthorizedKeys(TempDirTestCase):
    """Unit tests for auth_keys module"""

    keylist = []
    imported_keylist = []

    @classmethod
    def setUpClass(cls):
        """Create public keys needed for test"""

        super().setUpClass()

        for _ in range(3):
            key = asyncssh.generate_private_key('ssh-rsa')
            cls.keylist.append(key.export_public_key().decode('ascii'))
            cls.imported_keylist.append(key.convert_to_public())

    def build_keys(self, keys, from_file=False):
        """Build and import a list of authorized keys"""

        auth_keys = '# Comment line\n   # Comment line with whitespace\n\n'

        for options in keys:
            options = options + ' ' if options else ''
            keynum = 1 if 'cert-authority' in options else 0

            auth_keys += '%s%s' % (options, self.keylist[keynum])

        if from_file:
            with open('authorized_keys', 'w') as f:
                f.write(auth_keys)

            return asyncssh.read_authorized_keys('authorized_keys')
        else:
            return asyncssh.import_authorized_keys(auth_keys)

    def test_matches(self):
        """Test authorized keys matching"""

        tests = (
            ((None, 'cert-authority'),
             (('Match key', 0, '1.2.3.4', None, True),
              ('Match CA key', 1, '1.2.3.4', None, True),
              ('No match', 2, '1.2.3.4', None, False))),
            (('from="1.2.3.4"',),
             (('Match IP', 0, '1.2.3.4', None, True),)),
            (('from="1.2.3.0/24,!1.2.3.5"',),
             (('Match subnet', 0, '1.2.3.4', None, True),
              ('Exclude IP', 0, '1.2.3.5', None, False))),
            (('from="localhost*"',),
             (('Match host name', 0, '127.0.0.1', None, True),)),
            (('from="1.2.3.*,!1.2.3.5*"',),
             (('Match host pattern', 0, '1.2.3.4', None, True),
              ('Exclude host pattern', 0, '1.2.3.5', None, False))),
            (('cert-authority,principals="ab*,!abd"',),
             (('Match principal', 1, '1.2.3.4', ['abc'], True),
              ('Exclude principal', 1, '1.2.3.4', ['abd'], False)))
        )

        def getnameinfo(sockaddr, flags):
            """Mock reverse DNS lookup of client address"""

            # pylint: disable=unused-argument

            host, port = sockaddr

            if host == '127.0.0.1':
                return ('localhost', port)
            else:
                return sockaddr

        with patch('socket.getnameinfo', getnameinfo):
            for keys, matches in tests:
                auth_keys = self.build_keys(keys)
                for (msg, keynum, client_addr,
                     cert_principals, match) in matches:
                    with self.subTest(msg):
                        result = auth_keys.validate(
                            self.imported_keylist[keynum], client_addr,
                            cert_principals, keynum == 1)

                    self.assertEqual(result is not None, match)

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
