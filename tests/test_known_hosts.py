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

"""Unit tests for matching against known_hosts file

   Note: These tests assume that the ssh-keygen command is available on
         the system and in the user's path.

"""

import binascii
import hashlib
import hmac
import os

from asyncssh import import_public_key
from asyncssh.known_hosts import import_known_hosts, match_known_hosts

from .util import TempDirTestCase, run


def _hash(host):
    """Return a hashed version of a hostname in a known_hosts file"""

    salt = os.urandom(20)
    hosthash = hmac.new(salt, host.encode(), hashlib.sha1).digest()
    entry = b'|'.join((b'', b'1', binascii.b2a_base64(salt)[:-1],
                       binascii.b2a_base64(hosthash)[:-1]))

    return entry.decode()


class _TestKnownHosts(TempDirTestCase):
    """Unit tests for known_hosts module"""

    keylists = ([], [], [])
    imported_keylists = ([], [], [])

    @classmethod
    def setUpClass(cls):
        """Create public keys needed for test"""

        super().setUpClass()

        for keylist, imported_keylist in zip(cls.keylists,
                                             cls.imported_keylists):
            for _ in range(3):
                run('ssh-keygen -t rsa -N "" -f key')

                with open('key.pub', 'r') as f:
                    k = f.read()
                    keylist.append(k)
                    imported_keylist.append(import_public_key(k))

                run('rm key key.pub')

    def check_match(self, known_hosts, results=None, host='host',
                    addr='1.2.3.4', port=22):
        """Check the result of calling match_known_hosts"""

        if results:
            results = tuple([kl[r] for r in result]
                            for kl, result in zip(self.imported_keylists,
                                                  results))

        matches = match_known_hosts(known_hosts, host, addr, port)
        self.assertEqual(matches, results)

    def check_hosts(self, patlists, results=None, host='host', addr='1.2.3.4',
                    port=22, from_file=False, from_bytes=False):
        """Check a known_hosts file built from the specified patterns"""

        prefixes = ('', '@cert-authority ', '@revoked ')
        known_hosts = '# Comment line\n   # Comment line with whitespace\n\n'

        for prefix, patlist, key in zip(prefixes, patlists, self.keylists):
            for pattern, key in zip(patlist, key):
                known_hosts += '%s%s %s' % (prefix, pattern, key)

        if from_file:
            with open('known_hosts', 'w') as f:
                f.write(known_hosts)

            known_hosts = 'known_hosts'
        elif from_bytes:
            known_hosts = known_hosts.encode()
        else:
            known_hosts = import_known_hosts(known_hosts)

        return self.check_match(known_hosts, results, host, addr, port)

    def test_match(self):
        """Test known host matching"""

        matches = (
            ('Empty file', ([], [], []), ([], [], [])),
            ('Exact host and port', (['[host]:22'], [], []), ([0], [], [])),
            ('Exact host', (['host'], [], []), ([0], [], [])),
            ('Exact host CA', ([], ['host'], []), ([], [0], [])),
            ('Exact host revoked', ([], [], ['host']), ([], [], [0])),
            ('Multiple exact', (['host'], ['host'], []), ([0], [0], [])),
            ('Wildcard host', (['hos*'], [], []), ([0], [], [])),
            ('Mismatched port', (['[host]:23'], [], []), ([], [], [])),
            ('Negative host', (['hos*,!host'], [], []), ([], [], [])),
            ('Exact addr and port', (['[1.2.3.4]:22'], [], []), ([0], [], [])),
            ('Exact addr', (['1.2.3.4'], [], []), ([0], [], [])),
            ('Subnet', (['1.2.3.0/24'], [], []), ([0], [], [])),
            ('Negative addr', (['1.2.3.0/24,!1.2.3.4'], [], []), ([], [], [])),
            ('Hashed host', ([_hash('host')], [], []), ([0], [], [])),
            ('Hashed addr', ([_hash('1.2.3.4')], [], []), ([0], [], []))
        )

        for testname, patlists, result in matches:
            with self.subTest(testname):
                self.check_hosts(patlists, result)

    def test_no_addr(self):
        """Test match without providing addr"""

        self.check_hosts((['host'], [], []), ([0], [], []), addr=None)
        self.check_hosts((['1.2.3.4'], [], []), ([], [], []), addr=None)

    def test_no_port(self):
        """Test match without providing port"""

        self.check_hosts((['host'], [], []), ([0], [], []), port=None)
        self.check_hosts((['[host]:22'], [], []), ([], [], []), port=None)

    def test_no_match(self):
        """Test for cases where no match is found"""

        no_match = (([], [], []),
                    (['host1', 'host2'], [], []),
                    (['2.3.4.5', '3.4.5.6'], [], []),
                    (['[host]:2222', '[host]:22222'], [], []))

        for patlists in no_match:
            self.check_hosts(patlists, ([], [], []))

    def test_missing_key(self):
        """Test for line with missing key data"""

        with self.assertRaises(ValueError):
            self.check_match(b'xxx\n')

    def test_missing_key_with_tag(self):
        """Test for line with tag with missing key data"""

        with self.assertRaises(ValueError):
            self.check_match(b'@cert-authority xxx\n')

    def test_invalid_key(self):
        """Test for line with invaid key"""

        self.check_match(b'xxx yyy\n', ([], [], []))

    def test_invalid_marker(self):
        """Test for line with invaid marker"""

        with self.assertRaises(ValueError):
            self.check_match(b'@xxx yyy zzz\n')

    def test_incomplete_hash(self):
        """Test for line with incomplete host hash"""

        with self.assertRaises(ValueError):
            self.check_hosts((['|1|aaaa'], [], []))

    def test_invalid_hash(self):
        """Test for line with invalid host hash"""

        with self.assertRaises(ValueError):
            self.check_hosts((['|1|aaa'], [], []))

    def test_unknown_hash_type(self):
        """Test for line with unknown host hash type"""

        with self.assertRaises(ValueError):
            self.check_hosts((['|2|aaaa|'], [], []))

    def test_file(self):
        """Test match against file"""

        self.check_hosts((['host'], [], []), ([0], [], []), from_file=True)

    def test_bytes(self):
        """Test match against byte string"""

        self.check_hosts((['host'], [], []), ([0], [], []), from_bytes=True)
