# Copyright (c) 2017-2020 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for X.509 certificate handling"""

import time
import unittest

from cryptography import x509

from .util import get_test_key, x509_available

if x509_available: # pragma: no branch
    from asyncssh.crypto import X509Name, X509NamePattern
    from asyncssh.crypto import generate_x509_certificate
    from asyncssh.crypto import import_x509_certificate

_purpose_secureShellClient = x509.ObjectIdentifier('1.3.6.1.5.5.7.3.21')


@unittest.skipUnless(x509_available, 'X.509 not available')
class _TestX509(unittest.TestCase):
    """Unit tests for X.509 module"""

    @classmethod
    def setUpClass(cls):
        cls._privkey = get_test_key('ssh-rsa')
        cls._pubkey = cls._privkey.convert_to_public()
        cls._pubdata = cls._pubkey.export_public_key('pkcs8-der')

    def generate_certificate(self, subject='OU=name', issuer=None,
                             serial=None, valid_after=0,
                             valid_before=0xffffffffffffffff, ca=False,
                             ca_path_len=None, purposes=None,
                             user_principals=(), host_principals=(),
                             hash_alg='sha256', comment=None):
        """Generate and check an X.509 certificate"""

        cert = generate_x509_certificate(self._privkey.pyca_key,
                                         self._pubkey.pyca_key,
                                         subject, issuer, serial,
                                         valid_after, valid_before,
                                         ca, ca_path_len, purposes,
                                         user_principals, host_principals,
                                         hash_alg, comment)

        self.assertEqual(cert.data, import_x509_certificate(cert.data).data)

        self.assertEqual(cert.subject, X509Name(subject))
        self.assertEqual(cert.issuer, X509Name(issuer if issuer else subject))
        self.assertEqual(cert.key_data, self._pubdata)

        if isinstance(comment, str):
            comment = comment.encode('utf-8')

        self.assertEqual(cert.comment, comment)

        return cert

    def test_generate(self):
        """Test X.509 certificate generation"""

        cert = self.generate_certificate(purposes='secureShellClient')

        self.assertEqual(cert.purposes, set((_purpose_secureShellClient,)))

    def test_generate_ca(self):
        """Test X.509 CA certificate generation"""

        self.generate_certificate(ca=True, ca_path_len=0)

    def test_serial(self):
        """Test X.509 certificate generation with serial number"""

        self.generate_certificate(serial=1)

    def test_user_principals(self):
        """Test X.509 certificate generation with user principals"""

        cert = self.generate_certificate(user_principals='user1,user2')

        self.assertEqual(cert.user_principals, ['user1', 'user2'])

    def test_host_principals(self):
        """Test X.509 certificate generation with host principals"""

        cert = self.generate_certificate(host_principals='host1,host2')

        self.assertEqual(cert.host_principals, ['host1', 'host2'])

    def test_principal_in_common_name(self):
        """Test X.509 certificate generation with user principals"""

        cert = self.generate_certificate(subject='CN=name')

        self.assertEqual(cert.user_principals, ['name'])
        self.assertEqual(cert.host_principals, ['name'])

    def test_comment(self):
        """Test X.509 certificate generation with comment"""

        self.generate_certificate(comment=b'comment')
        self.generate_certificate(comment='comment')

    def test_unknown_hash(self):
        """Test X.509 certificate generation with unknown hash"""

        with self.assertRaises(ValueError):
            self.generate_certificate(hash_alg='xxx')

    def test_valid_self(self):
        """Test validation of X.509 self-signed certificate"""

        cert = self.generate_certificate()
        self.assertIsNone(cert.validate([cert], None, None, None))

    def test_untrusted_self(self):
        """Test failed validation of untrusted X.509 self-signed certificate"""

        cert1 = self.generate_certificate()
        cert2 = self.generate_certificate()

        with self.assertRaises(ValueError):
            cert1.validate([cert2], None, None, None)

    def test_valid_chain(self):
        """Test validation of X.509 certificate chain"""

        root_ca = self.generate_certificate('OU=root', ca=True, ca_path_len=1)

        int_ca = self.generate_certificate('OU=int', 'OU=root',
                                           ca=True, ca_path_len=0)

        cert = self.generate_certificate('OU=user', 'OU=int')

        self.assertIsNone(cert.validate([int_ca, root_ca], None, None, None))

    def test_incomplete_chain(self):
        """Test failed validation of incomplete X.509 certificate chain"""

        root_ca = self.generate_certificate('OU=root', ca=True, ca_path_len=1)

        int_ca = self.generate_certificate('OU=int', 'OU=root',
                                           ca=True, ca_path_len=0)

        cert = self.generate_certificate('OU=user', 'OU=int2')

        with self.assertRaises(ValueError):
            cert.validate([int_ca, root_ca], None, None, None)

    def test_not_yet_valid_self(self):
        """Test failed validation of not-yet-valid X.509 certificate"""

        cert = self.generate_certificate(valid_after=time.time() + 60)

        with self.assertRaises(ValueError):
            cert.validate([cert], None, None, None)

    def test_expired_self(self):
        """Test failed validation of expired X.509 certificate"""

        cert = self.generate_certificate(valid_before=time.time() - 60)

        with self.assertRaises(ValueError):
            cert.validate([cert], None, None, None)

    def test_expired_intermediate(self):
        """Test failed validation of expired X.509 intermediate CA"""

        root_ca = self.generate_certificate('OU=root', ca=True, ca_path_len=1)

        int_ca = self.generate_certificate('OU=int', 'OU=root',
                                           ca=True, ca_path_len=0,
                                           valid_before=time.time() - 60)

        cert = self.generate_certificate('OU=user', 'OU=int')

        with self.assertRaises(ValueError):
            cert.validate([int_ca, root_ca], None, None, None)

    def test_purpose_mismatch(self):
        """Test failed validation due to purpose mismatch"""

        cert = self.generate_certificate(purposes='secureShellClient')

        with self.assertRaises(ValueError):
            cert.validate([cert], 'secureShellServer', None, None)

    def test_user_principal_match(self):
        """Test validation of user principal"""

        cert = self.generate_certificate(user_principals='user')

        self.assertIsNone(cert.validate([cert], None, 'user', None))

    def test_user_principal_mismatch(self):
        """Test failed validation due to user principal mismatch"""

        cert = self.generate_certificate(user_principals='user1,user2')

        with self.assertRaises(ValueError):
            cert.validate([cert], None, 'user3', None)

    def test_host_principal_match(self):
        """Test validation of host principal"""

        cert = self.generate_certificate(host_principals='host')

        self.assertIsNone(cert.validate([cert], None, None, 'host'))

    def test_host_principal_mismatch(self):
        """Test failed validation due to host principal mismatch"""

        cert = self.generate_certificate(host_principals='host1,host2')

        with self.assertRaises(ValueError):
            cert.validate([cert], None, None, 'host3')

    def test_name(self):
        """Test X.509 distinguished name generation"""

        name = X509Name('O=Org,OU=Unit')

        self.assertEqual(name, X509Name('O=Org, OU=Unit'))
        self.assertEqual(name, X509Name(name))
        self.assertEqual(name, X509Name(name.rdns))

        self.assertEqual(len(name), 2)
        self.assertEqual(len(name.rdns), 2)

        self.assertEqual(str(name), 'O=Org,OU=Unit')
        self.assertNotEqual(name, X509Name('OU=Unit,O=Org'))

    def test_multiple_attrs_in_rdn(self):
        """Test multiple attributes in a relative distinguished name"""

        name1 = X509Name('O=Org,OU=Unit1+OU=Unit2')
        name2 = X509Name('O=Org,OU=Unit2+OU=Unit1')

        self.assertEqual(name1, name2)
        self.assertEqual(len(name1), 3)
        self.assertEqual(len(name1.rdns), 2)

    def test_invalid_attribute(self):
        """Test X.509 distinguished name with invalid attributes"""

        with self.assertRaises(ValueError):
            X509Name('xxx')

        with self.assertRaises(ValueError):
            X509Name('X=xxx')

    def test_exact_name_pattern(self):
        """Test X.509 distinguished name exact match"""

        pattern1 = X509NamePattern('O=Org,OU=Unit')
        pattern2 = X509NamePattern('O=Org, OU=Unit')
        self.assertEqual(pattern1, pattern2)
        self.assertEqual(hash(pattern1), hash(pattern2))

        self.assertTrue(pattern1.matches(X509Name('O=Org,OU=Unit')))
        self.assertFalse(pattern1.matches(X509Name('O=Org,OU=Unit2')))

    def test_prefix_pattern(self):
        """Test X.509 distinguished name prefix match"""

        pattern = X509NamePattern('O=Org,*')
        self.assertTrue(pattern.matches(X509Name('O=Org,OU=Unit')))
        self.assertFalse(pattern.matches(X509Name('O=Org2,OU=Unit')))
