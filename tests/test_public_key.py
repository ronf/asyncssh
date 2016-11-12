# Copyright (c) 2014-2016 by Ron Frederick <ronf@timeheart.net>.
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

"""Unit tests for reading and writing public and private keys

   Note: These tests look for the openssl and ssh-keygen commands in
         the user's path and will whenever possible use them to perform
         interoperability tests. Otherwise, these tests will only test
         AsyncSSH against itself.

"""

import binascii
from datetime import datetime
import os
import subprocess

import asyncssh

from asyncssh.asn1 import der_encode, BitString, ObjectIdentifier
from asyncssh.asn1 import TaggedDERObject
from asyncssh.packet import MPInt, String, UInt32
from asyncssh.pbe import pkcs1_decrypt
from asyncssh.public_key import CERT_TYPE_USER, CERT_TYPE_HOST, SSHKey
from asyncssh.public_key import get_public_key_algs, get_certificate_algs

from .util import bcrypt_available, libnacl_available
from .util import make_certificate, run, TempDirTestCase


_ES1_SHA1_DES = ObjectIdentifier('1.2.840.113549.1.5.10')
_P12_RC4_40 = ObjectIdentifier('1.2.840.113549.1.12.1.2')
_ES2 = ObjectIdentifier('1.2.840.113549.1.5.13')
_ES2_PBKDF2 = ObjectIdentifier('1.2.840.113549.1.5.12')
_ES2_AES128 = ObjectIdentifier('2.16.840.1.101.3.4.1.2')
_ES2_DES3 = ObjectIdentifier('1.2.840.113549.3.7')

try:
    _openssl_version = run('openssl version')
except subprocess.CalledProcessError: # pragma: no cover
    _openssl_version = b''

_openssl_available = _openssl_version != b''

# The openssl "-v2prf" option is only available in OpenSSL 1.0.2 or later
_openssl_supports_v2prf = _openssl_version >= b'OpenSSL 1.0.2'

try:
    _openssh_version = run('ssh -V')
except subprocess.CalledProcessError: # pragma: no cover
    _openssh_version = b''

_openssh_available = _openssh_version != b''

# GCM & Chacha tests require OpenSSH 6.9 due to a bug in earlier versions:
#     https://bugzilla.mindrot.org/show_bug.cgi?id=2366
_openssh_supports_gcm_chacha = _openssh_version >= b'OpenSSH_6.9'

# pylint: disable=bad-whitespace

pkcs1_ciphers = (('aes128-cbc', '-aes128'),
                 ('aes192-cbc', '-aes192'),
                 ('aes256-cbc', '-aes256'),
                 ('des-cbc',    '-des'),
                 ('des3-cbc',   '-des3'))

pkcs8_ciphers = (
    ('aes128-cbc',   'sha224', 2, '-v2 aes-128-cbc '
     '-v2prf hmacWithSHA224', _openssl_supports_v2prf),
    ('aes128-cbc',   'sha256', 2, '-v2 aes-128-cbc '
     '-v2prf hmacWithSHA256', _openssl_supports_v2prf),
    ('aes128-cbc',   'sha384', 2, '-v2 aes-128-cbc '
     '-v2prf hmacWithSHA384', _openssl_supports_v2prf),
    ('aes128-cbc',   'sha512', 2, '-v2 aes-128-cbc '
     '-v2prf hmacWithSHA512', _openssl_supports_v2prf),
    ('des-cbc',      'md5',    1, '-v1 PBE-MD5-DES',       _openssl_available),
    ('des-cbc',      'sha1',   1, '-v1 PBE-SHA1-DES',      _openssl_available),
    ('des2-cbc',     'sha1',   1, '-v1 PBE-SHA1-2DES',     _openssl_available),
    ('des3-cbc',     'sha1',   1, '-v1 PBE-SHA1-3DES',     _openssl_available),
    ('rc4-40',       'sha1',   1, '-v1 PBE-SHA1-RC4-40',   _openssl_available),
    ('rc4-128',      'sha1',   1, '-v1 PBE-SHA1-RC4-128',  _openssl_available),
    ('aes128-cbc',   'sha1',   2, '-v2 aes-128-cbc',       _openssl_available),
    ('aes192-cbc',   'sha1',   2, '-v2 aes-192-cbc',       _openssl_available),
    ('aes256-cbc',   'sha1',   2, '-v2 aes-256-cbc',       _openssl_available),
    ('blowfish-cbc', 'sha1',   2, '-v2 bf-cbc',            _openssl_available),
    ('cast128-cbc',  'sha1',   2, '-v2 cast-cbc',          _openssl_available),
    ('des-cbc',      'sha1',   2, '-v2 des-cbc',           _openssl_available),
    ('des3-cbc',     'sha1',   2, '-v2 des-ede3-cbc',      _openssl_available))

openssh_ciphers = (
    ('aes128-gcm@openssh.com',  _openssh_supports_gcm_chacha),
    ('aes256-gcm@openssh.com',  _openssh_supports_gcm_chacha),
    ('aes128-cbc',              _openssh_available),
    ('aes192-cbc',              _openssh_available),
    ('aes256-cbc',              _openssh_available),
    ('aes128-ctr',              _openssh_available),
    ('aes192-ctr',              _openssh_available),
    ('aes256-ctr',              _openssh_available),
    ('arcfour',                 _openssh_available),
    ('arcfour128',              _openssh_available),
    ('arcfour256',              _openssh_available),
    ('blowfish-cbc',            _openssh_available),
    ('cast128-cbc',             _openssh_available),
    ('3des-cbc',                _openssh_available)
)

# pylint: enable=bad-whitespace

# Only test Chacha if libnacl is installed
if libnacl_available: # pragma: no branch
    openssh_ciphers += (('chacha20-poly1305@openssh.com',
                         _openssh_supports_gcm_chacha),)


def select_passphrase(cipher, pbe_version=0):
    """Randomize between string and bytes version of passphrase"""

    if cipher is None:
        return None
    elif os.urandom(1)[0] & 1:
        return 'passphrase'
    elif pbe_version == 1 and cipher in ('des2-cbc', 'des3-cbc',
                                         'rc4-40', 'rc4-128'):
        return 'passphrase'.encode('utf-16-be')
    else:
        return 'passphrase'.encode('utf-8')


class _TestPublicKey(TempDirTestCase):
    """Unit tests for public key modules"""

    keyclass = None
    base_format = None
    private_formats = ()
    public_formats = ()
    default_cert_version = ''
    generate_args = ()

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

        self.privkey = None
        self.pubkey = None
        self.privca = None
        self.pubca = None
        self.usercert = None
        self.hostcert = None

    def make_certificate(self, *args, **kwargs):
        """Construct an SSH certificate"""

        return make_certificate(self.default_cert_version, *args, **kwargs)

    def check_private(self, passphrase=None):
        """Check for a private key match"""

        newkey = asyncssh.read_private_key('new', passphrase)
        keydata = newkey.get_ssh_public_key()

        self.assertEqual(newkey, self.privkey)
        self.assertEqual(hash(newkey), hash(self.privkey))

        keylist = asyncssh.load_keypairs('new', passphrase)
        self.assertEqual(keylist[0].get_key_type(), 'local')
        self.assertEqual(keylist[0].get_algorithm(), newkey.get_algorithm())
        self.assertEqual(keylist[0].public_data, keydata)

        keylist = asyncssh.load_keypairs(['new'], passphrase)
        self.assertEqual(keylist[0].get_algorithm(), newkey.get_algorithm())
        self.assertEqual(keylist[0].public_data, keydata)

        if passphrase:
            with self.assertRaises((asyncssh.KeyEncryptionError,
                                    asyncssh.KeyImportError)):
                asyncssh.read_private_key('new', 'xxx')
        else:
            run('cat new new > list')
            keylist = asyncssh.load_keypairs('list')
            self.assertEqual(keylist[0].public_data, keydata)
            self.assertEqual(keylist[1].public_data, keydata)

    def check_public(self):
        """Check for a public key match"""

        newkey = asyncssh.read_public_key('new')
        self.assertEqual(newkey, self.pubkey)
        self.assertEqual(hash(newkey), hash(self.pubkey))

        keylist = asyncssh.load_public_keys('new')
        self.assertEqual(keylist[0], newkey)

        keylist = asyncssh.load_public_keys(['new'])
        self.assertEqual(keylist[0], newkey)

        run('cat new new > list')
        keylist = asyncssh.load_public_keys('list')
        self.assertEqual(keylist[0], newkey)
        self.assertEqual(keylist[1], newkey)

    def check_certificate(self, cert_type):
        """Check for a certificate match"""

        cert = asyncssh.read_certificate('cert')
        self.assertEqual(cert.key, self.pubkey)
        self.assertEqual(cert.signing_key, self.pubca)
        self.assertIsNone(cert.validate(cert_type, 'name'))

        run('cat cert cert > list')
        certlist = asyncssh.read_certificate_list('list')
        self.assertEqual(certlist[0].data, cert.data)
        self.assertEqual(certlist[1].data, cert.data)

    def import_pkcs1_private(self, fmt, cipher=None, args=None):
        """Check import of a PKCS#1 private key"""

        if _openssl_available: # pragma: no branch
            if cipher:
                run('openssl %s %s -in priv -inform pem -out new -outform %s '
                    '-passout pass:passphrase' % (self.keyclass, args, fmt))
            else:
                run('openssl %s -in priv -inform pem -out new -outform %s' %
                    (self.keyclass, fmt))
        else: # pragma: no cover
            self.privkey.write_private_key('new', 'pkcs1-%s' % fmt,
                                           select_passphrase(cipher), cipher)

        self.check_private(select_passphrase(cipher))

    def export_pkcs1_private(self, fmt, cipher=None):
        """Check export of a PKCS#1 private key"""

        self.privkey.write_private_key('privout', 'pkcs1-%s' % fmt,
                                       select_passphrase(cipher), cipher)

        if _openssl_available: # pragma: no branch
            if cipher:
                run('openssl %s -in privout -inform %s -out new -outform pem '
                    '-passin pass:passphrase' % (self.keyclass, fmt))
            else:
                run('openssl %s -in privout -inform %s -out new -outform pem' %
                    (self.keyclass, fmt))
        else: # pragma: no cover
            priv = asyncssh.read_private_key('privout',
                                             select_passphrase(cipher))
            priv.write_private_key('new', 'pkcs1-%s' % fmt)

        self.check_private()

    def import_pkcs1_public(self, fmt):
        """Check import of a PKCS#1 public key"""

        if (not _openssl_available or self.keyclass == 'dsa' or
                _openssl_version < b'OpenSSL 1.0.0'): # pragma: no cover
            # OpenSSL no longer has support for PKCS#1 DSA, and PKCS#1
            # RSA is not supported before OpenSSL 1.0.0, so we only test
            # against ourselves in these cases.

            self.pubkey.write_public_key('new', 'pkcs1-%s' % fmt)
        else:
            run('openssl %s -pubin -in pub -inform pem -RSAPublicKey_out '
                '-out new -outform %s' % (self.keyclass, fmt))

        self.check_public()

    def export_pkcs1_public(self, fmt):
        """Check export of a PKCS#1 public key"""

        self.privkey.write_public_key('pubout', 'pkcs1-%s' % fmt)

        if not _openssl_available or self.keyclass == 'dsa': # pragma: no cover
            # OpenSSL no longer has support for PKCS#1 DSA, so we can
            # only test against ourselves.

            pub = asyncssh.read_public_key('pubout')
            pub.write_public_key('new', 'pkcs1-%s' % fmt)
        else:
            run('openssl %s -RSAPublicKey_in -in pubout -inform %s -out new '
                '-outform pem' % (self.keyclass, fmt))

        self.check_public()

    def import_pkcs8_private(self, fmt, use_openssl, cipher=None,
                             hash_alg=None, pbe_version=None, args=None):
        """Check import of a PKCS#8 private key"""

        if use_openssl: # pragma: no branch
            if cipher:
                run('openssl pkcs8 -topk8 %s -in priv -inform pem -out new '
                    '-outform %s -passout pass:passphrase' % (args, fmt))
            else:
                run('openssl pkcs8 -topk8 -nocrypt -in priv -inform pem '
                    '-out new -outform %s' % fmt)
        else: # pragma: no cover
            self.privkey.write_private_key('new', 'pkcs8-%s' % fmt,
                                           select_passphrase(cipher,
                                                             pbe_version),
                                           cipher, hash_alg, pbe_version)

        self.check_private(select_passphrase(cipher, pbe_version))

    def export_pkcs8_private(self, fmt, use_openssl, cipher=None,
                             hash_alg=None, pbe_version=None):
        """Check export of a PKCS#8 private key"""

        self.privkey.write_private_key('privout', 'pkcs8-%s' % fmt,
                                       select_passphrase(cipher, pbe_version),
                                       cipher, hash_alg, pbe_version)

        if use_openssl: # pragma: no branch
            if cipher:
                run('openssl pkcs8 -in privout -inform %s -out new '
                    '-outform pem -passin pass:passphrase' % fmt)
            else:
                run('openssl pkcs8 -nocrypt -in privout -inform %s -out new '
                    '-outform pem' % fmt)
        else: # pragma: no cover
            priv = asyncssh.read_private_key('privout',
                                             select_passphrase(cipher,
                                                               pbe_version))
            priv.write_private_key('new', 'pkcs8-%s' % fmt)

        self.check_private()

    def import_pkcs8_public(self, fmt):
        """Check import of a PKCS#8 public key"""

        if _openssl_available: # pragma: no branch
            run('openssl %s -pubin -in pub -inform pem -out new -outform %s' %
                (self.keyclass, fmt))
        else: # pragma: no cover
            self.pubkey.write_public_key('new', 'pkcs8-%s' % fmt)

        self.check_public()

    def export_pkcs8_public(self, fmt):
        """Check export of a PKCS#8 public key"""

        self.privkey.write_public_key('pubout', 'pkcs8-%s' % fmt)

        if _openssl_available: # pragma: no branch
            run('openssl %s -pubin -in pubout -inform %s -out new '
                '-outform pem' % (self.keyclass, fmt))
        else: # pragma: no cover
            pub = asyncssh.read_public_key('pubout')
            pub.write_public_key('new', 'pkcs8-%s' % fmt)

        self.check_public()

    def import_openssh_private(self, use_openssh, cipher=None):
        """Check import of an OpenSSH private key"""

        if use_openssh: # pragma: no branch
            run('cp -p priv new')

            if cipher:
                run('ssh-keygen -p -N passphrase -Z %s -o -f new' % cipher)
            else:
                run('ssh-keygen -p -N "" -o -f new')
        else: # pragma: no cover
            self.privkey.write_private_key('new', 'openssh',
                                           select_passphrase(cipher), cipher)

        self.check_private(select_passphrase(cipher))

    def export_openssh_private(self, use_openssh, cipher=None):
        """Check export of an OpenSSH private key"""

        self.privkey.write_private_key('new', 'openssh',
                                       select_passphrase(cipher), cipher)

        if use_openssh: # pragma: no branch
            run('chmod 600 new')

            if cipher:
                run('ssh-keygen -p -P passphrase -N "" -o -f new')
            else:
                run('ssh-keygen -p -N "" -o -f new')
        else: # pragma: no cover
            priv = asyncssh.read_private_key('new', select_passphrase(cipher))
            priv.write_private_key('new', 'openssh')

        self.check_private()

    def import_openssh_public(self):
        """Check import of an OpenSSH public key"""

        run('cp -p sshpub new')

        self.check_public()

    def export_openssh_public(self):
        """Check export of an OpenSSH public key"""

        self.privkey.write_public_key('pubout', 'openssh')

        if _openssh_available: # pragma: no branch
            run('ssh-keygen -e -f pubout -m rfc4716 > new')
        else: # pragma: no cover
            pub = asyncssh.read_public_key('pubout')
            pub.write_public_key('new', 'rfc4716')

        self.check_public()

    def import_openssh_certificate(self, cert_type, cert):
        """Check import of an OpenSSH certificate"""

        run('cp -p %s cert' % cert)

        self.check_certificate(cert_type)

    def export_openssh_certificate(self, cert_type, cert):
        """Check export of an OpenSSH certificate"""

        cert.write_certificate('certout', 'openssh')

        if _openssh_available: # pragma: no branch
            run('ssh-keygen -e -f certout -m rfc4716 > cert')
        else: # pragma: no cover
            cert = asyncssh.read_certificate('certout')
            cert.write_certificate('cert', 'rfc4716')

        self.check_certificate(cert_type)

    def import_rfc4716_public(self):
        """Check import of an RFC4716 public key"""

        if _openssh_available: # pragma: no branch
            run('ssh-keygen -e -f sshpub -m rfc4716 > new')
        else: # pragma: no cover
            self.pubkey.write_public_key('new', 'rfc4716')

        self.check_public()

    def export_rfc4716_public(self):
        """Check export of an RFC4716 public key"""

        self.pubkey.write_public_key('pubout', 'rfc4716')

        if _openssh_available: # pragma: no branch
            run('ssh-keygen -i -f pubout -m rfc4716 > new')
        else: # pragma: no cover
            pub = asyncssh.read_public_key('pubout')
            pub.write_public_key('new', 'openssh')

        self.check_public()

    def import_rfc4716_certificate(self, cert_type, cert):
        """Check import of an RFC4716 certificate"""

        if _openssh_available: # pragma: no branch
            run('ssh-keygen -e -f %s -m rfc4716 > cert' % cert)
        else: # pragma: no cover
            if cert_type == CERT_TYPE_USER:
                cert = self.usercert
            else:
                cert = self.hostcert

            cert.write_certificate('cert', 'rfc4716')

        self.check_certificate(cert_type)

    def export_rfc4716_certificate(self, cert_type, cert):
        """Check export of an RFC4716 certificate"""

        cert.write_certificate('certout', 'rfc4716')

        if _openssh_available: # pragma: no branch
            run('ssh-keygen -i -f certout -m rfc4716 > cert')
        else: # pragma: no cover
            cert = asyncssh.read_certificate('certout')
            cert.write_certificate('cert', 'openssh')

        self.check_certificate(cert_type)

    def check_encode_errors(self):
        """Check error code paths in key encoding"""

        for fmt in ('pkcs1-der', 'pkcs1-pem', 'pkcs8-der', 'pkcs8-pem',
                    'openssh', 'rfc4716', 'xxx'):
            with self.subTest('Encode private from public (%s)' % fmt):
                with self.assertRaises(asyncssh.KeyExportError):
                    self.pubkey.export_private_key(fmt)

        with self.subTest('Encode with unknown key format'):
            with self.assertRaises(asyncssh.KeyExportError):
                self.privkey.export_public_key('xxx')

        with self.subTest('Encode encrypted pkcs1-der'):
            with self.assertRaises(asyncssh.KeyExportError):
                self.privkey.export_private_key('pkcs1-der', 'x')

        if self.keyclass == 'ec':
            with self.subTest('Encode EC public key with PKCS#1'):
                with self.assertRaises(asyncssh.KeyExportError):
                    self.privkey.export_public_key('pkcs1-pem')

        if 'pkcs1' in self.private_formats:
            with self.subTest('Encode with unknown PKCS#1 cipher'):
                with self.assertRaises(asyncssh.KeyEncryptionError):
                    self.privkey.export_private_key('pkcs1-pem', 'x', 'xxx')

        if 'pkcs8' in self.private_formats:
            with self.subTest('Encode with unknown PKCS#8 cipher'):
                with self.assertRaises(asyncssh.KeyEncryptionError):
                    self.privkey.export_private_key('pkcs8-pem', 'x', 'xxx')

            with self.subTest('Encode with unknown PKCS#8 hash'):
                with self.assertRaises(asyncssh.KeyEncryptionError):
                    self.privkey.export_private_key('pkcs8-pem', 'x',
                                                    'aes128-cbc', 'xxx')

            with self.subTest('Encode with unknown PKCS#8 version'):
                with self.assertRaises(asyncssh.KeyEncryptionError):
                    self.privkey.export_private_key('pkcs8-pem', 'x',
                                                    'aes128-cbc', 'sha1', 3)

        if ('openssh' in self.private_formats and # pragma: no branch
                bcrypt_available):
            with self.subTest('Encode with unknown openssh cipher'):
                with self.assertRaises(asyncssh.KeyEncryptionError):
                    self.privkey.export_private_key('openssh', 'x', 'xxx')

        with self.subTest('Encode agent cert private from public'):
            with self.assertRaises(asyncssh.KeyExportError):
                self.pubkey.encode_agent_cert_private()

    def check_decode_errors(self):
        """Check error code paths in key decoding"""

        private_errors = [
            ('Non-ASCII', '\xff'),
            ('Incomplete ASN.1', b''),
            ('Invalid PKCS#1', der_encode(None)),
            ('Invalid PKCS#1 params',
             der_encode((1, b'', TaggedDERObject(0, b'')))),
            ('Invalid PKCS#1 EC named curve OID',
             der_encode((1, b'',
                         TaggedDERObject(0, ObjectIdentifier('1.1'))))),
            ('Invalid PKCS#8',
             der_encode((0, (self.privkey.pkcs8_oid, ()), der_encode(None)))),
            ('Invalid PKCS#8 ASN.1',
             der_encode((0, (self.privkey.pkcs8_oid, None), b''))),
            ('Invalid PKCS#8 params',
             der_encode((1, (self.privkey.pkcs8_oid, b''),
                         der_encode((1, b''))))),
            ('Invalid PEM header', b'-----BEGIN XXX-----\n'),
            ('Missing PEM footer', b'-----BEGIN PRIVATE KEY-----\n'),
            ('Invalid PEM key type',
             b'-----BEGIN XXX PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(None)) +
             b'-----END XXX PRIVATE KEY-----'),
            ('Invalid PEM Base64',
             b'-----BEGIN PRIVATE KEY-----\n'
             b'X\n'
             b'-----END PRIVATE KEY-----'),
            ('Missing PKCS#1 passphrase',
             b'-----BEGIN DSA PRIVATE KEY-----\n'
             b'Proc-Type: 4,ENCRYPTED\n'
             b'-----END DSA PRIVATE KEY-----'),
            ('Incomplete PEM ASN.1',
             b'-----BEGIN PRIVATE KEY-----\n'
             b'-----END PRIVATE KEY-----'),
            ('Missing PEM PKCS#8 passphrase',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(None)) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#1 key',
             b'-----BEGIN DSA PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(None)) +
             b'-----END DSA PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 key',
             b'-----BEGIN PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(None)) +
             b'-----END PRIVATE KEY-----'),
            ('Unknown format OpenSSH key',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b'XXX') +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Incomplete OpenSSH key',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b'openssh-key-v1\0') +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH nkeys',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String(''), String(''), String(''),
                  UInt32(2), String(''), String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Missing OpenSSH passphrase',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('xxx'), String(''), String(''),
                  UInt32(1), String(''), String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Mismatched OpenSSH check bytes',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('none'), String(''), String(''),
                  UInt32(1), String(''), String(b''.join((UInt32(1),
                                                          UInt32(2))))))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH algorithm',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('none'), String(''), String(''),
                  UInt32(1), String(''), String(b''.join((UInt32(1), UInt32(1),
                                                          String('xxx'))))))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH pad',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('none'), String(''), String(''),
                  UInt32(1), String(''), String(b''.join((UInt32(1), UInt32(1),
                                                          String('ssh-dss'),
                                                          5*MPInt(0),
                                                          String(''),
                                                          b'\0')))))) +
             b'-----END OPENSSH PRIVATE KEY-----')
        ]

        decrypt_errors = [
            ('Invalid PKCS#1', der_encode(None)),
            ('Invalid PKCS#8', der_encode((0, (self.privkey.pkcs8_oid, ()),
                                           der_encode(None)))),
            ('Invalid PEM params', b'-----BEGIN DSA PRIVATE KEY-----\n'
                                   b'Proc-Type: 4,ENCRYPTED\n'
                                   b'DEK-Info: XXX\n'
                                   b'-----END DSA PRIVATE KEY-----'),
            ('Invalid PEM cipher', b'-----BEGIN DSA PRIVATE KEY-----\n'
                                   b'Proc-Type: 4,ENCRYPTED\n'
                                   b'DEK-Info: XXX,00\n'
                                   b'-----END DSA PRIVATE KEY-----'),
            ('Invalid PEM IV', b'-----BEGIN DSA PRIVATE KEY-----\n'
                               b'Proc-Type: 4,ENCRYPTED\n'
                               b'DEK-Info: AES-256-CBC,XXX\n'
                               b'-----END DSA PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 encrypted data',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(None)) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 encrypted header',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode((None, None))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 encryption algorithm',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(((None, None), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES1 encryption parameters',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(((_ES1_SHA1_DES, None), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES1 PKCS#12 encryption parameters',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(((_P12_RC4_40, None), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES1 PKCS#12 salt',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(((_P12_RC4_40, (b'', 0)), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES1 PKCS#12 iteration count',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(((_P12_RC4_40, (b'x', 0)), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES2 encryption parameters',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(((_ES2, None), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES2 KDF algorithm',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((None, None), (None, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES2 encryption algorithm',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, None), (None, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES2 PBKDF2 parameters',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, None), (_ES2_AES128, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES2 PBKDF2 salt',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, (None, None)),
                          (_ES2_AES128, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES2 PBKDF2 iteration count',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, (b'', None)),
                          (_ES2_AES128, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES2 PBKDF2 PRF',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, (b'', 0, None)),
                          (_ES2_AES128, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Unknown PEM PKCS#8 PBES2 PBKDF2 PRF',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, (b'', 0,
                                         (ObjectIdentifier('1.1'), None))),
                          (_ES2_AES128, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES2 encryption parameters',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, (b'', 0)),
                          (_ES2_AES128, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid length PEM PKCS#8 PBES2 IV',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, (b'', 0)),
                          (_ES2_AES128, b''))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid OpenSSH cipher',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('xxx'), String(''), String(''),
                  UInt32(1), String(''), String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH kdf',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('aes256-cbc'), String('xxx'),
                  String(''), UInt32(1), String(''), String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH kdf data',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('aes256-cbc'), String('bcrypt'),
                  String(''), UInt32(1), String(''), String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH salt',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('aes256-cbc'), String('bcrypt'),
                  String(b''.join((String(b''), UInt32(1)))), UInt32(1),
                  String(''), String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH encrypted data',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('aes256-cbc'), String('bcrypt'),
                  String(b''.join((String(16*b'\0'), UInt32(1)))), UInt32(1),
                  String(''), String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Unexpected OpenSSH trailing data',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('aes256-cbc'), String('bcrypt'),
                  String(b''.join((String(16*b'\0'), UInt32(1)))), UInt32(1),
                  String(''), String(''), String('xxx')))) +
             b'-----END OPENSSH PRIVATE KEY-----')
        ]

        public_errors = [
            ('Non-ASCII', '\xff'),
            ('Incomplete ASN.1', b''),
            ('Invalid ASN.1', b'\x30'),
            ('Invalid PKCS#1', der_encode(None)),
            ('Invalid PKCS#8', der_encode(((self.pubkey.pkcs8_oid, ()),
                                           BitString(der_encode(None))))),
            ('Invalid PKCS#8 ASN.1', der_encode(((self.pubkey.pkcs8_oid,
                                                  None), BitString(b'')))),
            ('Invalid PEM header', b'-----BEGIN XXX-----\n'),
            ('Missing PEM footer', b'-----BEGIN PUBLIC KEY-----\n'),
            ('Invalid PEM key type',
             b'-----BEGIN XXX PUBLIC KEY-----\n' +
             binascii.b2a_base64(der_encode(None)) +
             b'-----END XXX PUBLIC KEY-----'),
            ('Invalid PEM Base64',
             b'-----BEGIN PUBLIC KEY-----\n'
             b'X\n'
             b'-----END PUBLIC KEY-----'),
            ('Incomplete PEM ASN.1',
             b'-----BEGIN PUBLIC KEY-----\n'
             b'-----END PUBLIC KEY-----'),
            ('Invalid PKCS#1 key data',
             b'-----BEGIN DSA PUBLIC KEY-----\n' +
             binascii.b2a_base64(der_encode(None)) +
             b'-----END DSA PUBLIC KEY-----'),
            ('Invalid PKCS#8 key data',
             b'-----BEGIN PUBLIC KEY-----\n' +
             binascii.b2a_base64(der_encode(None)) +
             b'-----END PUBLIC KEY-----'),
            ('Invalid OpenSSH', b'xxx'),
            ('Invalid OpenSSH Base64', b'ssh-dss X'),
            ('Unknown OpenSSH algorithm',
             b'ssh-dss ' + binascii.b2a_base64(String('xxx'))),
            ('Invalid OpenSSH body',
             b'ssh-dss ' + binascii.b2a_base64(String('ssh-dss'))),
            ('Invalid RFC4716 header', b'---- XXX ----\n'),
            ('Missing RFC4716 footer', b'---- BEGIN SSH2 PUBLIC KEY ----\n'),
            ('Invalid RFC4716 header',
             b'---- BEGIN SSH2 PUBLIC KEY ----\n'
             b'Comment: comment\n'
             b'XXX:\\\n'
             b'---- END SSH2 PUBLIC KEY ----\n'),
            ('Invalid RFC4716 Base64',
             b'---- BEGIN SSH2 PUBLIC KEY ----\n'
             b'X\n'
             b'---- END SSH2 PUBLIC KEY ----\n')
        ]

        keypair_errors = [
            ('Mismatched certificate',
             (self.privca, self.usercert)),
            ('Invalid signature algorithm string',
             (self.privkey, None, 'xxx')),
            ('Invalid signature algorithm bytes',
             (self.privkey, None, b'xxx'))
        ]

        for fmt, data in private_errors:
            with self.subTest('Decode private (%s)' % fmt):
                with self.assertRaises(asyncssh.KeyImportError):
                    asyncssh.import_private_key(data)

        for fmt, data in decrypt_errors:
            with self.subTest('Decrypt private (%s)' % fmt):
                with self.assertRaises((asyncssh.KeyEncryptionError,
                                        asyncssh.KeyImportError)):
                    asyncssh.import_private_key(data, 'x')

        for fmt, data in public_errors:
            with self.subTest('Decode public (%s)' % fmt):
                with self.assertRaises(asyncssh.KeyImportError):
                    asyncssh.import_public_key(data)

        for fmt, key in keypair_errors:
            with self.subTest('Load keypair (%s)' % fmt):
                with self.assertRaises(ValueError):
                    asyncssh.load_keypairs([key])

    def check_sshkey_base_errors(self):
        """Check SSHKey base class errors"""

        key = SSHKey()

        with self.subTest('SSHKey base class errors'):
            with self.assertRaises(asyncssh.KeyExportError):
                key.encode_pkcs1_private()

            with self.assertRaises(asyncssh.KeyExportError):
                key.encode_pkcs1_public()

            with self.assertRaises(asyncssh.KeyExportError):
                key.encode_pkcs8_private()

            with self.assertRaises(asyncssh.KeyExportError):
                key.encode_pkcs8_public()

            with self.assertRaises(asyncssh.KeyExportError):
                key.encode_ssh_private()

            with self.assertRaises(asyncssh.KeyExportError):
                key.encode_ssh_public()

    def check_sign_and_verify(self):
        """Check key signing and verification"""

        with self.subTest('Sign/verify test'):
            data = os.urandom(8)

            for sig_alg in self.privkey.sig_algorithms:
                with self.subTest('Good signature', sig_alg=sig_alg):
                    sig = self.privkey.sign(data, sig_alg)
                    with self.subTest('Good signature'):
                        self.assertTrue(self.pubkey.verify(data, sig))

                    badsig = bytearray(sig)
                    badsig[-1] ^= 0xff
                    badsig = bytes(badsig)
                    with self.subTest('Bad signature'):
                        self.assertFalse(self.pubkey.verify(data, badsig))

            with self.subTest('Empty signature'):
                self.assertFalse(self.pubkey.verify(
                    data, String(self.pubkey.algorithm) + String(b'')))

            with self.subTest('Sign with bad algorithm'):
                with self.assertRaises(ValueError):
                    self.privkey.sign(data, 'xxx')

            badalg = String('xxx')
            with self.subTest('Verify with bad algorithm'):
                self.assertFalse(self.pubkey.verify(data, badalg))

            with self.subTest('Sign with public key'):
                with self.assertRaises(ValueError):
                    self.pubkey.sign(data, self.pubkey.algorithm)

    def check_comment(self):
        """Check getting and setting comments"""

        with self.subTest('Comment test'):
            self.assertEqual(self.privkey.get_comment(), 'comment')
            self.assertEqual(self.pubkey.get_comment(), 'comment')

            key = asyncssh.import_private_key(
                self.privkey.export_private_key('openssh'))
            self.assertEqual(key.get_comment(), 'comment')

            for fmt in ('openssh', 'rfc4716'):
                key = asyncssh.import_public_key(
                    self.pubkey.export_public_key(fmt))
                self.assertEqual(key.get_comment(), 'comment')

                key = asyncssh.import_public_key(
                    self.pubca.export_public_key(fmt))
                self.assertEqual(key.get_comment(), None)

            self.assertEqual(self.usercert.get_comment(), 'cert_comment')

            for fmt in ('openssh', 'rfc4716'):
                cert = asyncssh.import_certificate(
                    self.usercert.export_certificate(fmt))
                self.assertEqual(cert.get_comment(), 'cert_comment')

                cert = asyncssh.import_certificate(
                    self.hostcert.export_certificate(fmt))
                self.assertEqual(cert.get_comment(), None)

            with self.assertRaises(asyncssh.KeyImportError):
                self.privkey.set_comment(b'\xff')

            with self.assertRaises(asyncssh.KeyImportError):
                self.pubkey.set_comment(b'\xff')

            with self.assertRaises(asyncssh.KeyImportError):
                self.usercert.set_comment(b'\xff')

            with self.assertRaises(asyncssh.KeyImportError):
                keypairs = asyncssh.load_keypairs([self.privkey])
                keypairs[0].set_comment(b'\xff')

    def check_pkcs1_private(self):
        """Check PKCS#1 private key format"""

        with self.subTest('Import PKCS#1 PEM private'):
            self.import_pkcs1_private('pem')

        with self.subTest('Export PKCS#1 PEM private'):
            self.export_pkcs1_private('pem')

        with self.subTest('Import PKCS#1 DER private'):
            self.import_pkcs1_private('der')

        with self.subTest('Export PKCS#1 DER private'):
            self.export_pkcs1_private('der')

        for cipher, args in pkcs1_ciphers:
            with self.subTest('Import PKCS#1 PEM private (%s)' % cipher):
                self.import_pkcs1_private('pem', cipher, args)

            with self.subTest('Export PKCS#1 PEM private (%s)' % cipher):
                self.export_pkcs1_private('pem', cipher)

    def check_pkcs1_public(self):
        """Check PKCS#1 public key format"""

        with self.subTest('Import PKCS#1 PEM public'):
            self.import_pkcs1_public('pem')

        with self.subTest('Export PKCS#1 PEM public'):
            self.export_pkcs1_public('pem')

        with self.subTest('Import PKCS#1 DER public'):
            self.import_pkcs1_public('der')

        with self.subTest('Export PKCS#1 DER public'):
            self.export_pkcs1_public('der')

    def check_pkcs8_private(self):
        """Check PKCS#8 private key format"""

        with self.subTest('Import PKCS#8 PEM private'):
            self.import_pkcs8_private('pem', _openssl_available)

        with self.subTest('Export PKCS#8 PEM private'):
            self.export_pkcs8_private('pem', _openssl_available)

        with self.subTest('Import PKCS#8 DER private'):
            self.import_pkcs8_private('der', _openssl_available)

        with self.subTest('Export PKCS#8 DER private'):
            self.export_pkcs8_private('der', _openssl_available)

        for cipher, hash_alg, pbe_version, args, use_openssl in pkcs8_ciphers:
            with self.subTest('Import PKCS#8 PEM private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.import_pkcs8_private('pem', use_openssl, cipher,
                                          hash_alg, pbe_version, args)

            with self.subTest('Export PKCS#8 PEM private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.export_pkcs8_private('pem', use_openssl, cipher,
                                          hash_alg, pbe_version)

            with self.subTest('Import PKCS#8 DER private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.import_pkcs8_private('der', use_openssl, cipher,
                                          hash_alg, pbe_version, args)

            with self.subTest('Export PKCS#8 DER private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.export_pkcs8_private('der', use_openssl, cipher,
                                          hash_alg, pbe_version)

    def check_pkcs8_public(self):
        """Check PKCS#8 public key format"""

        with self.subTest('Import PKCS#8 PEM public'):
            self.import_pkcs8_public('pem')

        with self.subTest('Export PKCS#8 PEM public'):
            self.export_pkcs8_public('pem')

        with self.subTest('Import PKCS#8 DER public'):
            self.import_pkcs8_public('der')

        with self.subTest('Export PKCS#8 DER public'):
            self.export_pkcs8_public('der')

    def check_openssh_private(self):
        """Check OpenSSH private key format"""

        with self.subTest('Import OpenSSH private'):
            self.import_openssh_private(_openssh_available)

        with self.subTest('Export OpenSSH private'):
            self.export_openssh_private(_openssh_available)

        if bcrypt_available: # pragma: no branch
            for cipher, use_openssh in openssh_ciphers:
                with self.subTest('Import OpenSSH private (%s)' % cipher):
                    self.import_openssh_private(use_openssh, cipher)

                with self.subTest('Export OpenSSH private (%s)' % cipher):
                    self.export_openssh_private(use_openssh, cipher)

    def check_openssh_public(self):
        """Check OpenSSH public key format"""

        with self.subTest('Import OpenSSH public'):
            self.import_openssh_public()

        with self.subTest('Export OpenSSH public'):
            self.export_openssh_public()

    def check_openssh_certificate(self):
        """Check OpenSSH certificate format"""

        with self.subTest('Import OpenSSH user certificate'):
            self.import_openssh_certificate(CERT_TYPE_USER, 'usercert')

        with self.subTest('Export OpenSSH user certificate'):
            self.export_openssh_certificate(CERT_TYPE_USER, self.usercert)

        with self.subTest('Import OpenSSH host certificate'):
            self.import_openssh_certificate(CERT_TYPE_HOST, 'hostcert')

        with self.subTest('Export OpenSSH host certificate'):
            self.export_openssh_certificate(CERT_TYPE_HOST, self.hostcert)

    def check_rfc4716_public(self):
        """Check RFC4716 public key format"""

        with self.subTest('Import RFC4716 public'):
            self.import_rfc4716_public()

        with self.subTest('Export RFC4716 public'):
            self.export_rfc4716_public()

    def check_rfc4716_certificate(self):
        """Check RFC4716 certificate format"""

        with self.subTest('Import RFC4716 user certificate'):
            self.import_rfc4716_certificate(CERT_TYPE_USER, 'usercert')

        with self.subTest('Export RFC4716 user certificate'):
            self.export_rfc4716_certificate(CERT_TYPE_USER, self.usercert)

        with self.subTest('Import RFC4716 host certificate'):
            self.import_rfc4716_certificate(CERT_TYPE_HOST, 'hostcert')

        with self.subTest('Export RFC4716 host certificate'):
            self.export_rfc4716_certificate(CERT_TYPE_HOST, self.hostcert)

    def check_certificate_options(self):
        """Check SSH certificate options"""

        cert = self.privca.generate_user_certificate(
            self.pubkey, 'name', force_command='command',
            source_address=['1.2.3.4'], permit_x11_forwarding=False,
            permit_agent_forwarding=False,
            permit_port_forwarding=False, permit_pty=False,
            permit_user_rc=False)

        cert.write_certificate('cert')
        self.check_certificate(CERT_TYPE_USER)

        for valid_after, valid_before in ((0, 1.),
                                          (datetime.now(), '+1m'),
                                          ('20160101', '20160102'),
                                          ('20160101000000', '20160102235959'),
                                          ('now', '1w2d3h4m5s'),
                                          ('-52w', '+52w')):

            cert = self.privca.generate_host_certificate(
                self.pubkey, 'name', valid_after=valid_after,
                valid_before=valid_before)

            cert.write_certificate('cert')
            cert2 = asyncssh.read_certificate('cert')
            self.assertEqual(cert2.data, cert.data)

    def check_certificate_errors(self, cert_type):
        """Check SSH certificate error cases"""

        with self.subTest('Non-ASCII certificate'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate('\u0080\n')

        with self.subTest('Invalid SSH format'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate('xxx\n')

        with self.subTest('Invalid certificate packetization'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate(
                    b'xxx ' + binascii.b2a_base64(b'\x00'))

        with self.subTest('Invalid certificate algorithm'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate(
                    b'xxx ' + binascii.b2a_base64(String(b'xxx')))

        with self.subTest('Invalid certificate critical option'):
            with self.assertRaises(asyncssh.KeyImportError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',),
                                             options={b'xxx': b''})
                asyncssh.import_certificate(cert)

        with self.subTest('Ignored certificate extension'):
            cert = self.make_certificate(cert_type, self.pubkey,
                                         self.privca, ('name',),
                                         extensions={b'xxx': b''})
            self.assertIsNotNone(asyncssh.import_certificate(cert))

        with self.subTest('Invalid certificate signature'):
            with self.assertRaises(asyncssh.KeyImportError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',),
                                             bad_signature=True)
                asyncssh.import_certificate(cert)

        with self.subTest('Invalid characters in certificate key ID'):
            with self.assertRaises(asyncssh.KeyImportError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',),
                                             key_id=b'\xff')
                asyncssh.import_certificate(cert)

        with self.subTest('Invalid characters in certificate principal'):
            with self.assertRaises(asyncssh.KeyImportError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, (b'\xff',))
                asyncssh.import_certificate(cert)

        if cert_type == CERT_TYPE_USER:
            with self.subTest('Invalid characters in force-command'):
                with self.assertRaises(asyncssh.KeyImportError):
                    cert = self.make_certificate(cert_type, self.pubkey,
                                                 self.privca, ('name',),
                                                 options={'force-command':
                                                          String(b'\xff')})
                    asyncssh.import_certificate(cert)

            with self.subTest('Invalid characters in source-address'):
                with self.assertRaises(asyncssh.KeyImportError):
                    cert = self.make_certificate(cert_type, self.pubkey,
                                                 self.privca, ('name',),
                                                 options={'source-address':
                                                          String(b'\xff')})
                    asyncssh.import_certificate(cert)

            with self.subTest('Invalid IP network in source-address'):
                with self.assertRaises(asyncssh.KeyImportError):
                    cert = self.make_certificate(cert_type, self.pubkey,
                                                 self.privca, ('name',),
                                                 options={'source-address':
                                                          String('1.1.1.256')})
                    asyncssh.import_certificate(cert)

        with self.subTest('Invalid certificate type'):
            with self.assertRaises(asyncssh.KeyImportError):
                cert = self.make_certificate(0, self.pubkey,
                                             self.privca, ('name',))
                asyncssh.import_certificate(cert)

        with self.subTest('Mismatched certificate type'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',))
                cert = asyncssh.import_certificate(cert)
                cert.validate(cert_type ^ 3, 'name')

        with self.subTest('Certificate not yet valid'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',),
                                             valid_after=0xffffffffffffffff)
                cert = asyncssh.import_certificate(cert)
                cert.validate(cert_type, 'name')

        with self.subTest('Certificate expired'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',),
                                             valid_before=0)
                cert = asyncssh.import_certificate(cert)
                cert.validate(cert_type, 'name')

        with self.subTest('Certificate principal mismatch'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',))
                cert = asyncssh.import_certificate(cert)
                cert.validate(cert_type, 'name2')

        with self.subTest('Invalid certificate export format'):
            with self.assertRaises(asyncssh.KeyExportError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',))
                cert = asyncssh.import_certificate(cert)
                cert.export_certificate('xxx')

    def test_keys(self):
        """Check keys and certificates"""

        for alg_name, kwargs in self.generate_args:
            with self.subTest(alg_name=alg_name, **kwargs):
                self.privkey = asyncssh.generate_private_key(alg_name,
                                                             comment='comment',
                                                             **kwargs)
                self.privkey.write_private_key('priv', self.base_format)

                self.pubkey = self.privkey.convert_to_public()
                self.pubkey.write_public_key('pub', self.base_format)
                self.pubkey.write_public_key('sshpub', 'openssh')

                self.privca = asyncssh.generate_private_key(alg_name, **kwargs)
                self.privca.write_private_key('privca', self.base_format)

                self.pubca = self.privca.convert_to_public()
                self.pubca.write_public_key('pubca', self.base_format)

                self.usercert = self.privca.generate_user_certificate(
                    self.pubkey, 'name', comment='cert_comment')
                self.usercert.write_certificate('usercert')

                self.hostcert = self.privca.generate_host_certificate(
                    self.pubkey, 'name', comment=None)
                self.hostcert.write_certificate('hostcert')

                run('chmod 600 priv privca')

                self.assertEqual(self.privkey.get_algorithm(), alg_name)

                self.assertEqual(self.usercert.get_algorithm(),
                                 alg_name + '-cert-v01@openssh.com')

                self.check_encode_errors()
                self.check_decode_errors()
                self.check_sshkey_base_errors()
                self.check_sign_and_verify()
                self.check_comment()

                if 'pkcs1' in self.private_formats:
                    self.check_pkcs1_private()

                if 'pkcs1' in self.public_formats:
                    self.check_pkcs1_public()

                if 'pkcs8' in self.private_formats:
                    self.check_pkcs8_private()

                if 'pkcs8' in self.public_formats:
                    self.check_pkcs8_public()

                if 'openssh' in self.private_formats: # pragma: no branch
                    self.check_openssh_private()

                if 'openssh' in self.public_formats: # pragma: no branch
                    self.check_openssh_public()
                    self.check_openssh_certificate()

                if 'rfc4716' in self.public_formats: # pragma: no branch
                    self.check_rfc4716_public()
                    self.check_rfc4716_certificate()

                self.check_certificate_options()

                for cert_type in (CERT_TYPE_USER, CERT_TYPE_HOST):
                    self.check_certificate_errors(cert_type)


class TestDSA(_TestPublicKey):
    """Test DSA public keys"""

    keyclass = 'dsa'
    base_format = 'pkcs8-pem'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')
    default_cert_version = 'ssh-dss-cert-v01@openssh.com'
    generate_args = (('ssh-dss', {}),)


class TestRSA(_TestPublicKey):
    """Test RSA public keys"""

    keyclass = 'rsa'
    base_format = 'pkcs8-pem'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')
    default_cert_version = 'ssh-rsa-cert-v01@openssh.com'
    generate_args = (('ssh-rsa', {'key_size': 1024}),
                     ('ssh-rsa', {'key_size': 2048}),
                     ('ssh-rsa', {'key_size': 3072}),
                     ('ssh-rsa', {'exponent': 3}))


class TestEC(_TestPublicKey):
    """Test elliptic curve public keys"""

    keyclass = 'ec'
    base_format = 'pkcs8-pem'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs8', 'openssh', 'rfc4716')
    generate_args = (('ecdsa-sha2-nistp256', {}),
                     ('ecdsa-sha2-nistp384', {}),
                     ('ecdsa-sha2-nistp521', {}))

    @property
    def default_cert_version(self):
        """Return default SSH certificate version"""

        return self.privkey.algorithm.decode('ascii') + '-cert-v01@openssh.com'


if libnacl_available: # pragma: no branch
    class TestEd25519(_TestPublicKey):
        """Test Ed25519 public keys"""

        keyclass = 'ed25519'
        base_format = 'openssh'
        private_formats = ('openssh')
        public_formats = ('openssh', 'rfc4716')
        default_cert_version = 'ssh-ed25519-cert-v01@openssh.com'
        generate_args = (('ssh-ed25519', {}),)


del _TestPublicKey


class _TestPublicKeyTopLevel(TempDirTestCase):
    """Top-level public key module tests"""

    def test_public_key(self):
        """Test public key top-level functions"""

        self.assertIsNotNone(get_public_key_algs())
        self.assertIsNotNone(get_certificate_algs())

    def test_pad_error(self):
        """Test for missing RFC 1423 padding on PBE decrypt"""

        with self.assertRaises(asyncssh.KeyEncryptionError):
            pkcs1_decrypt(b'', b'AES-128-CBC', os.urandom(16), 'x')

    def test_ec_explicit(self):
        """Test EC certificate with explcit parameters"""

        if _openssl_available: # pragma: no branch
            for curve in ('secp256r1', 'secp384r1', 'secp521r1'):
                with self.subTest('Import EC key with explicit parameters',
                                  curve=curve):
                    run('openssl ecparam -out priv -noout -genkey -name %s '
                        '-param_enc explicit' % curve)
                    asyncssh.read_private_key('priv')

            with self.subTest('Import EC key with unknown explicit parameters'):
                run('openssl ecparam -out priv -noout -genkey -name secp112r1 '
                    '-param_enc explicit')
                with self.assertRaises(asyncssh.KeyImportError):
                    asyncssh.read_private_key('priv')

    def test_generate_errors(self):
        """Test errors in private key and certificate generation"""

        for alg_name, kwargs in (('xxx', {}),
                                 ('ssh-dss', {'xxx': 0}),
                                 ('ssh-rsa', {'xxx': 0}),
                                 ('ecdsa-sha2-nistp256', {'xxx': 0}),
                                 ('ssh-ed25519', {'xxx': 0})):
            with self.subTest(alg_name=alg_name, **kwargs):
                with self.assertRaises(asyncssh.KeyGenerationError):
                    asyncssh.generate_private_key(alg_name, **kwargs)

        privkey = asyncssh.generate_private_key('ssh-rsa')
        pubkey = privkey.convert_to_public()
        privca = asyncssh.generate_private_key('ssh-rsa')

        with self.assertRaises(asyncssh.KeyGenerationError):
            privca.generate_user_certificate(pubkey, 'name', version=0)

        with self.assertRaises(ValueError):
            privca.generate_user_certificate(pubkey, 'name', valid_after=())

        with self.assertRaises(ValueError):
            privca.generate_user_certificate(pubkey, 'name', valid_after='xxx')

        with self.assertRaises(ValueError):
            privca.generate_user_certificate(pubkey, 'name', valid_after='now',
                                             valid_before='-1m')
