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

   Note: These tests assume that the openssl and ssh-keygen commands are
         available on the system and in the user's path.

"""

import binascii
import os

from .util import bcrypt_available, libnacl_available
from .util import make_certificate, run, TempDirTestCase

from asyncssh import import_private_key, import_public_key, import_certificate
from asyncssh import read_private_key, read_public_key, read_certificate
from asyncssh import read_private_key_list, read_public_key_list
from asyncssh import read_certificate_list
from asyncssh import KeyImportError, KeyExportError, KeyEncryptionError
from asyncssh.asn1 import der_encode, BitString, ObjectIdentifier
from asyncssh.asn1 import TaggedDERObject
from asyncssh.packet import MPInt, String, UInt32
from asyncssh.pbe import pkcs1_decrypt
from asyncssh.public_key import CERT_TYPE_USER, CERT_TYPE_HOST, SSHKey
from asyncssh.public_key import get_public_key_algs, get_certificate_algs


_ES1_SHA1_DES = ObjectIdentifier('1.2.840.113549.1.5.10')
_P12_RC4_40 = ObjectIdentifier('1.2.840.113549.1.12.1.2')
_ES2 = ObjectIdentifier('1.2.840.113549.1.5.13')
_ES2_PBKDF2 = ObjectIdentifier('1.2.840.113549.1.5.12')
_ES2_AES128 = ObjectIdentifier('2.16.840.1.101.3.4.1.2')
_ES2_DES3 = ObjectIdentifier('1.2.840.113549.3.7')


# pylint: disable=bad-whitespace

pkcs1_ciphers = (('aes128-cbc', '-aes128'),
                 ('aes192-cbc', '-aes192'),
                 ('aes256-cbc', '-aes256'),
                 ('des-cbc',    '-des'),
                 ('des3-cbc',   '-des3'))

pkcs8_ciphers = (('des-cbc',      'md5',    1, '-v1 PBE-MD5-DES'),
                 ('des-cbc',      'sha1',   1, '-v1 PBE-SHA1-DES'),
                 ('des2-cbc',     'sha1',   1, '-v1 PBE-SHA1-2DES'),
                 ('des3-cbc',     'sha1',   1, '-v1 PBE-SHA1-3DES'),
                 ('rc4-40',       'sha1',   1, '-v1 PBE-SHA1-RC4-40'),
                 ('rc4-128',      'sha1',   1, '-v1 PBE-SHA1-RC4-128'),
                 ('aes128-cbc',   'sha1',   2, '-v2 aes-128-cbc'),
                 ('aes192-cbc',   'sha1',   2, '-v2 aes-192-cbc'),
                 ('aes256-cbc',   'sha1',   2, '-v2 aes-256-cbc'),
                 ('blowfish-cbc', 'sha1',   2, '-v2 bf-cbc'),
                 ('cast128-cbc',  'sha1',   2, '-v2 cast-cbc'),
                 ('des-cbc',      'sha1',   2, '-v2 des-cbc'),
                 ('des3-cbc',     'sha1',   2, '-v2 des-ede3-cbc'))

openssh_ciphers = ('aes128-cbc', 'aes192-cbc', 'aes256-cbc',
                   'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
                   'arcfour', 'arcfour128', 'arcfour256',
                   'blowfish-cbc', 'cast128-cbc', '3des-cbc')

# pylint: enable=bad-whitespace

_openssl_version = run('openssl version')

_pkcs1_public_supported = _openssl_version >= b'OpenSSL 1.0.0'

if _openssl_version >= b'OpenSSL 1.0.2': # pragma: no branch
    # pylint: disable=bad-whitespace

    pkcs8_ciphers += (
        ('aes128-cbc',   'sha224', 2, '-v2 aes-128-cbc '
                                      '-v2prf hmacWithSHA224'),
        ('aes128-cbc',   'sha256', 2, '-v2 aes-128-cbc '
                                      '-v2prf hmacWithSHA256'),
        ('aes128-cbc',   'sha384', 2, '-v2 aes-128-cbc '
                                      '-v2prf hmacWithSHA384'),
        ('aes128-cbc',   'sha512', 2, '-v2 aes-128-cbc '
                                      '-v2prf hmacWithSHA512')
    )

if run('ssh -V') >= b'OpenSSH_6.9': # pragma: no branch
    # GCM & Chacha tests require OpenSSH 6.9 due to a bug in earlier versions:
    #     https://bugzilla.mindrot.org/show_bug.cgi?id=2366

    openssh_ciphers += ('aes128-gcm@openssh.com', 'aes256-gcm@openssh.com')

    # Only test Chacha if libnacl is installed
    if libnacl_available: # pragma: no branch
        openssh_ciphers += ('chacha20-poly1305@openssh.com',)


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
    keytypes = ()
    base_format = None
    private_formats = ()
    public_formats = ()
    default_cert_version = ''

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

        self.privkey = None
        self.pubkey = None
        self.privca = None
        self.pubca = None

    def make_keypair(self, privfile, pubfile, keytype):
        """Method to make a keypair defined by subclasses"""

        raise NotImplementedError

    def make_certificate(self, *args, **kwargs):
        """Construct an SSH certificate"""

        return make_certificate(self.default_cert_version, *args, **kwargs)

    def check_private(self, passphrase=None):
        """Check for a private key match"""

        newkey = read_private_key('new', passphrase)
        self.assertEqual(newkey, self.privkey)
        self.assertEqual(hash(newkey), hash(self.privkey))

        if passphrase:
            with self.assertRaises((KeyEncryptionError, KeyImportError)):
                read_private_key('new', 'xxx')
        else:
            run('cat new new > list')
            keylist = read_private_key_list('list', passphrase)
            self.assertEqual(keylist[0], newkey)
            self.assertEqual(keylist[1], newkey)

    def check_public(self):
        """Check for a public key match"""

        newkey = read_public_key('new')
        self.assertEqual(newkey, self.pubkey)
        self.assertEqual(hash(newkey), hash(self.pubkey))

        run('cat new new > list')
        keylist = read_public_key_list('list')
        self.assertEqual(keylist[0], newkey)
        self.assertEqual(keylist[1], newkey)

    def import_pkcs1_private(self, fmt, cipher=None, args=None):
        """Check import of a PKCS#1 private key"""

        if cipher:
            run('openssl %s %s -in priv -inform pem -out new -outform %s '
                '-passout pass:passphrase' % (self.keyclass, args, fmt))
        else:
            run('openssl %s -in priv -inform pem -out new -outform %s' %
                (self.keyclass, fmt))

        self.check_private(select_passphrase(cipher))

    def export_pkcs1_private(self, fmt, cipher=None):
        """Check export of a PKCS#1 private key"""

        self.privkey.write_private_key('privout', 'pkcs1-%s' % fmt,
                                       select_passphrase(cipher), cipher)

        if cipher:
            run('openssl %s -in privout -inform %s -out new -outform pem '
                '-passin pass:passphrase' % (self.keyclass, fmt))
        else:
            run('openssl %s -in privout -inform %s -out new -outform pem' %
                (self.keyclass, fmt))

        self.check_private()

    def import_pkcs1_public(self, fmt):
        """Check import of a PKCS#1 public key"""

        if self.keyclass == 'dsa':
            # OpenSSL no longer has support for PKCS#1 DSA, so we can
            # only test against ourselves.
            self.pubkey.write_public_key('new', 'pkcs1-%s' % fmt)
        else:
            run('openssl %s -pubin -in pub -inform pem -RSAPublicKey_out '
                '-out new -outform %s' % (self.keyclass, fmt))

        self.check_public()

    def export_pkcs1_public(self, fmt):
        """Check export of a PKCS#1 public key"""

        self.privkey.write_public_key('pubout', 'pkcs1-%s' % fmt)

        if self.keyclass == 'dsa':
            # OpenSSL no longer has support for PKCS#1 DSA, so we can
            # only test against ourselves.
            read_public_key('pubout').write_public_key('new', 'pkcs1-%s' % fmt)
        else:
            run('openssl %s -RSAPublicKey_in -in pubout -inform %s -out new '
                '-outform pem' % (self.keyclass, fmt))

        self.check_public()

    def import_pkcs8_private(self, fmt, cipher=None, pbe_version=None,
                             args=None):
        """Check import of a PKCS#8 private key"""

        if cipher:
            run('openssl pkcs8 -topk8 %s -in priv -inform pem -out new '
                '-outform %s -passout pass:passphrase' % (args, fmt))
        else:
            run('openssl pkcs8 -topk8 -nocrypt -in priv -inform pem -out new '
                '-outform %s' % fmt)

        self.check_private(select_passphrase(cipher, pbe_version))

    def export_pkcs8_private(self, fmt, cipher=None, hash_alg=None,
                             pbe_version=None):
        """Check export of a PKCS#8 private key"""

        self.privkey.write_private_key('privout', 'pkcs8-%s' % fmt,
                                       select_passphrase(cipher, pbe_version),
                                       cipher, hash_alg, pbe_version)

        if cipher:
            run('openssl pkcs8 -in privout -inform %s -out new '
                '-outform pem -passin pass:passphrase' % fmt)
        else:
            run('openssl pkcs8 -nocrypt -in privout -inform %s -out new '
                '-outform pem' % fmt)

        self.check_private()

    def import_pkcs8_public(self, fmt):
        """Check import of a PKCS#8 public key"""

        run('openssl %s -pubin -in pub -inform pem -out new -outform %s' %
            (self.keyclass, fmt))

        self.check_public()

    def export_pkcs8_public(self, fmt):
        """Check export of a PKCS#8 public key"""

        self.privkey.write_public_key('pubout', 'pkcs8-%s' % fmt)

        run('openssl %s -pubin -in pubout -inform %s -out new -outform pem' %
            (self.keyclass, fmt))

        self.check_public()

    def import_openssh_private(self, cipher=None):
        """Check import of an OpenSSH private key"""

        run('cp -p priv new')

        if cipher:
            run('ssh-keygen -p -N passphrase -Z %s -o -f new' % cipher)
        else:
            run('ssh-keygen -p -N "" -o -f new')

        self.check_private(select_passphrase(cipher))

    def export_openssh_private(self, cipher=None):
        """Check export of an OpenSSH private key"""

        self.privkey.write_private_key('new', 'openssh',
                                       select_passphrase(cipher), cipher)

        run('chmod 600 new')

        if cipher:
            run('ssh-keygen -p -P passphrase -N "" -o -f new')
        else:
            run('ssh-keygen -p -N "" -o -f new')

        self.check_private()

    def import_openssh_public(self):
        """Check import of an OpenSSH public key"""

        run('cp -p sshpub new')

        self.check_public()

    def export_openssh_public(self):
        """Check export of an OpenSSH public key"""

        self.privkey.write_public_key('pubout', 'openssh')

        run('ssh-keygen -e -f pubout -m rfc4716 > new')

        self.check_public()

    def import_rfc4716_public(self):
        """Check import of an RFC4716 public key"""

        run('ssh-keygen -e -f sshpub -m rfc4716 > new')

        self.check_public()

    def export_rfc4716_public(self):
        """Check export of an RFC4716 public key"""

        self.privkey.write_public_key('pubout', 'rfc4716')

        run('ssh-keygen -i -f pubout -m rfc4716 > new')

        self.check_public()

    def check_encode_errors(self):
        """Check error code paths in key encoding"""

        for fmt in ('pkcs1-der', 'pkcs1-pem', 'pkcs8-der', 'pkcs8-pem',
                    'openssh', 'rfc4716', 'xxx'):
            with self.subTest('Encode private from public (%s)' % fmt):
                with self.assertRaises(KeyExportError):
                    self.pubkey.export_private_key(fmt)

        with self.subTest('Encode with unknown key format'):
            with self.assertRaises(KeyExportError):
                self.privkey.export_public_key('xxx')

        with self.subTest('Encode encrypted pkcs1-der'):
            with self.assertRaises(KeyExportError):
                self.privkey.export_private_key('pkcs1-der', 'x')

        if self.keyclass == 'ec':
            with self.subTest('Encode EC public key with PKCS#1'):
                with self.assertRaises(KeyExportError):
                    self.privkey.export_public_key('pkcs1-pem')

        if 'pkcs1' in self.private_formats:
            with self.subTest('Encode with unknown PKCS#1 cipher'):
                with self.assertRaises(KeyEncryptionError):
                    self.privkey.export_private_key('pkcs1-pem', 'x', 'xxx')

        if 'pkcs8' in self.private_formats:
            with self.subTest('Encode with unknown PKCS#8 cipher'):
                with self.assertRaises(KeyEncryptionError):
                    self.privkey.export_private_key('pkcs8-pem', 'x', 'xxx')

            with self.subTest('Encode with unknown PKCS#8 hash'):
                with self.assertRaises(KeyEncryptionError):
                    self.privkey.export_private_key('pkcs8-pem', 'x',
                                                    'aes128-cbc', 'xxx')

            with self.subTest('Encode with unknown PKCS#8 version'):
                with self.assertRaises(KeyEncryptionError):
                    self.privkey.export_private_key('pkcs8-pem', 'x',
                                                    'aes128-cbc', 'sha1', 3)

        if ('openssh' in self.private_formats and # pragma: no branch
                bcrypt_available):
            with self.subTest('Encode with unknown openssh cipher'):
                with self.assertRaises(KeyEncryptionError):
                    self.privkey.export_private_key('openssh', 'x', 'xxx')

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
             b'XXX:\\\n'
             b'---- END SSH2 PUBLIC KEY ----\n'),
            ('Invalid RFC4716 Base64',
             b'---- BEGIN SSH2 PUBLIC KEY ----\n'
             b'X\n'
             b'---- END SSH2 PUBLIC KEY ----\n')
        ]

        for fmt, data in private_errors:
            with self.subTest('Decode private (%s)' % fmt):
                with self.assertRaises(KeyImportError):
                    import_private_key(data)

        for fmt, data in decrypt_errors:
            with self.subTest('Decrypt private (%s)' % fmt):
                with self.assertRaises((KeyImportError, KeyEncryptionError)):
                    import_private_key(data, 'x')

        for fmt, data in public_errors:
            with self.subTest('Decode public (%s)' % fmt):
                with self.assertRaises(KeyImportError):
                    import_public_key(data)

    def check_sshkey_base_errors(self):
        """Check SSHKey base class errors"""

        key = SSHKey()

        with self.subTest('SSHKey base class errors'):
            with self.assertRaises(KeyExportError):
                key.encode_pkcs1_private()

            with self.assertRaises(KeyExportError):
                key.encode_pkcs1_public()

            with self.assertRaises(KeyExportError):
                key.encode_pkcs8_private()

            with self.assertRaises(KeyExportError):
                key.encode_pkcs8_public()

            with self.assertRaises(KeyExportError):
                key.encode_ssh_private()

            with self.assertRaises(KeyExportError):
                key.encode_ssh_public()

    def check_sign_and_verify(self):
        """Check key signing and verification"""

        with self.subTest('Sign/verify test'):
            pubkey = read_public_key('pub')
            data = os.urandom(8)

            sig = self.privkey.sign(data)
            with self.subTest('Good signature'):
                self.assertTrue(pubkey.verify(data, sig))

            badsig = bytearray(sig)
            badsig[-1] ^= 0xff
            badsig = bytes(badsig)
            with self.subTest('Bad signature'):
                self.assertFalse(pubkey.verify(data, badsig))

            with self.subTest('Empty signature'):
                self.assertFalse(pubkey.verify(data, String(pubkey.algorithm) +
                                               String(b'')))

            badalg = String('xxx')
            with self.subTest('Bad algorithm'):
                self.assertFalse(pubkey.verify(data, badalg))

            with self.subTest('Sign with public key'):
                with self.assertRaises(ValueError):
                    pubkey.sign(data)

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
            self.import_pkcs8_private('pem')

        with self.subTest('Export PKCS#8 PEM private'):
            self.export_pkcs8_private('pem')

        with self.subTest('Import PKCS#8 DER private'):
            self.import_pkcs8_private('der')

        with self.subTest('Export PKCS#8 DER private'):
            self.export_pkcs8_private('der')

        for cipher, hash_alg, pbe_version, args in pkcs8_ciphers:
            with self.subTest('Import PKCS#8 PEM private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.import_pkcs8_private('pem', cipher, pbe_version, args)

            with self.subTest('Export PKCS#8 PEM private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.export_pkcs8_private('pem', cipher, hash_alg, pbe_version)

            with self.subTest('Import PKCS#8 DER private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.import_pkcs8_private('der', cipher, pbe_version, args)

            with self.subTest('Export PKCS#8 DER private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.export_pkcs8_private('der', cipher, hash_alg, pbe_version)

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
            self.import_openssh_private()

        with self.subTest('Export OpenSSH private'):
            self.export_openssh_private()

        if bcrypt_available: # pragma: no branch
            for cipher in openssh_ciphers:
                with self.subTest('Import OpenSSH private (%s)' % cipher):
                    self.import_openssh_private(cipher)

                with self.subTest('Export OpenSSH private (%s)' % cipher):
                    self.export_openssh_private(cipher)

    def check_openssh_public(self):
        """Check OpenSSH public key format"""

        with self.subTest('Import OpenSSH public'):
            self.import_openssh_public()

        with self.subTest('Export OpenSSH public'):
            self.export_openssh_public()

    def check_rfc4716_public(self):
        """Check RFC4716 public key format"""

        with self.subTest('Import RFC4716 public'):
            self.import_rfc4716_public()

        with self.subTest('Export RFC4716 public'):
            self.export_rfc4716_public()

    def check_certificate(self, cert_type, fmt):
        """Check SSH certificate import"""

        with self.subTest('Import certificate'):
            typearg = '-h ' if cert_type == CERT_TYPE_HOST else ''

            if cert_type == CERT_TYPE_USER:
                options = '-O force-command=xxx -O source-address=127.0.0.1 '
            else:
                options = ''

            run('ssh-keygen -s privca %s%s-I name sshpub' % (typearg, options))

            if fmt == 'openssh':
                run('mv sshpub-cert.pub cert')
            else:
                run('ssh-keygen -e -m %s -f sshpub-cert.pub > cert' % fmt)

            cert = read_certificate('cert')
            self.assertEqual(cert.key, self.pubkey)

        with self.subTest('Validate certificate'):
            self.assertIsNone(cert.validate(cert_type, 'name'))

        with self.subTest('Import certificate list'):
            run('cat cert cert > list')
            certlist = read_certificate_list('list')
            self.assertEqual(certlist[0].key, cert.key)
            self.assertEqual(certlist[1].key, cert.key)

    def check_certificate_errors(self, cert_type):
        """Check SSH certificate error cases"""

        with self.subTest('Non-ASCII certificate'):
            with self.assertRaises(KeyImportError):
                import_certificate('\u0080\n')

        with self.subTest('Invalid SSH format'):
            with self.assertRaises(KeyImportError):
                import_certificate('xxx\n')

        with self.subTest('Invalid certificate packetization'):
            with self.assertRaises(KeyImportError):
                import_certificate(b'xxx ' + binascii.b2a_base64(b'\x00'))

        with self.subTest('Invalid certificate algorithm'):
            with self.assertRaises(KeyImportError):
                import_certificate(b'xxx ' +
                                   binascii.b2a_base64(String(b'xxx')))

        with self.subTest('Invalid certificate critical option'):
            with self.assertRaises(KeyImportError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, 'name',
                                             options={b'xxx': b''})
                import_certificate(cert)

        with self.subTest('Ignored certificate extension'):
            cert = self.make_certificate(cert_type, self.pubkey,
                                         self.privca, 'name',
                                         extensions={b'xxx': b''})
            self.assertIsNotNone(import_certificate(cert))

        with self.subTest('Invalid certificate signature'):
            with self.assertRaises(KeyImportError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, 'name',
                                             bad_signature=True)
                import_certificate(cert)

        with self.subTest('Invalid characters in certificate principal'):
            with self.assertRaises(KeyImportError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, (b'\xff',))
                import_certificate(cert)

        if cert_type == CERT_TYPE_USER:
            with self.subTest('Invalid characters in force-command'):
                with self.assertRaises(KeyImportError):
                    cert = self.make_certificate(cert_type, self.pubkey,
                                                 self.privca, ('name',),
                                                 options={'force-command':
                                                          String(b'\xff')})
                    import_certificate(cert)

            with self.subTest('Invalid characters in source-address'):
                with self.assertRaises(KeyImportError):
                    cert = self.make_certificate(cert_type, self.pubkey,
                                                 self.privca, ('name',),
                                                 options={'source-address':
                                                          String(b'\xff')})
                    import_certificate(cert)

            with self.subTest('Invalid IP network in source-address'):
                with self.assertRaises(KeyImportError):
                    cert = self.make_certificate(cert_type, self.pubkey,
                                                 self.privca, ('name',),
                                                 options={'source-address':
                                                          String('1.1.1.256')})
                    import_certificate(cert)

        with self.subTest('Invalid certificate type'):
            with self.assertRaises(KeyImportError):
                cert = self.make_certificate(0, self.pubkey,
                                             self.privca, ('name',))
                import_certificate(cert)

        with self.subTest('Mismatched certificate type'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',))
                cert = import_certificate(cert)
                cert.validate(cert_type ^ 3, 'name')

        with self.subTest('Certificate not yet valid'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',),
                                             valid_after=0xffffffffffffffff)
                cert = import_certificate(cert)
                cert.validate(cert_type, 'name')

        with self.subTest('Certificate expired'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',),
                                             valid_before=0)
                cert = import_certificate(cert)
                cert.validate(cert_type, 'name')

        with self.subTest('Certificate principal mismatch'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',))
                cert = import_certificate(cert)
                cert.validate(cert_type, 'name2')

    def test_key(self):
        """Check key import and export"""

        for keytype in self.keytypes:
            with self.subTest(keytype=keytype):
                self.make_keypair('priv', 'pub', keytype)
                self.make_keypair('privca', 'pubca', keytype)

                run('chmod 600 priv privca')

                if self.base_format == 'openssh':
                    run('cp -p pub sshpub')
                else:
                    run('ssh-keygen -i -f pub -m %s > sshpub' %
                        self.base_format)

                self.privkey = read_private_key('priv')
                self.pubkey = read_public_key('pub')
                self.privca = read_private_key('privca')
                self.pubca = read_public_key('pubca')

                self.check_encode_errors()
                self.check_decode_errors()
                self.check_sshkey_base_errors()
                self.check_sign_and_verify()

                if 'pkcs1' in self.private_formats:
                    self.check_pkcs1_private()

                if 'pkcs1' in self.public_formats and _pkcs1_public_supported:
                    self.check_pkcs1_public()

                if 'pkcs8' in self.private_formats:
                    self.check_pkcs8_private()

                if 'pkcs8' in self.public_formats:
                    self.check_pkcs8_public()

                if 'openssh' in self.private_formats: # pragma: no branch
                    self.check_openssh_private()

                if 'openssh' in self.public_formats: # pragma: no branch
                    self.check_openssh_public()

                if 'rfc4716' in self.public_formats: # pragma: no branch
                    self.check_rfc4716_public()

                for cert_type in (CERT_TYPE_USER, CERT_TYPE_HOST):
                    for fmt in ('openssh', 'rfc4716'):
                        with self.subTest(cert_type=cert_type, fmt=fmt):
                            self.check_certificate(cert_type, fmt)

                    self.check_certificate_errors(cert_type)

class TestDSA(_TestPublicKey):
    """Test DSA public keys"""

    keyclass = 'dsa'
    keytypes = (1024,)
    base_format = 'pkcs8'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')
    default_cert_version = 'ssh-dss-cert-v01@openssh.com'

    def make_keypair(self, privfile, pubfile, keytype):
        """Make a DSA key pair"""

        # pylint: disable=no-self-use

        run('openssl dsaparam -out %s -noout -genkey %s' % (privfile, keytype))
        run('openssl dsa -pubout -in %s -out %s' % (privfile, pubfile))

class TestRSA(_TestPublicKey):
    """Test RSA public keys"""

    keyclass = 'rsa'
    keytypes = (1024, 2048)
    base_format = 'pkcs8'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')
    default_cert_version = 'ssh-rsa-cert-v01@openssh.com'

    def make_keypair(self, privfile, pubfile, keytype):
        """Make an RSA key pair"""

        # pylint: disable=no-self-use

        run('openssl genrsa -out %s %s' % (privfile, keytype))
        run('openssl rsa -pubout -in %s -out %s' % (privfile, pubfile))

class TestEC(_TestPublicKey):
    """Test elliptic curve public keys"""

    keyclass = 'ec'
    keytypes = ('secp256r1', 'secp384r1', 'secp521r1')
    base_format = 'pkcs8'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs8', 'openssh', 'rfc4716')

    @property
    def default_cert_version(self):
        """Return default SSH certificate version"""

        return self.privkey.algorithm.decode('ascii') + '-cert-v01@openssh.com'

    def make_keypair(self, privfile, pubfile, keytype):
        """Make an elliptic curve key pair"""

        # pylint: disable=no-self-use

        run('openssl ecparam -out %s -noout -genkey -name %s' %
            (privfile, keytype))
        run('openssl ec -pubout -in %s -out %s' % (privfile, pubfile))

if libnacl_available: # pragma: no branch
    class TestEd25519(_TestPublicKey):
        """Test Ed25519 public keys"""

        keyclass = 'ed25519'
        keytypes = (256,)
        base_format = 'openssh'
        private_formats = ('openssh')
        public_formats = ('openssh', 'rfc4716')
        default_cert_version = 'ssh-ed25519-cert-v01@openssh.com'

        def make_keypair(self, privfile, pubfile, keytype):
            """Make an Ed25519 key pair"""

            # pylint: disable=no-self-use,unused-argument

            run('ssh-keygen -t ed25519 -N "" -f %s' % privfile)
            run('mv %s.pub %s' % (privfile, pubfile))

del _TestPublicKey

class _TestPublicKeyTopLevel(TempDirTestCase):
    """Top-level public key module tests"""

    def test_public_key(self):
        """Test public key top-level functions"""

        self.assertIsNotNone(get_public_key_algs())
        self.assertIsNotNone(get_certificate_algs())

    def test_pad_error(self):
        """Test for missing RFC 1423 padding on PBE decrypt"""

        with self.assertRaises(KeyEncryptionError):
            pkcs1_decrypt(b'', b'AES-128-CBC', os.urandom(16), 'x')

    def test_ec_explicit(self):
        """Test EC certificate with explcit parameters"""

        for curve in ('secp256r1', 'secp384r1', 'secp521r1'):
            with self.subTest('Import EC key with explicit parameters',
                              curve=curve):
                run('openssl ecparam -out priv -noout -genkey -name %s '
                    '-param_enc explicit' % curve)
                read_private_key('priv')

        with self.subTest('Import EC key with unknown explicit parameters'):
            run('openssl ecparam -out priv -noout -genkey -name secp112r1 '
                '-param_enc explicit')
            with self.assertRaises(KeyImportError):
                read_private_key('priv')
