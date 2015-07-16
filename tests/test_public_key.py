# Copyright (c) 2014-2015 by Ron Frederick <ronf@timeheart.net>.
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
import importlib.util
import os
import subprocess
import tempfile
import unittest

bcrypt_available = importlib.util.find_spec('bcrypt')
libnacl_available = importlib.util.find_spec('libnacl')

from asyncssh import import_private_key, import_public_key
from asyncssh import read_private_key, read_public_key
from asyncssh import read_private_key_list, read_public_key_list
from asyncssh import KeyImportError, KeyExportError, KeyEncryptionError
from asyncssh.asn1 import der_encode, BitString, ObjectIdentifier
from asyncssh.packet import MPInt, String, UInt32
from asyncssh.public_key import SSHKey


def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True,
                                       stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        print(exc.output.decode())
        raise


pkcs1_ciphers = (('aes128-cbc', '-aes128'),
                 ('aes192-cbc', '-aes192'),
                 ('aes256-cbc', '-aes256'),
                 ('des-cbc',    '-des'),
                 ('des3-cbc',   '-des3'))

pkcs8_ciphers = (('des-cbc',      'md5',  1, '-v1 PBE-MD5-DES'),
                 ('des-cbc',      'sha1', 1, '-v1 PBE-SHA1-DES'),
                 ('rc2-64-cbc',   'md5',  1, '-v1 PBE-MD5-RC2-64'),
                 ('rc2-64-cbc',   'sha1', 1, '-v1 PBE-SHA1-RC2-64'),
                 ('des2-cbc',     'sha1', 1, '-v1 PBE-SHA1-2DES'),
                 ('des3-cbc',     'sha1', 1, '-v1 PBE-SHA1-3DES'),
                 ('rc2-40-cbc',   'sha1', 1, '-v1 PBE-SHA1-RC2-40'),
                 ('rc2-128-cbc',  'sha1', 1, '-v1 PBE-SHA1-RC2-128'),
                 ('rc4-40',       'sha1', 1, '-v1 PBE-SHA1-RC4-40'),
                 ('rc4-128',      'sha1', 1, '-v1 PBE-SHA1-RC4-128'),
                 ('aes128-cbc',   'sha1', 2, '-v2 aes-128-cbc'),
                 ('aes192-cbc',   'sha1', 2, '-v2 aes-192-cbc'),
                 ('aes256-cbc',   'sha1', 2, '-v2 aes-256-cbc'),
                 ('blowfish-cbc', 'sha1', 2, '-v2 bf-cbc'),
                 ('cast128-cbc',  'sha1', 2, '-v2 cast-cbc'),
                 ('des-cbc',      'sha1', 2, '-v2 des-cbc'),
                 ('des3-cbc',     'sha1', 2, '-v2 des-ede3-cbc'),
                 ('rc2-40-cbc',   'sha1', 2, '-v2 rc2-40-cbc'),
                 ('rc2-64-cbc',   'sha1', 2, '-v2 rc2-64-cbc'),
                 ('rc2-128-cbc',  'sha1', 2, '-v2 rc2-cbc'))

openssh_ciphers = ('aes128-cbc', 'aes192-cbc', 'aes256-cbc',
                   'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
                   'arcfour', 'arcfour128', 'arcfour256',
                   'blowfish-cbc', 'cast128-cbc', '3des-cbc')

if run('ssh -V') >= b'OpenSSH_6.9':
    # GCM & Chacha tests require OpenSSH 6.9 due to a bug in earlier versions:
    #     https://bugzilla.mindrot.org/show_bug.cgi?id=2366
    openssh_ciphers = openssh_ciphers + ('aes128-gcm@openssh.com',
                                         'aes256-gcm@openssh.com',
                                         'chacha20-poly1305@openssh.com')

passphrase = 'passphrase'


class _TestKeys(unittest.TestCase):
    def check_private(self, passphrase=None):
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
        newkey = read_public_key('new')
        self.assertEqual(newkey, self.pubkey)
        self.assertEqual(hash(newkey), hash(self.pubkey))

        run('cat new new > list')
        keylist = read_public_key_list('list')
        self.assertEqual(keylist[0], newkey)
        self.assertEqual(keylist[1], newkey)

    def import_pkcs1_private(self, format, cipher=None, args=None):
        if cipher:
            run('openssl %s %s -in priv -inform pem -out new -outform %s '
                '-passout pass:%s' % (self.keyclass, args, format, passphrase))
        else:
            run('openssl %s -in priv -inform pem -out new -outform %s' %
                    (self.keyclass, format))

        self.check_private(passphrase if cipher else None)

    def export_pkcs1_private(self, format, cipher=None):
        self.privkey.write_private_key('privout', 'pkcs1-%s' % format,
                                       passphrase if cipher else None, cipher)

        if cipher:
            run('openssl %s -in privout -inform %s -out new -outform pem '
                '-passin pass:%s' % (self.keyclass, format, passphrase))
        else:
            run('openssl %s -in privout -inform %s -out new -outform pem' %
                    (self.keyclass, format))

        self.check_private()

    def import_pkcs1_public(self, format):
        if self.keyclass == 'dsa':
            # OpenSSL no longer has support for PKCS#1 DSA, so we can
            # only test against ourselves.
            self.pubkey.write_public_key('new', 'pkcs1-%s' % format)
        else:
            run('openssl %s -pubin -in pub -inform pem -RSAPublicKey_out '
                '-out new -outform %s' % (self.keyclass, format))

        self.check_public()

    def export_pkcs1_public(self, format):
        self.privkey.write_public_key('pubout', 'pkcs1-%s' % format)

        if self.keyclass == 'dsa':
            # OpenSSL no longer has support for PKCS#1 DSA, so we can
            # only test against ourselves.
            read_public_key('pubout').write_public_key('new', 'pkcs1-%s' % format)
        else:
            run('openssl %s -RSAPublicKey_in -in pubout -inform %s -out new '
                '-outform pem' % (self.keyclass, format))

        self.check_public()

    def import_pkcs8_private(self, format, cipher=None, args=None):
        if cipher:
            run('openssl pkcs8 -topk8 %s -in priv -inform pem -out new '
                    '-outform %s -passout pass:%s' % (args, format, passphrase))
        else:
            run('openssl pkcs8 -topk8 -nocrypt -in priv -inform pem -out new '
                '-outform %s' % format)

        self.check_private(passphrase if cipher else None)

    def export_pkcs8_private(self, format, cipher=None, hash_alg=None,
                             pbe_version=None):
        self.privkey.write_private_key('privout', 'pkcs8-%s' % format,
                                       passphrase if cipher else None, cipher,
                                       hash_alg, pbe_version)

        if cipher:
            run('openssl pkcs8 -in privout -inform %s -out new '
                '-outform pem -passin pass:%s' % (format, passphrase))
        else:
            run('openssl pkcs8 -nocrypt -in privout -inform %s -out new '
                '-outform pem' % format)

        self.check_private()

    def import_pkcs8_public(self, format):
        run('openssl %s -pubin -in pub -inform pem -out new -outform %s' %
                (self.keyclass, format))

        self.check_public()

    def export_pkcs8_public(self, format):
        self.privkey.write_public_key('pubout', 'pkcs8-%s' % format)

        run('openssl %s -pubin -in pubout -inform %s -out new -outform pem' %
                (self.keyclass, format))

        self.check_public()

    def import_openssh_private(self, cipher=None):
        run('cp -p priv new')

        if cipher:
            run('ssh-keygen -p -N %s -Z %s -o -f new' % (passphrase, cipher))
        else:
            run('ssh-keygen -p -N "" -o -f new')

        self.check_private(passphrase if cipher else None)

    def export_openssh_private(self, cipher=None):
        self.privkey.write_private_key('new', 'openssh',
                                       passphrase if cipher else None, cipher)

        run('chmod 600 new')

        if cipher:
            run('ssh-keygen -p -P %s -N "" -o -f new' % passphrase)
        else:
            run('ssh-keygen -p -N "" -o -f new')

        self.check_private()

    def import_openssh_public(self):
        if self.baseformat == 'openssh':
            run('cp -p pub new')
        else:
            run('ssh-keygen -i -f pub -m %s > new' % self.baseformat)

        self.check_public()

    def export_openssh_public(self):
        self.privkey.write_public_key('pubout', 'openssh')

        run('ssh-keygen -e -f pubout -m rfc4716 > new')

        self.check_public()

    def import_rfc4716_public(self):
        if self.baseformat == 'openssh':
            run('cp -p pub sshpub')
        else:
            run('ssh-keygen -i -f pub -m pkcs8 > sshpub')

        run('ssh-keygen -e -f sshpub -m rfc4716 > new')

        self.check_public()

    def export_rfc4716_public(self):
        self.privkey.write_public_key('pubout', 'rfc4716')

        run('ssh-keygen -i -f pubout -m rfc4716 > new')

        self.check_public()

    def check_encode_errors(self):
        for format in ('pkcs1-der', 'pkcs1-pem', 'pkcs8-der', 'pkcs8-pem',
                       'openssh', 'rfc4716', 'xxx'):
            with self.subTest('Encode private from public (%s)' % format):
                with self.assertRaises(KeyExportError):
                    self.pubkey.export_private_key(format)

        with self.subTest('Encode with unknown key format'):
            with self.assertRaises(KeyExportError):
                self.privkey.export_public_key('xxx')

        with self.subTest('Encode encrypted pkcs1-der'):
            with self.assertRaises(KeyExportError):
                self.privkey.export_private_key('pkcs1-der', 'passphrase')

        with self.subTest('Encode with unknown openssh cipher'):
            with self.assertRaises(KeyEncryptionError):
                self.privkey.export_private_key('openssh', 'passphrase', 'xxx')

    def check_decode_errors(self):
        private_errors = [
            ('Non-ASCII', '\xff'),
            ('Incomplete ASN.1', b''),
            ('Invalid PKCS#1', der_encode(None)),
            ('Invalid PKCS#8', der_encode((0, (self.privkey.pkcs8_oid, ()),
                                           der_encode(None)))),
            ('Invalid PKCS#8 ASN.1', der_encode((0, (self.privkey.pkcs8_oid,
                                                     None), b''))),
            ('Invalid PEM header', b'-----BEGIN XXX-----\n'),
            ('Missing PEM footer', b'-----BEGIN PRIVATE KEY-----\n'),
            ('Invalid PEM key type', b'-----BEGIN XXX PRIVATE KEY-----\n' +
                                     binascii.b2a_base64(der_encode(None)) +
                                     b'-----END XXX PRIVATE KEY-----'),
            ('Invalid PEM Base64', b'-----BEGIN PRIVATE KEY-----\n'
                                   b'X\n'
                                   b'-----END PRIVATE KEY-----'),
            ('Missing PKCS#1 passphrase', b'-----BEGIN DSA PRIVATE KEY-----\n'
                                          b'Proc-Type: 4,ENCRYPTED\n'
                                          b'-----END DSA PRIVATE KEY-----'),
            ('Incomplete PEM ASN.1', b'-----BEGIN PRIVATE KEY-----\n'
                                     b'-----END PRIVATE KEY-----'),
            ('Missing PEM PKCS#8 passphrase',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(None)) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#1 key', b'-----BEGIN DSA PRIVATE KEY-----\n' +
                                       binascii.b2a_base64(der_encode(None)) +
                                       b'-----END DSA PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 key', b'-----BEGIN PRIVATE KEY-----\n' +
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
            ('Invalid OpenSSH cipher',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join((b'openssh-key-v1\0', String('xxx'),
                                           String(''), String(''), UInt32(1),
                                           String(''), String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH kdf',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join((b'openssh-key-v1\0',
                                           String('aes256-cbc'), String('xxx'),
                                           String(''), UInt32(1), String(''),
                                           String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH kdf data',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join((b'openssh-key-v1\0',
                                           String('aes256-cbc'),
                                           String('bcrypt'), String(''),
                                           UInt32(1), String(''),
                                           String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH salt',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join((b'openssh-key-v1\0',
                                           String('aes256-cbc'),
                                           String('bcrypt'),
                                           String(b''.join((String(b''),
                                                            UInt32(1)))),
                                           UInt32(1), String(''),
                                           String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH encrypted data',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join((b'openssh-key-v1\0',
                                           String('aes256-cbc'),
                                           String('bcrypt'),
                                           String(b''.join((String(16*b'\0'),
                                                            UInt32(1)))),
                                           UInt32(1), String(''),
                                           String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Unexpected OpenSSH trailing data',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join((b'openssh-key-v1\0',
                                           String('aes256-cbc'),
                                           String('bcrypt'),
                                           String(b''.join((String(16*b'\0'),
                                                            UInt32(1)))),
                                           UInt32(1), String(''),
                                           String(''), String('xxx')))) +
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
            ('Invalid PEM key type', b'-----BEGIN XXX PUBLIC KEY-----\n' +
                                     binascii.b2a_base64(der_encode(None)) +
                                     b'-----END XXX PUBLIC KEY-----'),
            ('Invalid PEM Base64', b'-----BEGIN PUBLIC KEY-----\n'
                                   b'X\n'
                                   b'-----END PUBLIC KEY-----'),
            ('Incomplete PEM ASN.1', b'-----BEGIN PUBLIC KEY-----\n'
                                     b'-----END PUBLIC KEY-----'),
            ('Invalid PKCS#1 key data', b'-----BEGIN DSA PUBLIC KEY-----\n' +
                                        binascii.b2a_base64(der_encode(None)) +
                                        b'-----END DSA PUBLIC KEY-----'),
            ('Invalid PKCS#8 key data', b'-----BEGIN PUBLIC KEY-----\n' +
                                        binascii.b2a_base64(der_encode(None)) +
                                        b'-----END PUBLIC KEY-----'),
            ('Invalid OpenSSH', b'xxx'),
            ('Invalid OpenSSH Base64', b'ssh-dss X'),
            ('Unknown OpenSSH algorithm', b'ssh-dss ' +
                                          binascii.b2a_base64(String('xxx'))),
            ('Invalid OpenSSH body', b'ssh-dss ' +
                                     binascii.b2a_base64(String('ssh-dss'))),
            ('Invalid RFC4716 header', b'---- XXX ----\n'),
            ('Missing RFC4716 footer', b'---- BEGIN SSH2 PUBLIC KEY ----\n'),
            ('Invalid RFC4716 header', b'---- BEGIN SSH2 PUBLIC KEY ----\n'
                                       b'XXX:\\\n'
                                       b'---- END SSH2 PUBLIC KEY ----\n'),
            ('Invalid RFC4716 Base64', b'---- BEGIN SSH2 PUBLIC KEY ----\n'
                                       b'X\n'
                                       b'---- END SSH2 PUBLIC KEY ----\n')
        ]

        for format, data in private_errors:
            with self.subTest('Decode private (%s)' % format):
                with self.assertRaises(KeyImportError):
                    import_private_key(data)

        for format, data in decrypt_errors:
            with self.subTest('Decrypt private (%s)' % format):
                with self.assertRaises((KeyImportError, KeyEncryptionError)):
                    import_private_key(data, 'passphrase')

        for format, data in public_errors:
            with self.subTest('Decode public (%s)' % format):
                with self.assertRaises(KeyImportError):
                    import_public_key(data)

    def check_sshkey_base_errors(self):
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
        with self.subTest('Sign/verify test'):
            pubkey = read_public_key('pub')
            data = os.urandom(8)

            sig = self.privkey.sign(data)
            self.assertTrue(pubkey.verify(data, sig))

            badsig = bytearray(sig)
            badsig[-1] ^= 0xff
            badsig = bytes(badsig)
            self.assertFalse(pubkey.verify(data, badsig))

            badalg = String('xxx')
            self.assertFalse(pubkey.verify(data, badalg))

            with self.assertRaises(ValueError):
                pubkey.sign(data)

    def check_pkcs1_private(self):
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
        with self.subTest('Import PKCS#1 PEM public'):
            self.import_pkcs1_public('pem')

        with self.subTest('Export PKCS#1 PEM public'):
            self.export_pkcs1_public('pem')

        with self.subTest('Import PKCS#1 DER public'):
            self.import_pkcs1_public('der')

        with self.subTest('Export PKCS#1 DER public'):
            self.export_pkcs1_public('der')

    def check_pkcs8_private(self):
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
                self.import_pkcs8_private('pem', cipher, args)

            with self.subTest('Export PKCS#8 PEM private (%s-%s-v%s)' %
                                  (cipher, hash_alg, pbe_version)):
                self.export_pkcs8_private('pem', cipher, hash_alg, pbe_version)

            with self.subTest('Import PKCS#8 DER private (%s-%s-v%s)' %
                                  (cipher, hash_alg, pbe_version)):
                self.import_pkcs8_private('der', cipher, args)

            with self.subTest('Export PKCS#8 DER private (%s-%s-v%s)' %
                                  (cipher, hash_alg, pbe_version)):
                self.export_pkcs8_private('der', cipher, hash_alg, pbe_version)

    def check_pkcs8_public(self):
        with self.subTest('Import PKCS#8 PEM public'):
            self.import_pkcs8_public('pem')

        with self.subTest('Export PKCS#8 PEM public'):
            self.export_pkcs8_public('pem')

        with self.subTest('Import PKCS#8 DER public'):
            self.import_pkcs8_public('der')

        with self.subTest('Export PKCS#8 DER public'):
            self.export_pkcs8_public('der')

    def check_openssh_private(self):
        with self.subTest('Import OpenSSH private'):
            self.import_openssh_private()

        with self.subTest('Export OpenSSH private'):
            self.export_openssh_private()

        if bcrypt_available:
            for cipher in openssh_ciphers:
                with self.subTest('Import OpenSSH private (%s)' % cipher):
                    self.import_openssh_private(cipher)

                with self.subTest('Export OpenSSH private (%s)' % cipher):
                    self.export_openssh_private(cipher)

    def check_openssh_public(self):
        with self.subTest('Import OpenSSH public'):
            self.import_openssh_public()

        with self.subTest('Export OpenSSH public'):
            self.export_openssh_public()

    def check_rfc4716_public(self):
        with self.subTest('Import RFC4716 public'):
            self.import_rfc4716_public()

        with self.subTest('Export RFC4716 public'):
            self.export_rfc4716_public()

    def test_key(self):
        tmpdir = tempfile.TemporaryDirectory()
        os.chdir(tmpdir.name)

        for keytype in self.keytypes:
            with self.subTest(keytype=keytype):
                self.make_keypair(keytype)

                run('chmod 600 priv pub')

                self.privkey = read_private_key('priv')
                self.pubkey = read_public_key('pub')

                self.check_encode_errors()
                self.check_decode_errors()
                self.check_sshkey_base_errors()
                self.check_sign_and_verify()

                if 'pkcs1' in self.private_formats:
                    self.check_pkcs1_private()

                if 'pkcs1' in self.public_formats:
                    self.check_pkcs1_public()

                if 'pkcs8' in self.private_formats:
                    self.check_pkcs8_private()

                if 'pkcs8' in self.public_formats:
                    self.check_pkcs8_public()

                if 'openssh' in self.private_formats:
                    self.check_openssh_private()

                if 'openssh' in self.public_formats:
                    self.check_openssh_public()

                if 'rfc4716' in self.public_formats:
                    self.check_rfc4716_public()

        tmpdir.cleanup()

class TestDSA(_TestKeys):
    keyclass = 'dsa'
    keytypes = (1024,)
    baseformat = 'pkcs8'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')

    def make_keypair(self, keytype):
        run('openssl dsaparam -out priv -noout -genkey %s' % keytype)
        run('openssl dsa -pubout -in priv -out pub')

class TestRSA(_TestKeys):
    keyclass = 'rsa'
    keytypes = (1024, 2048)
    baseformat = 'pkcs8'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')

    def make_keypair(self, keytype):
        run('openssl genrsa -out priv %s' % keytype)
        run('openssl rsa -pubout -in priv -out pub')

class TestEC(_TestKeys):
    keyclass = 'ec'
    keytypes = ('secp256r1', 'secp384r1', 'secp521r1')
    baseformat = 'pkcs8'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs8', 'openssh', 'rfc4716')

    def make_keypair(self, keytype):
        run('openssl ecparam -out priv -noout -genkey -name %s' % keytype)
        run('openssl ec -pubout -in priv -out pub')

if libnacl_available:
    class TestEd25519(_TestKeys):
        keyclass = 'ed25519'
        keytypes = (256,)
        baseformat = 'openssh'
        private_formats = ('openssh')
        public_formats = ('openssh', 'rfc4716')

        def make_keypair(self, keytype):
            run('ssh-keygen -t ed25519 -N "" -f priv')
            run('mv priv.pub pub')

del _TestKeys
