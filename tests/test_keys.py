# Copyright (c) 2014 by Ron Frederick <ronf@timeheart.net>.
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

import os, subprocess, tempfile, unittest

from asyncssh import read_private_key, read_public_key

pkcs1_ciphers = ('aes128', 'aes192', 'aes256', 'des', 'des3')

pkcs8_ciphers = (('des',     'md5',  1, '-v1 PBE-MD5-DES'),
                 ('des',     'sha1', 1, '-v1 PBE-SHA1-DES'),
                 ('rc2-64',  'md5',  1, '-v1 PBE-MD5-RC2-64'),
                 ('rc2-64',  'sha1', 1, '-v1 PBE-SHA1-RC2-64'),
                 ('des2',    'sha1', 1, '-v1 PBE-SHA1-2DES'),
                 ('des3',    'sha1', 1, '-v1 PBE-SHA1-3DES'),
                 ('rc2-40',  'sha1', 1, '-v1 PBE-SHA1-RC2-40'),
                 ('rc2-128', 'sha1', 1, '-v1 PBE-SHA1-RC2-128'),
                 ('rc4-40',  'sha1', 1, '-v1 PBE-SHA1-RC4-40'),
                 ('rc4-128', 'sha1', 1, '-v1 PBE-SHA1-RC4-128'),
                 ('aes128',  'sha1', 2, '-v2 aes-128-cbc'),
                 ('aes192',  'sha1', 2, '-v2 aes-192-cbc'),
                 ('aes256',  'sha1', 2, '-v2 aes-256-cbc'),
                 ('bf',      'sha1', 2, '-v2 bf-cbc'),
                 ('cast128', 'sha1', 2, '-v2 cast-cbc'),
                 ('des',     'sha1', 2, '-v2 des-cbc'),
                 ('des3',    'sha1', 2, '-v2 des-ede3-cbc'),
                 ('rc2-40',  'sha1', 2, '-v2 rc2-40-cbc'),
                 ('rc2-64',  'sha1', 2, '-v2 rc2-64-cbc'),
                 ('rc2-128', 'sha1', 2, '-v2 rc2-cbc'))

passphrase = 'passphrase'

def run(cmd):
    try:
        subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        #print('Command failed:', cmd)
        #print(e.output.decode())
        raise

class _TestKeys(unittest.TestCase):
    def check_private(self, passphrase):
        newkey = read_private_key('new', passphrase)
        #self.assertTrue(0)
        self.assertEqual(newkey.encode_ssh_public(), self.sshpub)

    def check_public(self):
        newkey = read_public_key('new')
        self.assertEqual(newkey.encode_ssh_public(), self.sshpub)

    def import_pkcs1_private(self, format, cipher=None):
        if cipher:
            run('openssl %s -%s -in priv -inform pem -out new -outform %s '
                '-passout pass:%s' % (self.keyclass, cipher, format,
                                      passphrase))
        else:
            run('openssl %s -in priv -inform pem -out new -outform %s' %
                    (self.keyclass, format))

        self.check_private(passphrase if cipher else None)

    def export_pkcs1_private(self, format, cipher=None):
        self.key.write_private_key('privout', 'pkcs1-%s' % format,
                                   passphrase if cipher else None, cipher)

        if cipher:
            run('openssl %s -in privout -inform %s -out new -outform pem '
                '-passin pass:%s' % (self.keyclass, format, passphrase))
        else:
            run('openssl %s -in privout -inform %s -out new -outform pem' %
                    (self.keyclass, format))

        self.check_private(passphrase if cipher else None)

    def import_pkcs8_private(self, format, cipher=None, args=None):
        if cipher:
            run('openssl pkcs8 -topk8 %s -in priv -inform pem -out new '
                    '-outform %s -passout pass:%s' % (args, format, passphrase))
        else:
            run('openssl pkcs8 -topk8 -nocrypt -in priv -inform pem -out new '
                '-outform %s' % format)

        self.check_private(passphrase if cipher else None)

    def export_pkcs8_private(self, format, cipher=None, hash=None,
                             pbe_version=None):
        self.key.write_private_key('privout', 'pkcs8-%s' % format,
                                   passphrase if cipher else None, cipher,
                                   hash, pbe_version)

        if cipher:
            run('openssl pkcs8 -in privout -inform %s -out new '
                '-outform pem -passin pass:%s' % (format, passphrase))
        else:
            run('openssl pkcs8 -nocrypt -in privout -inform %s -out new '
                '-outform pem' % format)

        self.check_private(passphrase if cipher else None)

    def import_pkcs8_public(self, format):
        run('openssl %s -pubin -in pub -inform pem -out new -outform %s' %
                (self.keyclass, format))

        self.check_public()

    def export_pkcs8_public(self, format):
        self.key.write_public_key('pubout', 'pkcs8-%s' % format)

        run('openssl %s -pubin -in pubout -inform %s -out new -outform pem' %
                (self.keyclass, format))

        self.check_public()

    def import_openssh_public(self):
        run('ssh-keygen -i -f pub -m pkcs8 > new')

        self.check_public()

    def export_openssh_public(self):
        self.key.write_public_key('pubout', 'openssh')

        run('ssh-keygen -e -f pubout -m rfc4716 > new')

        self.check_public()

    def import_rfc4716_public(self):
        run('ssh-keygen -i -f pub -m pkcs8 > new')
        run('ssh-keygen -e -f pub -m rfc4716 > new')

        self.check_public()

    def export_rfc4716_public(self):
        self.key.write_public_key('pubout', 'rfc4716')

        run('ssh-keygen -i -f pubout -m rfc4716 > new')

        self.check_public()

    def test_key(self):
        tmpdir = tempfile.TemporaryDirectory()
        os.chdir(tmpdir.name)

        for keytype in self.keytypes:
            with self.subTest(keytype=keytype):
                self.make_private(keytype)

                run('openssl %s -pubout -in priv -out pub' % self.keyclass)
                run('chmod 600 priv pub')

                with self.subTest('Import PKCS#1 PEM private'):
                    self.key = read_private_key('priv')
                    self.sshpub = self.key.encode_ssh_public()
                    self.assertTrue(self.sshpub)

                with self.subTest('Export PKCS#1 PEM private'):
                    self.export_pkcs1_private('pem')

                with self.subTest('Import PKCS#1 DER private'):
                    self.import_pkcs1_private('der')

                with self.subTest('Export PKCS#1 DER private'):
                    self.export_pkcs1_private('der')

                for cipher in pkcs1_ciphers:
                    with self.subTest('Import PKCS#1 PEM private (%s)' %
                            cipher):
                        self.import_pkcs1_private('pem', cipher)
                        
                    with self.subTest('Export PKCS#1 PEM private (%s)' %
                            cipher):
                        self.export_pkcs1_private('pem', cipher)

                with self.subTest('Import PKCS#8 PEM private'):
                    self.import_pkcs8_private('pem')

                with self.subTest('Export PKCS#8 PEM private'):
                    self.export_pkcs8_private('pem')

                with self.subTest('Import PKCS#8 DER private'):
                    self.import_pkcs8_private('der')

                with self.subTest('Export PKCS#8 DER private'):
                    self.export_pkcs8_private('der')

                for cipher, hash, pbe_version, args in pkcs8_ciphers:
                    with self.subTest('Import PKCS#8 PEM private '
                                      '(%s-%s-v%s)' % (cipher, hash,
                                      pbe_version)):
                        self.import_pkcs8_private('pem', cipher, args)
                        
                    with self.subTest('Export PKCS#8 PEM private '
                                      '(%s-%s-v%s)' % (cipher, hash,
                                      pbe_version)):
                        self.export_pkcs8_private('pem', cipher, hash,
                                                  pbe_version)

                    with self.subTest('Import PKCS#8 DER private '
                                      '(%s-%s-v%s)' % (cipher, hash,
                                      pbe_version)):
                        self.import_pkcs8_private('der', cipher, args)
                        
                    with self.subTest('Export PKCS#8 DER private '
                                      '(%s-%s-v%s)' % (cipher, hash,
                                      pbe_version)):
                        self.export_pkcs8_private('der', cipher, hash,
                                                  pbe_version)

                with self.subTest('Import PKCS#8 PEM public'):
                    self.import_pkcs8_public('pem')

                with self.subTest('Export PKCS#8 PEM public'):
                    self.export_pkcs8_public('pem')

                with self.subTest('Import PKCS#8 DER public'):
                    self.import_pkcs8_public('der')

                with self.subTest('Export PKCS#8 DER public'):
                    self.export_pkcs8_public('der')

                with self.subTest('Import OpenSSH public'):
                    self.import_openssh_public()

                with self.subTest('Export OpenSSH public'):
                    self.export_openssh_public()

                with self.subTest('Import RFC4716 public'):
                    self.import_openssh_public()

                with self.subTest('Export RFC4716 public'):
                    self.export_openssh_public()

        tmpdir.cleanup()

class TestDSA(_TestKeys):
    keyclass = 'dsa'
    keytypes = (1024, 2048)

    def make_private(self, keytype):
        run('openssl dsaparam -out priv -noout -genkey %s' % keytype)

class TestRSA(_TestKeys):
    keyclass = 'rsa'
    keytypes = (1024, 2048)

    def make_private(self, keytype):
        run('openssl genrsa -out priv %s' % keytype)

class TestEC(_TestKeys):
    keyclass = 'ec'
    keytypes = ('secp256r1', 'secp384r1', 'secp521r1')

    def make_private(self, keytype):
        run('openssl ecparam -out priv -noout -genkey -name %s' % keytype)

del _TestKeys
