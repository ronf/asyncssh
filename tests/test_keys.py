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
                   'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com',
                   'arcfour', 'arcfour128', 'arcfour256',
                   'blowfish-cbc', 'cast128-cbc', '3des-cbc')

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
        self.assertEqual(newkey.encode_ssh_public(), self.sshpub)

    def check_public(self):
        newkey = read_public_key('new')
        self.assertEqual(newkey.encode_ssh_public(), self.sshpub)

    def import_pkcs1_private(self, format, cipher=None, args=None):
        if cipher:
            run('openssl %s %s -in priv -inform pem -out new -outform %s '
                '-passout pass:%s' % (self.keyclass, args, format, passphrase))
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

    def import_openssh_private(self, cipher=None):
        run('cp -p priv new')

        if cipher:
            run('ssh-keygen -p -N %s -Z %s -o -f new' % (passphrase, cipher))
        else:
            run('ssh-keygen -p -N "" -o -f new')

        self.check_private(passphrase if cipher else None)

    def export_openssh_private(self, cipher=None):
        self.key.write_private_key('new', 'openssh',
                                   passphrase if cipher else None, cipher)

        run('chmod 600 new')

        if cipher:
            run('ssh-keygen -p -P %s -N "" -o -f new' % passphrase)
        else:
            run('ssh-keygen -p -N "" -o -f new')

        self.check_private(passphrase if cipher else None)

    def import_openssh_public(self):
        if self.baseformat == 'openssh':
            run('cp -p pub new')
        else:
            run('ssh-keygen -i -f pub -m %s > new' % self.baseformat)

        self.check_public()

    def export_openssh_public(self):
        self.key.write_public_key('pubout', 'openssh')

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
        self.key.write_public_key('pubout', 'rfc4716')

        run('ssh-keygen -i -f pubout -m rfc4716 > new')

        self.check_public()

    def check_pkcs1(self):
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

    def check_pkcs8(self):
        with self.subTest('Import PKCS#8 PEM private'):
            self.import_pkcs8_private('pem')

        with self.subTest('Export PKCS#8 PEM private'):
            self.export_pkcs8_private('pem')

        with self.subTest('Import PKCS#8 DER private'):
            self.import_pkcs8_private('der')

        with self.subTest('Export PKCS#8 DER private'):
            self.export_pkcs8_private('der')

        for cipher, hash, pbe_version, args in pkcs8_ciphers:
            with self.subTest('Import PKCS#8 PEM private (%s-%s-v%s)' %
                                  (cipher, hash, pbe_version)):
                self.import_pkcs8_private('pem', cipher, args)

            with self.subTest('Export PKCS#8 PEM private (%s-%s-v%s)' %
                                  (cipher, hash, pbe_version)):
                self.export_pkcs8_private('pem', cipher, hash, pbe_version)

            with self.subTest('Import PKCS#8 DER private (%s-%s-v%s)' %
                                  (cipher, hash, pbe_version)):
                self.import_pkcs8_private('der', cipher, args)

            with self.subTest('Export PKCS#8 DER private (%s-%s-v%s)' %
                                  (cipher, hash, pbe_version)):
                self.export_pkcs8_private('der', cipher, hash, pbe_version)

        with self.subTest('Import PKCS#8 PEM public'):
            self.import_pkcs8_public('pem')

        with self.subTest('Export PKCS#8 PEM public'):
            self.export_pkcs8_public('pem')

        with self.subTest('Import PKCS#8 DER public'):
            self.import_pkcs8_public('der')

        with self.subTest('Export PKCS#8 DER public'):
            self.export_pkcs8_public('der')

    def check_openssh(self):
        with self.subTest('Import OpenSSH private'):
            self.import_openssh_private()

        with self.subTest('Export OpenSSH private'):
            self.export_openssh_private()

        for cipher in openssh_ciphers:
            with self.subTest('Import OpenSSH private (%s)' % cipher):
                self.import_openssh_private(cipher)

            with self.subTest('Export OpenSSH private (%s)' % cipher):
                self.export_openssh_private(cipher)

        with self.subTest('Import OpenSSH public'):
            self.import_openssh_public()

        with self.subTest('Export OpenSSH public'):
            self.export_openssh_public()

    def check_rfc4716(self):
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

                self.key = read_private_key('priv')
                self.sshpub = self.key.encode_ssh_public()

                if 'pkcs1' in self.formats:
                    self.check_pkcs1()

                if 'pkcs8' in self.formats:
                    self.check_pkcs8()

                if 'openssh' in self.formats:
                    self.check_openssh()

                if 'rfc4716' in self.formats:
                    self.check_rfc4716()

        tmpdir.cleanup()

class TestDSA(_TestKeys):
    keyclass = 'dsa'
    keytypes = (1024, 2048)
    baseformat = 'pkcs8'
    formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')

    def make_keypair(self, keytype):
        run('openssl dsaparam -out priv -noout -genkey %s' % keytype)
        run('openssl dsa -pubout -in priv -out pub')

class TestRSA(_TestKeys):
    keyclass = 'rsa'
    keytypes = (1024, 2048)
    baseformat = 'pkcs8'
    formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')

    def make_keypair(self, keytype):
        run('openssl genrsa -out priv %s' % keytype)
        run('openssl rsa -pubout -in priv -out pub')

class TestEC(_TestKeys):
    keyclass = 'ec'
    keytypes = ('secp256r1', 'secp384r1', 'secp521r1')
    baseformat = 'pkcs8'
    formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')

    def make_keypair(self, keytype):
        run('openssl ecparam -out priv -noout -genkey -name %s' % keytype)
        run('openssl ec -pubout -in priv -out pub')

class TestEd25519(_TestKeys):
    keyclass = 'ed25519'
    keytypes = (256, )
    baseformat = 'openssh'
    formats = ('openssh', 'rfc4716')

    def make_keypair(self, keytype):
        run('ssh-keygen -t ed25519 -N "" -f priv')
        run('mv priv.pub pub')

del _TestKeys
