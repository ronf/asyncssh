# Copyright (c) 2014-2022 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for reading and writing public and private keys

   Note: These tests look for the openssl and ssh-keygen commands in
         the user's path and will whenever possible use them to perform
         interoperability tests. Otherwise, these tests will only test
         AsyncSSH against itself.

"""

import binascii
from datetime import datetime
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

from cryptography.exceptions import UnsupportedAlgorithm

import asyncssh

from asyncssh.asn1 import der_encode, BitString, ObjectIdentifier
from asyncssh.asn1 import TaggedDERObject
from asyncssh.crypto import chacha_available, ed25519_available, ed448_available
from asyncssh.misc import write_file
from asyncssh.packet import MPInt, String, UInt32
from asyncssh.pbe import pkcs1_decrypt
from asyncssh.public_key import CERT_TYPE_USER, CERT_TYPE_HOST, SSHKey
from asyncssh.public_key import SSHX509CertificateChain
from asyncssh.public_key import decode_ssh_certificate
from asyncssh.public_key import get_public_key_algs, get_certificate_algs
from asyncssh.public_key import get_x509_certificate_algs
from asyncssh.public_key import import_certificate_subject
from asyncssh.public_key import load_identities

from .sk_stub import sk_available, stub_sk, unstub_sk
from .util import bcrypt_available, get_test_key, x509_available
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

if _openssl_available: # pragma: no branch
    _openssl_curves = run('openssl ecparam -list_curves')
else: # pragma: no cover
    _openssl_curves = b''

# The openssl "-v2prf" option is only available in OpenSSL 1.0.2 or later
_openssl_supports_v2prf = _openssl_version >= b'OpenSSL 1.0.2'

# Ed25519/Ed448 support via "pkey" is only available in OpenSSL 1.1.1 or later
_openssl_supports_pkey = _openssl_version >= b'OpenSSL 1.1.1'

if _openssl_version >= b'OpenSSL 3': # pragma: no branch
    _openssl_legacy = '-provider default -provider legacy '
else: # pragma: no cover
    _openssl_legacy = ''

try:
    if sys.platform != 'win32':
        _openssh_version = run('ssh -V')
    else: # pragma: no cover
        _openssh_version = b''
except subprocess.CalledProcessError: # pragma: no cover
    _openssh_version = b''

_openssh_available = _openssh_version != b''

# GCM & Chacha tests require OpenSSH 6.9 due to a bug in earlier versions:
#     https://bugzilla.mindrot.org/show_bug.cgi?id=2366
_openssh_supports_gcm_chacha = _openssh_version >= b'OpenSSH_6.9'
_openssh_supports_arcfour_blowfish_cast = (_openssh_available and
                                           _openssh_version < b'OpenSSH_7.6')

pkcs1_ciphers = (('aes128-cbc', '-aes128', False),
                 ('aes192-cbc', '-aes192', False),
                 ('aes256-cbc', '-aes256', False),
                 ('des-cbc',    '-des',    True),
                 ('des3-cbc',   '-des3',   False))

pkcs8_ciphers = (
    ('aes128-cbc',   'sha224', 2, '-v2 aes-128-cbc '
     '-v2prf hmacWithSHA224', _openssl_supports_v2prf, False),
    ('aes128-cbc',   'sha256', 2, '-v2 aes-128-cbc '
     '-v2prf hmacWithSHA256', _openssl_supports_v2prf, False),
    ('aes128-cbc',   'sha384', 2, '-v2 aes-128-cbc '
     '-v2prf hmacWithSHA384', _openssl_supports_v2prf, False),
    ('aes128-cbc',   'sha512', 2, '-v2 aes-128-cbc '
     '-v2prf hmacWithSHA512', _openssl_supports_v2prf, False),
    ('des-cbc',      'md5',    1, '-v1 PBE-MD5-DES',
                              _openssl_available,      True),
    ('des-cbc',      'sha1',   1, '-v1 PBE-SHA1-DES',
                               _openssl_available,     True),
    ('des2-cbc',     'sha1',   1, '-v1 PBE-SHA1-2DES',
                              _openssl_available,      False),
    ('des3-cbc',     'sha1',   1, '-v1 PBE-SHA1-3DES',
                              _openssl_available,      False),
    ('rc4-40',       'sha1',   1, '-v1 PBE-SHA1-RC4-40',
                              _openssl_available,      True),
    ('rc4-128',      'sha1',   1, '-v1 PBE-SHA1-RC4-128',
                              _openssl_available,      True),
    ('aes128-cbc',   'sha1',   2, '-v2 aes-128-cbc',
                              _openssl_available,      False),
    ('aes192-cbc',   'sha1',   2, '-v2 aes-192-cbc',
                              _openssl_available,      False),
    ('aes256-cbc',   'sha1',   2, '-v2 aes-256-cbc',
                              _openssl_available,      False),
    ('blowfish-cbc', 'sha1',   2, '-v2 bf-cbc',
                              _openssl_available,      True),
    ('cast128-cbc',  'sha1',   2, '-v2 cast-cbc',
                              _openssl_available,      True),
    ('des-cbc',      'sha1',   2, '-v2 des-cbc',
                              _openssl_available,      True),
    ('des3-cbc',     'sha1',   2, '-v2 des-ede3-cbc',
                              _openssl_available,      False))

openssh_ciphers = (
    ('aes128-gcm@openssh.com',  _openssh_supports_gcm_chacha),
    ('aes256-gcm@openssh.com',  _openssh_supports_gcm_chacha),
    ('arcfour',                 _openssh_supports_arcfour_blowfish_cast),
    ('arcfour128',              _openssh_supports_arcfour_blowfish_cast),
    ('arcfour256',              _openssh_supports_arcfour_blowfish_cast),
    ('blowfish-cbc',            _openssh_supports_arcfour_blowfish_cast),
    ('cast128-cbc',             _openssh_supports_arcfour_blowfish_cast),
    ('aes128-cbc',              _openssh_available),
    ('aes192-cbc',              _openssh_available),
    ('aes256-cbc',              _openssh_available),
    ('aes128-ctr',              _openssh_available),
    ('aes192-ctr',              _openssh_available),
    ('aes256-ctr',              _openssh_available),
    ('3des-cbc',                _openssh_available)
)

if chacha_available: # pragma: no branch
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

    # pylint: disable=too-many-public-methods

    keyclass = None
    base_format = None
    private_formats = ()
    public_formats = ()
    default_cert_version = ''
    x509_supported = False
    generate_args = ()
    single_cipher = True
    use_openssh = _openssh_available
    use_openssl = _openssl_available

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

        self.privkey = None
        self.pubkey = None
        self.privca = None
        self.pubca = None
        self.usercert = None
        self.hostcert = None
        self.rootx509 = None
        self.userx509 = None
        self.hostx509 = None
        self.otherx509 = None

    def make_certificate(self, *args, **kwargs):
        """Construct an SSH certificate"""

        return make_certificate(self.default_cert_version, *args, **kwargs)

    def validate_openssh(self, cert, cert_type, name):
        """Check OpenSSH certificate validation"""

        self.assertIsNone(cert.validate(cert_type, name))

    def validate_x509(self, cert, user_principal=None):
        """Check X.509 certificate validation"""

        self.assertIsNone(cert.validate_chain([], [self.rootx509], [], 'any',
                                              user_principal, None))

        with self.assertRaises(ValueError):
            cert.validate_chain([self.rootx509], [], [], 'any', None, None)

        chain = SSHX509CertificateChain.construct_from_certs([cert])
        self.assertEqual(chain, decode_ssh_certificate(chain.public_data))

        self.assertIsNone(chain.validate_chain([self.rootx509], [], [], 'any',
                                               user_principal, None))

        self.assertIsNone(chain.validate_chain([self.rootx509],
                                               [], [self.otherx509], 'any',
                                               user_principal, None))

        with self.assertRaises(ValueError):
            chain.validate_chain([], [], [], 'any', user_principal, None)

        with self.assertRaises(ValueError):
            chain.validate_chain([self.rootx509], [], [cert], 'any',
                                 user_principal, None)

    def check_private(self, format_name, passphrase=None):
        """Check for a private key match"""

        newkey = asyncssh.read_private_key('new', passphrase)
        algorithm = newkey.get_algorithm()
        keydata = newkey.export_private_key()
        pubdata = newkey.public_data

        self.assertEqual(newkey, self.privkey)
        self.assertEqual(hash(newkey), hash(self.privkey))

        keypair = asyncssh.load_keypairs(newkey, passphrase)[0]
        self.assertEqual(keypair.get_key_type(), 'local')
        self.assertEqual(keypair.get_algorithm(), algorithm)
        self.assertEqual(keypair.public_data, pubdata)
        self.assertIsNotNone(keypair.get_agent_private_key())

        keypair = asyncssh.load_keypairs([keypair])[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs(keydata)[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs('new', passphrase)[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs([newkey])[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs([(newkey, None)])[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs([keydata])[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs([(keydata, None)])[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs(['new'], passphrase)[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs([('new', None)], passphrase)[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs(Path('new'), passphrase)[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs([Path('new')], passphrase)[0]
        self.assertEqual(keypair.public_data, pubdata)

        keypair = asyncssh.load_keypairs([(Path('new'), None)], passphrase)[0]
        self.assertEqual(keypair.public_data, pubdata)

        keylist = asyncssh.load_keypairs([])
        self.assertEqual(keylist, [])

        if passphrase:
            with self.assertRaises((asyncssh.KeyEncryptionError,
                                    asyncssh.KeyImportError)):
                asyncssh.load_keypairs('new', 'xxx')

            if format_name == 'openssh':
                identities = load_identities(['new'])
                self.assertEqual(identities[0], pubdata)
            else:
                with self.assertRaises(asyncssh.KeyImportError):
                    load_identities(['new'])

                identities = load_identities(['new'], skip_private=True)
                self.assertEqual(identities, [])
        else:
            newkey.write_private_key('list', format_name)
            newkey.append_private_key('list', format_name)

            keylist = asyncssh.read_private_key_list('list')
            self.assertEqual(keylist[0].public_data, pubdata)
            self.assertEqual(keylist[1].public_data, pubdata)

            newkey.write_private_key(Path('list'), format_name)
            newkey.append_private_key(Path('list'), format_name)

            keylist = asyncssh.load_keypairs(Path('list'))
            self.assertEqual(keylist[0].public_data, pubdata)
            self.assertEqual(keylist[1].public_data, pubdata)

        if self.x509_supported and format_name[-4:] == '-pem':
            cert = newkey.generate_x509_user_certificate(newkey, 'OU=user')
            chain = SSHX509CertificateChain.construct_from_certs([cert])

            cert.write_certificate('new_cert')

            keypair = asyncssh.load_keypairs(('new', 'new_cert'), passphrase)[0]
            self.assertEqual(keypair.public_data, chain.public_data)
            self.assertIsNotNone(keypair.get_agent_private_key())

            keypair = asyncssh.load_keypairs('new', passphrase, 'new_cert')[0]
            self.assertEqual(keypair.public_data, chain.public_data)
            self.assertIsNotNone(keypair.get_agent_private_key())

            newkey.write_private_key('new_bundle', format_name, passphrase)
            cert.append_certificate('new_bundle', 'pem')

            keypair = asyncssh.load_keypairs('new_bundle', passphrase)[0]
            self.assertEqual(keypair.public_data, chain.public_data)

            with self.assertRaises(OSError):
                asyncssh.load_keypairs(('new', 'not_found'), passphrase)

    def check_public(self, format_name):
        """Check for a public key match"""

        newkey = asyncssh.read_public_key('new')
        pubkey = newkey.export_public_key()
        pubdata = newkey.public_data

        self.assertEqual(newkey, self.pubkey)
        self.assertEqual(hash(newkey), hash(self.pubkey))

        pubkey = asyncssh.load_public_keys('new')[0]
        self.assertEqual(pubkey, newkey)

        pubkey = asyncssh.load_public_keys([newkey])[0]
        self.assertEqual(pubkey, newkey)

        pubkey = asyncssh.load_public_keys([pubkey])[0]
        self.assertEqual(pubkey, newkey)

        pubkey = asyncssh.load_public_keys(['new'])[0]
        self.assertEqual(pubkey, newkey)

        pubkey = asyncssh.load_public_keys(Path('new'))[0]
        self.assertEqual(pubkey, newkey)

        pubkey = asyncssh.load_public_keys([Path('new')])[0]
        self.assertEqual(pubkey, newkey)

        identity = load_identities(['new'])[0]
        self.assertEqual(identity, pubdata)

        newkey.write_public_key('list', format_name)
        newkey.append_public_key('list', format_name)

        keylist = asyncssh.read_public_key_list('list')
        self.assertEqual(keylist[0], newkey)
        self.assertEqual(keylist[1], newkey)

        newkey.write_public_key(Path('list'), format_name)
        newkey.append_public_key(Path('list'), format_name)

        write_file('list', b'Extra text at end of key list\n', 'ab')

        keylist = asyncssh.load_public_keys(Path('list'))
        self.assertEqual(keylist[0], newkey)
        self.assertEqual(keylist[1], newkey)

        for hash_name in ('md5', 'sha1', 'sha256', 'sha384', 'sha512'):
            fp = newkey.get_fingerprint(hash_name)

            if self.use_openssh: # pragma: no branch
                keygen_fp = run('ssh-keygen -l -E %s -f sshpub' % hash_name)
                self.assertEqual(fp, keygen_fp.decode('ascii').split()[1])

        with self.assertRaises(ValueError):
            newkey.get_fingerprint('xxx')

    def check_certificate(self, cert_type, format_name):
        """Check for a certificate match"""

        cert = asyncssh.read_certificate('cert')
        certdata = cert.export_certificate()

        self.assertEqual(cert.key, self.pubkey)

        if cert.is_x509:
            self.validate_x509(cert)
        else:
            self.validate_openssh(cert, cert_type, 'name')

        certlist = asyncssh.load_certificates(cert)
        self.assertEqual(certlist[0], cert)
        self.assertEqual(hash(certlist[0]), hash(cert))

        if cert.is_x509:
            self.assertEqual(certlist[0].x509_cert, cert.x509_cert)
            self.assertEqual(hash(certlist[0].x509_cert), hash(cert.x509_cert))

        certlist = asyncssh.load_certificates(certdata)
        self.assertEqual(certlist[0], cert)

        certlist = asyncssh.load_certificates([cert])
        self.assertEqual(certlist[0], cert)

        certlist = asyncssh.load_certificates([certdata])
        self.assertEqual(certlist[0], cert)

        certlist = asyncssh.load_certificates('cert')
        self.assertEqual(certlist[0], cert)

        certlist = asyncssh.load_certificates(Path('cert'))
        self.assertEqual(certlist[0], cert)

        certlist = asyncssh.load_certificates([Path('cert')])
        self.assertEqual(certlist[0], cert)

        certlist = asyncssh.load_certificates(certdata +
                                              b'Extra  text in the middle\n' +
                                              certdata)
        self.assertEqual(certlist[0], cert)
        self.assertEqual(certlist[1], cert)

        cert.write_certificate('list', format_name)
        cert.append_certificate('list', format_name)

        certlist = asyncssh.load_certificates('list')
        self.assertEqual(certlist[0], cert)
        self.assertEqual(certlist[1], cert)

        cert.write_certificate(Path('list'), format_name)
        cert.append_certificate(Path('list'), format_name)

        write_file('list', b'Extra text at end of certificate list\n', 'ab')

        certlist = asyncssh.load_certificates(Path('list'))
        self.assertEqual(certlist[0], cert)
        self.assertEqual(certlist[1], cert)

        certlist = asyncssh.load_certificates(['list', [cert]])
        self.assertEqual(certlist[0], cert)
        self.assertEqual(certlist[1], cert)
        self.assertEqual(certlist[2], cert)

        certlist = asyncssh.load_certificates(['list', certdata])
        self.assertEqual(certlist[0], cert)
        self.assertEqual(certlist[1], cert)
        self.assertEqual(certlist[2], cert)

        if format_name == 'openssh':
            certlist = asyncssh.load_certificates(certdata[:-1])
            self.assertEqual(certlist[0], cert)

            certlist = asyncssh.load_certificates(certdata + certdata[:-1])
            self.assertEqual(certlist[0], cert)
            self.assertEqual(certlist[1], cert)

            certlist = asyncssh.load_certificates(certdata[1:-1])
            self.assertEqual(len(certlist), 0)

            certlist = asyncssh.load_certificates(certdata[1:] + certdata[:-1])
            self.assertEqual(len(certlist), 1)
            self.assertEqual(certlist[0], cert)


    def import_pkcs1_private(self, fmt, cipher=None, args=None):
        """Check import of a PKCS#1 private key"""

        format_name = 'pkcs1-%s' % fmt

        if self.use_openssl: # pragma: no branch
            if cipher:
                run('openssl %s %s -in priv -inform pem -out new -outform %s '
                    '-passout pass:passphrase' % (self.keyclass, args, fmt))
            else:
                run('openssl %s -in priv -inform pem -out new -outform %s' %
                    (self.keyclass, fmt))
        else: # pragma: no cover
            self.privkey.write_private_key('new', format_name,
                                           select_passphrase(cipher), cipher)

        self.check_private(format_name, select_passphrase(cipher))

    def export_pkcs1_private(self, fmt, cipher=None, legacy_args=None):
        """Check export of a PKCS#1 private key"""

        format_name = 'pkcs1-%s' % fmt
        self.privkey.write_private_key('privout', format_name,
                                       select_passphrase(cipher), cipher)

        if self.use_openssl: # pragma: no branch
            if cipher:
                run('openssl %s %s -in privout -inform %s -out new '
                    '-outform pem -passin pass:passphrase' %
                    (self.keyclass, legacy_args, fmt))
            else:
                run('openssl %s -in privout -inform %s -out new -outform pem' %
                    (self.keyclass, fmt))
        else: # pragma: no cover
            priv = asyncssh.read_private_key('privout',
                                             select_passphrase(cipher))
            priv.write_private_key('new', format_name)

        self.check_private(format_name)

    def import_pkcs1_public(self, fmt):
        """Check import of a PKCS#1 public key"""

        format_name = 'pkcs1-%s' % fmt

        if (not self.use_openssl or self.keyclass == 'dsa' or
                _openssl_version < b'OpenSSL 1.0.0'): # pragma: no cover
            # OpenSSL no longer has support for PKCS#1 DSA, and PKCS#1
            # RSA is not supported before OpenSSL 1.0.0, so we only test
            # against ourselves in these cases.

            self.pubkey.write_public_key('new', format_name)
        else:
            run('openssl %s -pubin -in pub -inform pem -RSAPublicKey_out '
                '-out new -outform %s' % (self.keyclass, fmt))

        self.check_public(format_name)

    def export_pkcs1_public(self, fmt):
        """Check export of a PKCS#1 public key"""

        format_name = 'pkcs1-%s' % fmt
        self.privkey.write_public_key('pubout', format_name)

        if not self.use_openssl or self.keyclass == 'dsa': # pragma: no cover
            # OpenSSL no longer has support for PKCS#1 DSA, so we can
            # only test against ourselves.

            pub = asyncssh.read_public_key('pubout')
            pub.write_public_key('new', 'pkcs1-%s' % fmt)
        else:
            run('openssl %s -RSAPublicKey_in -in pubout -inform %s -out new '
                '-outform pem' % (self.keyclass, fmt))

        self.check_public(format_name)

    def import_pkcs8_private(self, fmt, openssl_ok=True, cipher=None,
                             hash_alg=None, pbe_version=None, args=None):
        """Check import of a PKCS#8 private key"""

        format_name = 'pkcs8-%s' % fmt

        if self.use_openssl and openssl_ok: # pragma: no branch
            if cipher:
                run('openssl pkcs8 -topk8 %s -in priv -inform pem -out new '
                    '-outform %s -passout pass:passphrase' % (args, fmt))
            else:
                run('openssl pkcs8 -topk8 -nocrypt -in priv -inform pem '
                    '-out new -outform %s' % fmt)
        else: # pragma: no cover
            self.privkey.write_private_key('new', format_name,
                                           select_passphrase(cipher,
                                                             pbe_version),
                                           cipher, hash_alg, pbe_version)

        self.check_private(format_name, select_passphrase(cipher, pbe_version))

    def export_pkcs8_private(self, fmt, openssl_ok=True, cipher=None,
                             hash_alg=None, pbe_version=None,
                             legacy_args=None):
        """Check export of a PKCS#8 private key"""

        format_name = 'pkcs8-%s' % fmt
        self.privkey.write_private_key('privout', format_name,
                                       select_passphrase(cipher, pbe_version),
                                       cipher, hash_alg, pbe_version)

        if self.use_openssl and openssl_ok: # pragma: no branch
            if cipher:
                run('openssl pkcs8 %s -in privout -inform %s -out new '
                    '-outform pem -passin pass:passphrase' %
                    (legacy_args, fmt))
            else:
                run('openssl pkcs8 -nocrypt -in privout -inform %s -out new '
                    '-outform pem' % fmt)
        else: # pragma: no cover
            priv = asyncssh.read_private_key('privout',
                                             select_passphrase(cipher,
                                                               pbe_version))
            priv.write_private_key('new', format_name)

        self.check_private(format_name)

    def import_pkcs8_public(self, fmt):
        """Check import of a PKCS#8 public key"""

        format_name = 'pkcs8-%s' % fmt

        if self.use_openssl:
            if _openssl_supports_pkey:
                run('openssl pkey -pubin -in pub -inform pem -out new '
                    '-outform %s' % fmt)
            else: # pragma: no cover
                run('openssl %s -pubin -in pub -inform pem -out new '
                    '-outform %s' % (self.keyclass, fmt))
        else: # pragma: no cover
            self.pubkey.write_public_key('new', format_name)

        self.check_public(format_name)

    def export_pkcs8_public(self, fmt):
        """Check export of a PKCS#8 public key"""

        format_name = 'pkcs8-%s' % fmt
        self.privkey.write_public_key('pubout', format_name)

        if self.use_openssl:
            if _openssl_supports_pkey:
                run('openssl pkey -pubin -in pubout -inform %s -out new '
                    '-outform pem' % fmt)
            else: # pragma: no cover
                run('openssl %s -pubin -in pubout -inform %s -out new '
                    '-outform pem' % (self.keyclass, fmt))
        else: # pragma: no cover
            pub = asyncssh.read_public_key('pubout')
            pub.write_public_key('new', format_name)

        self.check_public(format_name)

    def import_openssh_private(self, openssh_ok=True, cipher=None):
        """Check import of an OpenSSH private key"""

        if self.use_openssh and openssh_ok: # pragma: no branch
            shutil.copy('priv', 'new')

            if cipher:
                run('ssh-keygen -p -a 1 -N passphrase -Z %s -o -f new' %
                    cipher)
            else:
                run('ssh-keygen -p -N "" -o -f new')
        else: # pragma: no cover
            self.privkey.write_private_key('new', 'openssh',
                                           select_passphrase(cipher), cipher,
                                           rounds=1, ignore_few_rounds=True)

        self.check_private('openssh', select_passphrase(cipher))

    def export_openssh_private(self, openssh_ok=True, cipher=None):
        """Check export of an OpenSSH private key"""

        self.privkey.write_private_key('new', 'openssh',
                                       select_passphrase(cipher), cipher,
                                       rounds=1, ignore_few_rounds=True)

        if self.use_openssh and openssh_ok: # pragma: no branch
            os.chmod('new', 0o600)

            if cipher:
                run('ssh-keygen -p -P passphrase -N "" -o -f new')
            else:
                run('ssh-keygen -p -N "" -o -f new')
        else: # pragma: no cover
            priv = asyncssh.read_private_key('new', select_passphrase(cipher))
            priv.write_private_key('new', 'openssh')

        self.check_private('openssh')

    def import_openssh_public(self):
        """Check import of an OpenSSH public key"""

        shutil.copy('sshpub', 'new')

        self.check_public('openssh')

    def export_openssh_public(self):
        """Check export of an OpenSSH public key"""

        self.privkey.write_public_key('pubout', 'openssh')

        if self.use_openssh: # pragma: no branch
            run('ssh-keygen -e -f pubout -m rfc4716 > new')
        else: # pragma: no cover
            pub = asyncssh.read_public_key('pubout')
            pub.write_public_key('new', 'rfc4716')

        self.check_public('openssh')

    def import_openssh_certificate(self, cert_type, cert):
        """Check import of an OpenSSH certificate"""

        shutil.copy(cert, 'cert')

        self.check_certificate(cert_type, 'openssh')

    def export_openssh_certificate(self, cert_type, cert):
        """Check export of an OpenSSH certificate"""

        cert.write_certificate('certout', 'openssh')

        if self.use_openssh: # pragma: no branch
            run('ssh-keygen -e -f certout -m rfc4716 > cert')
        else: # pragma: no cover
            cert = asyncssh.read_certificate('certout')
            cert.write_certificate('cert', 'rfc4716')

        self.check_certificate(cert_type, 'openssh')

    def import_rfc4716_public(self):
        """Check import of an RFC4716 public key"""

        if self.use_openssh: # pragma: no branch
            run('ssh-keygen -e -f sshpub -m rfc4716 > new')
        else: # pragma: no cover
            self.pubkey.write_public_key('new', 'rfc4716')

        self.check_public('rfc4716')

        pubdata = self.pubkey.export_public_key('rfc4716')
        write_file('new', pubdata.replace(b'\n', b'\nXXX:\n', 1))

        self.check_public('rfc4716')

    def export_rfc4716_public(self):
        """Check export of an RFC4716 public key"""

        self.pubkey.write_public_key('pubout', 'rfc4716')

        if self.use_openssh: # pragma: no branch
            run('ssh-keygen -i -f pubout -m rfc4716 > new')
        else: # pragma: no cover
            pub = asyncssh.read_public_key('pubout')
            pub.write_public_key('new', 'openssh')

        self.check_public('rfc4716')

    def import_rfc4716_certificate(self, cert_type, cert):
        """Check import of an RFC4716 certificate"""

        if self.use_openssh: # pragma: no branch
            run('ssh-keygen -e -f %s -m rfc4716 > cert' % cert)
        else: # pragma: no cover
            if cert_type == CERT_TYPE_USER:
                cert = self.usercert
            else:
                cert = self.hostcert

            cert.write_certificate('cert', 'rfc4716')

        self.check_certificate(cert_type, 'rfc4716')

    def export_rfc4716_certificate(self, cert_type, cert):
        """Check export of an RFC4716 certificate"""

        cert.write_certificate('certout', 'rfc4716')

        if self.use_openssh: # pragma: no branch
            run('ssh-keygen -i -f certout -m rfc4716 > cert')
        else: # pragma: no cover
            cert = asyncssh.read_certificate('certout')
            cert.write_certificate('cert', 'openssh')

        self.check_certificate(cert_type, 'rfc4716')


    def import_der_x509_certificate(self, cert_type, cert):
        """Check import of a DER X.509 certificate"""

        cert.write_certificate('cert', 'der')
        self.check_certificate(cert_type, 'der')

    def export_der_x509_certificate(self, cert_type, cert):
        """Check export of a DER X.509 certificate"""

        cert.write_certificate('certout', 'der')

        cert = asyncssh.read_certificate('certout')
        cert.write_certificate('cert', 'openssh')

        self.check_certificate(cert_type, 'der')

    def import_pem_x509_certificate(self, cert_type, cert, trusted=False):
        """Check import of a PEM X.509 certificate"""

        cert.write_certificate('cert', 'pem')

        if trusted:
            with open('cert') as f:
                lines = f.readlines()

            lines[0] = lines[0][:11] + 'TRUSTED ' + lines[0][11:]

            idx = lines[-2].find('=')
            lines[-2] = lines[-2][:idx] + 'XXXX' + lines[-2][idx:]

            lines[-1] = lines[-1][:9] + 'TRUSTED ' + lines[-1][9:]

            with open('cert', 'w') as f:
                f.writelines(lines)

        self.check_certificate(cert_type, 'pem')

    def export_pem_x509_certificate(self, cert_type, cert):
        """Check export of a PEM X.509 certificate"""

        cert.write_certificate('certout', 'pem')

        cert = asyncssh.read_certificate('certout')
        cert.write_certificate('cert', 'openssh')

        self.check_certificate(cert_type, 'pem')

    def import_openssh_x509_certificate(self, cert_type, cert):
        """Check import of an OpenSSH X.509 certificate"""

        cert.write_certificate('cert')
        self.check_certificate(cert_type, 'openssh')

    def export_openssh_x509_certificate(self, cert_type, cert):
        """Check export of an OpenSSH X.509 certificate"""

        cert.write_certificate('certout')

        cert = asyncssh.read_certificate('certout')
        cert.write_certificate('cert', 'pem')

        self.check_certificate(cert_type, 'openssh')

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

        if 'pkcs8' in self.private_formats: # pragma: no branch
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

        if bcrypt_available: # pragma: no branch
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
            ('Unknown PKCS#8 algorithm',
             der_encode((0, (ObjectIdentifier('1.1'), None), b''))),
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
                 ((_ES2, ((_ES2_PBKDF2, (b'', 1, None)),
                          (_ES2_AES128, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Unknown PEM PKCS#8 PBES2 PBKDF2 PRF',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, (b'', 1,
                                         (ObjectIdentifier('1.1'), None))),
                          (_ES2_AES128, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid PEM PKCS#8 PBES2 encryption parameters',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, (b'', 1)),
                          (_ES2_AES128, None))), b''))) +
             b'-----END ENCRYPTED PRIVATE KEY-----'),
            ('Invalid length PEM PKCS#8 PBES2 IV',
             b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
             binascii.b2a_base64(der_encode(
                 ((_ES2, ((_ES2_PBKDF2, (b'', 1)),
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
                  String(b''.join((String(b''), UInt32(128)))), UInt32(1),
                  String(''), String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Invalid OpenSSH encrypted data',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('aes256-cbc'), String('bcrypt'),
                  String(b''.join((String(16*b'\0'), UInt32(128)))), UInt32(1),
                  String(''), String('')))) +
             b'-----END OPENSSH PRIVATE KEY-----'),
            ('Unexpected OpenSSH trailing data',
             b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
             binascii.b2a_base64(b''.join(
                 (b'openssh-key-v1\0', String('aes256-cbc'), String('bcrypt'),
                  String(b''.join((String(16*b'\0'), UInt32(128)))), UInt32(1),
                  String(''), String(''), String('xxx')))) +
             b'-----END OPENSSH PRIVATE KEY-----')
        ]

        public_errors = [
            ('Non-ASCII', '\xff'),
            ('Invalid ASN.1', b'\x30'),
            ('Invalid PKCS#1', der_encode(None)),
            ('Invalid PKCS#8', der_encode(((self.pubkey.pkcs8_oid, ()),
                                           BitString(der_encode(None))))),
            ('Unknown PKCS#8 algorithm', der_encode(((ObjectIdentifier('1.1'),
                                                      None), BitString(b'')))),
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
            ('Invalid PKCS#1 ASN.1',
             b'-----BEGIN DSA PUBLIC KEY-----\n' +
             binascii.b2a_base64(b'\x30') +
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

        key = SSHKey(None)

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

            for cert in (None, self.usercert, self.userx509):
                keypair = asyncssh.load_keypairs([(self.privkey, cert)])[0]

                for sig_alg in keypair.sig_algorithms:
                    with self.subTest('Good signature', sig_alg=sig_alg):
                        try:
                            keypair.set_sig_algorithm(sig_alg)
                            sig = keypair.sign(data)

                            with self.subTest('Good signature'):
                                self.assertTrue(self.pubkey.verify(data, sig))

                            badsig = bytearray(sig)
                            badsig[-1] ^= 0xff
                            badsig = bytes(badsig)

                            with self.subTest('Bad signature'):
                                self.assertFalse(self.pubkey.verify(data,
                                                 badsig))
                        except UnsupportedAlgorithm: # pragma: no cover
                            pass

            with self.subTest('Missing signature'):
                self.assertFalse(self.pubkey.verify(
                    data, String(self.pubkey.sig_algorithms[0])))

            with self.subTest('Empty signature'):
                self.assertFalse(self.pubkey.verify(
                    data, String(self.pubkey.sig_algorithms[0]) + String(b'')))

            with self.subTest('Sign with bad algorithm'):
                with self.assertRaises(ValueError):
                    self.privkey.sign(data, b'xxx')

            with self.subTest('Verify with bad algorithm'):
                self.assertFalse(self.pubkey.verify(
                    data, String('xxx') + String('')))

            with self.subTest('Sign with public key'):
                with self.assertRaises(ValueError):
                    self.pubkey.sign(data, self.pubkey.sig_algorithms[0])

    def check_set_certificate(self):
        """Check setting certificate on existing keypair"""

        keypair = asyncssh.load_keypairs([self.privkey])[0]
        keypair.set_certificate(self.usercert)
        self.assertEqual(keypair.public_data, self.usercert.public_data)

        keypair = asyncssh.load_keypairs(self.privkey)[0]
        keypair = asyncssh.load_keypairs((keypair, self.usercert))[0]
        self.assertEqual(keypair.public_data, self.usercert.public_data)

        key2 = get_test_key('ssh-rsa', 1)

        with self.assertRaises(ValueError):
            asyncssh.load_keypairs((key2, self.usercert))

    def check_comment(self):
        """Check getting and setting comments"""

        with self.subTest('Comment test'):
            self.assertEqual(self.privkey.get_comment_bytes(), b'comment')
            self.assertEqual(self.privkey.get_comment(), 'comment')
            self.assertEqual(self.pubkey.get_comment_bytes(), b'pub_comment')
            self.assertEqual(self.pubkey.get_comment(), 'pub_comment')

            key = asyncssh.import_private_key(
                self.privkey.export_private_key('openssh'))
            self.assertEqual(key.get_comment_bytes(), b'comment')
            self.assertEqual(key.get_comment(), 'comment')

            key.set_comment('new_comment')
            self.assertEqual(key.get_comment_bytes(), b'new_comment')
            self.assertEqual(key.get_comment(), 'new_comment')

            key.set_comment(b'new_comment')
            self.assertEqual(key.get_comment_bytes(), b'new_comment')
            self.assertEqual(key.get_comment(), 'new_comment')

            key.set_comment(b'\xff')
            self.assertEqual(key.get_comment_bytes(), b'\xff')
            with self.assertRaises(UnicodeDecodeError):
                key.get_comment()

            cert = asyncssh.import_certificate(
                self.usercert.export_certificate())

            cert.set_comment(b'\xff')
            self.assertEqual(cert.get_comment_bytes(), b'\xff')
            with self.assertRaises(UnicodeDecodeError):
                cert.get_comment()

            if self.x509_supported:
                cert = asyncssh.import_certificate(
                    self.userx509.export_certificate())

                cert.set_comment(b'\xff')
                self.assertEqual(cert.get_comment_bytes(), b'\xff')
                with self.assertRaises(UnicodeDecodeError):
                    cert.get_comment()

            for fmt in ('openssh', 'rfc4716'):
                key = asyncssh.import_public_key(
                    self.pubkey.export_public_key(fmt))
                self.assertEqual(key.get_comment_bytes(), b'pub_comment')
                self.assertEqual(key.get_comment(), 'pub_comment')

                key = asyncssh.import_public_key(
                    self.pubca.export_public_key(fmt))
                self.assertEqual(key.get_comment_bytes(), None)
                self.assertEqual(key.get_comment(), None)

                key.set_comment('new_comment')
                self.assertEqual(key.get_comment_bytes(), b'new_comment')
                self.assertEqual(key.get_comment(), 'new_comment')

                key.set_comment(b'new_comment')
                self.assertEqual(key.get_comment_bytes(), b'new_comment')
                self.assertEqual(key.get_comment(), 'new_comment')

            for fmt in ('openssh', 'rfc4716'):
                cert = asyncssh.import_certificate(
                    self.usercert.export_certificate(fmt))
                self.assertEqual(cert.get_comment_bytes(), b'user_comment')
                self.assertEqual(cert.get_comment(), 'user_comment')

                cert = self.privca.generate_user_certificate(
                    self.pubkey, 'name', principals='name1,name2',
                    comment='cert_comment')
                self.assertEqual(cert.principals, ['name1', 'name2'])
                self.assertEqual(cert.get_comment_bytes(), b'cert_comment')
                self.assertEqual(cert.get_comment(), 'cert_comment')

                cert = asyncssh.import_certificate(
                    self.hostcert.export_certificate(fmt))
                self.assertEqual(cert.get_comment_bytes(), b'host_comment')
                self.assertEqual(cert.get_comment(), 'host_comment')

                cert = self.privca.generate_host_certificate(
                    self.pubkey, 'name', principals=['name1', 'name2'],
                    comment=b'\xff')
                self.assertEqual(cert.principals, ['name1', 'name2'])
                self.assertEqual(cert.get_comment_bytes(), b'\xff')
                with self.assertRaises(UnicodeDecodeError):
                    cert.get_comment()

                cert.set_comment('new_comment')
                self.assertEqual(cert.get_comment_bytes(), b'new_comment')
                self.assertEqual(cert.get_comment(), 'new_comment')

                cert.set_comment(b'new_comment')
                self.assertEqual(cert.get_comment_bytes(), b'new_comment')
                self.assertEqual(cert.get_comment(), 'new_comment')

            if self.x509_supported:
                for fmt in ('openssh', 'der', 'pem'):
                    cert = asyncssh.import_certificate(
                        self.rootx509.export_certificate(fmt))
                    self.assertEqual(cert.get_comment_bytes(), None)
                    self.assertEqual(cert.get_comment(), None)

                    cert = self.privca.generate_x509_ca_certificate(
                        self.pubkey, 'OU=root', comment='ca_comment')
                    self.assertEqual(cert.get_comment_bytes(), b'ca_comment')
                    self.assertEqual(cert.get_comment(), 'ca_comment')

                    cert = asyncssh.import_certificate(
                        self.userx509.export_certificate(fmt))
                    self.assertEqual(cert.get_comment_bytes(), b'user_comment')
                    self.assertEqual(cert.get_comment(), 'user_comment')

                    cert = self.privca.generate_x509_user_certificate(
                        self.pubkey, 'OU=user', 'OU=root',
                        comment='user_comment')
                    self.assertEqual(cert.get_comment_bytes(), b'user_comment')
                    self.assertEqual(cert.get_comment(), 'user_comment')

                    cert = asyncssh.import_certificate(
                        self.hostx509.export_certificate(fmt))
                    self.assertEqual(cert.get_comment_bytes(), b'host_comment')
                    self.assertEqual(cert.get_comment(), 'host_comment')

                    cert = self.privca.generate_x509_host_certificate(
                        self.pubkey, 'OU=host', 'OU=root',
                        comment='host_comment')
                    self.assertEqual(cert.get_comment_bytes(), b'host_comment')
                    self.assertEqual(cert.get_comment(), 'host_comment')

                    cert.set_comment('new_comment')
                    self.assertEqual(cert.get_comment_bytes(), b'new_comment')
                    self.assertEqual(cert.get_comment(), 'new_comment')

                    cert.set_comment(b'new_comment')
                    self.assertEqual(cert.get_comment_bytes(), b'new_comment')
                    self.assertEqual(cert.get_comment(), 'new_comment')

            keypair = asyncssh.load_keypairs([self.privkey])[0]
            self.assertEqual(keypair.get_comment_bytes(), b'comment')
            self.assertEqual(keypair.get_comment(), 'comment')

            keypair.set_comment('new_comment')
            self.assertEqual(keypair.get_comment_bytes(), b'new_comment')
            self.assertEqual(keypair.get_comment(), 'new_comment')

            keypair.set_comment(b'new_comment')
            self.assertEqual(keypair.get_comment_bytes(), b'new_comment')
            self.assertEqual(keypair.get_comment(), 'new_comment')

            keypair.set_comment(b'\xff')
            self.assertEqual(keypair.get_comment_bytes(), b'\xff')
            with self.assertRaises(UnicodeDecodeError):
                keypair.get_comment()

            priv = asyncssh.read_private_key('priv')
            priv.set_comment(None)

            keypair = asyncssh.load_keypairs((priv, self.pubkey))[0]
            self.assertEqual(keypair.get_comment(), 'pub_comment')

            keypair = asyncssh.load_keypairs((priv, self.usercert))[0]
            self.assertEqual(keypair.get_comment(), 'user_comment')

            keypair = asyncssh.load_keypairs(priv, None, self.usercert)[0]
            self.assertEqual(keypair.get_comment(), 'user_comment')

            pubdata = self.pubkey.export_public_key()
            keypair = asyncssh.load_keypairs((priv, pubdata))[0]
            self.assertEqual(keypair.get_comment(), 'pub_comment')

            certdata = self.usercert.export_certificate()
            keypair = asyncssh.load_keypairs((priv, certdata))[0]
            self.assertEqual(keypair.get_comment(), 'user_comment')

            keypair = asyncssh.load_keypairs(priv, None, certdata)[0]
            self.assertEqual(keypair.get_comment(), 'user_comment')

            priv.write_private_key('key')

            keypair = asyncssh.load_keypairs('key')[0]
            self.assertEqual(keypair.get_comment(), 'key')

            keypair = asyncssh.load_keypairs(('key', 'sshpub'))[0]
            self.assertEqual(keypair.get_comment(), 'pub_comment')

            keypair = asyncssh.load_keypairs(('key', 'usercert'))[0]
            self.assertEqual(keypair.get_comment(), 'user_comment')

            keypair = asyncssh.load_keypairs('key', None, 'usercert')[0]
            self.assertEqual(keypair.get_comment(), 'user_comment')

            self.pubkey.write_public_key('key.pub')

            keypair = asyncssh.load_keypairs('key')[0]
            self.assertEqual(keypair.get_comment(), 'pub_comment')

            self.usercert.write_certificate('key-cert.pub')

            keypair = asyncssh.load_keypairs('key')[0]
            self.assertEqual(keypair.get_comment(), 'user_comment')

            keypair = asyncssh.load_keypairs('key')[1]
            self.assertEqual(keypair.get_comment(), 'pub_comment')

            keypair = asyncssh.load_keypairs(('key', None))[0]
            self.assertEqual(keypair.get_comment(), 'pub_comment')

            key2 = get_test_key('ssh-rsa', 1)

            with self.assertRaises(ValueError):
                asyncssh.load_keypairs((key2, 'pub'))

            for f in ('key', 'key.pub', 'key-cert.pub'):
                os.remove(f)

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

        for cipher, args, legacy in pkcs1_ciphers:
            legacy_args = _openssl_legacy if legacy else ''

            with self.subTest('Import PKCS#1 PEM private (%s)' % cipher):
                self.import_pkcs1_private('pem', cipher, legacy_args + args)

            with self.subTest('Export PKCS#1 PEM private (%s)' % cipher):
                self.export_pkcs1_private('pem', cipher, legacy_args)

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

        for cipher, hash_alg, pbe_version, args, \
                openssl_ok, legacy in pkcs8_ciphers:
            legacy_args = _openssl_legacy if legacy else ''

            with self.subTest('Import PKCS#8 PEM private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.import_pkcs8_private('pem', openssl_ok, cipher,
                                          hash_alg, pbe_version,
                                          legacy_args + args)

            with self.subTest('Export PKCS#8 PEM private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.export_pkcs8_private('pem', openssl_ok, cipher,
                                          hash_alg, pbe_version, legacy_args)

            with self.subTest('Import PKCS#8 DER private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.import_pkcs8_private('der', openssl_ok, cipher,
                                          hash_alg, pbe_version,
                                          legacy_args + args)

            with self.subTest('Export PKCS#8 DER private (%s-%s-v%s)' %
                              (cipher, hash_alg, pbe_version)):
                self.export_pkcs8_private('der', openssl_ok, cipher,
                                          hash_alg, pbe_version, legacy_args)

            if self.single_cipher:
                break

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
            for cipher, openssh_ok in openssh_ciphers:
                with self.subTest('Import OpenSSH private (%s)' % cipher):
                    self.import_openssh_private(openssh_ok, cipher)

                with self.subTest('Export OpenSSH private (%s)' % cipher):
                    self.export_openssh_private(openssh_ok, cipher)

                if self.single_cipher:
                    break

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

    def check_der_x509_certificate(self):
        """Check DER X.509 certificate format"""

        with self.subTest('Import DER X.509 user certificate'):
            self.import_der_x509_certificate(CERT_TYPE_USER, self.userx509)

        with self.subTest('Export DER X.509 user certificate'):
            self.export_der_x509_certificate(CERT_TYPE_USER, self.userx509)

        with self.subTest('Import DER X.509 host certificate'):
            self.import_der_x509_certificate(CERT_TYPE_HOST, self.hostx509)

        with self.subTest('Export DER X.509 host certificate'):
            self.export_der_x509_certificate(CERT_TYPE_HOST, self.hostx509)

    def check_pem_x509_certificate(self):
        """Check PEM X.509 certificate format"""

        with self.subTest('Import PEM X.509 user certificate'):
            self.import_pem_x509_certificate(CERT_TYPE_USER, self.userx509)

        with self.subTest('Export PEM X.509 user certificate'):
            self.export_pem_x509_certificate(CERT_TYPE_USER, self.userx509)

        with self.subTest('Import PEM X.509 host certificate'):
            self.import_pem_x509_certificate(CERT_TYPE_HOST, self.hostx509)

        with self.subTest('Export PEM X.509 host certificate'):
            self.export_pem_x509_certificate(CERT_TYPE_HOST, self.hostx509)

        with self.subTest('Import PEM X.509 trusted user certificate'):
            self.import_pem_x509_certificate(CERT_TYPE_USER, self.userx509,
                                             trusted=True)

        with self.subTest('Import PEM X.509 trusted host certificate'):
            self.import_pem_x509_certificate(CERT_TYPE_HOST, self.hostx509,
                                             trusted=True)

    def check_openssh_x509_certificate(self):
        """Check OpenSSH X.509 certificate format"""

        with self.subTest('Import OpenSSH X.509 user certificate'):
            self.import_openssh_x509_certificate(CERT_TYPE_USER, self.userx509)

        with self.subTest('Export OpenSSH X.509 user certificate'):
            self.export_openssh_x509_certificate(CERT_TYPE_USER, self.userx509)

        with self.subTest('Import OpenSSH X.509 host certificate'):
            self.import_openssh_x509_certificate(CERT_TYPE_HOST, self.hostx509)

        with self.subTest('Export OpenSSH X.509 host certificate'):
            self.export_openssh_x509_certificate(CERT_TYPE_HOST, self.hostx509)

    def check_certificate_options(self):
        """Check SSH certificate options"""

        cert = self.privca.generate_user_certificate(
            self.pubkey, 'name', force_command='command',
            source_address=['1.2.3.4'], permit_x11_forwarding=False,
            permit_agent_forwarding=False,
            permit_port_forwarding=False, permit_pty=False,
            permit_user_rc=False, touch_required=False)

        cert.write_certificate('cert')
        self.check_certificate(CERT_TYPE_USER, 'openssh')

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
            self.assertEqual(cert2.public_data, cert.public_data)

    def check_certificate_errors(self, cert_type):
        """Check general and OpenSSH certificate error cases"""

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
                self.validate_openssh(cert, cert_type ^ 3, 'name')

        with self.subTest('Certificate not yet valid'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',),
                                             valid_after=0xffffffffffffffff)
                cert = asyncssh.import_certificate(cert)
                self.validate_openssh(cert, cert_type, 'name')

        with self.subTest('Certificate expired'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',),
                                             valid_before=0)
                cert = asyncssh.import_certificate(cert)
                self.validate_openssh(cert, cert_type, 'name')

        with self.subTest('Certificate principal mismatch'):
            with self.assertRaises(ValueError):
                cert = self.make_certificate(cert_type, self.pubkey,
                                             self.privca, ('name',))
                cert = asyncssh.import_certificate(cert)
                self.validate_openssh(cert, cert_type, 'name2')

        for fmt in ('der', 'pem', 'xxx'):
            with self.subTest('Invalid certificate export format', fmt=fmt):
                with self.assertRaises(asyncssh.KeyExportError):
                    self.usercert.export_certificate(fmt)

    def check_x509_certificate_errors(self):
        """Check X.509 certificate error cases"""

        with self.subTest('Invalid DER format'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate(b'\x30\x00')

        with self.subTest('Invalid DER format in certificate list'):
            with self.assertRaises(asyncssh.KeyImportError):
                write_file('certlist', b'\x30\x00')
                asyncssh.read_certificate_list('certlist')

        with self.subTest('Invalid PEM format'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate('-----')

        with self.subTest('Invalid PEM certificate type'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate('-----BEGIN XXX CERTIFICATE-----\n'
                                            '-----END XXX CERTIFICATE-----\n')

        with self.subTest('Missing PEM footer'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate('-----BEGIN CERTIFICATE-----\n')

        with self.subTest('Invalid PEM Base64'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate('-----BEGIN CERTIFICATE-----\n'
                                            'X\n'
                                            '-----END CERTIFICATE-----\n')

        with self.subTest('Invalid PEM trusted certificate'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate(
                    '-----BEGIN TRUSTED CERTIFICATE-----\n'
                    'MA==\n'
                    '-----END TRUSTED CERTIFICATE-----\n')

        with self.subTest('Invalid PEM certificate data'):
            with self.assertRaises(asyncssh.KeyImportError):
                asyncssh.import_certificate('-----BEGIN CERTIFICATE-----\n'
                                            'XXXX\n'
                                            '-----END CERTIFICATE-----\n')

        with self.subTest('Certificate not yet valid'):
            cert = self.privca.generate_x509_user_certificate(
                self.pubkey, 'OU=user', 'OU=root',
                valid_after=0xfffffffffffffffe)

            with self.assertRaises(ValueError):
                self.validate_x509(cert)

        with self.subTest('Certificate expired'):
            cert = self.privca.generate_x509_user_certificate(
                self.pubkey, 'OU=user', 'OU=root', valid_before=1)

            with self.assertRaises(ValueError):
                self.validate_x509(cert)

        with self.subTest('Certificate principal mismatch'):
            cert = self.privca.generate_x509_user_certificate(
                self.pubkey, 'OU=user', 'OU=root', principals=['name'])

            with self.assertRaises(ValueError):
                self.validate_x509(cert, 'name2')

        for fmt in ('rfc4716', 'xxx'):
            with self.subTest('Invalid certificate export format', fmt=fmt):
                with self.assertRaises(asyncssh.KeyExportError):
                    self.userx509.export_certificate(fmt)

        with self.subTest('Empty certificate chain'):
            with self.assertRaises(asyncssh.KeyImportError):
                decode_ssh_certificate(String('x509v3-ssh-rsa') +
                                       UInt32(0) + UInt32(0))

    def check_x509_certificate_subject(self):
        """Check X.509 certificate subject cases"""

        with self.subTest('Missing certificate subject algorithm'):
            with self.assertRaises(asyncssh.KeyImportError):
                import_certificate_subject('xxx')

        with self.subTest('Unknown certificate subject algorithm'):
            with self.assertRaises(asyncssh.KeyImportError):
                import_certificate_subject('xxx subject=OU=name')

        with self.subTest('Invalid certificate subject'):
            with self.assertRaises(asyncssh.KeyImportError):
                import_certificate_subject('x509v3-ssh-rsa xxx')

        subject = import_certificate_subject('x509v3-ssh-rsa subject=OU=name')
        self.assertEqual(subject, 'OU=name')

    def test_keys(self):
        """Check keys and certificates"""

        for alg_name, kwargs in self.generate_args:
            with self.subTest(alg_name=alg_name, **kwargs):
                self.privkey = get_test_key(
                    alg_name, comment='comment', **kwargs)
                self.privkey.write_private_key('priv', self.base_format)

                self.pubkey = self.privkey.convert_to_public()
                self.pubkey.set_comment('pub_comment')

                self.pubkey.write_public_key('pub', self.base_format)
                self.pubkey.write_public_key('sshpub', 'openssh')

                self.privca = get_test_key(alg_name, 1, **kwargs)
                self.privca.write_private_key('privca', self.base_format)

                self.pubca = self.privca.convert_to_public()
                self.pubca.write_public_key('pubca', self.base_format)

                self.usercert = self.privca.generate_user_certificate(
                    self.pubkey, 'name', comment='user_comment')
                self.usercert.write_certificate('usercert')

                hostcert_sig_alg = self.privca.sig_algorithms[0].decode()
                self.hostcert = self.privca.generate_host_certificate(
                    self.pubkey, 'name', sig_alg=hostcert_sig_alg,
                    comment='host_comment')
                self.hostcert.write_certificate('hostcert')

                for f in ('priv', 'privca'):
                    os.chmod(f, 0o600)

                self.assertEqual(self.privkey.get_algorithm(), alg_name)

                self.assertEqual(self.usercert.get_algorithm(),
                                 self.default_cert_version)

                if self.x509_supported:
                    self.rootx509 = self.privca.generate_x509_ca_certificate(
                        self.pubca, 'OU=root')

                    self.rootx509.write_certificate('rootx509')

                    self.userx509 = self.privca.generate_x509_user_certificate(
                        self.pubkey, 'OU=user', 'OU=root',
                        comment='user_comment')

                    self.assertEqual(self.userx509.get_algorithm(),
                                     'x509v3-' + alg_name)

                    self.userx509.write_certificate('userx509')

                    self.hostx509 = self.privca.generate_x509_host_certificate(
                        self.pubkey, 'OU=host', 'OU=root',
                        comment='host_comment')

                    self.hostx509.write_certificate('hostx509')

                    self.otherx509 = self.privca.generate_x509_user_certificate(
                        self.pubkey, 'OU=other', 'OU=root')

                    self.otherx509.write_certificate('otherx509')

                self.check_encode_errors()
                self.check_decode_errors()
                self.check_sshkey_base_errors()
                self.check_sign_and_verify()
                self.check_set_certificate()
                self.check_comment()

                if 'pkcs1' in self.private_formats:
                    self.check_pkcs1_private()

                if 'pkcs1' in self.public_formats:
                    self.check_pkcs1_public()

                if 'pkcs8' in self.private_formats: # pragma: no branch
                    self.check_pkcs8_private()

                if 'pkcs8' in self.public_formats: # pragma: no branch
                    self.check_pkcs8_public()

                self.check_openssh_private()
                self.check_openssh_public()
                self.check_openssh_certificate()

                self.check_rfc4716_public()
                self.check_rfc4716_certificate()

                self.check_certificate_options()

                for cert_type in (CERT_TYPE_USER, CERT_TYPE_HOST):
                    self.check_certificate_errors(cert_type)

                if self.x509_supported:
                    self.check_der_x509_certificate()
                    self.check_pem_x509_certificate()
                    self.check_openssh_x509_certificate()
                    self.check_x509_certificate_errors()
                    self.check_x509_certificate_subject()


class TestDSA(_TestPublicKey):
    """Test DSA keys"""

    keyclass = 'dsa'
    base_format = 'pkcs8-pem'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')
    default_cert_version = 'ssh-dss-cert-v01@openssh.com'
    x509_supported = x509_available
    generate_args = (('ssh-dss', {}),)
    use_openssh = False


class TestRSA(_TestPublicKey):
    """Test RSA keys"""

    keyclass = 'rsa'
    base_format = 'pkcs8-pem'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs1', 'pkcs8', 'openssh', 'rfc4716')
    default_cert_version = 'ssh-rsa-cert-v01@openssh.com'
    x509_supported = x509_available
    generate_args = (('ssh-rsa', {'key_size': 1024}),
                     ('ssh-rsa', {'key_size': 2048}),
                     ('ssh-rsa', {'key_size': 3072}),
                     ('ssh-rsa', {'exponent': 3}))


class TestECDSA(_TestPublicKey):
    """Test ECDSA keys"""

    keyclass = 'ec'
    base_format = 'pkcs8-pem'
    private_formats = ('pkcs1', 'pkcs8', 'openssh')
    public_formats = ('pkcs8', 'openssh', 'rfc4716')
    x509_supported = x509_available
    generate_args = (('ecdsa-sha2-nistp256', {}),
                     ('ecdsa-sha2-nistp384', {}),
                     ('ecdsa-sha2-nistp521', {}))

    @property
    def default_cert_version(self):
        """Return default SSH certificate version"""

        return self.privkey.algorithm.decode('ascii') + '-cert-v01@openssh.com'


@unittest.skipUnless(ed25519_available, 'ed25519 not available')
class TestEd25519(_TestPublicKey):
    """Test Ed25519 keys"""

    keyclass = 'ed25519'
    base_format = 'pkcs8-pem'
    private_formats = ('pkcs8', 'openssh')
    public_formats = ('pkcs8', 'openssh', 'rfc4716')
    x509_supported = x509_available
    default_cert_version = 'ssh-ed25519-cert-v01@openssh.com'
    generate_args = (('ssh-ed25519', {}),)
    single_cipher = False
    use_openssh = False
    use_openssl = _openssl_supports_pkey


@unittest.skipUnless(ed448_available, 'ed448 not available')
class TestEd448(_TestPublicKey):
    """Test Ed448 keys"""

    keyclass = 'ed448'
    base_format = 'pkcs8-pem'
    private_formats = ('pkcs8', 'openssh')
    public_formats = ('pkcs8', 'openssh', 'rfc4716')
    x509_supported = x509_available
    default_cert_version = 'ssh-ed448-cert-v01@openssh.com'
    generate_args = (('ssh-ed448', {}),)
    use_openssh = False
    use_openssl = _openssl_supports_pkey


@unittest.skipUnless(sk_available, 'security key support not available')
class TestSKECDSA(_TestPublicKey):
    """Test U2F ECDSA keys"""

    keyclass = 'sk-ecdsa'
    base_format = 'openssh'
    private_formats = ('openssh',)
    public_formats = ('openssh',)
    generate_args = (('sk-ecdsa-sha2-nistp256@openssh.com', {}),)
    use_openssh = False

    def setUp(self):
        """Set up ECDSA security key test"""

        super().setUp()
        self.addCleanup(unstub_sk, *stub_sk([1]))

    @property
    def default_cert_version(self):
        """Return default SSH certificate version"""

        return self.privkey.algorithm.decode('ascii')[:-12] + \
            '-cert-v01@openssh.com'


@unittest.skipUnless(sk_available, 'security key support not available')
@unittest.skipUnless(ed25519_available, 'ed25519 not available')
class TestSKEd25519(_TestPublicKey):
    """Test U2F Ed25519 keys"""

    keyclass = 'sk-ed25519'
    base_format = 'openssh'
    private_formats = ('openssh',)
    public_formats = ('openssh',)
    default_cert_version = 'sk-ssh-ed25519-cert-v01@openssh.com'
    generate_args = (('sk-ssh-ed25519@openssh.com', {}),)
    use_openssh = False

    def setUp(self):
        """Set up Ed25519 security key test"""

        super().setUp()
        self.addCleanup(unstub_sk, *stub_sk([2]))


del _TestPublicKey


class _TestPublicKeyTopLevel(TempDirTestCase):
    """Top-level public key module tests"""

    def test_public_key(self):
        """Test public key top-level functions"""

        self.assertIsNotNone(get_public_key_algs())
        self.assertIsNotNone(get_certificate_algs())
        self.assertEqual(bool(get_x509_certificate_algs()), x509_available)

    def test_public_key_algorithm_mismatch(self):
        """Test algorithm mismatch in SSH public key"""

        privkey = get_test_key('ssh-rsa')
        keydata = privkey.export_public_key('openssh')
        keydata = b'ssh-dss ' + keydata.split(None, 1)[1]

        with self.assertRaises(asyncssh.KeyImportError):
            asyncssh.import_public_key(keydata)

        write_file('list', keydata)

        with self.assertRaises(asyncssh.KeyImportError):
            asyncssh.read_public_key_list('list')

    def test_pad_error(self):
        """Test for missing RFC 1423 padding on PBE decrypt"""

        with self.assertRaises(asyncssh.KeyEncryptionError):
            pkcs1_decrypt(b'', b'AES-128-CBC', os.urandom(16), 'x')

    def test_ec_explicit(self):
        """Test EC certificate with explicit parameters"""

        if _openssl_available: # pragma: no branch
            for curve in ('secp256r1', 'secp384r1', 'secp521r1'):
                with self.subTest('Import EC key with explicit parameters',
                                  curve=curve):
                    run('openssl ecparam -out priv -noout -genkey -name %s '
                        '-param_enc explicit' % curve)
                    asyncssh.read_private_key('priv')

    @unittest.skipIf(not _openssl_available, "openssl isn't available")
    @unittest.skipIf(b'secp224r1' not in _openssl_curves,
                     "this openssl doesn't support secp224r1")
    def test_ec_explicit_unknown(self):
        """Import EC key with unknown explicit parameters"""

        run('openssl ecparam -out priv -noout -genkey -name secp224r1 '
            '-param_enc explicit')

        with self.assertRaises(asyncssh.KeyImportError):
            asyncssh.read_private_key('priv')

    def test_generate_errors(self):
        """Test errors in private key and certificate generation"""

        for alg_name, kwargs in (('xxx', {}),
                                 ('ssh-dss', {'xxx': 0}),
                                 ('ssh-rsa', {'xxx': 0}),
                                 ('ecdsa-sha2-nistp256', {'xxx': 0}),
                                 ('ssh-ed25519', {'xxx': 0}),
                                 ('ssh-ed448', {'xxx': 0})):
            with self.subTest(alg_name=alg_name, **kwargs):
                with self.assertRaises(asyncssh.KeyGenerationError):
                    asyncssh.generate_private_key(alg_name, **kwargs)

        privkey = get_test_key('ssh-rsa')
        pubkey = privkey.convert_to_public()
        privca = get_test_key('ssh-rsa', 1)

        with self.assertRaises(asyncssh.KeyGenerationError):
            privca.generate_user_certificate(pubkey, 'name', version=0)

        with self.assertRaises(ValueError):
            privca.generate_user_certificate(pubkey, 'name', valid_after=())

        with self.assertRaises(ValueError):
            privca.generate_user_certificate(pubkey, 'name', valid_after='xxx')

        with self.assertRaises(ValueError):
            privca.generate_user_certificate(pubkey, 'name', valid_after='now',
                                             valid_before='-1m')

        with self.assertRaises(ValueError):
            privca.generate_x509_user_certificate(pubkey, 'OU=user',
                                                  valid_after=())

        with self.assertRaises(ValueError):
            privca.generate_x509_user_certificate(pubkey, 'OU=user',
                                                  valid_after='xxx')

        with self.assertRaises(ValueError):
            privca.generate_x509_user_certificate(pubkey, 'OU=user',
                                                  valid_after='now',
                                                  valid_before='-1m')

        privca.x509_algorithms = None

        with self.assertRaises(asyncssh.KeyGenerationError):
            privca.generate_x509_user_certificate(pubkey, 'OU=user')

    def test_rsa_encrypt_error(self):
        """Test RSA encryption error"""

        privkey = get_test_key('ssh-rsa', 2048)
        pubkey = privkey.convert_to_public()

        self.assertIsNone(pubkey.encrypt(os.urandom(256), pubkey.algorithm))

    def test_rsa_decrypt_error(self):
        """Test RSA decryption error"""

        privkey = get_test_key('ssh-rsa', 2048)

        self.assertIsNone(privkey.decrypt(b'', privkey.algorithm))

    @unittest.skipUnless(x509_available, 'x509 not available')
    def test_x509_certificate_hashes(self):
        """Test X.509 certificate hash algorithms"""

        privkey = get_test_key('ssh-rsa')
        pubkey = privkey.convert_to_public()

        for hash_alg in ('sha256', 'sha512'):
            cert = privkey.generate_x509_user_certificate(
                pubkey, 'OU=user', hash_alg=hash_alg)

            cert.write_certificate('cert', 'pem')

            cert2 = asyncssh.read_certificate('cert')
            self.assertEqual(str(cert2.subject), 'OU=user')
