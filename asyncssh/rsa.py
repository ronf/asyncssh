# Copyright (c) 2013-2021 by Ron Frederick <ronf@timeheart.net> and others.
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

"""RSA public key encryption handler"""

from .asn1 import ASN1DecodeError, ObjectIdentifier, der_encode, der_decode
from .crypto import RSAPrivateKey, RSAPublicKey
from .misc import all_ints
from .packet import MPInt, String
from .public_key import SSHKey, SSHOpenSSHCertificateV01, KeyExportError
from .public_key import register_public_key_alg, register_certificate_alg
from .public_key import register_x509_certificate_alg


_hash_algs = {b'ssh-rsa':                'sha1',
              b'rsa-sha2-256':           'sha256',
              b'rsa-sha2-512':           'sha512',
              b'ssh-rsa-sha224@ssh.com': 'sha224',
              b'ssh-rsa-sha256@ssh.com': 'sha256',
              b'ssh-rsa-sha384@ssh.com': 'sha384',
              b'ssh-rsa-sha512@ssh.com': 'sha512',
              b'rsa1024-sha1':           'sha1',
              b'rsa2048-sha256':         'sha256'}


class _RSAKey(SSHKey):
    """Handler for RSA public key encryption"""

    algorithm = b'ssh-rsa'
    default_hash_alg = 'sha256'
    pem_name = b'RSA'
    pkcs8_oid = ObjectIdentifier('1.2.840.113549.1.1.1')
    sig_algorithms = (b'rsa-sha2-256', b'rsa-sha2-512',
                      b'ssh-rsa-sha224@ssh.com', b'ssh-rsa-sha256@ssh.com',
                      b'ssh-rsa-sha384@ssh.com', b'ssh-rsa-sha512@ssh.com',
                      b'ssh-rsa')
    x509_sig_algorithms = (b'rsa2048-sha256', b'ssh-rsa')
    x509_algorithms = tuple(b'x509v3-' + alg for alg in x509_sig_algorithms)
    all_sig_algorithms = set(x509_sig_algorithms + sig_algorithms)

    def __eq__(self, other):
        # This isn't protected access - both objects are _RSAKey instances
        # pylint: disable=protected-access

        return (isinstance(other, type(self)) and
                self._key.n == other._key.n and
                self._key.e == other._key.e and
                self._key.d == other._key.d)

    def __hash__(self):
        return hash((self._key.n, self._key.e, self._key.d,
                     self._key.p, self._key.q))

    @classmethod
    def generate(cls, _algorithm, *, key_size=2048, exponent=65537):
        """Generate a new RSA private key"""

        return cls(RSAPrivateKey.generate(key_size, exponent))

    @classmethod
    def make_private(cls, n, e, d, p, q, dmp1, dmq1, iqmp):
        """Construct an RSA private key"""

        return cls(RSAPrivateKey.construct(n, e, d, p, q, dmp1, dmq1, iqmp))

    @classmethod
    def make_public(cls, n, e):
        """Construct an RSA public key"""

        return cls(RSAPublicKey.construct(n, e))

    @classmethod
    def decode_pkcs1_private(cls, key_data):
        """Decode a PKCS#1 format RSA private key"""

        if (isinstance(key_data, tuple) and all_ints(key_data) and
                len(key_data) >= 9):
            return key_data[1:9]
        else:
            return None

    @classmethod
    def decode_pkcs1_public(cls, key_data):
        """Decode a PKCS#1 format RSA public key"""

        if (isinstance(key_data, tuple) and all_ints(key_data) and
                len(key_data) == 2):
            return key_data
        else:
            return None

    @classmethod
    def decode_pkcs8_private(cls, alg_params, data):
        """Decode a PKCS#8 format RSA private key"""

        if alg_params is not None:
            return None

        try:
            key_data = der_decode(data)
        except ASN1DecodeError:
            return None

        return cls.decode_pkcs1_private(key_data)

    @classmethod
    def decode_pkcs8_public(cls, alg_params, data):
        """Decode a PKCS#8 format RSA public key"""

        if alg_params is not None:
            return None

        try:
            key_data = der_decode(data)
        except ASN1DecodeError:
            return None

        return cls.decode_pkcs1_public(key_data)

    @classmethod
    def decode_ssh_private(cls, packet):
        """Decode an SSH format RSA private key"""

        n = packet.get_mpint()
        e = packet.get_mpint()
        d = packet.get_mpint()
        iqmp = packet.get_mpint()
        p = packet.get_mpint()
        q = packet.get_mpint()

        return n, e, d, p, q, d % (p-1), d % (q-1), iqmp

    @classmethod
    def decode_ssh_public(cls, packet):
        """Decode an SSH format RSA public key"""

        e = packet.get_mpint()
        n = packet.get_mpint()

        return n, e

    def encode_pkcs1_private(self):
        """Encode a PKCS#1 format RSA private key"""

        if not self._key.d:
            raise KeyExportError('Key is not private')

        return (0, self._key.n, self._key.e, self._key.d, self._key.p,
                self._key.q, self._key.dmp1, self._key.dmq1, self._key.iqmp)

    def encode_pkcs1_public(self):
        """Encode a PKCS#1 format RSA public key"""

        return self._key.n, self._key.e

    def encode_pkcs8_private(self):
        """Encode a PKCS#8 format RSA private key"""

        return None, der_encode(self.encode_pkcs1_private())

    def encode_pkcs8_public(self):
        """Encode a PKCS#8 format RSA public key"""

        return None, der_encode(self.encode_pkcs1_public())

    def encode_ssh_private(self):
        """Encode an SSH format RSA private key"""

        if not self._key.d:
            raise KeyExportError('Key is not private')

        return b''.join((MPInt(self._key.n), MPInt(self._key.e),
                         MPInt(self._key.d), MPInt(self._key.iqmp),
                         MPInt(self._key.p), MPInt(self._key.q)))

    def encode_ssh_public(self):
        """Encode an SSH format RSA public key"""

        return b''.join((MPInt(self._key.e), MPInt(self._key.n)))

    def encode_agent_cert_private(self):
        """Encode RSA certificate private key data for agent"""

        if not self._key.d:
            raise KeyExportError('Key is not private')

        return b''.join((MPInt(self._key.d), MPInt(self._key.iqmp),
                         MPInt(self._key.p), MPInt(self._key.q)))

    def sign_ssh(self, data, sig_algorithm):
        """Compute an SSH-encoded signature of the specified data"""

        if not self._key.d:
            raise ValueError('Private key needed for signing')

        return String(self._key.sign(data, _hash_algs[sig_algorithm]))

    def verify_ssh(self, data, sig_algorithm, packet):
        """Verify an SSH-encoded signature of the specified data"""

        sig = packet.get_string()
        packet.check_end()

        return self._key.verify(data, sig, _hash_algs[sig_algorithm])

    def encrypt(self, data, algorithm):
        """Encrypt a block of data with this key"""

        return self._key.encrypt(data, _hash_algs[algorithm])

    def decrypt(self, data, algorithm):
        """Decrypt a block of data with this key"""

        return self._key.decrypt(data, _hash_algs[algorithm])


register_public_key_alg(b'ssh-rsa', _RSAKey, True)

register_certificate_alg(1, b'ssh-rsa', b'ssh-rsa-cert-v01@openssh.com',
                         _RSAKey, SSHOpenSSHCertificateV01, True)

for alg in _RSAKey.x509_algorithms:
    register_x509_certificate_alg(alg, True)
