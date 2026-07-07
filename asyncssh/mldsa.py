# Copyright (c) 2026 by Ron Frederick <ronf@timeheart.net> and others.
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

"""MLDSA public key encryption handler"""

from typing import Optional, Tuple, Union, cast

from .asn1 import ASN1DecodeError, ObjectIdentifier, RawDERObject
from .asn1 import der_encode, der_decode
from .crypto import mldsa_available, MLDSAPrivateKey, MLDSAPublicKey
from .packet import String, SSHPacket
from .public_key import OMIT, SSHKey, SSHOpenSSHCertificateV01
from .public_key import KeyImportError, KeyExportError
from .public_key import register_public_key_alg, register_certificate_alg


_PrivateKeyArgs = Tuple[bytes]
_PublicKeyArgs = Tuple[bytes]


class _MLDSAKey(SSHKey):
    """Handler for MLDSA public key encryption"""

    _key: Union[MLDSAPrivateKey, MLDSAPublicKey]

    algorithm = b''

    def __eq__(self, other: object) -> bool:
        # This isn't protected access - both objects are _MLDSAKey instances
        # pylint: disable=protected-access

        return (isinstance(other, type(self)) and
                self._key.public_value == other._key.public_value and
                self._key.private_value == other._key.private_value)

    def __hash__(self) -> int:
        return hash((self._key.public_value, self._key.private_value))

    @classmethod
    def generate(cls, algorithm: bytes) -> '_MLDSAKey': # type: ignore
        """Generate a new MLDSA private key"""

        # pylint: disable=arguments-differ

        # Strip 'ssh-' prefix of algorithm to get the dimension
        return cls(MLDSAPrivateKey.generate(algorithm[4:]))

    @classmethod
    def make_private(cls, key_params: object) -> SSHKey:
        """Construct an MLDSA private key"""

        try:
            private_value, = cast(_PrivateKeyArgs, key_params)

            return cls(MLDSAPrivateKey.construct(cls.algorithm[4:],
                                                 private_value))
        except (TypeError, ValueError):
            raise KeyImportError('Invalid MLDSA private key') from None

    @classmethod
    def make_public(cls, key_params: object) -> SSHKey:
        """Construct an MLDSA public key"""

        try:
            public_value, = cast(_PublicKeyArgs, key_params)

            return cls(MLDSAPublicKey.construct(cls.algorithm[4:],
                                                public_value))
        except (TypeError, ValueError):
            raise KeyImportError('Invalid MLDSA public key') from None

    @classmethod
    def decode_pkcs8_private(cls, alg_params: object,
                             data: bytes) -> Optional[_PrivateKeyArgs]:
        """Decode a PKCS#8 format MLDSA private key"""

        # pylint: disable=unused-argument

        try:
            key_data =  der_decode(data)
        except ASN1DecodeError:
            return None

        if isinstance(key_data, tuple) and len(key_data) == 2:
            return (key_data[0],)
        elif isinstance(key_data, RawDERObject) and key_data.tag == 0:
            return (key_data.content,)
        else:
            return None

    @classmethod
    def decode_pkcs8_public(cls, alg_params: object,
                            data: bytes) -> Optional[_PublicKeyArgs]:
        """Decode a PKCS#8 format MLDSA public key"""

        # pylint: disable=unused-argument

        return (data,)

    @classmethod
    def decode_ssh_private(cls, packet: SSHPacket) -> _PrivateKeyArgs:
        """Decode an SSH format MLDSA private key"""

        public_value = packet.get_string()
        private_value = packet.get_string()

        return (private_value[:-len(public_value)],)

    @classmethod
    def decode_ssh_public(cls, packet: SSHPacket) -> _PublicKeyArgs:
        """Decode an SSH format MLDSA public key"""

        public_value = packet.get_string()

        return (public_value,)

    def encode_pkcs8_private(self) -> Tuple[object, object]:
        """Encode a PKCS#8 format MLDSA private key"""

        if not self._key.private_value:
            raise KeyExportError('Key is not private')

        return OMIT, der_encode(RawDERObject(0, self._key.private_value))

    def encode_pkcs8_public(self) -> Tuple[object, object]:
        """Encode a PKCS#8 format MLDSA public key"""

        return OMIT, self._key.public_value

    def encode_ssh_private(self) -> bytes:
        """Encode an SSH format MLDSA private key"""

        if self._key.private_value is None:
            raise KeyExportError('Key is not private')

        return b''.join((String(self._key.public_value),
                         String(self._key.private_value +
                                self._key.public_value)))

    def encode_ssh_public(self) -> bytes:
        """Encode an SSH format MLDSA public key"""

        return String(self._key.public_value)

    def encode_agent_cert_private(self) -> bytes:
        """Encode MLDSA certificate private key data for agent"""

        return self.encode_ssh_private()

    def sign_ssh(self, data: bytes, sig_algorithm: bytes) -> bytes:
        """Compute an SSH-encoded signature of the specified data"""

        # pylint: disable=unused-argument

        if not self._key.private_value:
            raise ValueError('Private key needed for signing')

        return String(self._key.sign(data))

    def verify_ssh(self, data: bytes, sig_algorithm: bytes,
                   packet: SSHPacket) -> bool:
        """Verify an SSH-encoded signature of the specified data"""

        # pylint: disable=unused-argument

        sig = packet.get_string()
        packet.check_end()

        return self._key.verify(data, sig)


class _MLDSA44Key(_MLDSAKey):
    """Handler for MLDSA-44 public key encryption"""

    algorithm = b'ssh-mldsa-44'
    pkcs8_oid = ObjectIdentifier('2.16.840.1.101.3.4.3.17')
    sig_algorithms = (algorithm,)
    all_sig_algorithms = set(sig_algorithms)


class _MLDSA65Key(_MLDSAKey):
    """Handler for MLDSA-65 public key encryption"""

    algorithm = b'ssh-mldsa-65'
    pkcs8_oid = ObjectIdentifier('2.16.840.1.101.3.4.3.18')
    sig_algorithms = (algorithm,)
    all_sig_algorithms = set(sig_algorithms)


class _MLDSA87Key(_MLDSAKey):
    """Handler for MLDSA-87 public key encryption"""

    algorithm = b'ssh-mldsa-87'
    pkcs8_oid = ObjectIdentifier('2.16.840.1.101.3.4.3.19')
    sig_algorithms = (algorithm,)
    all_sig_algorithms = set(sig_algorithms)


if mldsa_available: # pragma: no branch
    register_public_key_alg(b'ssh-mldsa-44', _MLDSA44Key, True)
    register_public_key_alg(b'ssh-mldsa-65', _MLDSA65Key, True)
    register_public_key_alg(b'ssh-mldsa-87', _MLDSA87Key, True)

    register_certificate_alg(1, b'ssh-mldsa-44',
                             b'ssh-mldsa-44-cert-v01@openssh.com',
                             _MLDSA44Key, SSHOpenSSHCertificateV01, True)
    register_certificate_alg(1, b'ssh-mldsa-65',
                             b'ssh-mldsa-65-cert-v01@openssh.com',
                             _MLDSA65Key, SSHOpenSSHCertificateV01, True)
    register_certificate_alg(1, b'ssh-mldsa-87',
                             b'ssh-mldsa-87-cert-v01@openssh.com',
                             _MLDSA87Key, SSHOpenSSHCertificateV01, True)
