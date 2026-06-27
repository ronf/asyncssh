# Copyright (c) 2022-2026 by Ron Frederick <ronf@timeheart.net> and others.
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

"""A shim around liboqs for Streamlined NTRU Prime post-quantum encryption"""

import ctypes
import ctypes.util
from typing import Mapping, Protocol, Tuple, Type, Union

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import mlkem


class PQKey(Protocol):
    """Protocol for performing post-quantum key exchange"""

    pubkey_bytes: int
    privkey_bytes: int
    ciphertext_bytes: int
    secret_bytes: int

    # pylint: disable=super-init-not-called
    def __init__(self, alg_name: bytes) -> None:
        """Construct a PQKey"""

    def get_public(self) -> bytes:
        """Return the public key to send in the handshake"""

    def encaps(self, peer_public: bytes) -> Tuple[bytes, bytes]:
        """Generate a random secret and encrypt it with a public key"""

    def decaps(self, ciphertext: bytes) -> bytes:
        """Decrypt an encrypted secret using a private key"""

PQClass = Type[PQKey]


_pq_alg_sizes: Mapping[bytes, Tuple[int, int, int, int]] = {
    b'mlkem768':  (1184, 2400, 1088, 32),
    b'mlkem1024': (1568, 3168, 1568, 32),
    b'sntrup761': (1158, 1763, 1039, 32)
}

_pyca_pq_alg_classes: Mapping[bytes, Tuple[Type, Type]] = {
    b'mlkem768': (mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey),
    b'mlkem1024': (mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey)
}

_oqs_pq_alg_names: Mapping[bytes, str] = {
    b'mlkem768':  'KEM_ml_kem_768',
    b'mlkem1024': 'KEM_ml_kem_1024',
    b'sntrup761': 'KEM_ntruprime_sntrup761'
}


class _KEM:
    """An implementation of post-quantum key exchange algorithms"""

    def __init__(self, alg_name: bytes) -> None:
        try:
            self.pubkey_bytes, self.privkey_bytes, self.ciphertext_bytes, \
                self.secret_bytes = _pq_alg_sizes[alg_name]
        except KeyError:
            raise ValueError('Unknown PQ algorithm ' +
                             alg_name.decode()) from None


class _PyCAKEM(_KEM):
    """A shim around PyCA for post-quantum key exchange algorithms"""

    def __init__(self, alg_name: bytes) -> None:
        super().__init__(alg_name)

        try:
            self._priv_cls, self._pub_cls = _pyca_pq_alg_classes[alg_name]
        except KeyError: # pragma: no cover
            raise ValueError('Unknown PQ algorithm ' +
                             alg_name.decode()) from None

        self._priv_key = self._priv_cls.generate()

    def get_public(self) -> bytes:
        """Return the public key to send in the handshake"""

        return self._priv_key.public_key().public_bytes_raw()

    def encaps(self, peer_public: bytes) -> Tuple[bytes, bytes]:
        """Generate a random secret and encrypt it with a public key"""

        peer_pubkey = self._pub_cls.from_public_bytes(peer_public)

        return peer_pubkey.encapsulate()

    def decaps(self, ciphertext: bytes) -> bytes:
        """Decrypt an encrypted secret using a private key"""

        return self._priv_key.decapsulate(ciphertext)


class _OQSKEM(_KEM):
    """A shim around liboqs for post-quantum key exchange algorithms"""

    def __init__(self, alg_name: bytes) -> None:
        super().__init__(alg_name)

        try:
            oqs_name = _oqs_pq_alg_names[alg_name]
        except KeyError: # pragma: no cover
            raise ValueError('Unknown PQ algorithm ' +
                             alg_name.decode()) from None

        if not hasattr(_oqs, 'OQS_' + oqs_name + # pragma: no cover
                       '_keypair'):
            oqs_name += '_ipd'

        self._keypair = getattr(_oqs, 'OQS_' + oqs_name + '_keypair')
        self._encaps = getattr(_oqs, 'OQS_' + oqs_name + '_encaps')
        self._decaps = getattr(_oqs, 'OQS_' + oqs_name + '_decaps')

        pubkey = ctypes.create_string_buffer(self.pubkey_bytes)
        privkey = ctypes.create_string_buffer(self.privkey_bytes)
        self._keypair(pubkey, privkey)

        self._pub_key = pubkey.raw
        self._priv_key = privkey.raw

    def get_public(self) -> bytes:
        """Return the public key to send in the handshake"""

        return self._pub_key

    def encaps(self, peer_public: bytes) -> Tuple[bytes, bytes]:
        """Generate a random secret and encrypt it with a public key"""

        if len(peer_public) != self.pubkey_bytes:
            raise ValueError('Invalid public key')

        ciphertext = ctypes.create_string_buffer(self.ciphertext_bytes)
        secret = ctypes.create_string_buffer(self.secret_bytes)

        self._encaps(ciphertext, secret, peer_public)

        return secret.raw, ciphertext.raw

    def decaps(self, ciphertext: bytes) -> bytes:
        """Decrypt an encrypted secret using a private key"""

        if len(ciphertext) != self.ciphertext_bytes:
            raise ValueError('Invalid ciphertext')

        secret = ctypes.create_string_buffer(self.secret_bytes)

        self._decaps(secret, ciphertext, self._priv_key)

        return secret.raw


mlkem_available = False
sntrup_available = False

MLKEM = _PyCAKEM  # type: Union[Type[_PyCAKEM], Type[_OQSKEM]]
SNTRUP = _OQSKEM

if backend.mlkem_supported(): # pragma: no branch
    mlkem_available = True

for lib in ('oqs', 'liboqs'):
    _oqs_lib = ctypes.util.find_library(lib)

    if _oqs_lib: # pragma: no branch
        break
else: # pragma: no cover
    _oqs_lib = None

if _oqs_lib: # pragma: no branch
    _oqs = ctypes.cdll.LoadLibrary(_oqs_lib)

    if not mlkem_available: # pragma: no cover
        mlkem_available = (hasattr(_oqs, 'OQS_KEM_ml_kem_768_keypair') or
                           hasattr(_oqs, 'OQS_KEM_ml_kem_768_ipd_keypair'))
        MLKEM = _OQSKEM

    sntrup_available = hasattr(_oqs, 'OQS_KEM_ntruprime_sntrup761_keypair')
