# Copyright (c) 2020-2021 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Stub PKCS#11 security key module for unit tests"""

import asyncssh
from asyncssh.asn1 import der_decode
from asyncssh.pkcs11 import pkcs11_available
from .util import get_test_key

if pkcs11_available: # pragma: no branch
    import pkcs11
    from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

    def _encode_public(key):
        """Stub to encode a PKCS#11 public key"""

        return key.encode_public()

    _encoders = {KeyType.RSA: _encode_public,
                 KeyType.EC:  _encode_public}

    _key_types = {'ssh-rsa':             KeyType.RSA,
                  'ecdsa-sha2-nistp256': KeyType.EC,
                  'ecdsa-sha2-nistp384': KeyType.EC,
                  'ssh-ed25519':         KeyType.EC_EDWARDS}

    _hash_algs = {Mechanism.SHA1_RSA_PKCS:   'sha1',
                  Mechanism.SHA224_RSA_PKCS: 'sha224',
                  Mechanism.SHA256_RSA_PKCS: 'sha256',
                  Mechanism.SHA384_RSA_PKCS: 'sha384',
                  Mechanism.SHA512_RSA_PKCS: 'sha512',
                  Mechanism.ECDSA_SHA256:    'sha256',
                  Mechanism.ECDSA_SHA384:    'sha384',
                  Mechanism.ECDSA_SHA512:    'sha512'}


class _PKCS11Key:
    """Stub for unit testing PKCS#11 keys"""

    def __init__(self, alg_name, key_type, key_label, key_id):
        self._priv = get_test_key(alg_name, key_id, comment=key_label)
        self.key_type = key_type
        self.label = key_label
        self.id = key_id

    def get_cert(self):
        """Return self-signed X.509 cert for this key"""

        return self._priv.generate_x509_user_certificate(
            self._priv, 'OU=%s,CN=ckey' % self.label)

    def get_public(self):
        """Return public key corresponding to this key"""

        return self._priv.convert_to_public()

    def encode_public(self):
        """Stub to encode a PKCS#11 public key"""

        return self._priv.export_public_key('pkcs8-der')

    def sign(self, data, mechanism):
        """Sign a block of data with this key"""

        sig = self._priv.sign_raw(data, _hash_algs[mechanism])

        if self.key_type == KeyType.EC:
            r, s = der_decode(sig)
            length = (max(r.bit_length(), s.bit_length()) + 7) // 8
            sig = r.to_bytes(length, 'big') + s.to_bytes(length, 'big')

        return sig


class _PKCS11Cert:
    """Stub for unit testing PKCS#11 certificates"""

    def __init__(self, key):
        self._cert = key.get_cert()

    def __getitem__(self, key):
        if key == Attribute.VALUE: # pragma: no branch
            return self._cert.export_certificate('der')

    def get_cert(self):
        """Return cert object"""

        return self._cert


class _PKCS11Session:
    """Stub for unit testing PKCS#11 security token sessions"""

    def __init__(self, keys, certs):
        self._keys = keys
        self._certs = certs

    def get_objects(self, attrs):
        """Return a list of PKCS#11 key or certificate objects"""

        label = attrs.get(Attribute.LABEL)
        obj_id = attrs.get(Attribute.OBJECT_ID)

        objs = self._keys if attrs[Attribute.CLASS] == \
                   ObjectClass.PRIVATE_KEY else self._certs

        for obj in objs:
            if label is not None and obj.label != label:
                continue

            if obj_id is not None and obj.id != obj_id:
                continue

            yield obj

    def close(self):
        """Close this session"""


class _PKCS11Token:
    """Stub for unit testing PKCS#11 security tokens"""

    def __init__(self, label, serial, key_info):
        self.manufacturer_id = 'Test'
        self.label = label
        self.serial = serial

        self._keys = []
        self._pubkeys = []
        self._certs = []

        for i, (alg, key_label) in enumerate(key_info, 1):
            self._add_key(alg, _key_types[alg], key_label, i)

    def _add_key(self, alg, key_type, key_label, key_id):
        """Add key to this token"""

        key = _PKCS11Key(alg, key_type, key_label, bytes((key_id,)))

        self._keys.append(key)
        self._pubkeys.append(key.get_public())
        self._certs.append(_PKCS11Cert(key))

    def get_pubkeys(self):
        """Return public keys associated with this token"""

        return self._pubkeys

    def get_certs(self):
        """Return X.509 certificates associated with this token"""

        return [cert.get_cert() for cert in self._certs]

    def open(self, user_pin=None):
        """Open a session to access a security token"""

        # pylint: disable=unused-argument

        return _PKCS11Session(self._keys, self._certs)


class PKCS11Lib:
    """"Stub for unit testing PKCS#11 providers"""

    tokens = []
    public_keys = []
    certs = []

    @classmethod
    def init_tokens(cls, token_info):
        """Initialize PKCS#11 token stubs for unit testing"""

        cls.tokens = [_PKCS11Token(*info) for info in token_info]
        cls.public_keys = sum((token.get_pubkeys() for token in cls.tokens), [])
        cls.certs = sum((token.get_certs() for token in cls.tokens), [])

    def __init__(self, provider):
        # pylint: disable=unused-argument

        pass

    def get_tokens(self, token_label=None, token_serial=None):
        """Return PKCS#11 security tokens"""

        for token in self.tokens:
            if token_label is not None and token.label != token_label:
                continue

            if token_serial is not None and token.serial != token_serial:
                continue

            yield token


def get_pkcs11_public_keys():
    """Return PKCS#11 public keys to trust in unit tests"""

    return PKCS11Lib.public_keys


def get_pkcs11_certs():
    """Return PKCS#11 X.509 certificates to trust in unit tests"""

    return PKCS11Lib.certs


def stub_pkcs11(token_info):
    """Stub out PKCS#11 security token functions for unit testing"""

    old_lib = pkcs11.lib
    old_encoders = asyncssh.pkcs11.encoders

    pkcs11.lib = PKCS11Lib
    asyncssh.pkcs11.encoders = _encoders

    PKCS11Lib.init_tokens(token_info)

    return old_lib, old_encoders


def unstub_pkcs11(old_lib, old_encoders):
    """Restore PKCS#11 security token functions"""

    pkcs11.lib = old_lib
    asyncssh.pkcs11.encoders = old_encoders
