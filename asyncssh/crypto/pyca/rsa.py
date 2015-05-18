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

"""A shim around PyCA for RSA public and private keys"""

from asyncssh.asn1 import der_decode

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from cryptography.hazmat.primitives.hashes import SHA1 

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers
from cryptography.hazmat.primitives.asymmetric.rsa import rsa_crt_dmp1
from cryptography.hazmat.primitives.asymmetric.rsa import rsa_crt_dmq1
from cryptography.hazmat.primitives.asymmetric.rsa import rsa_crt_iqmp


class RSAPrivateKey:
    def __init__(self, n, e, d, p, q):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q

        dmp1 = rsa_crt_dmp1(d, p)
        dmq1 = rsa_crt_dmq1(d, q)
        iqmp = rsa_crt_iqmp(p, q)

        pub = RSAPublicNumbers(e, n)
        priv = RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub)
        self._key = priv.private_key(default_backend())

    def sign(self, data):
        signer = self._key.signer(PKCS1v15(), SHA1())
        signer.update(data)
        return signer.finalize()


class RSAPublicKey:
    def __init__(self, n, e):
        self.n = n
        self.e = e

        self._key = RSAPublicNumbers(e, n).public_key(default_backend())

    def verify(self, data, sig):
        verifier = self._key.verifier(sig, PKCS1v15(), SHA1())
        verifier.update(data)

        try:
            verifier.verify()
            return True
        except InvalidSignature:
            return False
