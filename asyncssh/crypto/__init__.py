# Copyright (c) 2014-2018 by Ron Frederick <ronf@timeheart.net>.
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

"""A shim for accessing cryptographic primitives needed by asyncssh"""

from .cipher import BasicCipher, GCMCipher, register_cipher, get_cipher_params

from .dsa import DSAPrivateKey, DSAPublicKey

from .ec import ECDSAPrivateKey, ECDSAPublicKey, ECDH

from .ec_params import lookup_ec_curve_by_params

from .kdf import pbkdf2_hmac

from .rsa import RSAPrivateKey, RSAPublicKey

# Import chacha20-poly1305 cipher if available
from .chacha import ChachaCipher

# Import curve25519 DH if available
try:
    from .curve25519 import Curve25519DH
except ImportError: # pragma: no cover
    pass

# Import umac cryptographic hash if available
try:
    from .umac import umac32, umac64, umac96, umac128
except (ImportError, AttributeError, OSError): # pragma: no cover
    pass

# Import X.509 certificate support if available
try:
    from .x509 import X509Name, X509NamePattern
    from .x509 import generate_x509_certificate, import_x509_certificate
except ImportError: # pragma: no cover
    pass
