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

"""A shim for accessing cryptographic primitives needed by asyncssh"""

import importlib.util

from .cipher import register_cipher, lookup_cipher

try:
    from .curve25519 import Curve25519DH
except ImportError: # pragma: no cover
    pass

from . import chacha

pyca_available = importlib.util.find_spec('cryptography')
pycrypto_available = importlib.util.find_spec('Crypto')

if pyca_available: # pragma: no branch
    from . import pyca

if pycrypto_available: # pragma: no branch
    from . import pycrypto

if pyca_available:
    from .pyca.dsa import DSAPrivateKey, DSAPublicKey
    from .pyca.rsa import RSAPrivateKey, RSAPublicKey
elif pycrypto_available: # pragma: no cover
    from .pycrypto.dsa import DSAPrivateKey, DSAPublicKey
    from .pycrypto.rsa import RSAPrivateKey, RSAPublicKey
else: # pragma: no cover
    raise ImportError('No suitable crypto library found.')
