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

"""A shim for accessing cryptographic primitives needed by asyncssh"""

import importlib

from .cipher import register_cipher, lookup_cipher

from . import chacha

pyca_available = importlib.find_loader('cryptography')
pycrypto_available =  importlib.find_loader('Crypto')

if pyca_available:
    from . import pyca

if pycrypto_available:
    from . import pycrypto

if pyca_available:
    from .pyca.dsa import DSAPrivateKey, DSAPublicKey
    from .pyca.rsa import RSAPrivateKey, RSAPublicKey
elif pycrypto_available:
    from .pycrypto.dsa import DSAPrivateKey, DSAPublicKey
    from .pycrypto.rsa import RSAPrivateKey, RSAPublicKey
else:
    raise ImportError('No suitable crypto library found.')
