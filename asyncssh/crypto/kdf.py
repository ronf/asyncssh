# Copyright (c) 2017-2018 by Ron Frederick <ronf@timeheart.net>.
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

"""A shim around PyCA for key derivation functions"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA1, SHA224, SHA256
from cryptography.hazmat.primitives.hashes import SHA384, SHA512
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


_hashes = {h.name: h for h in (SHA1, SHA224, SHA256, SHA384, SHA512)}


def pbkdf2_hmac(hash_name, passphrase, salt, count, key_size):
    """A shim around PyCA for PBKDF2 HMAC key derivation"""

    return PBKDF2HMAC(_hashes[hash_name](), key_size, salt, count,
                      default_backend()).derive(passphrase)
