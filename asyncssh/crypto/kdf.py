# Copyright (c) 2017-2018 by Ron Frederick <ronf@timeheart.net> and others.
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
