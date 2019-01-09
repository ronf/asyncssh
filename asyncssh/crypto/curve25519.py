# Copyright (c) 2015-2018 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Curve25519 key exchange handler primitives"""

from cryptography.exceptions import InternalError
from cryptography.hazmat.primitives.asymmetric import x25519


class Curve25519DH:
    """Curve25519 Diffie Hellman implementation"""

    def __init__(self):
        self._priv_key = x25519.X25519PrivateKey.generate()

    def get_public(self):
        """Return the public key to send in the handshake"""

        return self._priv_key.public_key().public_bytes()

    def get_shared(self, peer_public):
        """Return the shared key from the peer's public key"""

        try:
            peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public)
        except InternalError:
            raise ValueError('Invalid curve25519 public key') from None

        shared = self._priv_key.exchange(peer_key)
        return int.from_bytes(shared, 'big')
