# Copyright (c) 2015 by Ron Frederick <ronf@timeheart.net>.
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

"""Elliptic curve Diffie-Hellman key exchange handler primitives"""

from ..misc import randrange

from .ec import get_ec_curve_params, PrimePoint

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class ECDH:
    """Elliptic curve Diffie-Hellman implementation"""

    def __init__(self, curve_id):
        G, n = get_ec_curve_params(curve_id)

        while True:
            self._d = randrange(2, n)
            self._Q = self._d * G

            if self._Q: # pragma: no branch
                break

    def get_public(self):
        """Return the public key to send in the handshake"""

        return self._Q.encode()

    def get_shared(self, peer_public):
        """Return the shared key from the peer's public key"""

        P = self._d * PrimePoint.decode(self._Q.curve, peer_public)
        if not P: # pragma: no cover
            raise ValueError('ECDH multiplication failed')

        return P.x
