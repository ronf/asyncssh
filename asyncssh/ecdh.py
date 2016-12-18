# Copyright (c) 2013-2016 by Ron Frederick <ronf@timeheart.net>.
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

"""Elliptic curve Diffie-Hellman key exchange handler"""

from hashlib import sha256, sha384, sha512

from .constants import DISC_KEY_EXCHANGE_FAILED, DISC_PROTOCOL_ERROR
from .kex import Kex, register_kex_alg
from .misc import DisconnectError
from .packet import Byte, MPInt, String

# pylint: disable=bad-whitespace

# SSH KEX ECDH message values
MSG_KEX_ECDH_INIT  = 30
MSG_KEX_ECDH_REPLY = 31

# pylint: enable=bad-whitespace


class _KexECDH(Kex):
    """Handler for elliptic curve Diffie-Hellman key exchange"""

    def __init__(self, alg, conn, hash_alg, ecdh_class, *args):
        super().__init__(alg, conn, hash_alg)

        self._priv = ecdh_class(*args)
        pub = self._priv.get_public()

        if conn.is_client():
            self._client_pub = pub
            self._conn.send_packet(Byte(MSG_KEX_ECDH_INIT), String(pub))
        else:
            self._server_pub = pub

    def _compute_hash(self, host_key_data, k):
        """Compute a hash of key information associated with the connection"""

        hash_obj = self._hash_alg()
        hash_obj.update(self._conn.get_hash_prefix())
        hash_obj.update(String(host_key_data))
        hash_obj.update(String(self._client_pub))
        hash_obj.update(String(self._server_pub))
        hash_obj.update(MPInt(k))
        return hash_obj.digest()

    def _process_init(self, pkttype, packet):
        """Process an ECDH init message"""

        # pylint: disable=unused-argument

        if self._conn.is_client():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex init msg')

        self._client_pub = packet.get_string()
        packet.check_end()

        try:
            k = self._priv.get_shared(self._client_pub)
        except (AssertionError, ValueError):
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid kex init msg') from None

        host_key = self._conn.get_server_host_key()

        h = self._compute_hash(host_key.public_data, k)
        sig = host_key.sign(h)

        self._conn.send_packet(Byte(MSG_KEX_ECDH_REPLY),
                               String(host_key.public_data),
                               String(self._server_pub), String(sig))

        self._conn.send_newkeys(k, h)

    def _process_reply(self, pkttype, packet):
        """Process an ECDH reply message"""

        # pylint: disable=unused-argument

        if self._conn.is_server():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex reply msg')

        host_key_data = packet.get_string()
        self._server_pub = packet.get_string()
        sig = packet.get_string()
        packet.check_end()

        try:
            k = self._priv.get_shared(self._server_pub)
        except (AssertionError, ValueError):
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid kex reply msg') from None

        host_key = self._conn.validate_server_host_key(host_key_data)

        h = self._compute_hash(host_key_data, k)
        if not host_key.verify(h, sig):
            raise DisconnectError(DISC_KEY_EXCHANGE_FAILED,
                                  'Key exchange hash mismatch')

        self._conn.send_newkeys(k, h)

    packet_handlers = {
        MSG_KEX_ECDH_INIT:  _process_init,
        MSG_KEX_ECDH_REPLY: _process_reply
    }


try:
    # pylint: disable=wrong-import-position
    from .crypto import Curve25519DH
except ImportError: # pragma: no cover
    pass
else:
    register_kex_alg(b'curve25519-sha256', _KexECDH, sha256, Curve25519DH)
    register_kex_alg(b'curve25519-sha256@libssh.org', _KexECDH,
                     sha256, Curve25519DH)

try:
    # pylint: disable=wrong-import-position
    from .crypto import ECDH
except ImportError: # pragma: no cover
    pass
else:
    for _curve_id, _hash_alg in ((b'nistp521', sha512),
                                 (b'nistp384', sha384),
                                 (b'nistp256', sha256)):
        register_kex_alg(b'ecdh-sha2-' + _curve_id, _KexECDH,
                         _hash_alg, ECDH, _curve_id)
