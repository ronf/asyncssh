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

"""Curve25519 key exchange handler"""

from hashlib import sha256

from .constants import DISC_KEY_EXCHANGE_FAILED, DISC_PROTOCOL_ERROR
from .kex import Kex, register_kex_alg
from .misc import DisconnectError
from .packet import Byte, MPInt, String


# pylint: disable=bad-whitespace

# SSH KEX ECDH message values (also used by Curve25519)
MSG_KEX_ECDH_INIT  = 30
MSG_KEX_ECDH_REPLY = 31

# pylint: enable=bad-whitespace


class _KexCurve25519DH(Kex):
    """Handler for Curve25519 Diffie-Hellman key exchange"""

    def __init__(self, alg, conn, hash_alg):
        super().__init__(alg, conn, hash_alg)

        self._priv = Curve25519DH()
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
        """Process a curve25519 ECDH init message"""

        # pylint: disable=unused-argument

        if self._conn.is_client():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex init msg')

        self._client_pub = packet.get_string()
        packet.check_end()

        try:
            shared = self._priv.get_shared(self._client_pub)
        except AssertionError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid kex init msg') from None

        host_key, host_key_data = self._conn.get_server_host_key()

        k = int.from_bytes(shared, 'big')
        h = self._compute_hash(host_key_data, k)
        sig = host_key.sign(h)

        self._conn.send_packet(Byte(MSG_KEX_ECDH_REPLY), String(host_key_data),
                               String(self._server_pub), String(sig))

        self._conn.send_newkeys(k, h)

    def _process_reply(self, pkttype, packet):
        """Process a curve25519 ECDH reply message"""

        # pylint: disable=unused-argument

        if self._conn.is_server():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex reply msg')

        host_key_data = packet.get_string()
        self._server_pub = packet.get_string()
        sig = packet.get_string()
        packet.check_end()

        try:
            shared = self._priv.get_shared(self._server_pub)
        except AssertionError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid kex reply msg') from None

        host_key = self._conn.validate_server_host_key(host_key_data)

        k = int.from_bytes(shared, 'big')
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
    from .crypto import Curve25519DH
except ImportError:
    pass
else:
    register_kex_alg(b'curve25519-sha256@libssh.org', _KexCurve25519DH, sha256)
