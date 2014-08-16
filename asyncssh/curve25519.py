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

"""Curve25519 public key encryption handler"""

from hashlib import sha256

from .kex import *
from .misc import *
from .packet import *
from .public_key import *

# SSH KEX ECDH message values (also used by Curve25519)
MSG_KEX_ECDH_INIT  = 30
MSG_KEX_ECDH_REPLY = 31


class _KexCurve25519DH(Kex):
    """Handler for Curve25519 Diffie-Hellman key exchange"""

    def __init__(self, alg, conn, hash):
        Kex.__init__(self, alg, conn, hash)

        self._priv = curve25519.Private()
        pub = self._priv.get_public().serialize()

        if conn.is_client():
            self._client_pub = pub
            self._conn._send_packet(Byte(MSG_KEX_ECDH_INIT), String(pub))
        else:
            self._server_pub = pub

    def _compute_hash(self, server_host_key, k):
        hash = self._hash()
        hash.update(String(self._conn._client_version))
        hash.update(String(self._conn._server_version))
        hash.update(String(self._conn._client_kexinit))
        hash.update(String(self._conn._server_kexinit))
        hash.update(String(server_host_key.encode_ssh_public()))
        hash.update(String(self._client_pub))
        hash.update(String(self._server_pub))
        hash.update(MPInt(k))
        return hash.digest()

    def _process_init(self, pkttype, packet):
        if self._conn.is_client():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex init msg')

        self._client_pub = packet.get_string()
        packet.check_end()

        try:
            pub = curve25519.Public(self._client_pub)
        except AssertionError:
                raise DisconnectError(DISC_PROTOCOL_ERROR,
                                      'Invalid kex init msg')

        server_host_key = self._conn._server_host_key

        shared = self._priv.get_shared_key(pub, hashfunc=lambda x: x)
        k = int.from_bytes(shared, 'big')
        h = self._compute_hash(server_host_key, k)
        sig = server_host_key.sign(h)

        self._conn._send_packet(Byte(MSG_KEX_ECDH_REPLY),
                                String(server_host_key.encode_ssh_public()),
                                String(self._server_pub), String(sig))

        self._conn._send_newkeys(k, h)

    def _process_reply(self, pkttype, packet):
        if self._conn.is_server():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex reply msg')

        server_host_key = packet.get_string()
        self._server_pub = packet.get_string()
        sig = packet.get_string()
        packet.check_end()

        try:
            pub = curve25519.Public(self._server_pub)
        except AssertionError:
                raise DisconnectError(DISC_PROTOCOL_ERROR,
                                      'Invalid kex reply msg')

        server_host_key = decode_ssh_public_key(server_host_key)

        if not self._conn._verify_server_host_key(server_host_key):
            raise DisconnectError(DISC_HOST_KEY_NOT_VERIFYABLE,
                                  'Host key verification failed')

        shared = self._priv.get_shared_key(pub, hashfunc=lambda x: x)
        k = int.from_bytes(shared, 'big')
        h = self._compute_hash(server_host_key, k)
        if not server_host_key.verify(h, sig):
            raise DisconnectError(DISC_KEY_EXCHANGE_FAILED,
                                  'Key exchange hash mismatch')

        self._conn._send_newkeys(k, h)

    packet_handlers = {
        MSG_KEX_ECDH_INIT:  _process_init,
        MSG_KEX_ECDH_REPLY: _process_reply
    }


try:
    import curve25519
    register_kex_alg(b'curve25519-sha256@libssh.org', _KexCurve25519DH, sha256)
except ImportError:
    pass
