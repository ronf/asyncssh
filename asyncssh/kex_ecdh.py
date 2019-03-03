# Copyright (c) 2013-2019 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Elliptic and Edwards curve Diffie-Hellman key exchange handlers"""

from hashlib import sha256, sha384, sha512

from .crypto import curve25519_available, curve448_available
from .crypto import Curve25519DH, Curve448DH, ECDH
from .kex import Kex, register_kex_alg
from .misc import KeyExchangeFailed, ProtocolError, get_symbol_names
from .packet import MPInt, String

# pylint: disable=bad-whitespace

# SSH KEX ECDH message values
MSG_KEX_ECDH_INIT  = 30
MSG_KEX_ECDH_REPLY = 31

# pylint: enable=bad-whitespace


class _KexECDH(Kex):
    """Handler for elliptic curve Diffie-Hellman key exchange"""

    _handler_names = get_symbol_names(globals(), 'MSG_KEX_ECDH_')

    def __init__(self, alg, conn, hash_alg, ecdh_class, *args):
        super().__init__(alg, conn, hash_alg)

        self._priv = ecdh_class(*args)
        pub = self._priv.get_public()

        if conn.is_client():
            self._client_pub = pub
        else:
            self._server_pub = pub

    def start(self):
        """Start ECDH key exchange"""

        if self._conn.is_client():
            self.send_packet(MSG_KEX_ECDH_INIT, String(self._client_pub))

    def _compute_hash(self, host_key_data, k):
        """Compute a hash of key information associated with the connection"""

        hash_obj = self._hash_alg()
        hash_obj.update(self._conn.get_hash_prefix())
        hash_obj.update(String(host_key_data))
        hash_obj.update(String(self._client_pub))
        hash_obj.update(String(self._server_pub))
        hash_obj.update(MPInt(k))
        return hash_obj.digest()

    def _process_init(self, pkttype, pktid, packet):
        """Process an ECDH init message"""

        # pylint: disable=unused-argument

        if self._conn.is_client():
            raise ProtocolError('Unexpected kex init msg')

        self._client_pub = packet.get_string()
        packet.check_end()

        try:
            k = self._priv.get_shared(self._client_pub)
        except ValueError:
            raise ProtocolError('Invalid kex init msg') from None

        host_key = self._conn.get_server_host_key()

        h = self._compute_hash(host_key.public_data, k)
        sig = host_key.sign(h)

        self.send_packet(MSG_KEX_ECDH_REPLY, String(host_key.public_data),
                         String(self._server_pub), String(sig))

        self._conn.send_newkeys(k, h)

    def _process_reply(self, pkttype, pktid, packet):
        """Process an ECDH reply message"""

        # pylint: disable=unused-argument

        if self._conn.is_server():
            raise ProtocolError('Unexpected kex reply msg')

        host_key_data = packet.get_string()
        self._server_pub = packet.get_string()
        sig = packet.get_string()
        packet.check_end()

        try:
            k = self._priv.get_shared(self._server_pub)
        except ValueError:
            raise ProtocolError('Invalid kex reply msg') from None

        host_key = self._conn.validate_server_host_key(host_key_data)

        h = self._compute_hash(host_key_data, k)
        if not host_key.verify(h, sig):
            raise KeyExchangeFailed('Key exchange hash mismatch')

        self._conn.send_newkeys(k, h)

    _packet_handlers = {
        MSG_KEX_ECDH_INIT:  _process_init,
        MSG_KEX_ECDH_REPLY: _process_reply
    }


if curve25519_available: # pragma: no branch
    register_kex_alg(b'curve25519-sha256', _KexECDH, sha256, Curve25519DH)
    register_kex_alg(b'curve25519-sha256@libssh.org', _KexECDH,
                     sha256, Curve25519DH)

if curve448_available: # pragma: no branch
    register_kex_alg(b'curve448-sha512', _KexECDH, sha512, Curve448DH)

for _curve_id, _hash_alg in ((b'nistp521', sha512),
                             (b'nistp384', sha384),
                             (b'nistp256', sha256),
                             (b'1.3.132.0.10', sha256)):
    register_kex_alg(b'ecdh-sha2-' + _curve_id, _KexECDH,
                     _hash_alg, ECDH, _curve_id)
