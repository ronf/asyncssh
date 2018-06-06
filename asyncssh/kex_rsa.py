# Copyright (c) 2018 by Ron Frederick <ronf@timeheart.net>.
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

"""RSA key exchange handler"""

from hashlib import sha1, sha256

import asyncssh

from .constants import DISC_KEY_EXCHANGE_FAILED, DISC_PROTOCOL_ERROR
from .kex import Kex, register_kex_alg
from .misc import DisconnectError, get_symbol_names, randrange
from .packet import MPInt, String, SSHPacket
from .public_key import decode_ssh_public_key

# pylint: disable=bad-whitespace

# SSH KEXRSA message values
MSG_KEXRSA_PUBKEY  = 30
MSG_KEXRSA_SECRET  = 31
MSG_KEXRSA_DONE    = 32

# pylint: enable=bad-whitespace

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _KexRSA(Kex):
    """Handler for RSA key exchange"""

    _handler_names = get_symbol_names(globals(), 'MSG_KEXRSA')

    def __init__(self, alg, conn, hash_alg, key_size, hash_size):
        super().__init__(alg, conn, hash_alg)

        self._key_size = key_size
        self._k_limit = 1 << (key_size - 2*hash_size - 49)

        self._host_key_data = None

        self._trans_key = None
        self._trans_key_data = None

        self._k = None
        self._encrypted_k = None

    def start(self):
        """Start RSA key exchange"""

        if self._conn.is_server():
            host_key = self._conn.get_server_host_key()
            self._host_key_data = host_key.public_data

            self._trans_key = asyncssh.generate_private_key('ssh-rsa',
                                                            self._key_size)
            self._trans_key_data = self._trans_key.get_ssh_public_key()

            self.send_packet(MSG_KEXRSA_PUBKEY, String(self._host_key_data),
                             String(self._trans_key_data))

    def _compute_hash(self):
        """Compute a hash of key information associated with the connection"""

        hash_obj = self._hash_alg()
        hash_obj.update(self._conn.get_hash_prefix())
        hash_obj.update(String(self._host_key_data))
        hash_obj.update(String(self._trans_key_data))
        hash_obj.update(String(self._encrypted_k))
        hash_obj.update(MPInt(self._k))
        return hash_obj.digest()

    def _process_pubkey(self, pkttype, pktid, packet):
        """Process a KEXRSA pubkey message"""

        # pylint: disable=unused-argument

        if self._conn.is_server():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected KEXRSA pubkey msg')

        self._host_key_data = packet.get_string()
        self._trans_key_data = packet.get_string()
        packet.check_end()

        try:
            trans_key = decode_ssh_public_key(self._trans_key_data)
        except asyncssh.KeyImportError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid KEXRSA pubkey msg') from None

        self._k = randrange(self._k_limit)
        self._encrypted_k = trans_key.encrypt(MPInt(self._k), self.algorithm)

        self.send_packet(MSG_KEXRSA_SECRET, String(self._encrypted_k))

    def _process_secret(self, pkttype, pktid, packet):
        """Process a KEXRSA secret message"""

        # pylint: disable=unused-argument

        if self._conn.is_client():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected KEXRSA secret msg')

        self._encrypted_k = packet.get_string()
        packet.check_end()

        decrypted_k = self._trans_key.decrypt(self._encrypted_k, self.algorithm)
        if not decrypted_k:
            raise DisconnectError(DISC_KEY_EXCHANGE_FAILED,
                                  'Key exchange decryption failed')

        packet = SSHPacket(decrypted_k)
        self._k = packet.get_mpint()
        packet.check_end()

        host_key = self._conn.get_server_host_key()

        h = self._compute_hash()
        sig = host_key.sign(h)

        self.send_packet(MSG_KEXRSA_DONE, String(sig))

        self._conn.send_newkeys(self._k, h)

    def _process_done(self, pkttype, pktid, packet):
        """Process a KEXRSA done message"""

        # pylint: disable=unused-argument

        if self._conn.is_server():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected KEXRSA done msg')

        sig = packet.get_string()
        packet.check_end()

        host_key = self._conn.validate_server_host_key(self._host_key_data)

        h = self._compute_hash()
        if not host_key.verify(h, sig):
            raise DisconnectError(DISC_KEY_EXCHANGE_FAILED,
                                  'Key exchange hash mismatch')

        self._conn.send_newkeys(self._k, h)

    _packet_handlers = {
        MSG_KEXRSA_PUBKEY: _process_pubkey,
        MSG_KEXRSA_SECRET: _process_secret,
        MSG_KEXRSA_DONE:   _process_done
    }


# pylint: disable=bad-whitespace

for _name, _hash_alg, _key_size, _hash_size  in (
        (b'rsa2048-sha256', sha256, 2048, 256),
        (b'rsa1024-sha1',   sha1,   1024, 160)):
    register_kex_alg(_name, _KexRSA, _hash_alg, _key_size, _hash_size)
