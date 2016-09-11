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

"""SSH Diffie-Hellman key exchange handlers"""

from hashlib import sha1, sha256, sha512

from .constants import DISC_KEY_EXCHANGE_FAILED, DISC_PROTOCOL_ERROR
from .kex import Kex, register_kex_alg
from .misc import DisconnectError, randrange
from .packet import Byte, MPInt, String, UInt32


# pylint: disable=bad-whitespace,line-too-long

# SSH KEX DH message values
MSG_KEXDH_INIT  = 30
MSG_KEXDH_REPLY = 31

# SSH KEX DH group exchange message values
MSG_KEX_DH_GEX_REQUEST_OLD = 30
MSG_KEX_DH_GEX_GROUP       = 31
MSG_KEX_DH_GEX_INIT        = 32
MSG_KEX_DH_GEX_REPLY       = 33
MSG_KEX_DH_GEX_REQUEST     = 34

# SSH KEX group exchange key sizes
KEX_DH_GEX_MIN_SIZE        = 1024
KEX_DH_GEX_PREFERRED_SIZE  = 2048
KEX_DH_GEX_MAX_SIZE        = 8192

# SSH Diffie-Hellman group 1 parameters
_group1_g = 2
_group1_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff

# SSH Diffie-Hellman group 14 parameters
_group14_g = 2
_group14_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff

# SSH Diffie-Hellman group 16 parameters
_group16_g = 2
_group16_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff

# SSH Diffie-Hellman group 18 parameters
_group18_g = 2
_group18_p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e438777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8afc47ed2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652de3fdb8befc848ad922222e04a4037c0713eb57a81a23f0c73473fc646cea306b4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a062b3cf5b3a278a66d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31cc50846851df9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f924009438b481c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa9e3050e2765694dfc81f56e880b96e7160c980dd98edd3dfffffffffffffffff

# pylint: enable=bad-whitespace,line-too-long

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _KexDHBase(Kex):
    """Abstract base class for Diffie-Hellman key exchange"""

    _replytype = None

    def __init__(self, alg, conn, hash_alg):
        super().__init__(alg, conn, hash_alg)

        self._g = None
        self._p = None
        self._q = None
        self._x = None
        self._e = None
        self._f = None

    def _compute_hash(self, host_key_data, k):
        """Abstract method for computing connection hash"""

        # Provided by subclass
        raise NotImplementedError

    def _send_init(self, pkttype):
        """Send a DH init message"""

        self._x = randrange(2, self._q)
        self._e = pow(self._g, self._x, self._p)

        self._conn.send_packet(Byte(pkttype), MPInt(self._e))

    def _send_reply(self, pkttype):
        """Send a DH reply message"""

        if not 1 <= self._e < self._p:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Kex DH e out of range')

        y = randrange(2, self._q)
        self._f = pow(self._g, y, self._p)

        k = pow(self._e, y, self._p)

        if k < 1: # pragma: no cover, shouldn't be possible with valid p
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Kex DH k out of range')

        host_key = self._conn.get_server_host_key()

        h = self._compute_hash(host_key.public_data, k)
        sig = host_key.sign(h)

        self._conn.send_packet(Byte(pkttype), String(host_key.public_data),
                               MPInt(self._f), String(sig))

        self._conn.send_newkeys(k, h)

    def _verify_reply(self, host_key_data, sig):
        """Verify a DH reply message"""

        if not 1 <= self._f < self._p:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Kex DH f out of range')

        host_key = self._conn.validate_server_host_key(host_key_data)

        k = pow(self._f, self._x, self._p)

        if k < 1: # pragma: no cover, shouldn't be possible with valid p
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Kex DH k out of range')

        h = self._compute_hash(host_key_data, k)
        if not host_key.verify(h, sig):
            raise DisconnectError(DISC_KEY_EXCHANGE_FAILED,
                                  'Key exchange hash mismatch')

        self._conn.send_newkeys(k, h)

    def _process_init(self, pkttype, packet):
        """Process a DH init message"""

        # pylint: disable=unused-argument

        if self._conn.is_client() or not self._p:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex init msg')

        self._e = packet.get_mpint()
        packet.check_end()

        self._send_reply(self._replytype)

    def _process_reply(self, pkttype, packet):
        """Process a DH reply message"""

        # pylint: disable=unused-argument

        if self._conn.is_server() or not self._p:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex reply msg')

        host_key_data = packet.get_string()
        self._f = packet.get_mpint()
        sig = packet.get_string()
        packet.check_end()

        self._verify_reply(host_key_data, sig)


class _KexDH(_KexDHBase):
    """Handler for Diffie-Hellman key exchange"""

    _replytype = MSG_KEXDH_REPLY

    def __init__(self, alg, conn, hash_alg, g, p):
        super().__init__(alg, conn, hash_alg)

        self._g = g
        self._p = p
        self._q = (p - 1) // 2

        if conn.is_client():
            self._send_init(MSG_KEXDH_INIT)

    def _compute_hash(self, host_key_data, k):
        """Compute a hash of key information associated with the connection"""

        hash_obj = self._hash_alg()
        hash_obj.update(self._conn.get_hash_prefix())
        hash_obj.update(String(host_key_data))
        hash_obj.update(MPInt(self._e))
        hash_obj.update(MPInt(self._f))
        hash_obj.update(MPInt(k))
        return hash_obj.digest()

    packet_handlers = {
        MSG_KEXDH_INIT:     _KexDHBase._process_init,
        MSG_KEXDH_REPLY:    _KexDHBase._process_reply
    }


class _KexDHGex(_KexDHBase):
    """Handler for Diffie-Hellman group exchange"""

    _replytype = MSG_KEX_DH_GEX_REPLY

    def __init__(self, alg, conn, hash_alg, old=False, preferred_size=0):
        super().__init__(alg, conn, hash_alg)

        if conn.is_client():
            if old:
                # Send old request message for unit test
                self._request = UInt32(preferred_size)
                conn.send_packet(Byte(MSG_KEX_DH_GEX_REQUEST_OLD),
                                 self._request)
            else:
                self._request = (UInt32(KEX_DH_GEX_MIN_SIZE) +
                                 UInt32(KEX_DH_GEX_PREFERRED_SIZE) +
                                 UInt32(KEX_DH_GEX_MAX_SIZE))
                conn.send_packet(Byte(MSG_KEX_DH_GEX_REQUEST), self._request)

    def _compute_hash(self, host_key_data, k):
        """Compute a hash of key information associated with the connection"""

        hash_obj = self._hash_alg()
        hash_obj.update(self._conn.get_hash_prefix())
        hash_obj.update(String(host_key_data))
        hash_obj.update(self._request)
        hash_obj.update(MPInt(self._p))
        hash_obj.update(MPInt(self._g))
        hash_obj.update(MPInt(self._e))
        hash_obj.update(MPInt(self._f))
        hash_obj.update(MPInt(k))
        return hash_obj.digest()

    def _process_request(self, pkttype, packet):
        """Process a DH gex request message"""

        if self._conn.is_client():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex request msg')

        self._request = packet.get_remaining_payload()

        # The min/max sizes will be needed to fully implement DHGex
        # pylint: disable=unused-variable

        if pkttype == MSG_KEX_DH_GEX_REQUEST_OLD:
            min_size = KEX_DH_GEX_MIN_SIZE
            requested_size = packet.get_uint32()
            max_size = KEX_DH_GEX_MAX_SIZE
        else:
            min_size = packet.get_uint32()
            requested_size = packet.get_uint32()
            max_size = packet.get_uint32()

        packet.check_end()

        # TODO: For now, just select between group1 and group14 primes
        #       based on the requested group size

        if requested_size <= 1024:
            self._p, self._g = _group1_p, _group1_g
        else:
            self._p, self._g = _group14_p, _group14_g

        self._q = (self._p - 1) // 2

        self._conn.send_packet(Byte(MSG_KEX_DH_GEX_GROUP), MPInt(self._p),
                               MPInt(self._g))

    def _process_group(self, pkttype, packet):
        """Process a DH gex group message"""

        # pylint: disable=unused-argument

        if self._conn.is_server():
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Unexpected kex group msg')

        self._p = packet.get_mpint()
        self._g = packet.get_mpint()
        packet.check_end()

        self._q = (self._p - 1) // 2

        self._send_init(MSG_KEX_DH_GEX_INIT)

    packet_handlers = {
        MSG_KEX_DH_GEX_REQUEST_OLD: _process_request,
        MSG_KEX_DH_GEX_GROUP:       _process_group,
        MSG_KEX_DH_GEX_INIT:        _KexDHBase._process_init,
        MSG_KEX_DH_GEX_REPLY:       _KexDHBase._process_reply,
        MSG_KEX_DH_GEX_REQUEST:     _process_request
    }


# pylint: disable=bad-whitespace

register_kex_alg(b'diffie-hellman-group-exchange-sha256', _KexDHGex, sha256)
register_kex_alg(b'diffie-hellman-group16-sha512',        _KexDH,    sha512,
                 _group16_g, _group16_p)
register_kex_alg(b'diffie-hellman-group18-sha512',        _KexDH,    sha512,
                 _group18_g, _group18_p)
register_kex_alg(b'diffie-hellman-group14-sha256',        _KexDH,    sha256,
                 _group14_g, _group14_p)
register_kex_alg(b'diffie-hellman-group-exchange-sha1',   _KexDHGex, sha1)
register_kex_alg(b'diffie-hellman-group14-sha1',          _KexDH,    sha1,
                 _group14_g, _group14_p)
register_kex_alg(b'diffie-hellman-group1-sha1',           _KexDH,    sha1,
                 _group1_g,  _group1_p)
