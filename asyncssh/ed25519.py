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

"""Ed25519 public key encryption handler"""

from .logging import *
from .packet import *
from .public_key import *


class _Ed25519Key(SSHKey):
    """Handler for Ed25519 public key encryption"""

    algorithm = b'ssh-ed25519'

    def __init__(self, vk, sk):
        self._vk = vk
        self._sk = sk

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self._vk == other._vk and self._sk == other._sk)

    def __hash__(self):
        return hash(self._vk)

    @classmethod
    def make_private(cls, vk, sk):
        return cls(vk, sk)

    @classmethod
    def make_public(cls, vk):
        return cls(vk, None)

    @classmethod
    def decode_ssh_private(cls, packet):
        vk = packet.get_string()
        sk = packet.get_string()

        return vk, sk

    @classmethod
    def decode_ssh_public(cls, packet):
        vk = packet.get_string()

        return (vk,)

    def encode_ssh_private(self):
        if self._sk is None:
            raise KeyExportError('Key is not private')

        return b''.join((String(self.algorithm), String(self._vk),
                         String(self._sk)))

    def encode_ssh_public(self):
        return b''.join((String(self.algorithm), String(self._vk)))

    def sign(self, data):
        if self._sk is None:
            raise ValueError('Private key needed for signing')

        sig = libnacl.crypto_sign(data, self._sk)
        return b''.join((String(self.algorithm), String(sig[:-len(data)])))

    def verify(self, data, sig):
        packet = SSHPacket(sig)

        if packet.get_string() != self.algorithm:
            return False

        sig = packet.get_string()
        packet.check_end()

        try:
            return libnacl.crypto_sign_open(sig + data, self._vk) == data
        except ValueError:
            return False


try:
    import libnacl
except ImportError:
    pass
else:
    register_public_key_alg(b'ssh-ed25519', _Ed25519Key)

    register_certificate_alg(b'ssh-ed25519-cert-v01@openssh.com',
                             _Ed25519Key, SSHCertificateV01)
