# Copyright (c) 2015-2017 by Ron Frederick <ronf@timeheart.net>.
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

from .packet import String
from .public_key import SSHKey, SSHOpenSSHCertificateV01, KeyExportError
from .public_key import register_public_key_alg, register_certificate_alg

# Short variable names are used here, matching names in the spec
# pylint: disable=invalid-name


class _Ed25519Key(SSHKey):
    """Handler for Ed25519 public key encryption"""

    algorithm = b'ssh-ed25519'
    sig_algorithms = (algorithm,)
    all_sig_algorithms = set(sig_algorithms)

    def __init__(self, vk, sk):
        super().__init__()

        self._vk = vk
        self._sk = sk

    def __eq__(self, other):
        # This isn't protected access - both objects are _Ed25519Key instances
        # pylint: disable=protected-access

        return (isinstance(other, type(self)) and
                self._vk == other._vk and self._sk == other._sk)

    def __hash__(self):
        return hash(self._vk)

    @classmethod
    def generate(cls, algorithm):
        """Generate a new Ed25519 private key"""

        # pylint: disable=unused-argument

        return cls(*libnacl.crypto_sign_keypair())

    @classmethod
    def make_private(cls, vk, sk):
        """Construct an Ed25519 private key"""

        return cls(vk, sk)

    @classmethod
    def make_public(cls, vk):
        """Construct an Ed25519 public key"""

        return cls(vk, None)

    @classmethod
    def decode_ssh_private(cls, packet):
        """Decode an SSH format Ed25519 private key"""

        vk = packet.get_string()
        sk = packet.get_string()

        return vk, sk

    @classmethod
    def decode_ssh_public(cls, packet):
        """Decode an SSH format Ed25519 public key"""

        vk = packet.get_string()

        return (vk,)

    def encode_ssh_private(self):
        """Encode an SSH format Ed25519 private key"""

        if self._sk is None:
            raise KeyExportError('Key is not private')

        return b''.join((String(self._vk), String(self._sk)))

    def encode_ssh_public(self):
        """Encode an SSH format Ed25519 public key"""

        return String(self._vk)

    def encode_agent_cert_private(self):
        """Encode Ed25519 certificate private key data for agent"""

        return self.encode_ssh_private()

    def sign_der(self, data, sig_algorithm):
        """Return a DER-encoded signature of the specified data"""

        # pylint: disable=unused-argument

        if self._sk is None:
            raise ValueError('Private key needed for signing')

        sig = libnacl.crypto_sign(data, self._sk)
        return sig[:-len(data)]

    def verify_der(self, data, sig_algorithm, sig):
        """Verify a DER-encoded signature of the specified data"""

        # pylint: disable=unused-argument

        try:
            return libnacl.crypto_sign_open(sig + data, self._vk) == data
        except ValueError:
            return False

    def sign_ssh(self, data, sig_algorithm):
        """Return an SSH-encoded signature of the specified data"""

        return self.sign_der(data, sig_algorithm)

    def verify_ssh(self, data, sig_algorithm, sig):
        """Verify an SSH-encoded signature of the specified data"""

        return self.verify_der(data, sig_algorithm, sig)


try:
    # pylint: disable=wrong-import-position,wrong-import-order
    import libnacl
except (ImportError, OSError): # pragma: no cover
    pass
else:
    register_public_key_alg(b'ssh-ed25519', _Ed25519Key)

    register_certificate_alg(1, b'ssh-ed25519',
                             b'ssh-ed25519-cert-v01@openssh.com',
                             _Ed25519Key, SSHOpenSSHCertificateV01)
