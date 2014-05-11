# Copyright (c) 2013-2014 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH asymmetric encryption handlers"""

import binascii

from .asn1 import *
from .packet import *
from .misc import *
from .pbe import *

_public_key_algs = []
_alg_map = {}
_pem_map = {}
_pkcs8_oid_map = {}

def _wrap_base64(data):
    """Break a Base64 value into multiple lines, each 64 characters wide."""

    data = binascii.b2a_base64(data)[:-1]
    return b'\n'.join(data[i:i+64] for i in range(0, len(data), 64)) + b'\n'


class KeyImportError(ValueError):
    """Key import error

       This exception is raised by key import functions when the
       data provided cannot be imported as a valid key.

    """


class KeyExportError(ValueError):
    """Key export error

       This exception is raised by key export functions when the
       requested format is unknown or encryption is requested for a
       format which doesn't support it.

    """


class SSHKey:
    """Parent class which holds an asymmetric encryption key"""

    def export_private_key(self, format, passphrase=None, cipher='aes256',
                           hash='sha256', pbe_version=2):
        """Export a private key in the requested format

           This function returns this object's private key encoded in the
           requested format. If a passphrase is specified, the key will
           be exported in encrypted form.

           Available formats include:

               pkcs1-der, pkcs1-pem, pkcs8-der, pkcs8-pem

           Encryption is supported in pkcs1-pem, pkcs8-der, and pkcs8-pem
           formats. For pkcs1-pem, only the cipher can be specified. The
           hash and PBE version are ignored.

           Available ciphers include:

               aes128, aes192, aes256, bf, cast128, des, des2, des3,
               rc2-40, rc2-64, rc2-128, rc4-40, rc4-128

           Available hashes include:

               md5, sha1, sha256, sha384, sha512, sha512-224, sha512-256

           Available PBE versions include 1 for PBES1 and 2 for PBES2.

           Not all combinations of cipher, hash, and version are supported.

           The default cipher is aes256. In the pkcs8 formats, the default
           hash is sha256 and default version is PBES2.

           :param string format:
               The format to export the key in.
           :param string passphrase: (optional)
               A passphrase to encrypt the private key with.
           :param string cipher: (optional)
               The cipher to use for private key encryption.
           :param string hash: (optional)
               The hash to use for private key encryption.
           :param integer pbe_version: (optional)
               The PBE version to use for private key encryption.

        """

        if format in ('pkcs1-der', 'pkcs1-pem'):
            data = der_encode(self.encode_pkcs1_private())

            if passphrase is not None:
                if format == 'pkcs1-der':
                    raise KeyExportError('PKCS#1 DER format does not support '
                                         'private key encryption')

                alg, iv, data = pkcs1_encrypt(data, cipher, passphrase)
                headers = (b'Proc-Type: 4,ENCRYPTED\n' +
                           b'DEK-Info: ' + alg + b',' +
                           binascii.b2a_hex(iv).upper() + b'\n\n')
            else:
                headers = b''

            if format == 'pkcs1-pem':
                type = self.pem_name + b' PRIVATE KEY'
                data = (b'-----BEGIN ' + type + b'-----\n' +
                        headers + _wrap_base64(data) +
                        b'-----END ' + type + b'-----\n')

            return data
        elif format in ('pkcs8-der', 'pkcs8-pem'):
            alg_params, data = self.encode_pkcs8_private()

            data = der_encode((0, (self.pkcs8_oid, alg_params), data))

            if passphrase is not None:
                data = pkcs8_encrypt(data, cipher, hash,
                                     pbe_version, passphrase)

            if format == 'pkcs8-pem':
                if passphrase is not None:
                    type = b'ENCRYPTED PRIVATE KEY'
                else:
                    type = b'PRIVATE KEY'

                data = (b'-----BEGIN ' + type + b'-----\n' +
                        _wrap_base64(data) +
                        b'-----END ' + type + b'-----\n')

            return data
        else:
            raise KeyExportError('Unknown export format')

    def export_public_key(self, format):
        """Export a public key in the requested format

           This function returns this object's public key encoded in the
           requested format. Available formats include:

               pkcs1-der, pkcs1-pem, pkcs8-der, pkcs8-pem, openssh, rfc4716

           :param string format:
               The format to export the key in.

        """

        if format in ('pkcs1-der', 'pkcs1-pem'):
            data = der_encode(self.encode_pkcs1_public())

            if format == 'pkcs1-pem':
                type = self.pem_name + b' PUBLIC KEY'
                data = (b'-----BEGIN ' + type + b'-----\n' +
                        _wrap_base64(data) +
                        b'-----END ' + type + b'-----\n')

            return data
        elif format in ('pkcs8-der', 'pkcs8-pem'):
            alg_params, data = self.encode_pkcs8_public()

            data = der_encode(((self.pkcs8_oid, alg_params), BitString(data)))

            if format == 'pkcs8-pem':
                data = (b'-----BEGIN PUBLIC KEY-----\n' +
                        _wrap_base64(data) +
                        b'-----END PUBLIC KEY-----\n')

            return data
        elif format == 'openssh':
            data = self.encode_ssh_public()

            return self.algorithm + b' ' + binascii.b2a_base64(data)
        elif format == 'rfc4716':
            return (b'---- BEGIN SSH2 PUBLIC KEY ----\n' +
                    _wrap_base64(self.encode_ssh_public()) +
                    b'---- END SSH2 PUBLIC KEY ----\n')
        else:
            raise KeyExportError('Unknown export format')

    def write_private_key(self, filename, *args, **kwargs):
        """Write a private key to a file in the requested format

           This function is a simple wrapper around export_private_key
           which writes the exported key data to a file.

           :param string filename:
               The filename to write the private key to.
           :param \*args,\ \*\*kwargs:
               Additional arguments to pass through to
               :func:`export_private_key`.

        """

        with open(filename, 'wb') as f:
            f.write(self.export_private_key(*args, **kwargs))

    def write_public_key(self, filename, *args, **kwargs):
        """Write a public key to a file in the requested format

           This function is a simple wrapper around export_public_key
           which writes the exported key data to a file.

           :param string filename:
               The filename to write the public key to.
           :param \*args,\ \*\*kwargs:
               Additional arguments to pass through to
               :func:`export_public_key`.

        """

        with open(filename, 'wb') as f:
            f.write(self.export_public_key(*args, **kwargs))


def _decode_pkcs8_private(key_data):
    """Decode a PKCS#8 format private key"""

    if (isinstance(key_data, tuple) and len(key_data) == 3 and
        key_data[0] == 0 and isinstance(key_data[1], tuple) and
        len(key_data[1]) == 2 and isinstance(key_data[2], bytes)):
        alg, alg_params = key_data[1]

        if alg in _pkcs8_oid_map:
            return _pkcs8_oid_map[alg].decode_pkcs8_private(alg_params,
                                                            key_data[2])
        else:
            raise KeyImportError('Unknown PKCS#8 algorithm')
    else:
        raise KeyImportError('Invalid PKCS#8 private key')

def _decode_pkcs8_public(key_data):
    """Decode a PKCS#8 format public key"""

    if (isinstance(key_data, tuple) and len(key_data) == 2 and
        isinstance(key_data[0], tuple) and len(key_data[0]) == 2 and
        isinstance(key_data[1], BitString) and key_data[1].unused == 0):
        alg, alg_params = key_data[0]

        if alg in _pkcs8_oid_map:
            return _pkcs8_oid_map[alg].decode_pkcs8_public(alg_params,
                                                           key_data[1].value)
        else:
            raise KeyImportError('Unknown PKCS#8 algorithm')
    else:
        raise KeyImportError('Invalid PKCS#8 public key')

def _decode_der_private(data, passphrase):
    """Decode a DER format private key"""

    try:
        key_data, end = der_decode(data, partial_ok=True)
    except ASN1DecodeError:
        raise KeyImportError('Invalid DER private key')

    # First, if there's a passphrase, try to decrypt PKCS#8
    if passphrase is not None:
        try:
            key_data = pkcs8_decrypt(key_data, passphrase)
        except KeyEncryptionError:
            # Decryption failed - try decoding it as unencrypted
            pass

    # Then, try to decode PKCS#8
    try:
        return _decode_pkcs8_private(key_data), end
    except KeyImportError:
        # PKCS#8 failed - try PKCS#1 instead
        pass

    # If that fails, try each of the possible PKCS#1 encodings
    for pem_name in _pem_map:
        try:
            return _pem_map[pem_name].decode_pkcs1_private(key_data), end
        except KeyImportError:
            # Try the next PKCS#1 encoding
            pass

    raise KeyImportError('Invalid DER private key')

def _decode_der_public(data):
    """Decode a DER format public key"""

    try:
        key_data, end = der_decode(data, partial_ok=True)
    except ASN1DecodeError:
        raise KeyImportError('Invalid DER public key')

    # First, try to decode PKCS#8
    try:
        return _decode_pkcs8_public(key_data), end
    except KeyImportError:
        # PKCS#8 failed - try PKCS#1 instead
        pass

    # If that fails, try each of the possible PKCS#1 encodings
    for pem_name in _pem_map:
        try:
            return _pem_map[pem_name].decode_pkcs1_public(key_data), end
        except KeyImportError:
            # Try the next PKCS#1 encoding
            pass

    raise KeyImportError('Invalid DER public key')

def _decode_pem(lines, type):
    """Decode a PEM format key"""

    start = None
    for i, line in enumerate(lines):
        line = line.strip()
        if (line.startswith(b'-----BEGIN ') and
            line.endswith(b' ' + type + b'-----')):
            start = i+1
            break

    if not start:
        raise KeyImportError('Missing PEM header of type ' + type.decode())

    pem_name = line[11:-(6+len(type))].strip()
    if pem_name:
        type = pem_name + b' ' + type

    headers = {}
    for start, line in enumerate(lines[start:], start):
        line = line.strip()
        if b':' in line:
            hdr, value = line.split(b':')
            headers[hdr.strip()] = value.strip()
        else:
            break

    end = None
    tail = b'-----END ' + type + b'-----'
    for i, line in enumerate(lines[start:], start):
        line = line.strip()
        if line == tail:
            end = i
            break

    if not end:
        raise KeyImportError('Missing PEM footer')

    try:
        data = binascii.a2b_base64(b''.join(lines[start:end]))
    except binascii.Error:
        raise KeyImportError('Invalid PEM data')

    return pem_name, headers, data, end+1

def _decode_pem_private(lines, passphrase):
    """Decode a PEM format private key"""

    pem_name, headers, data, end = _decode_pem(lines, b'PRIVATE KEY')

    if headers.get(b'Proc-Type') == b'4,ENCRYPTED':
        if passphrase is None:
            raise KeyImportError('Passphrase must be specified to import '
                                 'encrypted private keys')

        dek_info = headers.get(b'DEK-Info').split(b',')
        if len(dek_info) != 2:
            raise KeyImportError('Invalid PEM encryption params')

        alg, iv = dek_info
        try:
            iv = binascii.a2b_hex(iv)
        except binascii.Error:
            raise KeyImportError('Invalid PEM encryption params')

        try:
            data = pkcs1_decrypt(data, alg, iv, passphrase)
        except KeyEncryptionError:
            raise KeyImportError('Unable to decrypt PKCS#1 private key')

    try:
        key_data = der_decode(data)
    except ASN1DecodeError:
        raise KeyImportError('Invalid PEM private key')

    if pem_name == b'ENCRYPTED':
        if passphrase is None:
            raise KeyImportError('Passphrase must be specified to import '
                                 'encrypted private keys')

        pem_name = b''

        try:
            key_data = pkcs8_decrypt(key_data, passphrase)
        except KeyEncryptionError:
            raise KeyImportError('Unable to decrypt PKCS#8 private key')

    if not pem_name:
        return _decode_pkcs8_private(key_data), end
    elif pem_name in _pem_map:
        return _pem_map[pem_name].decode_pkcs1_private(key_data), end
    else:
        raise KeyImportError('Unknown PEM key type: %s' % pem_name.decode())

def _decode_pem_public(lines):
    """Decode a PEM format public key"""

    pem_name, headers, data, end = _decode_pem(lines, b'PUBLIC KEY')

    try:
        key_data = der_decode(data)
    except ASN1DecodeError:
        raise KeyImportError('Invalid PEM public key')

    if not pem_name:
        return _decode_pkcs8_public(key_data), end
    elif pem_name in _pem_map:
        return _pem_map[pem_name].decode_pkcs1_public(key_data), end
    else:
        raise KeyImportError('Unknown PEM key type: %s' % pem_name.decode())

def _decode_openssh(line):
    """Decode an OpenSSH format public key"""

    line = line.split()
    if len(line) < 2:
        raise KeyImportError('Invalid OpenSSH public key')

    try:
        data = binascii.a2b_base64(line[1])
    except binascii.Error:
        raise KeyImportError('Invalid OpenSSH public key')

    return decode_ssh_public_key(data)

def _decode_rfc4716(lines):
    """Decode an RFC 4716 format public key"""

    start = None
    for i, line in enumerate(lines):
        line = line.strip()
        if line == b'---- BEGIN SSH2 PUBLIC KEY ----':
            start = i+1
            break

    if not start:
        raise KeyImportError('Missing RFC 4716 header')

    continuation = False
    for start, line in enumerate(lines[start:], start):
        line = line.strip()
        if continuation or b':' in line:
            continuation = line.endswith(b'\\')
        else:
            break

    end = None
    for i, line in enumerate(lines[start:], start):
        line = line.strip()
        if line == b'---- END SSH2 PUBLIC KEY ----':
            end = i
            break

    if not end:
        raise KeyImportError('Missing RFC 4716 footer')

    try:
        data = binascii.a2b_base64(b''.join(lines[start:end]))
    except binascii.Error:
        raise KeyImportError('Invalid RFC 4716 public key')

    return decode_ssh_public_key(data), end+1

def register_public_key_alg(handler):
    """Register a new public key algorithm"""

    if hasattr(handler, 'algorithms'):
        algs = handler.algorithms
    else:
        algs = (handler.algorithm,)

    for alg in algs:
        _public_key_algs.append(alg)
        _alg_map[alg] = handler

    _pem_map[handler.pem_name] = handler

    _pkcs8_oid_map[handler.pkcs8_oid] = handler

def get_public_key_algs():
    """Return supported public key algorithms"""

    return _public_key_algs

def decode_ssh_public_key(data):
    """Decode a packetized SSH public key"""

    try:
        packet = SSHPacket(data)

        alg = packet.get_string()
        if alg not in _alg_map:
            raise KeyImportError('Unknown SSH key algorithm: %s' % alg.decode())

        return _alg_map[alg].decode_ssh_public(packet)
    except DisconnectError:
        # Fall through and return a key import error
        pass

    raise KeyImportError('Invalid SSH public key')

def import_private_key(data, passphrase=None):
    """Import a private key

       This function imports a private key encoded in PKCS#1 or PKCS#8 DER
       or PEM format. Encrypted private keys can be imported by specifying
       the passphrase needed to decrypt them.

       :param bytes data:
           The data to import.
       :param string passphrase: (optional)
           The passphrase to use to decrypt the key.

       :returns: An :class:`SSHKey` private key

    """

    stripped_key = data.lstrip()
    if stripped_key.startswith(b'-----'):
        key, _ = _decode_pem_private(stripped_key.splitlines(), passphrase)
    else:
        key, _ = _decode_der_private(data, passphrase)

    return key

def import_public_key(data):
    """Import a public key

       This function imports a public key encoded in OpenSSH, RFC4716, or
       PKCS#1 or PKCS#8 DER or PEM format.

       :param bytes data:
           The data to import.

       :returns: An :class:`SSHKey` public key

    """

    stripped_key = data.lstrip()
    if stripped_key.startswith(b'-----'):
        key, _ = _decode_pem_public(stripped_key.splitlines())
    elif stripped_key.startswith(b'---- '):
        key, _ = _decode_rfc4716(stripped_key.splitlines())
    elif data.startswith(b'\x30'):
        key, _ = _decode_der_public(data)
    else:
        key = _decode_openssh(stripped_key.splitlines()[0])

    return key

def read_private_key(filename, passphrase=None):
    """Read a private key from a file

       This function reads a private key from a file. See the function
       import_private_key for information about the formats supported.

       :param string filename:
           The file to read the key from.
       :param string passphrase: (optional)
           The passphrase to use to decrypt the key.

       :returns: An :class:`SSHKey` private key

    """

    with open(filename, 'rb') as f:
        return import_private_key(f.read(), passphrase)

def read_public_key(filename):
    """Read a public key from a file

       This function reads a public key from a file. See the function
       import_public_key for information about the formats supported.

       :param string filename:
           The file to read the key from.

       :returns: An :class:`SSHKey` public key

    """

    with open(filename, 'rb') as f:
        return import_public_key(f.read())

def read_private_key_list(filename, passphrase=None):
    """Read a list of private keys from a file

       This function reads a list of private keys from a file. See the
       function import_private_key for information about the formats
       supported. If any of the keys are encrypted, they must all be
       encrypted with the same passphrase.

       :param string filename:
           The file to read the keys from.
       :param string passphrase: (optional)
           The passphrase to use to decrypt the keys.

       :returns: A list of :class:`SSHKey` private keys

    """

    with open(filename, 'rb') as f:
        data = f.read()

    keys = []

    stripped_key = data.strip()
    if stripped_key.startswith(b'-----'):
        lines = stripped_key.splitlines()
        while lines:
            key, end = _decode_pem_private(lines, passphrase)
            keys.append(key)
            lines = lines[end:]
    else:
        while data:
            key, end = _decode_der_private(data, passphrase)
            keys.append(key)
            data = data[end:]

    return keys

def read_public_key_list(filename):
    """Read a list of public keys from a file

       This function reads a list of public keys from a file. See the
       function import_public_key for information about the formats
       supported.

       :param string filename:
           The file to read the keys from.

       :returns: A list of :class:`SSHKey` public keys

    """

    with open(filename, 'rb') as f:
        data = f.read()

    keys = []

    stripped_key = data.strip()
    if stripped_key.startswith(b'-----'):
        lines = stripped_key.splitlines()
        while lines:
            key, end = _decode_pem_public(lines)
            keys.append(key)
            lines = lines[end:]
    elif stripped_key.startswith(b'---- '):
        lines = stripped_key.splitlines()
        while lines:
            key, end = _decode_rfc4716(lines)
            keys.append(key)
            lines = lines[end:]
    elif data.startswith(b'\x30'):
        while data:
            key, end = _decode_der_public(data)
            keys.append(key)
            data = data[end:]
    else:
        for line in stripped_key.splitlines():
            keys.append(_decode_openssh(line))

    return keys
