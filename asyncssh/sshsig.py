# Copyright (c) 2026 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Support for creating and validating SSH signatures"""


import binascii
import time

from hashlib import sha256, sha512
from pathlib import PurePath
from typing import List, Optional, Sequence, Union, cast

from .misc import BytesOrFilePath, FilePath, OptionsParser
from .misc import open_file, read_file, match_base64, wrap_base64, parse_time
from .packet import String, UInt32, PacketDecodeError, SSHPacket
from .pattern import WildcardPatternList
from .public_key import CERT_TYPE_ANY, KeyImportError, KeyPairListArg
from .public_key import SSHKey, SSHOpenSSHCertificate
from .public_key import decode_ssh_public_key, decode_ssh_certificate
from .public_key import import_public_key, load_keypairs


_SSHSIG_MAGIC = b'SSHSIG'
_SSHSIG_VERSION = 1

SSHAllowedSignersArg = Union[bytes, str, Sequence[str], 'SSHAllowedSigners']

_hashes = {b'sha256': sha256, b'sha512': sha512}


class SSHAllowedSignersEntry(OptionsParser):
    """An entry in an SSH allowed_senders list"""

    def __init__(self, line: str):
        super().__init__()

        try:
            principals, line = line.split(None, 1)
        except ValueError:
            raise ValueError('Missing public key in allowed_signers') from None

        self.principals = WildcardPatternList(principals)

        try:
            self.key = import_public_key(line)
            return
        except KeyImportError:
            pass

        line = self._parse_options(line)
        self.key = import_public_key(line)

    def _set_pattern(self, option: str, value: str) -> None:
        """Set an option with a wildcard pattern value"""

        self.options[option] = WildcardPatternList(value)

    def _set_time(self, option: str, value: str) -> None:
        """Set an option with a time value"""

        self.options[option] = parse_time(value)

    _handlers = {
        'namespaces':   _set_pattern,
        'valid-after':  _set_time,
        'valid-before': _set_time
    }

    def match_options(self, principal: str, namespace: str):
        """Match options in entry"""

        if not self.principals.matches(principal):
            return False

        namespaces = cast(Optional[WildcardPatternList],
                          self.options.get('namespaces'))

        if namespaces is not None and not namespaces.matches(namespace):
            return False

        now = time.time()

        valid_after = cast(Optional[int], self.options.get('valid-after'))
        if valid_after is not None and now < valid_after:
            return False

        valid_before = cast(Optional[int], self.options.get('valid-before'))
        if valid_before is not None and now >= valid_before:
            return False

        return True


class SSHAllowedSigners:
    """An OpenSSH-compatible allowed signers list"""

    def __init__(self, allowed_signers: Optional[str] = None):
        self._key_entries: List[SSHAllowedSignersEntry] = []
        self._cert_entries: List[SSHAllowedSignersEntry] = []

        if allowed_signers:
            self.load(allowed_signers)

    def load(self, allowed_signers: str) -> None:
        """Load allowed signers data into this object"""

        for line in allowed_signers.splitlines():
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            try:
                entry = SSHAllowedSignersEntry(line)
            except KeyImportError:
                continue

            if 'cert-authority' in entry.options:
                self._cert_entries.append(entry)
            else:
                self._key_entries.append(entry)

        if not self._key_entries and not self._cert_entries:
            raise ValueError('No valid entries found in '
                             'allowed_signers')

    def validate(self, key: SSHKey, principal: str, namespace: str,
                 ca: bool = False) -> bool:
        """Return whether a public key or CA is valid for SSHSIG signing"""

        for entry in self._cert_entries if ca else self._key_entries:
            if entry.key == key and entry.match_options(principal, namespace):
                return True

        return False


def _signed_data(data: BytesOrFilePath, is_hashed: bool,
                 hash_name: bytes, namespace: str) -> bytes:
    """Return the data to be signed/verified"""

    try:
        hash_alg = _hashes[hash_name]
    except KeyError:
        raise ValueError('Unsupported hash algorithm') from None

    if not namespace:
        raise ValueError('Namespace must be a non-empty string')

    if isinstance(data, (PurePath, str)):
        h = hash_alg()

        with open_file(data, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)

        data = h.digest()
    elif not is_hashed:
        data = hash_alg(data).digest()
    elif len(data) != hash_alg().digest_size:
        raise ValueError('Incorrect hash size')

    return _SSHSIG_MAGIC + String(namespace) + String(b'') + \
           String(hash_name) + String(data)


def import_allowed_signers(data: str) -> SSHAllowedSigners:
    """Import SSH allowed signers for SSHSIG

       This function imports public keys and associated options in
       OpenSSH allowed signers format.

       :param data:
           The allowed signers data to import.
       :type data: `str`

       :returns: An :class:`SSHAllowedSigners` object

    """

    return SSHAllowedSigners(data)


def read_allowed_signers(filelist: Union[FilePath, Sequence[FilePath]]) -> \
        SSHAllowedSigners:
    """Read SSH allowed signers for SSHSIG from a file or list of files

       This function reads public keys and associated options in
       OpenSSH allowed signers format from a file or list of files.

       :param filelist:
           The file or list of files to read allowed signers from.
       :type filelist: `PurePath`, `str`, or a list of these

       :returns: An :class:`SSHAllowedSigners` object

    """

    allowed_signers = SSHAllowedSigners()

    if isinstance(filelist, (PurePath, str)):
        files: Sequence[FilePath] = [filelist]
    else:
        files = filelist

    for filename in files:
        allowed_signers.load(read_file(filename, 'r'))

    return allowed_signers


def create_sshsig(key: KeyPairListArg, data: BytesOrFilePath, *,
                  is_hashed: bool = False, hash_name: str = 'sha512',
                  namespace: str = 'file', raw: bool = False) -> bytes:
    """Create an SSHSIG signature

       This function creates and returns an SSHSIG for a block of data signed
       with the requested private key.

       :param key:
           The signing key to use. If this corresponds to multiple keys, the
           first one will be used.
       :param data:
           The data bytes to sign, or a string filename of where to read the
           data from.
       :param is_hashed: (optional)
           Whether or not hashing has already been performed on the data
           passed in. This can be useful when signing large blocks of data
           which have already had a hash calculated on them. If set to
           `True`, the `data` argument must be a byte string of the length
           required by the specified `hash_name`. This defualts to `False`,
           meaning that hashing will be performed on the data before signing.
       :param hash_name: (optional)
           The name of the hash algorithm to use. This can currently be
           `'sha256'` or `'sha512'`, defaulting to `'sha512'`.
       :param namespace: (optional)
           The namespace the hash should be created for, defaulting to
           `'file'`.
       :param raw: (optional)
           Whether to return the signature as a raw SSH blob or as a
           "armored" base64 encoded data with a PEM-style header and
           footer. This defaults to `False`, which returns the signature
           in standard "amored" format.
       :type key: *see* :ref:`SpecifyingPrivateKeys`
       :type data: `bytes` or `str`
       :type is_hashed: `bool`
       :type hash_name: `str`
       :type namespace: `str`
       :type raw: `bool`

       :returns: `bytes`

    """

    try:
        keypair = load_keypairs(key)[0]
    except IndexError:
        raise ValueError('No signing key specified') from None

    if keypair.has_x509_chain: # pragma: no cover
        raise ValueError('X.509 certificates not supported')

    hash_name = hash_name.encode('utf-8')

    if keypair.sig_algorithm == b'ssh-rsa':
        keypair.set_sig_algorithm(b'rsa-sha2-' + hash_name[-3:])

    data_to_sign = _signed_data(data, is_hashed, hash_name, namespace)

    sig = _SSHSIG_MAGIC + UInt32(_SSHSIG_VERSION) + \
          String(keypair.public_data) + String(namespace) + String(b'') + \
          String(hash_name) + String(keypair.sign(data_to_sign))

    if not raw:
        sig = wrap_base64(sig, b'SSH SIGNATURE')

    return sig


def validate_sshsig(data: BytesOrFilePath, sig: BytesOrFilePath,
                    principal: str, allowed_signers: SSHAllowedSignersArg, *,
                    is_hashed: bool = False) -> bool:
    """Validate an SSHSIG signature

       This function validates whether an SSHSIG signature on a block of
       data is valid and that the signing key used matches an entry in the
       allowed signers associated with the requested principal. If present,
       namespace and validity period restrictions on the allowed signers
       entry are also enforced.

       In the case where an SSH certificate is used to sign the block, the
       specified principal must also match the certificate principals and
       the validity period of the certificate is also enforced.

       The `allowed_signers` argument can be any of the following:

           * a string or list of strings containing filenames to load
             allowed signers from
           * a byte string containing allowed signer data to match against
           * an already loaded :class:`SSHAllowedSigners` object containing
             allowed signers to match against

       :param data:
           The data bytes to validate, or a string filename of where to read
           the data from.
       :param sig:
           The signature bytes to validate, or a string filename of where to
           read the signature from.
       :param principal:
           The principal to look up in the allowed signers list.
       :param allowed_signers:
           A mapping from principals to allowed public keys or certificates.
       :param is_hashed: (optional)
           Whether or not hashing has already been performed on the data
           passed in. This can be useful when signing large blocks of data
           which have already had a hash calculated on them. If set to
           `True`, the `data` argument must be a byte string of the length
           required by the specified `hash_name`. This defualts to `False`,
           meaning that hashing will be performed on the data before signing.
       :type data: `PurePath`, `str`, or `bytes`
       :type sig: `PurePath`, `str`, or `bytes`
       :type principal: `str`
       :type allowed_signers: *see* :ref:`SpecifyingAllowedSigners`
       :type is_hashed: `bool`

       :returns: `bool`

    """

    if isinstance(sig, (PurePath, str)):
        sig = read_file(sig)

    if sig[:1] == b'-':
        end = sig.find(b'\n') + 1

        if not end:
            return False

        line = sig[:end].rstrip()

        if line != b'-----BEGIN SSH SIGNATURE-----':
            return False

        try:
            sig, end = match_base64(sig[end:], 0, line)
            sig = binascii.a2b_base64(sig)
        except ValueError:
            return False

    try:
        packet = SSHPacket(sig)

        if (packet.get_bytes(6) != _SSHSIG_MAGIC or
                packet.get_uint32() != _SSHSIG_VERSION):
            return False

        pubdata = packet.get_string()

        try:
            cert = decode_ssh_certificate(pubdata)

            if cert.is_x509: # pragma: no cover
                raise ValueError('X.509 certificates not supported')

            cert = cast(SSHOpenSSHCertificate, cert)
            key = cert.key
        except KeyImportError:
            try:
                cert = None
                key = decode_ssh_public_key(pubdata)
            except KeyImportError:
                return False

        try:
            namespace = packet.get_string().decode('utf-8')
        except UnicodeDecodeError:
            return False

        _ = packet.get_string()             # reserved
        hash_name = packet.get_string()
        sig = packet.get_string()
        packet.check_end()
    except PacketDecodeError:
        return False

    data_to_verify = _signed_data(data, is_hashed, hash_name, namespace)

    if not key.verify(data_to_verify, sig):
        return False

    if isinstance(allowed_signers, bytes):
        allowed_signers = import_allowed_signers(allowed_signers.decode())
    elif not isinstance(allowed_signers, SSHAllowedSigners):
        allowed_signers = read_allowed_signers(allowed_signers)

    allowed_signers: SSHAllowedSigners

    result = allowed_signers.validate(key, principal, namespace)

    if cert and not result:
        result = allowed_signers.validate(cert.signing_key, principal,
                                          namespace, ca=True)

        if result:
            try:
                cert.validate(CERT_TYPE_ANY, principal)
            except ValueError:
                return False

    return result
