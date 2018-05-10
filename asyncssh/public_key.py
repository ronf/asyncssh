# Copyright (c) 2013-2018 by Ron Frederick <ronf@timeheart.net>.
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
from datetime import datetime, timedelta
import os
import re
import time

try:
    from .crypto import generate_x509_certificate, import_x509_certificate
    _x509_available = True
except ImportError: # pragma: no cover
    _x509_available = False

try:
    import bcrypt
    _bcrypt_available = hasattr(bcrypt, 'kdf')
except ImportError: # pragma: no cover
    _bcrypt_available = False

from .asn1 import ASN1DecodeError, BitString, der_encode, der_decode
from .encryption import get_encryption_params, get_encryption
from .misc import ip_network
from .packet import NameList, String, UInt32, UInt64
from .packet import PacketDecodeError, SSHPacket
from .pbe import KeyEncryptionError, pkcs1_encrypt, pkcs8_encrypt
from .pbe import pkcs1_decrypt, pkcs8_decrypt

# Default file names in .ssh directory to read private keys from
_DEFAULT_KEY_FILES = ('id_ed25519', 'id_ecdsa', 'id_rsa', 'id_dsa')

_public_key_algs = []
_certificate_algs = []
_x509_certificate_algs = []
_public_key_alg_map = {}
_certificate_alg_map = {}
_certificate_version_map = {}
_pem_map = {}
_pkcs8_oid_map = {}

_abs_date_pattern = re.compile(r'\d{8}')
_abs_time_pattern = re.compile(r'\d{14}')
_rel_time_pattern = re.compile(r'(?:(?P<weeks>[+-]?\d+)[Ww]|'
                               r'(?P<days>[+-]?\d+)[Dd]|'
                               r'(?P<hours>[+-]?\d+)[Hh]|'
                               r'(?P<minutes>[+-]?\d+)[Mm]|'
                               r'(?P<seconds>[+-]?\d+)[Ss])+')

_subject_pattern = re.compile(r'(?:Distinguished[ -_]?Name|Subject|DN)[=:]?\s?',
                              re.IGNORECASE)

# SSH certificate types
CERT_TYPE_USER = 1
CERT_TYPE_HOST = 2

_OPENSSH_KEY_V1 = b'openssh-key-v1\0'
_OPENSSH_SALT_LEN = 16
_OPENSSH_WRAP_LEN = 70


def _parse_time(t):
    """Parse a time value"""

    if isinstance(t, int):
        return t
    elif isinstance(t, float):
        return int(t)
    elif isinstance(t, datetime):
        return int(t.timestamp())
    elif isinstance(t, str):
        if t == 'now':
            return int(time.time())

        match = _abs_date_pattern.fullmatch(t)
        if match:
            return int(datetime.strptime(t, '%Y%m%d').timestamp())

        match = _abs_time_pattern.fullmatch(t)
        if match:
            return int(datetime.strptime(t, '%Y%m%d%H%M%S').timestamp())

        match = _rel_time_pattern.fullmatch(t)
        if match:
            delta = {k: int(v) for k, v in match.groupdict(0).items()}
            return int(time.time() + timedelta(**delta).total_seconds())

    raise ValueError('Unrecognized time value')


def _wrap_base64(data, wrap=64):
    """Break a Base64 value into multiple lines."""

    data = binascii.b2a_base64(data)[:-1]
    return b'\n'.join(data[i:i+wrap]
                      for i in range(0, len(data), wrap)) + b'\n'


class KeyGenerationError(ValueError):
    """Key generation error

       This exception is raised by :func:`generate_private_key`,
       :meth:`generate_user_certificate() <SSHKey.generate_user_certificate>`
       or :meth:`generate_host_certificate()
       <SSHKey.generate_host_certificate>` when the requested parameters are
       unsupported.

    """


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

    algorithm = None
    sig_algorithms = None
    x509_algorithms = None
    all_sig_algorithms = None
    pem_name = None
    pkcs8_oid = None

    def __init__(self, key=None):
        self._key = key
        self._comment = None

    @property
    def pyca_key(self):
        """Return PyCA key for use in X.509 module"""

        return self._key.pyca_key

    def _generate_certificate(self, key, version, serial, cert_type,
                              key_id, principals, valid_after,
                              valid_before, cert_options, comment):
        """Generate a new SSH certificate"""

        valid_after = _parse_time(valid_after)
        valid_before = _parse_time(valid_before)

        if valid_before <= valid_after:
            raise ValueError('Valid before time must be later than '
                             'valid after time')

        try:
            algorithm, cert_handler = _certificate_version_map[key.algorithm,
                                                               version]
        except KeyError:
            raise KeyGenerationError('Unknown certificate version') from None

        return cert_handler.generate(self, algorithm, key, serial, cert_type,
                                     key_id, principals, valid_after,
                                     valid_before, cert_options, comment)

    def _generate_x509_certificate(self, key, subject, issuer, serial,
                                   valid_after, valid_before, ca, ca_path_len,
                                   purposes, user_principals, host_principals,
                                   hash_alg, comment):
        """Generate a new X.509 certificate"""

        if not _x509_available: # pragma: no cover
            raise KeyGenerationError('X.509 certificate generation '
                                     'requires PyOpenSSL')

        if not self.x509_algorithms:
            raise KeyGenerationError('X.509 certificate generation not '
                                     'supported for ' + self.get_algorithm() +
                                     ' keys')

        valid_after = _parse_time(valid_after)
        valid_before = _parse_time(valid_before)

        if valid_before <= valid_after:
            raise ValueError('Valid before time must be later than '
                             'valid after time')

        return SSHX509Certificate.generate(self, key, subject, issuer, serial,
                                           valid_after, valid_before, ca,
                                           ca_path_len, purposes,
                                           user_principals, host_principals,
                                           hash_alg, comment)

    def get_algorithm(self):
        """Return the algorithm associated with this key"""

        return self.algorithm.decode('ascii')

    def get_comment_bytes(self):
        """Return the comment associated with this key as a byte string

           :returns: `bytes` or `None`

        """

        return self._comment

    def get_comment(self, encoding='utf-8'):
        """Return the comment associated with this key as a Unicode string

           :param encoding:
               The encoding to use to decode the comment as a Unicode
               string, defaulting to UTF-8
           :type encoding: `str`

           :returns: `str` or `None`

           :raises: :exc:`UnicodeDecodeError` if the comment cannot be
                    decoded using the specified encoding

        """

        return self._comment.decode(encoding) if self._comment else None

    def set_comment(self, comment, encoding='utf-8'):
        """Set the comment associated with this key

           :param comment:
               The new comment to associate with this key
           :param encoding:
               The Unicode encoding to use to encode the comment,
               defaulting to UTF-8
           :type comment: `str`, `bytes`, or `None`
           :type encoding: `str`

           :raises: :exc:`UnicodeEncodeError` if the comment cannot be
                    encoded using the specified encoding

        """

        if isinstance(comment, str):
            comment = comment.encode(encoding)

        self._comment = comment or None

    def sign_der(self, data, sig_algorithm):
        """Abstract method to compute a DER-encoded signature"""

        raise NotImplementedError

    def verify_der(self, data, sig_algorithm, sig):
        """Abstract method to verify a DER-encoded signature"""

        raise NotImplementedError

    def sign_ssh(self, data, sig_algorithm):
        """Abstract method to compute an SSH-encoded signature"""

        raise NotImplementedError

    def verify_ssh(self, data, sig_algorithm, sig):
        """Abstract method to verify an SSH-encoded signature"""

        raise NotImplementedError

    def sign(self, data, sig_algorithm):
        """Return an SSH-encoded signature of the specified data"""

        if sig_algorithm not in self.all_sig_algorithms:
            raise ValueError('Unrecognized signature algorithm')

        return b''.join((String(sig_algorithm),
                         String(self.sign_ssh(data, sig_algorithm))))

    def verify(self, data, sig):
        """Verify an SSH signature of the specified data using this key"""

        try:
            packet = SSHPacket(sig)
            sig_algorithm = packet.get_string()
            sig = packet.get_string()
            packet.check_end()

            if sig_algorithm not in self.all_sig_algorithms:
                return False

            return self.verify_ssh(data, sig_algorithm, sig)
        except PacketDecodeError:
            return False

    def encode_pkcs1_private(self):
        """Export parameters associated with a PKCS#1 private key"""

        # pylint: disable=no-self-use
        raise KeyExportError('PKCS#1 private key export not supported')

    def encode_pkcs1_public(self):
        """Export parameters associated with a PKCS#1 public key"""

        # pylint: disable=no-self-use
        raise KeyExportError('PKCS#1 public key export not supported')

    def encode_pkcs8_private(self):
        """Export parameters associated with a PKCS#8 private key"""

        # pylint: disable=no-self-use
        raise KeyExportError('PKCS#8 private key export not supported')

    def encode_pkcs8_public(self):
        """Export parameters associated with a PKCS#8 public key"""

        # pylint: disable=no-self-use
        raise KeyExportError('PKCS#8 public key export not supported')

    def encode_ssh_private(self):
        """Export parameters associated with an OpenSSH private key"""

        # pylint: disable=no-self-use
        raise KeyExportError('OpenSSH private key export not supported')

    def encode_ssh_public(self):
        """Export parameters associated with an OpenSSH public key"""

        # pylint: disable=no-self-use
        raise KeyExportError('OpenSSH public key export not supported')

    def get_ssh_private_key(self):
        """Return OpenSSH private key in binary format"""

        return String(self.algorithm) + self.encode_ssh_private()

    def get_ssh_public_key(self):
        """Return OpenSSH public key in binary format"""

        return String(self.algorithm) + self.encode_ssh_public()

    def convert_to_public(self):
        """Return public key corresponding to this key

           This method converts an :class:`SSHKey` object which contains
           a private key into one which contains only the corresponding
           public key. If it is called on something which is already
           a public key, it has no effect.

        """

        result = decode_ssh_public_key(self.get_ssh_public_key())
        result.set_comment(self.get_comment_bytes())
        return result

    def generate_user_certificate(self, user_key, key_id, version=1,
                                  serial=0, principals=(), valid_after=0,
                                  valid_before=0xffffffffffffffff,
                                  force_command=None, source_address=None,
                                  permit_x11_forwarding=True,
                                  permit_agent_forwarding=True,
                                  permit_port_forwarding=True,
                                  permit_pty=True, permit_user_rc=True,
                                  comment=()):
        """Generate a new SSH user certificate

           This method returns an SSH user certifcate with the requested
           attributes signed by this private key.

           :param user_key:
               The user's public key.
           :param key_id:
               The key identifier associated with this certificate.
           :param version: (optional)
               The version of certificate to create, defaulting to 1.
           :param serial: (optional)
               The serial number of the certificate, defaulting to 0.
           :param principals: (optional)
               The user names this certificate is valid for. By default,
               it can be used with any user name.
           :param valid_after: (optional)
               The earliest time the certificate is valid for, defaulting to
               no restriction on when the certificate starts being valid.
               See :ref:`SpecifyingTimeValues` for allowed time specifications.
           :param valid_before: (optional)
               The latest time the certificate is valid for, defaulting to
               no restriction on when the certificate stops being valid.
               See :ref:`SpecifyingTimeValues` for allowed time specifications.
           :param force_command: (optional)
               The command (if any) to force a session to run when this
               certificate is used.
           :param source_address: (optional)
               A list of source addresses and networks for which the
               certificate is valid, defaulting to all addresses.
           :param permit_x11_forwarding: (optional)
               Whether or not to allow this user to use X11 forwarding,
               defaulting to `True`.
           :param permit_agent_forwarding: (optional)
               Whether or not to allow this user to use agent forwarding,
               defaulting to `True`.
           :param permit_port_forwarding: (optional)
               Whether or not to allow this user to use port forwarding,
               defaulting to `True`.
           :param permit_pty: (optional)
               Whether or not to allow this user to allocate a
               pseudo-terminal, defaulting to `True`.
           :param permit_user_rc: (optional)
               Whether or not to run the user rc file when this certificate
               is used, defaulting to `True`.
           :param comment:
               The comment to associate with this certificate. By default,
               the comment will be set to the comment currently set on
               user_key.
           :type user_key: :class:`SSHKey`
           :type key_id: `str`
           :type version: `int`
           :type serial: `int`
           :type principals: `list` of `str`
           :type force_command: `str` or `None`
           :type source_address: list of ip_address and ip_network values
           :type permit_x11_forwarding: `bool`
           :type permit_agent_forwarding: `bool`
           :type permit_port_forwarding: `bool`
           :type permit_pty: `bool`
           :type permit_user_rc: `bool`
           :type comment: `str`, `bytes`, or `None`

           :returns: :class:`SSHCertificate`

           :raises: | :exc:`ValueError` if the validity times are invalid
                    | :exc:`KeyGenerationError` if the requested certificate
                      parameters are unsupported

        """

        cert_options = {}

        if force_command:
            cert_options['force-command'] = force_command

        if source_address:
            cert_options['source-address'] = [ip_network(addr)
                                              for addr in source_address]

        if permit_x11_forwarding:
            cert_options['permit-X11-forwarding'] = True

        if permit_agent_forwarding:
            cert_options['permit-agent-forwarding'] = True

        if permit_port_forwarding:
            cert_options['permit-port-forwarding'] = True

        if permit_pty:
            cert_options['permit-pty'] = True

        if permit_user_rc:
            cert_options['permit-user-rc'] = True

        if comment == ():
            comment = user_key.get_comment_bytes()

        return self._generate_certificate(user_key, version, serial,
                                          CERT_TYPE_USER, key_id,
                                          principals, valid_after,
                                          valid_before, cert_options, comment)

    def generate_host_certificate(self, host_key, key_id, version=1,
                                  serial=0, principals=(), valid_after=0,
                                  valid_before=0xffffffffffffffff,
                                  comment=()):
        """Generate a new SSH host certificate

           This method returns an SSH host certifcate with the requested
           attributes signed by this private key.

           :param host_key:
               The host's public key.
           :param key_id:
               The key identifier associated with this certificate.
           :param version: (optional)
               The version of certificate to create, defaulting to 1.
           :param serial: (optional)
               The serial number of the certificate, defaulting to 0.
           :param principals: (optional)
               The host names this certificate is valid for. By default,
               it can be used with any host name.
           :param valid_after: (optional)
               The earliest time the certificate is valid for, defaulting to
               no restriction on when the certificate starts being valid.
               See :ref:`SpecifyingTimeValues` for allowed time specifications.
           :param valid_before: (optional)
               The latest time the certificate is valid for, defaulting to
               no restriction on when the certificate stops being valid.
               See :ref:`SpecifyingTimeValues` for allowed time specifications.
           :param comment:
               The comment to associate with this certificate. By default,
               the comment will be set to the comment currently set on
               host_key.
           :type host_key: :class:`SSHKey`
           :type key_id: `str`
           :type version: `int`
           :type serial: `int`
           :type principals: `list` of `str`
           :type comment: `str`, `bytes`, or `None`

           :returns: :class:`SSHCertificate`

           :raises: | :exc:`ValueError` if the validity times are invalid
                    | :exc:`KeyGenerationError` if the requested certificate
                      parameters are unsupported
        """

        if comment == ():
            comment = host_key.get_comment_bytes()

        return self._generate_certificate(host_key, version, serial,
                                          CERT_TYPE_HOST, key_id,
                                          principals, valid_after,
                                          valid_before, {}, comment)

    def generate_x509_user_certificate(self, user_key, subject, issuer=None,
                                       serial=None, principals=(),
                                       valid_after=0,
                                       valid_before=0xffffffffffffffff,
                                       purposes='secureShellClient',
                                       hash_alg='sha256', comment=()):
        """Generate a new X.509 user certificate

           This method returns an X.509 user certifcate with the requested
           attributes signed by this private key.

           :param user_key:
               The user's public key.
           :param subject:
               The subject name in the certificate, expresed as a
               comma-separated list of X.509 `name=value` pairs.
           :param issuer: (optional)
               The issuer name in the certificate, expresed as a
               comma-separated list of X.509 `name=value` pairs. If
               not specified, the subject name will be used, creating
               a self-signed certificate.
           :param serial: (optional)
               The serial number of the certificate, defaulting to a random
               64-bit value.
           :param principals: (optional)
               The user names this certificate is valid for. By default,
               it can be used with any user name.
           :param valid_after: (optional)
               The earliest time the certificate is valid for, defaulting to
               no restriction on when the certificate starts being valid.
               See :ref:`SpecifyingTimeValues` for allowed time specifications.
           :param valid_before: (optional)
               The latest time the certificate is valid for, defaulting to
               no restriction on when the certificate stops being valid.
               See :ref:`SpecifyingTimeValues` for allowed time specifications.
           :param purposes: (optional)
               The allowed purposes for this certificate or `None` to
               not restrict the certificate's purpose, defaulting to
               'secureShellClient'
           :param hash_alg: (optional)
               The hash algorithm to use when signing the new certificate,
               defaulting to SHA256.
           :param comment: (optional)
               The comment to associate with this certificate. By default,
               the comment will be set to the comment currently set on
               user_key.
           :type user_key: :class:`SSHKey`
           :type subject: `str`
           :type issuer: `str`
           :type serial: `int`
           :type principals: `list` of `str`
           :type purposes: `list` of `str` or `None`
           :type hash_alg: `str`
           :type comment: `str`, `bytes`, or `None`

           :returns: :class:`SSHCertificate`

           :raises: | :exc:`ValueError` if the validity times are invalid
                    | :exc:`KeyGenerationError` if the requested certificate
                      parameters are unsupported

        """

        if comment == ():
            comment = user_key.get_comment_bytes()

        return self._generate_x509_certificate(user_key, subject, issuer,
                                               serial, valid_after,
                                               valid_before, False, None,
                                               purposes, principals, (),
                                               hash_alg, comment)

    def generate_x509_host_certificate(self, host_key, subject, issuer=None,
                                       serial=None, principals=(),
                                       valid_after=0,
                                       valid_before=0xffffffffffffffff,
                                       purposes='secureShellServer',
                                       hash_alg='sha256', comment=()):
        """Generate a new X.509 host certificate

           This method returns a X.509 host certifcate with the requested
           attributes signed by this private key.

           :param host_key:
               The host's public key.
           :param subject:
               The subject name in the certificate, expresed as a
               comma-separated list of X.509 `name=value` pairs.
           :param issuer: (optional)
               The issuer name in the certificate, expresed as a
               comma-separated list of X.509 `name=value` pairs. If
               not specified, the subject name will be used, creating
               a self-signed certificate.
           :param serial: (optional)
               The serial number of the certificate, defaulting to a random
               64-bit value.
           :param principals: (optional)
               The host names this certificate is valid for. By default,
               it can be used with any host name.
           :param valid_after: (optional)
               The earliest time the certificate is valid for, defaulting to
               no restriction on when the certificate starts being valid.
               See :ref:`SpecifyingTimeValues` for allowed time specifications.
           :param valid_before: (optional)
               The latest time the certificate is valid for, defaulting to
               no restriction on when the certificate stops being valid.
               See :ref:`SpecifyingTimeValues` for allowed time specifications.
           :param purposes: (optional)
               The allowed purposes for this certificate or `None` to
               not restrict the certificate's purpose, defaulting to
               'secureShellServer'
           :param hash_alg: (optional)
               The hash algorithm to use when signing the new certificate,
               defaulting to SHA256.
           :param comment: (optional)
               The comment to associate with this certificate. By default,
               the comment will be set to the comment currently set on
               host_key.
           :type host_key: :class:`SSHKey`
           :type subject: `str`
           :type issuer: `str`
           :type serial: `int`
           :type principals: `list` of `str`
           :type purposes: `list` of `str` or `None`
           :type hash_alg: `str`
           :type comment: `str`, `bytes`, or `None`

           :returns: :class:`SSHCertificate`

           :raises: | :exc:`ValueError` if the validity times are invalid
                    | :exc:`KeyGenerationError` if the requested certificate
                      parameters are unsupported
        """

        if comment == ():
            comment = host_key.get_comment_bytes()

        return self._generate_x509_certificate(host_key, subject, issuer,
                                               serial, valid_after,
                                               valid_before, False, None,
                                               purposes, (), principals,
                                               hash_alg, comment)

    def generate_x509_ca_certificate(self, ca_key, subject, issuer=None,
                                     serial=None, valid_after=0,
                                     valid_before=0xffffffffffffffff,
                                     ca_path_len=None, hash_alg='sha256',
                                     comment=()):
        """Generate a new X.509 CA certificate

           This method returns a X.509 CA certifcate with the requested
           attributes signed by this private key.

           :param ca_key:
               The new CA's public key.
           :param subject:
               The subject name in the certificate, expresed as a
               comma-separated list of X.509 `name=value` pairs.
           :param issuer: (optional)
               The issuer name in the certificate, expresed as a
               comma-separated list of X.509 `name=value` pairs. If
               not specified, the subject name will be used, creating
               a self-signed certificate.
           :param serial: (optional)
               The serial number of the certificate, defaulting to a random
               64-bit value.
           :param valid_after: (optional)
               The earliest time the certificate is valid for, defaulting to
               no restriction on when the certificate starts being valid.
               See :ref:`SpecifyingTimeValues` for allowed time specifications.
           :param valid_before: (optional)
               The latest time the certificate is valid for, defaulting to
               no restriction on when the certificate stops being valid.
               See :ref:`SpecifyingTimeValues` for allowed time specifications.
           :param ca_path_len: (optional)
               The maximum number of levels of intermediate CAs allowed
               below this new CA or `None` to not enforce a limit,
               defaulting to no limit.
           :param hash_alg: (optional)
               The hash algorithm to use when signing the new certificate,
               defaulting to SHA256.
           :param comment: (optional)
               The comment to associate with this certificate. By default,
               the comment will be set to the comment currently set on
               ca_key.
           :type ca_key: :class:`SSHKey`
           :type subject: `str`
           :type issuer: `str`
           :type serial: `int`
           :type ca_path_len: `int` or `None`
           :type hash_alg: `str`
           :type comment: `str`, `bytes`, or `None`

           :returns: :class:`SSHCertificate`

           :raises: | :exc:`ValueError` if the validity times are invalid
                    | :exc:`KeyGenerationError` if the requested certificate
                      parameters are unsupported
        """

        if comment == ():
            comment = ca_key.get_comment_bytes()

        return self._generate_x509_certificate(ca_key, subject, issuer,
                                               serial, valid_after,
                                               valid_before, True,
                                               ca_path_len, None, (), (),
                                               hash_alg, comment)

    def export_private_key(self, format_name='openssh', passphrase=None,
                           cipher_name='aes256-cbc', hash_name='sha256',
                           pbe_version=2, rounds=128, ignore_few_rounds=False):
        """Export a private key in the requested format

           This method returns this object's private key encoded in the
           requested format. If a passphrase is specified, the key will
           be exported in encrypted form.

           Available formats include:

               pkcs1-der, pkcs1-pem, pkcs8-der, pkcs8-pem, openssh

           By default, openssh format will be used.

           Encryption is supported in pkcs1-pem, pkcs8-der, pkcs8-pem,
           and openssh formats. For pkcs1-pem, only the cipher can be
           specified. For pkcs8-der and pkcs-8, cipher,  hash and PBE
           version can be specified. For openssh, cipher and rounds
           can be specified.

           Available ciphers for pkcs1-pem are:

               aes128-cbc, aes192-cbc, aes256-cbc, des-cbc, des3-cbc

           Available ciphers for pkcs8-der and pkcs8-pem are:

               aes128-cbc, aes192-cbc, aes256-cbc, blowfish-cbc,
               cast128-cbc, des-cbc, des2-cbc, des3-cbc, rc4-40, rc4-128

           Available ciphers for openssh format include the following
           :ref:`encryption algorithms <EncryptionAlgs>`.

           Available hashes include:

               md5, sha1, sha256, sha384, sha512

           Available PBE versions include 1 for PBES1 and 2 for PBES2.

           Not all combinations of cipher, hash, and version are supported.

           The default cipher is aes256. In the pkcs8 formats, the default
           hash is sha256 and default version is PBES2.

           In openssh format, the default number of rounds is 128.

           .. note:: The openssh format uses bcrypt for encryption, but
                     unlike the traditional bcrypt cost factor used in
                     password hashing which scales logarithmically, the
                     encryption strength here scales linearly with the
                     rounds value. Since the cipher is rekeyed 64 times
                     per round, the default rounds value of 128 corresponds
                     to 8192 total iterations, which is the equivalent of
                     a bcrypt cost factor of 13.

           :param format_name: (optional)
               The format to export the key in.
           :param passphrase: (optional)
               A passphrase to encrypt the private key with.
           :param cipher_name: (optional)
               The cipher to use for private key encryption.
           :param hash_name: (optional)
               The hash to use for private key encryption.
           :param pbe_version: (optional)
               The PBE version to use for private key encryption.
           :param rounds: (optional)
               The number of KDF rounds to apply to the passphrase.
           :type format_name: `str`
           :type passphrase: `str` or `bytes`
           :type cipher_name: `str`
           :type hash_name: `str`
           :type pbe_version: `int`
           :type rounds: `int`

           :returns: `bytes` representing the exported private key

        """

        if format_name in ('pkcs1-der', 'pkcs1-pem'):
            data = der_encode(self.encode_pkcs1_private())

            if passphrase is not None:
                if format_name == 'pkcs1-der':
                    raise KeyExportError('PKCS#1 DER format does not support '
                                         'private key encryption')

                alg, iv, data = pkcs1_encrypt(data, cipher_name, passphrase)
                headers = (b'Proc-Type: 4,ENCRYPTED\n' +
                           b'DEK-Info: ' + alg + b',' +
                           binascii.b2a_hex(iv).upper() + b'\n\n')
            else:
                headers = b''

            if format_name == 'pkcs1-pem':
                keytype = self.pem_name + b' PRIVATE KEY'
                data = (b'-----BEGIN ' + keytype + b'-----\n' +
                        headers + _wrap_base64(data) +
                        b'-----END ' + keytype + b'-----\n')

            return data
        elif format_name in ('pkcs8-der', 'pkcs8-pem'):
            alg_params, data = self.encode_pkcs8_private()

            data = der_encode((0, (self.pkcs8_oid, alg_params), data))

            if passphrase is not None:
                data = pkcs8_encrypt(data, cipher_name, hash_name,
                                     pbe_version, passphrase)

            if format_name == 'pkcs8-pem':
                if passphrase is not None:
                    keytype = b'ENCRYPTED PRIVATE KEY'
                else:
                    keytype = b'PRIVATE KEY'

                data = (b'-----BEGIN ' + keytype + b'-----\n' +
                        _wrap_base64(data) +
                        b'-----END ' + keytype + b'-----\n')

            return data
        elif format_name == 'openssh':
            check = os.urandom(4)
            nkeys = 1

            data = b''.join((check, check, self.get_ssh_private_key(),
                             String(self.get_comment_bytes() or b'')))

            if passphrase is not None:
                try:
                    alg = cipher_name.encode('ascii')
                    key_size, iv_size, block_size, _, _, _ = \
                        get_encryption_params(alg)
                except (KeyError, UnicodeEncodeError):
                    raise KeyEncryptionError('Unknown cipher: %s' %
                                             cipher_name) from None

                if not _bcrypt_available: # pragma: no cover
                    raise KeyExportError('OpenSSH private key encryption '
                                         'requires bcrypt with KDF support')

                kdf = b'bcrypt'
                salt = os.urandom(_OPENSSH_SALT_LEN)
                kdf_data = b''.join((String(salt), UInt32(rounds)))

                if isinstance(passphrase, str):
                    passphrase = passphrase.encode('utf-8')

                # pylint: disable=no-member
                key = bcrypt.kdf(passphrase, salt, key_size + iv_size,
                                 rounds, ignore_few_rounds)
                # pylint: enable=no-member

                cipher = get_encryption(alg, key[:key_size], key[key_size:])
                block_size = max(block_size, 8)
            else:
                cipher = None
                alg = b'none'
                kdf = b'none'
                kdf_data = b''
                block_size = 8
                mac = b''

            pad = len(data) % block_size
            if pad: # pragma: no branch
                data = data + bytes(range(1, block_size + 1 - pad))

            if cipher:
                data, mac = cipher.encrypt_packet(0, b'', data)
            else:
                mac = b''

            data = b''.join((_OPENSSH_KEY_V1, String(alg), String(kdf),
                             String(kdf_data), UInt32(nkeys),
                             String(self.get_ssh_public_key()),
                             String(data), mac))

            return (b'-----BEGIN OPENSSH PRIVATE KEY-----\n' +
                    _wrap_base64(data, _OPENSSH_WRAP_LEN) +
                    b'-----END OPENSSH PRIVATE KEY-----\n')
        else:
            raise KeyExportError('Unknown export format')

    def export_public_key(self, format_name='openssh'):
        """Export a public key in the requested format

           This method returns this object's public key encoded in the
           requested format. Available formats include:

               pkcs1-der, pkcs1-pem, pkcs8-der, pkcs8-pem, openssh, rfc4716

           By default, openssh format will be used.

           :param format_name: (optional)
               The format to export the key in.
           :type format_name: `str`

           :returns: `bytes` representing the exported public key

        """

        if format_name in ('pkcs1-der', 'pkcs1-pem'):
            data = der_encode(self.encode_pkcs1_public())

            if format_name == 'pkcs1-pem':
                keytype = self.pem_name + b' PUBLIC KEY'
                data = (b'-----BEGIN ' + keytype + b'-----\n' +
                        _wrap_base64(data) +
                        b'-----END ' + keytype + b'-----\n')

            return data
        elif format_name in ('pkcs8-der', 'pkcs8-pem'):
            alg_params, data = self.encode_pkcs8_public()

            data = der_encode(((self.pkcs8_oid, alg_params), BitString(data)))

            if format_name == 'pkcs8-pem':
                data = (b'-----BEGIN PUBLIC KEY-----\n' +
                        _wrap_base64(data) +
                        b'-----END PUBLIC KEY-----\n')

            return data
        elif format_name == 'openssh':
            data = self.get_ssh_public_key()

            if self._comment:
                comment = b' ' + self._comment
            else:
                comment = b''

            return (self.algorithm + b' ' +
                    binascii.b2a_base64(data)[:-1] + comment + b'\n')
        elif format_name == 'rfc4716':
            data = self.get_ssh_public_key()

            if self._comment:
                comment = (b'Comment: "' + self._comment + b'"\n')
            else:
                comment = b''

            return (b'---- BEGIN SSH2 PUBLIC KEY ----\n' +
                    comment + _wrap_base64(data) +
                    b'---- END SSH2 PUBLIC KEY ----\n')
        else:
            raise KeyExportError('Unknown export format')

    def write_private_key(self, filename, *args, **kwargs):
        """Write a private key to a file in the requested format

           This method is a simple wrapper around :meth:`export_private_key`
           which writes the exported key data to a file.

           :param filename:
               The filename to write the private key to.
           :param \\*args,\\ \\*\\*kwargs:
               Additional arguments to pass through to
               :meth:`export_private_key`.
           :type filename: `str`

        """

        with open(filename, 'wb') as f:
            f.write(self.export_private_key(*args, **kwargs))

    def write_public_key(self, filename, *args, **kwargs):
        """Write a public key to a file in the requested format

           This method is a simple wrapper around :meth:`export_public_key`
           which writes the exported key data to a file.

           :param filename:
               The filename to write the public key to.
           :param \\*args,\\ \\*\\*kwargs:
               Additional arguments to pass through to
               :meth:`export_public_key`.
           :type filename: `str`

        """

        with open(filename, 'wb') as f:
            f.write(self.export_public_key(*args, **kwargs))

    def append_private_key(self, filename, *args, **kwargs):
        """Append a private key to a file in the requested format

           This method is a simple wrapper around :meth:`export_private_key`
           which appends the exported key data to an existing file.

           :param filename:
               The filename to append the private key to.
           :param \\*args,\\ \\*\\*kwargs:
               Additional arguments to pass through to
               :meth:`export_private_key`.
           :type filename: `str`

        """

        with open(filename, 'ab') as f:
            f.write(self.export_private_key(*args, **kwargs))

    def append_public_key(self, filename, *args, **kwargs):
        """Append a public key to a file in the requested format

           This method is a simple wrapper around :meth:`export_public_key`
           which appends the exported key data to an existing file.

           :param filename:
               The filename to append the public key to.
           :param \\*args,\\ \\*\\*kwargs:
               Additional arguments to pass through to
               :meth:`export_public_key`.
           :type filename: `str`

        """

        with open(filename, 'ab') as f:
            f.write(self.export_public_key(*args, **kwargs))


class SSHCertificate:
    """Parent class which holds an SSH certificate"""

    is_x509 = False
    is_x509_chain = False

    def __init__(self, algorithm, sig_algorithms, host_key_algorithms,
                 key, data, comment):
        self.algorithm = algorithm
        self.sig_algorithms = sig_algorithms
        self.host_key_algorithms = host_key_algorithms
        self.key = key
        self.data = data

        self.set_comment(comment)

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.data == other.data

    def __hash__(self):
        return hash(self.data)

    def get_algorithm(self):
        """Return the algorithm associated with this certificate"""

        return self.algorithm.decode('ascii')

    def get_comment_bytes(self):
        """Return the comment associated with this certificate as a
           byte string

           :returns: `bytes` or `None`

        """

        return self._comment

    def get_comment(self, encoding='utf-8'):
        """Return the comment associated with this certificate as a
           Unicode string

           :param encoding:
               The encoding to use to decode the comment as a Unicode
               string, defaulting to UTF-8
           :type encoding: `str`

           :returns: `str` or `None`

           :raises: :exc:`UnicodeDecodeError` if the comment cannot be
                    decoded using the specified encoding

        """

        return self._comment.decode(encoding) if self._comment else None

    def set_comment(self, comment, encoding='utf-8'):
        """Set the comment associated with this certificate

           :param comment:
               The new comment to associate with this key
           :param encoding:
               The Unicode encoding to use to encode the comment,
               defaulting to UTF-8
           :type comment: `str`, `bytes`, or `None`
           :type encoding: `str`

           :raises: :exc:`UnicodeEncodeError` if the comment cannot be
                    encoded using the specified encoding

        """

        if isinstance(comment, str):
            comment = comment.encode(encoding)

        self._comment = comment or None

    def export_certificate(self, format_name='openssh'):
        """Export a certificate in the requested format

           This function returns this certificate encoded in the requested
           format. Available formats include:

               der, pem, openssh, rfc4716

           By default, OpenSSH format will be used.

           :param format_name: (optional)
               The format to export the certificate in.
           :type format_name: `str`

           :returns: `bytes` representing the exported certificate

        """

        if self.is_x509:
            if format_name == 'rfc4716':
                raise KeyExportError('RFC4716 format is not supported for '
                                     'X.509 certificates')
        else:
            if format_name in ('der', 'pem'):
                raise KeyExportError('DER and PEM formats are not supported '
                                     'for OpenSSH certificates')

        if format_name == 'der':
            return self.data
        elif format_name == 'pem':
            return (b'-----BEGIN CERTIFICATE-----\n' +
                    _wrap_base64(self.data) +
                    b'-----END CERTIFICATE-----\n')
        elif format_name == 'openssh':
            if self._comment:
                comment = b' ' + self._comment
            else:
                comment = b''

            return (self.algorithm + b' ' +
                    binascii.b2a_base64(self.data)[:-1] + comment + b'\n')
        elif format_name == 'rfc4716':
            if self._comment:
                comment = (b'Comment: "' + self._comment + b'"\n')
            else:
                comment = b''

            return (b'---- BEGIN SSH2 PUBLIC KEY ----\n' +
                    comment + _wrap_base64(self.data) +
                    b'---- END SSH2 PUBLIC KEY ----\n')
        else:
            raise KeyExportError('Unknown export format')

    def write_certificate(self, filename, *args, **kwargs):
        """Write a certificate to a file in the requested format

           This function is a simple wrapper around export_certificate
           which writes the exported certificate to a file.

           :param filename:
               The filename to write the certificate to.
           :param \\*args,\\ \\*\\*kwargs:
               Additional arguments to pass through to
               :meth:`export_certificate`.
           :type filename: `str`

        """

        with open(filename, 'wb') as f:
            f.write(self.export_certificate(*args, **kwargs))

    def append_certificate(self, filename, *args, **kwargs):
        """Append a certificate to a file in the requested format

           This function is a simple wrapper around export_certificate
           which appends the exported certificate to an existing file.

           :param filename:
               The filename to append the certificate to.
           :param \\*args,\\ \\*\\*kwargs:
               Additional arguments to pass through to
               :meth:`export_certificate`.
           :type filename: `str`

        """

        with open(filename, 'ab') as f:
            f.write(self.export_certificate(*args, **kwargs))


class SSHOpenSSHCertificate(SSHCertificate):
    """Class which holds an OpenSSH certificate"""

    _user_option_encoders = []
    _user_extension_encoders = []
    _host_option_encoders = []
    _host_extension_encoders = []

    _user_option_decoders = {}
    _user_extension_decoders = {}
    _host_option_decoders = {}
    _host_extension_decoders = {}

    def __init__(self, algorithm, key, data, principals, options, signing_key,
                 serial, cert_type, key_id, valid_after, valid_before,
                 comment):
        super().__init__(algorithm, key.sig_algorithms, (algorithm,),
                         key, data, comment)

        self.principals = principals
        self.options = options
        self.signing_key = signing_key

        self._serial = serial
        self._cert_type = cert_type
        self._key_id = key_id
        self._valid_after = valid_after
        self._valid_before = valid_before

    @classmethod
    def generate(cls, signing_key, algorithm, key, serial, cert_type, key_id,
                 principals, valid_after, valid_before, options, comment):
        """Generate a new SSH certificate"""

        principals = list(principals)
        cert_principals = b''.join(String(p) for p in principals)

        if cert_type == CERT_TYPE_USER:
            cert_options = cls._encode_options(options,
                                               cls._user_option_encoders)
            cert_extensions = cls._encode_options(options,
                                                  cls._user_extension_encoders)
        else:
            cert_options = cls._encode_options(options,
                                               cls._host_option_encoders)
            cert_extensions = cls._encode_options(options,
                                                  cls._host_extension_encoders)

        key = key.convert_to_public()

        data = b''.join((String(algorithm),
                         cls._encode(key, serial, cert_type, key_id,
                                     cert_principals, valid_after,
                                     valid_before, cert_options,
                                     cert_extensions),
                         String(signing_key.get_ssh_public_key())))

        data += String(signing_key.sign(data, signing_key.algorithm))

        signing_key = signing_key.convert_to_public()

        return cls(algorithm, key, data, principals, options, signing_key,
                   serial, cert_type, key_id, valid_after, valid_before,
                   comment)

    @classmethod
    def construct(cls, packet, algorithm, key_handler, comment):
        """Construct an SSH certificate from packetized data"""

        key_params, serial, cert_type, key_id, \
            principals, valid_after, valid_before, \
            options, extensions = cls._decode(packet, key_handler)

        signing_key = decode_ssh_public_key(packet.get_string())
        data = packet.get_consumed_payload()
        signature = packet.get_string()
        packet.check_end()

        if not signing_key.verify(data, signature):
            raise KeyImportError('Invalid certificate signature')

        key = key_handler.make_public(*key_params)
        data = packet.get_consumed_payload()

        try:
            key_id = key_id.decode('utf-8')
        except UnicodeDecodeError:
            raise KeyImportError('Invalid characters in key ID')

        packet = SSHPacket(principals)
        principals = []

        while packet:
            try:
                principal = packet.get_string().decode('utf-8')
            except UnicodeDecodeError:
                raise KeyImportError('Invalid characters in principal name')

            principals.append(principal)

        if cert_type == CERT_TYPE_USER:
            options = cls._decode_options(options, cls._user_option_decoders,
                                          True)
            options.update(cls._decode_options(extensions,
                                               cls._user_extension_decoders,
                                               False))
        elif cert_type == CERT_TYPE_HOST:
            options = cls._decode_options(options, cls._host_option_decoders,
                                          True)
            options.update(cls._decode_options(extensions,
                                               cls._host_extension_decoders,
                                               False))
        else:
            raise KeyImportError('Unknown certificate type')

        return cls(algorithm, key, data, principals, options, signing_key,
                   serial, cert_type, key_id, valid_after, valid_before,
                   comment)

    @classmethod
    def _encode(cls, key, serial, cert_type, key_id, principals,
                valid_after, valid_before, options, extensions):
        """Encode an SSH certificate"""

        raise NotImplementedError

    @classmethod
    def _decode(cls, packet, key_handler):
        """Decode an SSH certificate"""

        raise NotImplementedError

    @staticmethod
    def _encode_options(options, encoders):
        """Encode options found in this certificate"""

        result = []

        for name, encoder in encoders:
            value = options.get(name)
            if value:
                result.append(String(name) + String(encoder(value)))

        return b''.join(result)

    @staticmethod
    def _encode_bool(value):
        """Encode a boolean option value"""

        # pylint: disable=unused-argument

        return b''

    @staticmethod
    def _encode_force_cmd(force_command):
        """Encode a force-command option"""

        return String(force_command)

    @staticmethod
    def _encode_source_addr(source_address):
        """Encode a source-address option"""

        return NameList(str(addr).encode('ascii') for addr in source_address)

    @staticmethod
    def _decode_bool(packet):
        """Decode a boolean option value"""

        # pylint: disable=unused-argument

        return True

    @staticmethod
    def _decode_force_cmd(packet):
        """Decode a force-command option"""

        try:
            return packet.get_string().decode('utf-8')
        except UnicodeDecodeError:
            raise KeyImportError('Invalid characters in command') from None

    @staticmethod
    def _decode_source_addr(packet):
        """Decode a source-address option"""

        try:
            return [ip_network(addr.decode('ascii'))
                    for addr in packet.get_namelist()]
        except (UnicodeDecodeError, ValueError):
            raise KeyImportError('Invalid source address') from None

    @staticmethod
    def _decode_options(options, decoders, critical=True):
        """Decode options found in this certificate"""

        packet = SSHPacket(options)
        result = {}

        while packet:
            name = packet.get_string()

            decoder = decoders.get(name)
            if decoder:
                data_packet = SSHPacket(packet.get_string())
                result[name.decode('ascii')] = decoder(data_packet)
                data_packet.check_end()
            elif critical:
                raise KeyImportError('Unrecognized critical option: %s' %
                                     name.decode('ascii', errors='replace'))

        return result

    def validate(self, cert_type, principal):
        """Validate an OpenSSH certificate"""

        if self._cert_type != cert_type:
            raise ValueError('Invalid certificate type')

        now = time.time()

        if now < self._valid_after:
            raise ValueError('Certificate not yet valid')

        if now >= self._valid_before:
            raise ValueError('Certificate expired')

        if principal and self.principals and principal not in self.principals:
            raise ValueError('Certificate principal mismatch')


class SSHOpenSSHCertificateV01(SSHOpenSSHCertificate):
    """Encoder/decoder class for version 01 OpenSSH certificates"""

    # pylint: disable=bad-whitespace

    _user_option_encoders = (
        ('force-command',           SSHOpenSSHCertificate._encode_force_cmd),
        ('source-address',          SSHOpenSSHCertificate._encode_source_addr)
    )

    _user_extension_encoders = (
        ('permit-X11-forwarding',   SSHOpenSSHCertificate._encode_bool),
        ('permit-agent-forwarding', SSHOpenSSHCertificate._encode_bool),
        ('permit-port-forwarding',  SSHOpenSSHCertificate._encode_bool),
        ('permit-pty',              SSHOpenSSHCertificate._encode_bool),
        ('permit-user-rc',          SSHOpenSSHCertificate._encode_bool)
    )

    _user_option_decoders = {
        b'force-command':           SSHOpenSSHCertificate._decode_force_cmd,
        b'source-address':          SSHOpenSSHCertificate._decode_source_addr
    }

    _user_extension_decoders = {
        b'permit-X11-forwarding':   SSHOpenSSHCertificate._decode_bool,
        b'permit-agent-forwarding': SSHOpenSSHCertificate._decode_bool,
        b'permit-port-forwarding':  SSHOpenSSHCertificate._decode_bool,
        b'permit-pty':              SSHOpenSSHCertificate._decode_bool,
        b'permit-user-rc':          SSHOpenSSHCertificate._decode_bool
    }

    # pylint: enable=bad-whitespace

    @classmethod
    def _encode(cls, key, serial, cert_type, key_id, principals,
                valid_after, valid_before, options, extensions):
        """Encode a version 01 SSH certificate"""

        return b''.join((String(os.urandom(32)), key.encode_ssh_public(),
                         UInt64(serial), UInt32(cert_type), String(key_id),
                         String(principals), UInt64(valid_after),
                         UInt64(valid_before), String(options),
                         String(extensions), String('')))

    @classmethod
    def _decode(cls, packet, key_handler):
        """Decode a version 01 SSH certificate"""

        _ = packet.get_string()                             # nonce
        key_params = key_handler.decode_ssh_public(packet)
        serial = packet.get_uint64()
        cert_type = packet.get_uint32()
        key_id = packet.get_string()
        principals = packet.get_string()
        valid_after = packet.get_uint64()
        valid_before = packet.get_uint64()
        options = packet.get_string()
        extensions = packet.get_string()
        _ = packet.get_string()                             # reserved

        return (key_params, serial, cert_type, key_id, principals,
                valid_after, valid_before, options, extensions)


class SSHX509Certificate(SSHCertificate):
    """Encoder/decoder class for SSH X.509 certificates"""

    is_x509 = True

    def __init__(self, key, x509_cert):
        super().__init__(b'x509v3-' + key.algorithm, key.x509_algorithms,
                         key.x509_algorithms, key, x509_cert.data,
                         x509_cert.comment)

        self.subject = x509_cert.subject
        self.issuer = x509_cert.issuer
        self.issuer_hash = x509_cert.issuer_hash
        self.user_principals = x509_cert.user_principals
        self.x509_cert = x509_cert

    def _expand_trust_store(self, cert, trusted_cert_paths, trust_store):
        """Look up certificates by issuer hash to build a trust store"""

        issuer_hash = cert.issuer_hash

        for path in trusted_cert_paths:
            idx = 0

            try:
                while True:
                    cert_path = os.path.join(path, issuer_hash + '.' + str(idx))
                    idx += 1

                    c = read_certificate(cert_path)

                    if c.subject != cert.issuer or c in trust_store:
                        continue

                    trust_store.add(c)
                    self._expand_trust_store(c, trusted_cert_paths, trust_store)
            except (OSError, KeyImportError):
                pass

    @classmethod
    def generate(cls, signing_key, key, subject, issuer, serial, valid_after,
                 valid_before, ca, ca_path_len, purposes, user_principals,
                 host_principals, hash_alg, comment):
        """Generate a new X.509 certificate"""

        key = key.convert_to_public()

        if isinstance(comment, str):
            comment = comment.encode('utf-8')

        x509_cert = generate_x509_certificate(signing_key, key, subject, issuer,
                                              serial, valid_after, valid_before,
                                              ca, ca_path_len, purposes,
                                              user_principals, host_principals,
                                              hash_alg, comment)

        return cls(key, x509_cert)

    @classmethod
    def construct(cls, data):
        """Construct an SSH X.509 certificate from DER data"""

        try:
            x509_cert = import_x509_certificate(data)
            key = import_public_key(x509_cert.key_data)
        except ValueError as exc:
            raise KeyImportError(str(exc)) from None

        return cls(key, x509_cert)

    def validate_chain(self, trust_chain, trusted_certs, trusted_cert_paths,
                       purposes, user_principal=None, host_principal=None):
        """Validate an X.509 certificate chain"""

        trust_chain = set(c for c in trust_chain if c.subject != c.issuer)
        trust_store = trust_chain | set(c for c in trusted_certs)

        if trusted_cert_paths:
            self._expand_trust_store(self, trusted_cert_paths, trust_store)

            for c in trust_chain:
                self._expand_trust_store(c, trusted_cert_paths, trust_store)

        self.x509_cert.validate([c.x509_cert for c in trust_store],
                                purposes, user_principal, host_principal)


class SSHX509CertificateChain(SSHCertificate):
    """Encoder/decoder class for an SSH X.509 certificate chain"""

    is_x509_chain = True

    def __init__(self, algorithm, data, certs, ocsp_responses, comment):
        key = certs[0].key

        super().__init__(algorithm, key.x509_algorithms, key.x509_algorithms,
                         key, data, comment)

        self.subject = certs[0].subject
        self.issuer = certs[-1].issuer
        self.user_principals = certs[0].user_principals

        self._certs = certs
        self._ocsp_responses = ocsp_responses

    @classmethod
    def construct(cls, packet, algorithm, key_handler, comment=None):
        """Construct an SSH X.509 certificate from packetized data"""

        # pylint: disable=unused-argument

        cert_count = packet.get_uint32()
        certs = [import_certificate(packet.get_string())
                 for _ in range(cert_count)]

        ocsp_resp_count = packet.get_uint32()
        ocsp_responses = [packet.get_string() for _ in range(ocsp_resp_count)]

        packet.check_end()

        data = packet.get_consumed_payload()

        if not certs:
            raise KeyImportError('No certificates present')

        return cls(algorithm, data, certs, ocsp_responses, comment)

    @classmethod
    def construct_from_certs(cls, certs):
        """Construct an SSH X.509 certificate chain from certificates"""

        cert = certs[0]
        algorithm = cert.algorithm
        data = (String(algorithm) + UInt32(len(certs)) +
                b''.join(String(c.data) for c in certs) + UInt32(0))

        return cls(algorithm, data, certs, (), cert.get_comment_bytes())

    def validate_chain(self, trusted_certs, trusted_cert_paths, revoked_certs,
                       purposes, user_principal=None, host_principal=None):
        """Validate an X.509 certificate chain"""

        if revoked_certs:
            for cert in self._certs:
                if cert in revoked_certs:
                    raise ValueError('Revoked X.509 certificate in '
                                     'certificate chain')

        self._certs[0].validate_chain(self._certs[1:], trusted_certs,
                                      trusted_cert_paths, purposes,
                                      user_principal, host_principal)


class SSHKeyPair:
    """Parent class which represents an asymmetric key pair

       This is an abstract class which provides a method to sign data
       with a private key and members to access the corresponding
       algorithm and public key or certificate information needed to
       identify what key was used for signing.

    """

    _key_type = 'unknown'

    def __init__(self, algorithm, public_data, comment):
        self.algorithm = algorithm
        self.public_data = public_data
        self.set_comment(comment)

    def get_key_type(self):
        """Return what type of key pair this is

           This method returns 'local' for locally loaded keys, and
           'agent' for keys managed by an SSH agent.

        """

        return self._key_type

    def get_algorithm(self):
        """Return the algorithm associated with this key pair"""

        return self.algorithm.decode('ascii')

    def get_comment_bytes(self):
        """Return the comment associated with this key pair as a
           byte string

           :returns: `bytes` or `None`

        """

        return self._comment

    def get_comment(self, encoding='utf-8'):
        """Return the comment associated with this key pair as a
           Unicode string

           :param encoding:
               The encoding to use to decode the comment as a Unicode
               string, defaulting to UTF-8
           :type encoding: `str`

           :returns: `str` or `None`

           :raises: :exc:`UnicodeDecodeError` if the comment cannot be
                    decoded using the specified encoding

        """

        return self._comment.decode(encoding) if self._comment else None

    def set_comment(self, comment, encoding='utf-8'):
        """Set the comment associated with this key pair

           :param comment:
               The new comment to associate with this key
           :param encoding:
               The Unicode encoding to use to encode the comment,
               defaulting to UTF-8
           :type comment: `str`, `bytes`, or `None`
           :type encoding: `str`

           :raises: :exc:`UnicodeEncodeError` if the comment cannot be
                    encoded using the specified encoding

        """

        if isinstance(comment, str):
            comment = comment.encode(encoding)

        self._comment = comment or None

    def set_sig_algorithm(self, sig_algorithm):
        """Set the signature algorithm to use when signing data"""

        raise NotImplementedError

    def sign(self, data):
        """Sign a block of data with this private key"""

        raise NotImplementedError


class SSHLocalKeyPair(SSHKeyPair):
    """Class which holds a local asymmetric key pair

       This class holds a private key and associated public data
       which can either be the matching public key or a certificate
       which has signed that public key.

    """

    _key_type = 'local'

    def __init__(self, key, cert=None):
        super().__init__(cert.algorithm if cert else key.algorithm,
                         cert.data if cert else key.get_ssh_public_key(),
                         key.get_comment_bytes())

        self._key = key
        self._cert = cert

        self.sig_algorithm = key.algorithm

        if cert:
            if key.get_ssh_public_key() != cert.key.get_ssh_public_key():
                raise ValueError('Certificate key mismatch')

            self.sig_algorithms = cert.sig_algorithms
            self.host_key_algorithms = cert.host_key_algorithms
        else:
            self.sig_algorithms = key.sig_algorithms
            self.host_key_algorithms = key.sig_algorithms

    def get_agent_private_key(self):
        """Return binary encoding of keypair for upload to SSH agent"""

        if self._cert:
            data = String(self.public_data) + \
                       self._key.encode_agent_cert_private()
        else:
            data = self._key.encode_ssh_private()

        return String(self.algorithm) + data

    def set_sig_algorithm(self, sig_algorithm):
        """Set the signature algorithm to use when signing data"""

        if sig_algorithm.startswith(b'x509v3-'):
            sig_algorithm = sig_algorithm[7:]

        self.sig_algorithm = sig_algorithm

        if not self._cert:
            self.algorithm = sig_algorithm
        elif self._cert.algorithm.startswith(b'x509v3-'):
            self.algorithm = b'x509v3-' + sig_algorithm

    def sign(self, data):
        """Sign a block of data with this private key"""

        return self._key.sign(data, self.sig_algorithm)


def _decode_pkcs1_private(pem_name, key_data):
    """Decode a PKCS#1 format private key"""

    handler = _pem_map.get(pem_name)
    if handler is None:
        raise KeyImportError('Unknown PEM key type: %s' %
                             pem_name.decode('ascii'))

    key_params = handler.decode_pkcs1_private(key_data)
    if key_params is None:
        raise KeyImportError('Invalid %s private key' %
                             pem_name.decode('ascii'))

    return handler.make_private(*key_params)


def _decode_pkcs1_public(pem_name, key_data):
    """Decode a PKCS#1 format public key"""

    handler = _pem_map.get(pem_name)
    if handler is None:
        raise KeyImportError('Unknown PEM key type: %s' %
                             pem_name.decode('ascii'))

    key_params = handler.decode_pkcs1_public(key_data)
    if key_params is None:
        raise KeyImportError('Invalid %s public key' %
                             pem_name.decode('ascii'))

    return handler.make_public(*key_params)


def _decode_pkcs8_private(key_data):
    """Decode a PKCS#8 format private key"""

    if (isinstance(key_data, tuple) and len(key_data) >= 3 and
            key_data[0] in (0, 1) and isinstance(key_data[1], tuple) and
            len(key_data[1]) == 2 and isinstance(key_data[2], bytes)):
        alg, alg_params = key_data[1]

        handler = _pkcs8_oid_map.get(alg)
        if handler is None:
            raise KeyImportError('Unknown PKCS#8 algorithm')

        key_params = handler.decode_pkcs8_private(alg_params, key_data[2])
        if key_params is None:
            raise KeyImportError('Invalid %s private key' %
                                 handler.pem_name.decode('ascii'))

        return handler.make_private(*key_params)
    else:
        raise KeyImportError('Invalid PKCS#8 private key')


def _decode_pkcs8_public(key_data):
    """Decode a PKCS#8 format public key"""

    if (isinstance(key_data, tuple) and len(key_data) == 2 and
            isinstance(key_data[0], tuple) and len(key_data[0]) == 2 and
            isinstance(key_data[1], BitString) and key_data[1].unused == 0):
        alg, alg_params = key_data[0]

        handler = _pkcs8_oid_map.get(alg)
        if handler is None:
            raise KeyImportError('Unknown PKCS#8 algorithm')

        key_params = handler.decode_pkcs8_public(alg_params, key_data[1].value)
        if key_params is None:
            raise KeyImportError('Invalid %s public key' %
                                 handler.pem_name.decode('ascii'))

        return handler.make_public(*key_params)
    else:
        raise KeyImportError('Invalid PKCS#8 public key')


def _decode_openssh_private(data, passphrase):
    """Decode an OpenSSH format private key"""

    try:
        if not data.startswith(_OPENSSH_KEY_V1):
            raise KeyImportError('Unrecognized OpenSSH private key type')

        data = data[len(_OPENSSH_KEY_V1):]
        packet = SSHPacket(data)

        cipher_name = packet.get_string()
        kdf = packet.get_string()
        kdf_data = packet.get_string()
        nkeys = packet.get_uint32()
        _ = packet.get_string()                 # public_key
        key_data = packet.get_string()
        mac = packet.get_remaining_payload()

        if nkeys != 1:
            raise KeyImportError('Invalid OpenSSH private key')

        if cipher_name != b'none':
            if passphrase is None:
                raise KeyImportError('Passphrase must be specified to import '
                                     'encrypted private keys')

            try:
                key_size, iv_size, block_size, _, _, _ = \
                    get_encryption_params(cipher_name)
            except KeyError:
                raise KeyEncryptionError('Unknown cipher: %s' %
                                         cipher_name.decode('ascii')) from None

            if kdf != b'bcrypt':
                raise KeyEncryptionError('Unknown kdf: %s' %
                                         kdf.decode('ascii'))

            if not _bcrypt_available: # pragma: no cover
                raise KeyEncryptionError('OpenSSH private key encryption '
                                         'requires bcrypt with KDF support')

            packet = SSHPacket(kdf_data)
            salt = packet.get_string()
            rounds = packet.get_uint32()
            packet.check_end()

            if isinstance(passphrase, str):
                passphrase = passphrase.encode('utf-8')

            try:
                # pylint: disable=no-member
                key = bcrypt.kdf(passphrase, salt, key_size + iv_size,
                                 rounds, ignore_few_rounds=True)
                # pylint: enable=no-member
            except ValueError:
                raise KeyEncryptionError('Invalid OpenSSH '
                                         'private key') from None

            cipher = get_encryption(cipher_name, key[:key_size], key[key_size:])

            key_data = cipher.decrypt_packet(0, b'', key_data, 0, mac)

            if key_data is None:
                raise KeyEncryptionError('Incorrect passphrase')

            block_size = max(block_size, 8)
        else:
            block_size = 8

        packet = SSHPacket(key_data)

        check1 = packet.get_uint32()
        check2 = packet.get_uint32()
        if check1 != check2:
            if cipher_name != b'none':
                raise KeyEncryptionError('Incorrect passphrase') from None
            else:
                raise KeyImportError('Invalid OpenSSH private key')

        alg = packet.get_string()
        handler = _public_key_alg_map.get(alg)
        if not handler:
            raise KeyImportError('Unknown OpenSSH private key algorithm')

        key_params = handler.decode_ssh_private(packet)
        comment = packet.get_string()
        pad = packet.get_remaining_payload()

        if len(pad) >= block_size or pad != bytes(range(1, len(pad) + 1)):
            raise KeyImportError('Invalid OpenSSH private key')

        key = handler.make_private(*key_params)
        key.set_comment(comment)
        return key
    except PacketDecodeError:
        raise KeyImportError('Invalid OpenSSH private key')


def _decode_der_private(data, passphrase):
    """Decode a DER format private key"""

    try:
        # pylint: disable=unpacking-non-sequence
        key_data, end = der_decode(data, partial_ok=True)
        # pylint: enable=unpacking-non-sequence
    except ASN1DecodeError:
        raise KeyImportError('Invalid DER private key') from None

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
            return _decode_pkcs1_private(pem_name, key_data), end
        except KeyImportError:
            # Try the next PKCS#1 encoding
            pass

    raise KeyImportError('Invalid DER private key')


def _decode_der_public(data):
    """Decode a DER format public key"""

    try:
        # pylint: disable=unpacking-non-sequence
        key_data, end = der_decode(data, partial_ok=True)
        # pylint: enable=unpacking-non-sequence
    except ASN1DecodeError:
        raise KeyImportError('Invalid DER public key') from None

    # First, try to decode PKCS#8
    try:
        return _decode_pkcs8_public(key_data), end
    except KeyImportError:
        # PKCS#8 failed - try PKCS#1 instead
        pass

    # If that fails, try each of the possible PKCS#1 encodings
    for pem_name in _pem_map:
        try:
            return _decode_pkcs1_public(pem_name, key_data), end
        except KeyImportError:
            # Try the next PKCS#1 encoding
            pass

    raise KeyImportError('Invalid DER public key')


def _decode_der_certificate(data):
    """Decode a DER format X.509 certificate"""

    return SSHX509Certificate.construct(data)


def _decode_der_certificate_list(data):
    """Decode a DER format X.509 certificate list"""

    certs = []

    while data:
        try:
            _, end = der_decode(data, partial_ok=True)
        except ASN1DecodeError:
            raise KeyImportError('Invalid DER certificate') from None

        certs.append(_decode_der_certificate(data[:end]))
        data = data[end:]

    return certs

def _decode_pem(lines, keytype):
    """Decode a PEM format key"""

    start = None
    line = ''
    for i, line in enumerate(lines):
        line = line.strip()
        if (line.startswith(b'-----BEGIN ') and
                line.endswith(b' ' + keytype + b'-----')):
            start = i+1
            break

    if not start:
        raise KeyImportError('Missing PEM header of type %s' %
                             keytype.decode('ascii'))

    pem_name = line[11:-(6+len(keytype))].strip()
    if pem_name:
        keytype = pem_name + b' ' + keytype

    headers = {}
    for start, line in enumerate(lines[start:], start):
        line = line.strip()
        if b':' in line:
            hdr, value = line.split(b':')
            headers[hdr.strip()] = value.strip()
        else:
            break

    end = None
    tail = b'-----END ' + keytype + b'-----'
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
        raise KeyImportError('Invalid PEM data') from None

    return pem_name, headers, data, end+1


def _decode_pem_private(lines, passphrase):
    """Decode a PEM format private key"""

    pem_name, headers, data, end = _decode_pem(lines, b'PRIVATE KEY')

    if pem_name == b'OPENSSH':
        return _decode_openssh_private(data, passphrase), end

    if headers.get(b'Proc-Type') == b'4,ENCRYPTED':
        if passphrase is None:
            raise KeyImportError('Passphrase must be specified to import '
                                 'encrypted private keys')

        dek_info = headers.get(b'DEK-Info', b'').split(b',')
        if len(dek_info) != 2:
            raise KeyImportError('Invalid PEM encryption params')

        alg, iv = dek_info
        try:
            iv = binascii.a2b_hex(iv)
        except binascii.Error:
            raise KeyImportError('Invalid PEM encryption params') from None

        try:
            data = pkcs1_decrypt(data, alg, iv, passphrase)
        except KeyEncryptionError:
            raise KeyImportError('Unable to decrypt PKCS#1 '
                                 'private key') from None

    try:
        key_data = der_decode(data)
    except ASN1DecodeError:
        raise KeyImportError('Invalid PEM private key') from None

    if pem_name == b'ENCRYPTED':
        if passphrase is None:
            raise KeyImportError('Passphrase must be specified to import '
                                 'encrypted private keys')

        pem_name = b''

        try:
            key_data = pkcs8_decrypt(key_data, passphrase)
        except KeyEncryptionError:
            raise KeyImportError('Unable to decrypt PKCS#8 '
                                 'private key') from None

    if pem_name:
        return _decode_pkcs1_private(pem_name, key_data), end
    else:
        return _decode_pkcs8_private(key_data), end


def _decode_pem_public(lines):
    """Decode a PEM format public key"""

    pem_name, _, data, end = _decode_pem(lines, b'PUBLIC KEY')

    try:
        key_data = der_decode(data)
    except ASN1DecodeError:
        raise KeyImportError('Invalid PEM public key') from None

    if pem_name:
        return _decode_pkcs1_public(pem_name, key_data), end
    else:
        return _decode_pkcs8_public(key_data), end


def _decode_pem_certificate(lines):
    """Decode a PEM format X.509 certificate"""

    pem_name, _, data, end = _decode_pem(lines, b'CERTIFICATE')

    if pem_name:
        raise KeyImportError('Invalid PEM certificate')

    return SSHX509Certificate.construct(data), end


def _decode_pem_certificate_list(lines):
    """Decode a PEM format X.509 certificate list"""

    certs = []

    while lines:
        cert, end = _decode_pem_certificate(lines)
        certs.append(cert)
        lines = lines[end:]

    return certs


def _decode_openssh(line):
    """Decode an OpenSSH format public key or certificate"""

    line = line.split(None, 2)
    if len(line) < 2:
        raise KeyImportError('Invalid OpenSSH public key or certificate')
    elif len(line) == 2:
        comment = None
    else:
        comment = line[2]

    try:
        return line[0], binascii.a2b_base64(line[1]), comment
    except binascii.Error:
        raise KeyImportError('Invalid OpenSSH public key '
                             'or certificate') from None


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

    hdr = b''
    comment = None

    for start, line in enumerate(lines[start:], start):
        line = line.strip()
        if line[-1:] == b'\\':
            hdr += line[:-1]
        else:
            hdr += line
            if b':' in hdr:
                hdr, value = hdr.split(b':')

                if hdr.strip() == b'Comment':
                    comment = value.strip()
                    if comment[:1] == b'"' and comment[-1:] == b'"':
                        comment = comment[1:-1]

                hdr = b''
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
        return binascii.a2b_base64(b''.join(lines[start:end])), comment, end+1
    except binascii.Error:
        raise KeyImportError('Invalid RFC 4716 public key '
                             'or certificate') from None


def register_public_key_alg(algorithm, handler, sig_algorithms=None):
    """Register a new public key algorithm"""

    if not sig_algorithms:
        sig_algorithms = handler.sig_algorithms

    _public_key_alg_map[algorithm] = handler
    _public_key_algs.extend(sig_algorithms)

    if handler.pem_name:
        _pem_map[handler.pem_name] = handler

    if handler.pkcs8_oid:
        _pkcs8_oid_map[handler.pkcs8_oid] = handler


def register_certificate_alg(version, algorithm, cert_algorithm,
                             key_handler, cert_handler):
    """Register a new certificate algorithm"""

    _certificate_alg_map[cert_algorithm] = (key_handler, cert_handler)
    _certificate_algs.append(cert_algorithm)

    _certificate_version_map[algorithm, version] = \
        (cert_algorithm, cert_handler)


def register_x509_certificate_alg(cert_algorithm):
    """Register a new X.509 certificate algorithm"""

    if _x509_available: # pragma: no branch
        _certificate_alg_map[cert_algorithm] = (None, SSHX509CertificateChain)
        _x509_certificate_algs.append(cert_algorithm)


def get_public_key_algs():
    """Return supported public key algorithms"""

    return _public_key_algs


def get_certificate_algs():
    """Return supported certificate-based public key algorithms"""

    return _certificate_algs


def get_x509_certificate_algs():
    """Return supported X.509 certificate-based public key algorithms"""

    return _x509_certificate_algs


def decode_ssh_public_key(data):
    """Decode a packetized SSH public key"""

    try:
        packet = SSHPacket(data)
        alg = packet.get_string()
        handler = _public_key_alg_map.get(alg)

        if handler:
            key_params = handler.decode_ssh_public(packet)
            packet.check_end()

            key = handler.make_public(*key_params)
            key.algorithm = alg
            return key
        else:
            raise KeyImportError('Unknown key algorithm: %s' %
                                 alg.decode('ascii', errors='replace'))
    except PacketDecodeError:
        raise KeyImportError('Invalid public key') from None


def decode_ssh_certificate(data, comment=None):
    """Decode a packetized SSH certificate"""

    try:
        packet = SSHPacket(data)
        alg = packet.get_string()
        key_handler, cert_handler = _certificate_alg_map.get(alg, (None, None))

        if cert_handler:
            return cert_handler.construct(packet, alg, key_handler, comment)
        else:
            raise KeyImportError('Unknown certificate algorithm: %s' %
                                 alg.decode('ascii', errors='replace'))
    except (PacketDecodeError, ValueError):
        raise KeyImportError('Invalid OpenSSH certificate') from None


def generate_private_key(alg_name, comment=None, **kwargs):
    """Generate a new private key

       This function generates a new private key of a type matching
       the requested SSH algorithm. Depending on the algorithm, additional
       parameters can be passed which affect the generated key.

       Available algorithms include:

           ssh-dss, ssh-rsa, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384,
           ecdsa-sha2-nistp521, ssh-ed25519

       For ssh-dss, no parameters are supported. The key size is fixed at
       1024 bits due to the use of SHA1 signatures.

       For ssh-rsa, the key size can be specified using the `key_size`
       parameter, and the RSA public exponent can be changed using the
       `exponent` parameter. By default, generated keys are 2048 bits
       with a public exponent of 65537.

       For ecdsa, the curve to use is part of the SSH algorithm name
       and that determines the key size. No other parameters are supported.

       For ssh-ed25519, no parameters are supported. The key size is fixed
       by the algorithm at 256 bits.

       :param alg_name:
           The SSH algorithm name corresponding to the desired type of key.
       :param comment: (optional)
           A comment to associate with this key.
       :param key_size: (optional)
           The key size in bits for RSA keys.
       :param exponent: (optional)
           The public exponent for RSA keys.
       :type alg_name: `str`
       :type comment: `str`, `bytes`, or `None`
       :type key_size: `int`
       :type exponent: `int`

       :returns: An :class:`SSHKey` private key

       :raises: :exc:`KeyGenerationError` if the requested key parameters
                are unsupported
    """

    algorithm = alg_name.encode('utf-8')
    handler = _public_key_alg_map.get(algorithm)

    if handler:
        try:
            key = handler.generate(algorithm, **kwargs)
        except (TypeError, ValueError) as exc:
            raise KeyGenerationError(str(exc)) from None
    else:
        raise KeyGenerationError('Unknown algorithm: %s' % alg_name)

    key.set_comment(comment)
    return key

def import_private_key(data, passphrase=None):
    """Import a private key

       This function imports a private key encoded in PKCS#1 or PKCS#8 DER
       or PEM format or OpenSSH format. Encrypted private keys can be
       imported by specifying the passphrase needed to decrypt them.

       :param data:
           The data to import.
       :param passphrase: (optional)
           The passphrase to use to decrypt the key.
       :type data: `bytes` or ASCII `str`
       :type passphrase: `str` or `bytes`

       :returns: An :class:`SSHKey` private key

    """

    if isinstance(data, str):
        try:
            data = data.encode('ascii')
        except UnicodeEncodeError:
            raise KeyImportError('Invalid encoding for private key') from None

    stripped_key = data.lstrip()
    if stripped_key.startswith(b'-----'):
        key, _ = _decode_pem_private(stripped_key.splitlines(), passphrase)
    else:
        key, _ = _decode_der_private(data, passphrase)

    return key


def import_private_key_and_certs(data, passphrase=None):
    """Import a private key and optional certificate chain"""

    stripped_key = data.lstrip()
    if stripped_key.startswith(b'-----'):
        lines = stripped_key.splitlines()
        key, end = _decode_pem_private(lines, passphrase)

        lines = lines[end:]
        certs = _decode_pem_certificate_list(lines) if any(lines) else None
    else:
        key, end = _decode_der_private(data, passphrase)

        data = data[end:]
        certs = _decode_der_certificate_list(data) if data else None

    if certs:
        chain = SSHX509CertificateChain.construct_from_certs(certs)
    else:
        chain = None

    return key, chain


def import_public_key(data):
    """Import a public key

       This function imports a public key encoded in OpenSSH, RFC4716, or
       PKCS#1 or PKCS#8 DER or PEM format.

       :param data:
           The data to import.
       :type data: `bytes` or ASCII `str`

       :returns: An :class:`SSHKey` public key

    """

    if isinstance(data, str):
        try:
            data = data.encode('ascii')
        except UnicodeEncodeError:
            raise KeyImportError('Invalid encoding for public key') from None

    stripped_key = data.lstrip()
    if stripped_key.startswith(b'-----'):
        key, _ = _decode_pem_public(stripped_key.splitlines())
    elif stripped_key.startswith(b'---- '):
        data, comment, _ = _decode_rfc4716(stripped_key.splitlines())
        key = decode_ssh_public_key(data)
        key.set_comment(comment)
    elif data.startswith(b'\x30'):
        key, _ = _decode_der_public(data)
    elif data:
        algorithm, data, comment = _decode_openssh(stripped_key.splitlines()[0])
        key = decode_ssh_public_key(data)

        if algorithm != key.algorithm:
            raise KeyImportError('Public key algorithm mismatch')

        key.set_comment(comment)
    else:
        raise KeyImportError('Invalid public key')

    return key


def import_certificate(data):
    """Import a certificate

       This function imports an SSH certificate in DER, PEM, OpenSSH, or
       RFC4716 format.

       :param data:
           The data to import.
       :type data: `bytes` or ASCII `str`

       :returns: An :class:`SSHCertificate` object

    """

    if isinstance(data, str):
        try:
            data = data.encode('ascii')
        except UnicodeEncodeError:
            raise KeyImportError('Invalid encoding for certificate') from None

    stripped_key = data.lstrip()
    if stripped_key.startswith(b'-----'):
        cert, _ = _decode_pem_certificate(stripped_key.splitlines())
    elif data.startswith(b'\x30'):
        cert = _decode_der_certificate(data)
    elif stripped_key.startswith(b'---- '):
        data, comment, _ = _decode_rfc4716(stripped_key.splitlines())
        cert = decode_ssh_certificate(data, comment)
    else:
        algorithm, data, comment = _decode_openssh(stripped_key.splitlines()[0])

        if algorithm.startswith(b'x509v3-'):
            cert = _decode_der_certificate(data)
        else:
            cert = decode_ssh_certificate(data, comment)

    return cert


def import_certificate_subject(data):
    """Import an X.509 certificate subject name"""

    try:
        algorithm, data = data.strip().split(None, 1)
    except ValueError:
        raise KeyImportError('Missing certificate subject algorithm') from None

    if algorithm.startswith('x509v3-'):
        match = _subject_pattern.match(data)

        if match:
            return data[match.end():]

    raise KeyImportError('Invalid certificate subject')


def read_private_key(filename, passphrase=None):
    """Read a private key from a file

       This function reads a private key from a file. See the function
       :func:`import_private_key` for information about the formats
       supported.

       :param filename:
           The file to read the key from.
       :param passphrase: (optional)
           The passphrase to use to decrypt the key.
       :type filename: `str`
       :type passphrase: `str` or `bytes`

       :returns: An :class:`SSHKey` private key

    """

    with open(filename, 'rb') as f:
        key = import_private_key(f.read(), passphrase)

    if not key.get_comment_bytes():
        key.set_comment(filename)

    return key


def read_private_key_and_certs(filename, passphrase=None):
    """Read a private key and optional certificate chain from a file"""

    with open(filename, 'rb') as f:
        key, cert = import_private_key_and_certs(f.read(), passphrase)

    if not key.get_comment_bytes():
        key.set_comment(filename)

    return key, cert


def read_public_key(filename):
    """Read a public key from a file

       This function reads a public key from a file. See the function
       :func:`import_public_key` for information about the formats
       supported.

       :param filename:
           The file to read the key from.
       :type filename: `str`

       :returns: An :class:`SSHKey` public key

    """

    with open(filename, 'rb') as f:
        key = import_public_key(f.read())

    if not key.get_comment_bytes():
        key.set_comment(filename)

    return key


def read_certificate(filename):
    """Read a certificate from a file

       This function reads an SSH certificate from a file. See the
       function :func:`import_certificate` for information about the
       formats supported.

       :param filename:
           The file to read the certificate from.
       :type filename: `str`

       :returns: An :class:`SSHCertificate` object

    """

    with open(filename, 'rb') as f:
        return import_certificate(f.read())


def read_private_key_list(filename, passphrase=None):
    """Read a list of private keys from a file

       This function reads a list of private keys from a file. See the
       function :func:`import_private_key` for information about the
       formats supported. If any of the keys are encrypted, they must
       all be encrypted with the same passphrase.

       :param filename:
           The file to read the keys from.
       :param passphrase: (optional)
           The passphrase to use to decrypt the keys.
       :type filename: `str`
       :type passphrase: `str` or `bytes`

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

    for key in keys:
        if not key.get_comment_bytes():
            key.set_comment(filename)

    return keys


def read_public_key_list(filename):
    """Read a list of public keys from a file

       This function reads a list of public keys from a file. See the
       function :func:`import_public_key` for information about the
       formats supported.

       :param filename:
           The file to read the keys from.
       :type filename: `str`

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
            data, comment, end = _decode_rfc4716(lines)
            key = decode_ssh_public_key(data)
            key.set_comment(comment)
            keys.append(key)
            lines = lines[end:]
    elif data.startswith(b'\x30'):
        while data:
            key, end = _decode_der_public(data)
            keys.append(key)
            data = data[end:]
    else:
        for line in stripped_key.splitlines():
            algorithm, data, comment = _decode_openssh(line)
            key = decode_ssh_public_key(data)

            if algorithm != key.algorithm:
                raise KeyImportError('Public key algorithm mismatch')

            key.set_comment(comment)
            keys.append(key)

    for key in keys:
        if not key.get_comment_bytes():
            key.set_comment(filename)

    return keys


def read_certificate_list(filename):
    """Read a list of certificates from a file

       This function reads a list of SSH certificates from a file. See
       the function :func:`import_certificate` for information about
       the formats supported.

       :param filename:
           The file to read the certificates from.
       :type filename: `str`

       :returns: A list of :class:`SSHCertificate` certificates

    """

    with open(filename, 'rb') as f:
        data = f.read()

    certs = []

    stripped_key = data.strip()
    if stripped_key.startswith(b'-----'):
        certs = _decode_pem_certificate_list(stripped_key.splitlines())
    elif data.startswith(b'\x30'):
        certs = _decode_der_certificate_list(data)
    elif stripped_key.startswith(b'---- '):
        lines = stripped_key.splitlines()
        while lines:
            data, comment, end = _decode_rfc4716(lines)
            certs.append(decode_ssh_certificate(data, comment))
            lines = lines[end:]
    else:
        for line in stripped_key.splitlines():
            algorithm, data, comment = _decode_openssh(line)

            if algorithm.startswith(b'x509v3-'):
                cert = _decode_der_certificate(data)
            else:
                cert = decode_ssh_certificate(data, comment)

            certs.append(cert)

    return certs


def load_keypairs(keylist, passphrase=None):
    """Load SSH private keys and optional matching certificates

       This function loads a list of SSH keys and optional matching
       certificates.

       When certificates are specified, the private key is added to
       the list both with and without the certificate.

       :param keylist:
           The list of private keys and certificates to load.
       :param passphrase: (optional)
           The passphrase to use to decrypt private keys.
       :type keylist: *see* :ref:`SpecifyingPrivateKeys`
       :type passphrase: `str` or `bytes`

       :returns: A list of :class:`SSHKeyPair` objects

    """

    result = []

    if isinstance(keylist, str):
        try:
            keys = read_private_key_list(keylist, passphrase)

            if len(keys) > 1:
                return [SSHLocalKeyPair(key) for key in keys]
        except KeyImportError:
            pass

        keylist = [keylist]
    elif isinstance(keylist, (tuple, bytes, SSHKey, SSHKeyPair)):
        keylist = [keylist]
    elif not keylist:
        keylist = []

    for key in keylist:
        if isinstance(key, SSHKeyPair):
            result.append(key)
        else:
            allow_certs = False
            default_cert_file = None
            ignore_missing_cert = False

            if isinstance(key, str):
                allow_certs = True
                default_cert_file = key + '-cert.pub'
                ignore_missing_cert = True
            elif isinstance(key, bytes):
                allow_certs = True
            elif isinstance(key, tuple):
                key, certs = key
            else:
                certs = None

            if isinstance(key, str):
                if allow_certs:
                    key, certs = read_private_key_and_certs(key, passphrase)

                    if not certs and default_cert_file:
                        certs = default_cert_file
                else:
                    key = read_private_key(key, passphrase)
            elif isinstance(key, bytes):
                if allow_certs:
                    key, certs = import_private_key_and_certs(key, passphrase)
                else:
                    key = import_private_key(key, passphrase)

            if certs:
                try:
                    certs = load_certificates(certs)
                except OSError:
                    if ignore_missing_cert:
                        certs = None
                    else:
                        raise

            if certs is None:
                cert = None
            elif len(certs) == 1 and not certs[0].is_x509:
                cert = certs[0]
            else:
                cert = SSHX509CertificateChain.construct_from_certs(certs)

            if cert:
                result.append(SSHLocalKeyPair(key, cert))

            result.append(SSHLocalKeyPair(key, None))

    return result


def load_default_keypairs(passphrase=None):
    """Return a list of default keys from the user's home directory"""

    result = []

    for file in _DEFAULT_KEY_FILES:
        try:
            file = os.path.join(os.path.expanduser('~'), '.ssh', file)
            result.extend(load_keypairs(file, passphrase))
        except KeyImportError as exc:
            # Ignore encrypted default keys if a passphrase isn't provided
            if not str(exc).startswith('Passphrase'):
                raise
        except OSError:
            pass

    return result


def load_public_keys(keylist):
    """Load public keys

       This function loads a list of SSH public keys.

       :param keylist:
           The list of public keys to load.
       :type keylist: *see* :ref:`SpecifyingPublicKeys`

       :returns: A list of :class:`SSHKey` objects

    """

    if isinstance(keylist, str):
        return read_public_key_list(keylist)
    else:
        result = []

        for key in keylist:
            if isinstance(key, str):
                key = read_public_key(key)
            elif isinstance(key, bytes):
                key = import_public_key(key)

            result.append(key)

        return result


def load_certificates(certlist):
    """Load certificates

       This function loads a list of OpenSSH or X.509 certificates.

       :param certlist:
           The list of certificates to load.
       :type certlist: *see* :ref:`SpecifyingCertificates`

       :returns: A list of :class:`SSHCertificate` objects

    """

    if isinstance(certlist, SSHCertificate):
        return [certlist]
    elif isinstance(certlist, (bytes, str)):
        certlist = [certlist]

    result = []

    for cert in certlist:
        if isinstance(cert, str):
            certs = read_certificate_list(cert)
        elif isinstance(cert, bytes):
            certs = [import_certificate(cert)]
        elif isinstance(cert, SSHCertificate):
            certs = [cert]
        else:
            certs = cert

        result.extend(certs)

    return result
