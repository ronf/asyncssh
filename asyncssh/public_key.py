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

"""SSH asymmetric encryption handlers"""

import binascii
from datetime import datetime, timedelta
import os
import re
import time

try:
    import bcrypt
    _bcrypt_available = hasattr(bcrypt, 'kdf')
except ImportError: # pragma: no cover
    _bcrypt_available = False

from .asn1 import ASN1DecodeError, BitString, der_encode, der_decode
from .cipher import get_encryption_params, get_cipher
from .misc import ip_network
from .packet import NameList, String, UInt32, UInt64
from .packet import PacketDecodeError, SSHPacket
from .pbe import KeyEncryptionError, pkcs1_encrypt, pkcs8_encrypt
from .pbe import pkcs1_decrypt, pkcs8_decrypt


_public_key_algs = []
_certificate_algs = []
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
    pem_name = None
    pkcs8_oid = None

    def __init__(self):
        self._comment = None

    def _generate_certificate(self, key, version, serial, cert_type,
                              key_id, principals, valid_after,
                              valid_before, cert_options, comment):
        """Generate a new SSH certificate"""

        try:
            algorithm, cert_handler = _certificate_version_map[key.algorithm,
                                                               version]
        except KeyError:
            raise KeyGenerationError('Unknown certificate version') from None

        return cert_handler.generate(self, algorithm, key, serial, cert_type,
                                     key_id, principals, valid_after,
                                     valid_before, cert_options, comment)

    def get_algorithm(self):
        """Return the algorithm associated with this key"""

        return self.algorithm.decode('ascii')

    def get_comment(self):
        """Return the comment associated with this key

           :returns: `str` or ``None``

        """

        return self._comment

    def set_comment(self, comment):
        """Set the comment associated with this key

           :param comment:
               The new comment to associate with this key
           :type comment: `str` or ``None``

        """

        if isinstance(comment, bytes):
            try:
                comment = comment.decode('utf-8')
            except UnicodeDecodeError:
                raise KeyImportError('Invalid characters in comment') from None

        self._comment = comment or None

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
        result.set_comment(self.get_comment())
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

           This method returns a SSH user certifcate with the requested
           attributes signed by this private key.

           :param user_key:
               The user's public key.
           :param str key_id:
               The key identifier associated with this certificate.
           :param int version: (optional)
               The version of certificate to create, defaulting to 1.
           :param int serial: (optional)
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
           :param bool permit_x11_forwarding: (optional)
               Whether or not to allow this user to use X11 forwarding,
               defaulting to ``True``.
           :param bool permit_agent_forwarding: (optional)
               Whether or not to allow this user to use agent forwarding,
               defaulting to ``True``.
           :param bool permit_port_forwarding: (optional)
               Whether or not to allow this user to use port forwarding,
               defaulting to ``True``.
           :param bool permit_pty: (optional)
               Whether or not to allow this user to allocate a
               pseudo-terminal, defaulting to ``True``.
           :param bool permit_user_rc: (optional)
               Whether or not to run the user rc file when this certificate
               is used, defaulting to ``True``.
           :param comment:
               The comment to associate with this certificate. By default,
               the comment will be set to the comment currently set on
               user_key.
           :type user_key: :class:`SSHKey`
           :type principals: list of strings
           :type force_command: `str` or ``None``
           :type source_address: list of ip_address and ip_network values
           :type comment: `str` or ``None``

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

        if comment is ():
            comment = user_key.get_comment()

        return self._generate_certificate(user_key, version, serial,
                                          CERT_TYPE_USER, key_id,
                                          principals, valid_after,
                                          valid_before, cert_options, comment)

    def generate_host_certificate(self, host_key, key_id, version=1,
                                  serial=0, principals=(), valid_after=0,
                                  valid_before=0xffffffffffffffff,
                                  comment=()):
        """Generate a new SSH host certificate

           This method returns a SSH host certifcate with the requested
           attributes signed by this private key.

           :param host_key:
               The host's public key.
           :param str key_id:
               The key identifier associated with this certificate.
           :param int version: (optional)
               The version of certificate to create, defaulting to 1.
           :param int serial: (optional)
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
           :type principals: list of strings
           :type comment: `str` or ``None``

           :returns: :class:`SSHCertificate`

           :raises: | :exc:`ValueError` if the validity times are invalid
                    | :exc:`KeyGenerationError` if the requested certificate
                      parameters are unsupported
        """

        if comment is ():
            comment = host_key.get_comment()

        return self._generate_certificate(host_key, version, serial,
                                          CERT_TYPE_HOST, key_id,
                                          principals, valid_after,
                                          valid_before, {}, comment)

    def export_private_key(self, format_name='openssh', passphrase=None,
                           cipher_name='aes256-cbc', hash_name='sha256',
                           pbe_version=2, rounds=16):
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

               md5, sha1, sha256, sha384, sha512, sha512-224, sha512-256

           Available PBE versions include 1 for PBES1 and 2 for PBES2.

           Not all combinations of cipher, hash, and version are supported.

           The default cipher is aes256. In the pkcs8 formats, the default
           hash is sha256 and default version is PBES2. In openssh format,
           the default number of rounds is 16.

           :param str format_name: (optional)
               The format to export the key in.
           :param str passphrase: (optional)
               A passphrase to encrypt the private key with.
           :param str cipher_name: (optional)
               The cipher to use for private key encryption.
           :param str hash_name: (optional)
               The hash to use for private key encryption.
           :param int pbe_version: (optional)
               The PBE version to use for private key encryption.
           :param int rounds: (optional)
               The number of KDF rounds to apply to the passphrase.

           :returns: bytes representing the exported private key

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
                             String(self.get_comment() or '')))

            if passphrase is not None:
                try:
                    alg = cipher_name.encode('ascii')
                    key_size, iv_size, block_size, mode = \
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
                key = bcrypt.kdf(passphrase, salt, key_size + iv_size, rounds)
                # pylint: enable=no-member

                cipher = get_cipher(alg, key[:key_size], key[key_size:])
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
                if mode == 'chacha':
                    data, mac = cipher.encrypt_and_sign(b'', data, UInt64(0))
                elif mode == 'gcm':
                    data, mac = cipher.encrypt_and_sign(b'', data)
                else:
                    data, mac = cipher.encrypt(data), b''

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

           :param str format_name: (optional)
               The format to export the key in.

           :returns: bytes representing the exported public key

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
                comment = b' ' + self._comment.encode('utf-8')
            else:
                comment = b''

            return (self.algorithm + b' ' +
                    binascii.b2a_base64(data)[:-1] + comment + b'\n')
        elif format_name == 'rfc4716':
            data = self.get_ssh_public_key()

            if self._comment:
                comment = (b'Comment: "' +
                           self._comment.encode('utf-8') + b'"\n')
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

           :param str filename:
               The filename to write the private key to.
           :param \\*args,\\ \\*\\*kwargs:
               Additional arguments to pass through to
               :meth:`export_private_key`.

        """

        with open(filename, 'wb') as f:
            f.write(self.export_private_key(*args, **kwargs))

    def write_public_key(self, filename, *args, **kwargs):
        """Write a public key to a file in the requested format

           This method is a simple wrapper around :meth:`export_public_key`
           which writes the exported key data to a file.

           :param str filename:
               The filename to write the public key to.
           :param \\*args,\\ \\*\\*kwargs:
               Additional arguments to pass through to
               :meth:`export_public_key`.

        """

        with open(filename, 'wb') as f:
            f.write(self.export_public_key(*args, **kwargs))


class SSHCertificate:
    """Parent class which holds an SSH certificate"""

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
        self.algorithm = algorithm
        self.key = key
        self.data = data
        self.principals = principals
        self.options = options
        self.signing_key = signing_key

        self._serial = serial
        self._cert_type = cert_type
        self._key_id = key_id
        self._valid_after = valid_after
        self._valid_before = valid_before

        self.set_comment(comment)

    @classmethod
    def generate(cls, signing_key, algorithm, key, serial, cert_type, key_id,
                 principals, valid_after, valid_before, options, comment):
        """Generate a new SSH certificate"""

        principals = list(principals)
        valid_after = _parse_time(valid_after)
        valid_before = _parse_time(valid_before)

        if valid_before <= valid_after:
            raise ValueError('Valid before time must be later than '
                             'valid after time')

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

        data = b''.join((String(algorithm),
                         cls._encode(key, serial, cert_type, key_id,
                                     cert_principals, valid_after,
                                     valid_before, cert_options,
                                     cert_extensions),
                         String(signing_key.get_ssh_public_key())))

        data += String(signing_key.sign(data, signing_key.algorithm))

        key = key.convert_to_public()
        signing_key = signing_key.convert_to_public()

        return cls(algorithm, key, data, principals, options, signing_key,
                   serial, cert_type, key_id, valid_after, valid_before,
                   comment)

    @classmethod
    def construct(cls, packet, algorithm, key_handler, comment):
        """Construct an SSH certificate"""

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
    def _encode_force_command(force_command):
        """Encode a force-command option"""

        return String(force_command)

    @staticmethod
    def _encode_source_address(source_address):
        """Encode a source-address option"""

        return NameList(str(addr).encode('ascii') for addr in source_address)

    @staticmethod
    def _decode_bool(packet):
        """Decode a boolean option value"""

        # pylint: disable=unused-argument

        return True

    @staticmethod
    def _decode_force_command(packet):
        """Decode a force-command option"""

        try:
            return packet.get_string().decode('utf-8')
        except UnicodeDecodeError:
            raise KeyImportError('Invalid characters in command') from None

    @staticmethod
    def _decode_source_address(packet):
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

    def get_algorithm(self):
        """Return the algorithm associated with this certificate"""

        return self.algorithm.decode('ascii')

    def get_comment(self):
        """Return the comment associated with this certificate

           :returns: `str` or ``None``

        """

        return self._comment

    def set_comment(self, comment):
        """Set the comment associated with this certificate

           :param comment:
               The new comment to associate with this certificate
           :type comment: `str` or ``None``

        """

        if isinstance(comment, bytes):
            try:
                comment = comment.decode('utf-8')
            except UnicodeDecodeError:
                raise KeyImportError('Invalid characters in comment') from None

        self._comment = comment or None

    def export_certificate(self, format_name='openssh'):
        """Export a certificate in the requested format

           This function returns this certificate encoded in the requested
           format. Available formats include:

               openssh, rfc4716

           By default, openssh format will be used.

           :param str format_name: (optional)
               The format to export the certificate in.

           :returns: bytes representing the exported certificate

        """

        if format_name == 'openssh':
            if self._comment:
                comment = b' ' + self._comment.encode('utf-8')
            else:
                comment = b''

            return (self.algorithm + b' ' +
                    binascii.b2a_base64(self.data)[:-1] + comment + b'\n')
        elif format_name == 'rfc4716':
            if self._comment:
                comment = (b'Comment: "' +
                           self._comment.encode('utf-8') + b'"\n')
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

           :param str filename:
               The filename to write the certificate to.
           :param \\*args,\\ \\*\\*kwargs:
               Additional arguments to pass through to
               :meth:`export_certificate`.

        """

        with open(filename, 'wb') as f:
            f.write(self.export_certificate(*args, **kwargs))

    def validate(self, cert_type, principal):
        """Validate the certificate type, validity period, and principal

           This method validates that the certificate is of the specified
           type, that the current time is within the certificate validity
           period, and that the principal being authenticated is one of
           the certificate's valid principals.

           :param int cert_type:
               The expected :ref:`certificate type <CertificateTypes>`.
           :param str principal:
               The principal being authenticated.

           :raises: :exc:`ValueError` if any of the validity checks fail

        """

        if self._cert_type != cert_type:
            raise ValueError('Invalid certificate type')

        now = time.time()

        if now < self._valid_after:
            raise ValueError('Certificate not yet valid')

        if now >= self._valid_before:
            raise ValueError('Certificate expired')

        if principal and self.principals and principal not in self.principals:
            raise ValueError('Certificate principal mismatch')


class SSHCertificateV01(SSHCertificate):
    """Encoder/decoder class for version 01 SSH certificates"""

    # pylint: disable=bad-whitespace

    _user_option_encoders = (
        ('force-command',           SSHCertificate._encode_force_command),
        ('source-address',          SSHCertificate._encode_source_address)
    )

    _user_extension_encoders = (
        ('permit-X11-forwarding',   SSHCertificate._encode_bool),
        ('permit-agent-forwarding', SSHCertificate._encode_bool),
        ('permit-port-forwarding',  SSHCertificate._encode_bool),
        ('permit-pty',              SSHCertificate._encode_bool),
        ('permit-user-rc',          SSHCertificate._encode_bool)
    )

    _user_option_decoders = {
        b'force-command':           SSHCertificate._decode_force_command,
        b'source-address':          SSHCertificate._decode_source_address
    }

    _user_extension_decoders = {
        b'permit-X11-forwarding':   SSHCertificate._decode_bool,
        b'permit-agent-forwarding': SSHCertificate._decode_bool,
        b'permit-port-forwarding':  SSHCertificate._decode_bool,
        b'permit-pty':              SSHCertificate._decode_bool,
        b'permit-user-rc':          SSHCertificate._decode_bool
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


class SSHKeyPair:
    """Parent class which represents an asymmetric key pair

       This is an abstract class which provides a method to sign data
       with a private key and members to access the corresponding
       algorithm and public key or certificate information needed to
       identify what key was used for signing.

    """

    _key_type = 'unknown'

    def __init__(self, algorithm, comment):
        self.algorithm = algorithm
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

    def get_comment(self):
        """Return the comment associated with this key pair

           :returns: `str` or ``None``

        """

        return self._comment

    def set_comment(self, comment):
        """Set the comment associated with this key pair

           :param comment:
               The new comment to associate with this key pair
           :type comment: `str` or ``None``

        """

        if isinstance(comment, bytes):
            try:
                comment = comment.decode('utf-8')
            except UnicodeDecodeError:
                raise KeyImportError('Invalid characters in comment') from None

        self._comment = comment or None

    def set_sig_algorithm(self, sig_algorithm):
        """Set the signature algorithm to use when signing data"""

        raise NotImplementedError

    def sign(self, data):
        """Sign a block of data with this private key

           :param str data:
               The data to be signed.

           :returns: bytes containing the signature.

        """

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
                         key.get_comment())

        self._key = key
        self._cert = cert

        self.sig_algorithm = key.algorithm
        self.sig_algorithms = key.sig_algorithms

        if cert:
            if key.get_ssh_public_key() != cert.key.get_ssh_public_key():
                raise ValueError('Certificate key mismatch')

            self.host_key_algorithms = (cert.algorithm,)
            self.public_data = cert.data
        else:
            self.host_key_algorithms = self.sig_algorithms
            self.public_data = key.get_ssh_public_key()

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

        self.sig_algorithm = sig_algorithm

        if not self._cert:
            self.algorithm = sig_algorithm

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
                key_size, iv_size, block_size, mode = \
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
                key = bcrypt.kdf(passphrase, salt, key_size + iv_size, rounds)
                # pylint: enable=no-member
            except ValueError:
                raise KeyEncryptionError('Invalid OpenSSH '
                                         'private key') from None

            cipher = get_cipher(cipher_name, key[:key_size], key[key_size:])

            if mode == 'chacha':
                key_data = cipher.verify_and_decrypt(b'', key_data,
                                                     UInt64(0), mac)
                mac = b''
            elif mode == 'gcm':
                key_data = cipher.verify_and_decrypt(b'', key_data, mac)
                mac = b''
            else:
                key_data = cipher.decrypt(key_data)

            if key_data is None:
                raise KeyEncryptionError('Incorrect passphrase')

            block_size = max(block_size, 8)
        else:
            block_size = 8

        if mac:
            raise KeyImportError('Invalid OpenSSH private key')

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
        return binascii.a2b_base64(line[1]), comment
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


def get_public_key_algs():
    """Return supported public key algorithms"""

    return _public_key_algs


def get_certificate_algs():
    """Return supported certificate-based public key algorithms"""

    return _certificate_algs


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
    except PacketDecodeError:
        raise KeyImportError('Invalid certificate') from None


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

       For ssh-rsa, the key size can be specified using the ``key_size``
       parameter, and the RSA public exponent can be changed using the
       ``exponent`` parameter. By default, generated keys are 2048 bits
       with a public exponent of 65537.

       For ecdsa, the curve to use is part of the SSH algorithm name
       and that determines the key size. No other parameters are supported.

       For ssh-ed25519, no parameters are supported. The key size is fixed
       by the algorithm at 256 bits.

       :param str alg_name:
           The SSH algorithm name corresponding to the desired type of key.
       :param comment: (optional)
           A comment to associate with this key.
       :param int key_size: (optional)
           The key size in bits for RSA keys.
       :param int exponent: (optional)
           The public exponent for RSA keys.
       :type comment: `str` or ``None``

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
       :param str passphrase: (optional)
           The passphrase to use to decrypt the key.
       :type data: bytes or ASCII string

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


def import_public_key(data):
    """Import a public key

       This function imports a public key encoded in OpenSSH, RFC4716, or
       PKCS#1 or PKCS#8 DER or PEM format.

       :param data:
           The data to import.
       :type data: bytes or ASCII string

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
        data, comment = _decode_openssh(stripped_key.splitlines()[0])
        key = decode_ssh_public_key(data)
        key.set_comment(comment)
    else:
        raise KeyImportError('Invalid public key')

    return key


def import_certificate(data):
    """Import a certificate

       This function imports an SSH certificate in OpenSSH or RFC4716
       format.

       :param data:
           The data to import.
       :type data: bytes or ASCII string

       :returns: An :class:`SSHCertificate` certificate

    """

    if isinstance(data, str):
        try:
            data = data.encode('ascii')
        except UnicodeEncodeError:
            raise KeyImportError('Invalid encoding for certificate') from None

    stripped_key = data.lstrip()
    if stripped_key.startswith(b'---- '):
        data, comment, _ = _decode_rfc4716(stripped_key.splitlines())
    else:
        data, comment = _decode_openssh(stripped_key.splitlines()[0])

    return decode_ssh_certificate(data, comment)


def read_private_key(filename, passphrase=None):
    """Read a private key from a file

       This function reads a private key from a file. See the function
       :func:`import_private_key` for information about the formats
       supported.

       :param str filename:
           The file to read the key from.
       :param str passphrase: (optional)
           The passphrase to use to decrypt the key.

       :returns: An :class:`SSHKey` private key

    """

    with open(filename, 'rb') as f:
        key = import_private_key(f.read(), passphrase)

    if not key.get_comment():
        key.set_comment(filename)

    return key


def read_public_key(filename):
    """Read a public key from a file

       This function reads a public key from a file. See the function
       :func:`import_public_key` for information about the formats
       supported.

       :param str filename:
           The file to read the key from.

       :returns: An :class:`SSHKey` public key

    """

    with open(filename, 'rb') as f:
        key = import_public_key(f.read())

    if not key.get_comment():
        key.set_comment(filename)

    return key


def read_certificate(filename):
    """Read a certificate from a file

       This function reads an SSH certificate from a file. See the
       function :func:`import_certificate` for information about the
       formats supported.

       :param str filename:
           The file to read the certificate from.

       :returns: An :class:`SSHCertificate` certificate

    """

    with open(filename, 'rb') as f:
        return import_certificate(f.read())


def read_private_key_list(filename, passphrase=None):
    """Read a list of private keys from a file

       This function reads a list of private keys from a file. See the
       function :func:`import_private_key` for information about the
       formats supported. If any of the keys are encrypted, they must
       all be encrypted with the same passphrase.

       :param str filename:
           The file to read the keys from.
       :param str passphrase: (optional)
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

    for key in keys:
        if not key.get_comment():
            key.set_comment(filename)

    return keys


def read_public_key_list(filename):
    """Read a list of public keys from a file

       This function reads a list of public keys from a file. See the
       function :func:`import_public_key` for information about the
       formats supported.

       :param str filename:
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
            data, comment = _decode_openssh(line)
            key = decode_ssh_public_key(data)
            key.set_comment(comment)
            keys.append(key)

    for key in keys:
        if not key.get_comment():
            key.set_comment(filename)

    return keys


def read_certificate_list(filename):
    """Read a list of certificates from a file

       This function reads a list of SSH certificates from a file. See
       the function :func:`import_certificate` for information about
       the formats supported.

       :param str filename:
           The file to read the certificates from.

       :returns: A list of :class:`SSHCertificate` certificates

    """

    with open(filename, 'rb') as f:
        data = f.read()

    certs = []

    stripped_key = data.strip()
    if stripped_key.startswith(b'---- '):
        lines = stripped_key.splitlines()
        while lines:
            data, comment, end = _decode_rfc4716(lines)
            certs.append(decode_ssh_certificate(data, comment))
            lines = lines[end:]
    else:
        for line in stripped_key.splitlines():
            data, comment = _decode_openssh(line)
            certs.append(decode_ssh_certificate(data, comment))

    return certs


def load_keypairs(keylist, passphrase=None):
    """Load SSH private keys and optional matching certificates

       This function loads a list of SSH keys and optional matching
       certificates.

       When certificates are specified, the private key is added to
       the list both with and without the certificate.

       :param keylist:
           The list of private keys and certificates to import.
       :param str passphrase: (optional)
           The passphrase to use to decrypt private keys.
       :type keylist: *see* :ref:`SpecifyingPrivateKeys`

       :returns: A list of :class:`SSHKeyPair` objects

    """

    result = []

    if isinstance(keylist, str):
        keys = read_private_key_list(keylist, passphrase)

        if len(keys) == 1:
            try:
                cert = read_certificate(keylist + '-cert.pub')
            except OSError:
                cert = None

            if cert:
                result.append(SSHLocalKeyPair(keys[0], cert))

            result.append(SSHLocalKeyPair(keys[0]))
            return result
        else:
            return [SSHLocalKeyPair(key) for key in keys]
    elif isinstance(keylist, (tuple, bytes, SSHKey, SSHKeyPair)):
        keylist = [keylist]

    for key in keylist:
        if isinstance(key, SSHKeyPair):
            result.append(key)
        else:
            if isinstance(key, str):
                cert = key + '-cert.pub'
                ignore_missing_cert = True
            elif isinstance(key, tuple):
                key, cert = key
                ignore_missing_cert = False
            else:
                cert = None

            if isinstance(key, str):
                key = read_private_key(key, passphrase)
            elif isinstance(key, bytes):
                key = import_private_key(key, passphrase)

            if isinstance(cert, str):
                try:
                    cert = read_certificate(cert)
                except OSError:
                    if ignore_missing_cert:
                        cert = None
                    else:
                        raise
            elif isinstance(cert, bytes):
                cert = import_certificate(cert)

            if cert:
                result.append(SSHLocalKeyPair(key, cert))

            result.append(SSHLocalKeyPair(key, None))

    return result


def load_public_keys(keylist):
    """Load public keys

       This function loads a list of SSH public keys.

       :param keylist:
           The list of public keys to import.
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
