# Copyright (c) 2017 by Ron Frederick <ronf@timeheart.net>.
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

"""A shim around PyCA and PyOpenSSL for X.509 certificates"""

from datetime import datetime, timezone
from ipaddress import ip_address
import re
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import MD5, SHA1, SHA224
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography import x509

from OpenSSL import crypto

from ...asn1 import IA5String, der_decode, der_encode


# pylint: disable=bad-whitespace

_purpose_to_oid = {
    'serverAuth':        x509.ExtendedKeyUsageOID.SERVER_AUTH,
    'clientAuth':        x509.ExtendedKeyUsageOID.CLIENT_AUTH,
    'secureShellClient': x509.ObjectIdentifier('1.3.6.1.5.5.7.3.21'),
    'secureShellServer': x509.ObjectIdentifier('1.3.6.1.5.5.7.3.22')}

# pylint: enable=bad-whitespace

_purpose_any = x509.ObjectIdentifier('2.5.29.37.0')

_hashes = {h.name: h for h in (MD5, SHA1, SHA224, SHA256, SHA384, SHA512)}

_nscomment_oid = x509.ObjectIdentifier('2.16.840.1.113730.1.13')

if sys.platform == 'win32': # pragma: no cover
    # Windows' datetime.max is year 9999, but timestamps that large don't work
    _gen_time_max = datetime(2999, 12, 31, 23, 59, 59, 999999,
                             tzinfo=timezone.utc).timestamp() - 1
else:
    _gen_time_max = datetime.max.replace(tzinfo=timezone.utc).timestamp() - 1


def _to_generalized_time(t):
    """Convert a timestamp value to a datetime"""

    return datetime.utcfromtimestamp(max(1, min(t, _gen_time_max)))


def _to_purpose_oids(purposes):
    """Convert a list of purposes to purpose OIDs"""

    if isinstance(purposes, str):
        purposes = [p.strip() for p in purposes.split(',')]

    if not purposes or 'any' in purposes or _purpose_any in purposes:
        purposes = None
    else:
        purposes = set(_purpose_to_oid.get(p) or x509.ObjectIdentifier(p)
                       for p in purposes)

    return purposes


def _encode_user_principals(principals):
    """Encode user principals as e-mail addresses"""

    if isinstance(principals, str):
        principals = [p.strip() for p in principals.split(',')]

    return [x509.RFC822Name(name) for name in principals]


def _encode_host_principals(principals):
    """Encode host principals as DNS names or IP addresses"""

    def _encode_host(name):
        """Encode a host principal as a DNS name or IP address"""

        try:
            return x509.IPAddress(ip_address(name))
        except ValueError:
            return x509.DNSName(name)

    if isinstance(principals, str):
        principals = [p.strip() for p in principals.split(',')]

    return [_encode_host(name) for name in principals]


class X509Name(x509.Name):
    """A shim around PyCA for X.509 distinguished names"""

    _escape = re.compile(r'([,+\\])')
    _unescape = re.compile(r'\\([,+\\])')
    _split_rdn = re.compile(r'(?:[^+\\]+|\\.)+')
    _split_name = re.compile(r'(?:[^,\\]+|\\.)+')

# pylint: disable=bad-whitespace

    _attrs = (
        ('C',  x509.NameOID.COUNTRY_NAME),
        ('ST', x509.NameOID.STATE_OR_PROVINCE_NAME),
        ('L',  x509.NameOID.LOCALITY_NAME),
        ('O',  x509.NameOID.ORGANIZATION_NAME),
        ('OU', x509.NameOID.ORGANIZATIONAL_UNIT_NAME),
        ('CN', x509.NameOID.COMMON_NAME),
        ('DC', x509.NameOID.DOMAIN_COMPONENT))

# pylint: enable=bad-whitespace

    _to_oid = dict((k, v) for k, v in _attrs)
    _from_oid = dict((v, k) for k, v in _attrs)

    def __init__(self, name):
        if isinstance(name, str):
            name = self._parse_name(name)
        elif isinstance(name, x509.Name):
            name = name.rdns

        super().__init__(name)

    def __str__(self):
        return ','.join(self._format_rdn(rdn) for rdn in self.rdns)

    def _format_rdn(self, rdn):
        """Format an X.509 RelativeDistinguishedName as a string"""

        return '+'.join(sorted(self._format_attr(nameattr) for nameattr in rdn))

    def _format_attr(self, nameattr):
        """Format an X.509 NameAttribute as a string"""

        attr = self._from_oid.get(nameattr.oid) or nameattr.oid.dotted_string
        return attr + '=' + self._escape.sub(r'\\\1', nameattr.value)

    def _parse_name(self, name):
        """Parse an X.509 distinguished name"""

        return (self._parse_rdn(rdn) for rdn in self._split_name.findall(name))

    def _parse_rdn(self, rdn):
        """Parse an X.509 relative distinguished name"""

        return x509.RelativeDistinguishedName(
            self._parse_nameattr(av) for av in self._split_rdn.findall(rdn))

    def _parse_nameattr(self, av):
        """Parse an X.509 name attribute/value pair"""

        try:
            attr, value = av.split('=', 1)
        except ValueError:
            raise ValueError('Invalid X.509 name attribute: ' + av) from None

        try:
            attr = attr.strip()
            oid = self._to_oid.get(attr) or x509.ObjectIdentifier(attr)
        except ValueError:
            raise ValueError('Unknown X.509 attribute: ' + attr) from None

        return x509.NameAttribute(oid, self._unescape.sub(r'\1', value))


class X509NamePattern:
    """Match X.509 distinguished names"""

    def __init__(self, pattern):
        if pattern.endswith(',*'):
            self._pattern = X509Name(pattern[:-2])
            self._prefix_len = len(self._pattern.rdns)
        else:
            self._pattern = X509Name(pattern)
            self._prefix_len = None

    def __eq__(self, other):
        # This isn't protected access - both objects are _RSAKey instances
        # pylint: disable=protected-access

        return (isinstance(other, type(self)) and
                self._pattern == other._pattern and
                self._prefix_len == other._prefix_len)

    def __hash__(self):
        return hash((self._pattern, self._prefix_len))

    def matches(self, name):
        """Return whether an X.509 name matches this pattern"""

        return self._pattern.rdns == name.rdns[:self._prefix_len]


class X509Certificate:
    """A shim around PyCA and PyOpenSSL for X.509 certificates"""

    def __init__(self, cert, data):
        self.data = data

        self.subject = X509Name(cert.subject)
        self.issuer = X509Name(cert.issuer)
        self.key_data = cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        self.openssl_cert = crypto.X509.from_cryptography(cert)
        self.subject_hash = hex(self.openssl_cert.get_subject().hash())[2:]
        self.issuer_hash = hex(self.openssl_cert.get_issuer().hash())[2:]

        try:
            self.purposes = set(cert.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage).value)
        except x509.ExtensionNotFound:
            self.purposes = None

        try:
            sans = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value

            self.user_principals = sans.get_values_for_type(x509.RFC822Name)
            self.host_principals = sans.get_values_for_type(x509.DNSName) + \
                [str(ip) for ip in sans.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            principals = [attr.value for attr in cn]

            self.user_principals = principals
            self.host_principals = principals

        try:
            comment = cert.extensions.get_extension_for_oid(_nscomment_oid)
            self.comment = der_decode(comment.value.value).value
        except x509.ExtensionNotFound:
            self.comment = None

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.data == other.data

    def __hash__(self):
        return hash(self.data)

    def validate(self, trust_store, purposes, user_principal, host_principal):
        """Validate an X.509 certificate"""

        purposes = _to_purpose_oids(purposes)

        if purposes and self.purposes and not purposes & self.purposes:
            raise ValueError('Certificate purpose mismatch')

        if user_principal and user_principal not in self.user_principals:
            raise ValueError('Certificate user principal mismatch')

        if host_principal and host_principal not in self.host_principals:
            raise ValueError('Certificate host principal mismatch')

        x509_store = crypto.X509Store()

        for c in trust_store:
            x509_store.add_cert(c.openssl_cert)

        try:
            x509_ctx = crypto.X509StoreContext(x509_store, self.openssl_cert)
            x509_ctx.verify_certificate()
        except crypto.X509StoreContextError as exc:
            raise ValueError(str(exc)) from None


def generate_x509_certificate(signing_key, key, subject, issuer, serial,
                              valid_after, valid_before, ca, ca_path_len,
                              purposes, user_principals, host_principals,
                              hash_alg, comment):
    """Generate a new X.509 certificate"""

    subject = X509Name(subject)
    issuer = X509Name(issuer) if issuer else subject
    valid_after = _to_generalized_time(valid_after)
    valid_before = _to_generalized_time(valid_before)
    purposes = _to_purpose_oids(purposes)
    self_signed = subject == issuer

    if serial is None:
        serial = x509.random_serial_number()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(valid_after)
    builder = builder.not_valid_after(valid_before)
    builder = builder.public_key(key.pyca_key)

    if ca:
        basic_constraints = x509.BasicConstraints(
            ca=True, path_length=ca_path_len)
        key_usage = x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False)
    else:
        basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
        key_usage = x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=True, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False)

    builder = builder.add_extension(basic_constraints, critical=True)

    if ca or not self_signed:
        builder = builder.add_extension(key_usage, critical=True)

    if purposes:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(purposes), critical=False)

    sans = (_encode_user_principals(user_principals) +
            _encode_host_principals(host_principals))

    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False)

    if comment:
        comment = der_encode(IA5String(comment))
        builder = builder.add_extension(
            x509.UnrecognizedExtension(_nscomment_oid, comment), critical=False)

    try:
        hash_alg = _hashes[hash_alg]()
    except KeyError:
        raise ValueError('Unknown hash algorithm') from None

    cert = builder.sign(signing_key.pyca_key, hash_alg, default_backend())
    data = cert.public_bytes(Encoding.DER)

    return X509Certificate(cert, data)


def import_x509_certificate(data):
    """Construct an X.509 certificate from DER data"""

    cert = x509.load_der_x509_certificate(data, default_backend())
    return X509Certificate(cert, data)
