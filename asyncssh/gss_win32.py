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

"""GSSAPI wrapper for Windows"""

# Some of the imports below won't be found when running pylint on UNIX
# pylint: disable=import-error

from sspi import ClientAuth, ServerAuth
from sspi import error as SSPIError

from sspicon import ISC_REQ_DELEGATE, ISC_REQ_INTEGRITY, ISC_REQ_MUTUAL_AUTH
from sspicon import ISC_RET_INTEGRITY, ISC_RET_MUTUAL_AUTH
from sspicon import ASC_REQ_INTEGRITY, ASC_REQ_MUTUAL_AUTH
from sspicon import ASC_RET_INTEGRITY, ASC_RET_MUTUAL_AUTH
from sspicon import SECPKG_ATTR_NATIVE_NAMES

from .asn1 import ObjectIdentifier, der_encode


_krb5_oid = der_encode(ObjectIdentifier('1.2.840.113554.1.2.2'))


class _GSSBase:
    """GSS base class"""

    # Overridden in client classes
    _mutual_auth_flag = 0
    _integrity_flag = 0

    def __init__(self, host):
        if '@' in host:
            self._host = host
        else:
            self._host = 'host/' + host

        self._ctx = None
        self._init_token = None

    @property
    def mechs(self):
        """Return GSS mechanisms available for this host"""

        return [_krb5_oid]

    @property
    def complete(self):
        """Return whether or not GSS negotiation is complete"""

        return self._ctx.authenticated

    @property
    def provides_mutual_auth(self):
        """Return whether or not this context provides mutual authentication"""

        return self._ctx.ctxt_attr & self._mutual_auth_flag

    @property
    def provides_integrity(self):
        """Return whether or not this context provides integrity protection"""

        return self._ctx.ctxt_attr & self._integrity_flag

    @property
    def user(self):
        """Return user principal associated with this context"""

        names = self._ctx.ctxt.QueryContextAttributes(SECPKG_ATTR_NATIVE_NAMES)
        return names[0]

    @property
    def host(self):
        """Return host principal associated with this context"""

        names = self._ctx.ctxt.QueryContextAttributes(SECPKG_ATTR_NATIVE_NAMES)
        return names[1]

    def reset(self):
        """Reset GSS security context"""

        if self._ctx.authenticated:
            self._ctx.reset()

    def step(self, token=None):
        """Perform next step in GSS security exchange"""

        if self._init_token:
            token = self._init_token
            self._init_token = None
            return token

        try:
            _, buf = self._ctx.authorize(token)
            return buf[0].Buffer
        except SSPIError as exc:
            raise GSSError(details=exc.strerror) from None

    def sign(self, data):
        """Sign a block of data"""

        try:
            return self._ctx.sign(data)
        except SSPIError as exc:
            raise GSSError(details=exc.strerror) from None

    def verify(self, data, sig):
        """Verify a signature for a block of data"""

        try:
            self._ctx.verify(data, sig)
            return True
        except SSPIError:
            return False


class GSSClient(_GSSBase):
    """GSS client"""

    _mutual_auth_flag = ISC_RET_MUTUAL_AUTH
    _integrity_flag = ISC_RET_INTEGRITY

    def __init__(self, host, delegate_creds):
        super().__init__(host)

        flags = ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY

        if delegate_creds:
            flags |= ISC_REQ_DELEGATE

        try:
            self._ctx = ClientAuth('Kerberos', targetspn=self._host,
                                   scflags=flags)
        except SSPIError as exc:
            raise GSSError(1, 1, details=exc.strerror)

        self._init_token = self.step(None)


class GSSServer(_GSSBase):
    """GSS server"""

    _mutual_auth_flag = ASC_RET_MUTUAL_AUTH
    _integrity_flag = ASC_RET_INTEGRITY

    def __init__(self, host):
        super().__init__(host)

        flags = ASC_REQ_MUTUAL_AUTH | ASC_REQ_INTEGRITY

        try:
            self._ctx = ServerAuth('Kerberos', spn=self._host, scflags=flags)
        except SSPIError as exc:
            raise GSSError(1, 1, details=exc.strerror)


class GSSError(Exception):
    """Stub class for reporting that GSS is not available"""

    def __init__(self, maj_code=0, min_code=0, token=None, details=''):
        super().__init__(details)

        self.maj_code = maj_code
        self.min_code = min_code
        self.token = token
