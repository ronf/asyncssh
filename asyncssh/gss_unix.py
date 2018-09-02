# Copyright (c) 2017-2018 by Ron Frederick <ronf@timeheart.net> and others.
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

"""GSSAPI wrapper for UNIX"""

from gssapi import Credentials, Name, NameType
from gssapi import RequirementFlag, SecurityContext
from gssapi.exceptions import GSSError

from .asn1 import OBJECT_IDENTIFIER


def _mech_to_oid(mech):
    """Return a DER-encoded OID corresponding to the requested GSS mechanism"""

    mech = bytes(mech)
    return bytes((OBJECT_IDENTIFIER, len(mech))) + mech


class _GSSBase:
    """GSS base class"""

    def __init__(self, host, usage):
        if '@' in host:
            self._host = Name(host)
        else:
            self._host = Name('host@' + host, NameType.hostbased_service)

        if usage == 'initiate':
            self._creds = Credentials(usage=usage)
        else:
            self._creds = Credentials(name=self._host, usage=usage)

        self._mechs = [_mech_to_oid(mech) for mech in self._creds.mechs]
        self._ctx = None

    def _init_context(self):
        """Abstract method to construct GSS security context"""

        raise NotImplementedError

    @property
    def mechs(self):
        """Return GSS mechanisms available for this host"""

        return self._mechs

    @property
    def complete(self):
        """Return whether or not GSS negotiation is complete"""

        return self._ctx and self._ctx.complete

    @property
    def provides_mutual_auth(self):
        """Return whether or not this context provides mutual authentication"""

        return (RequirementFlag.mutual_authentication in
                self._ctx.actual_flags)

    @property
    def provides_integrity(self):
        """Return whether or not this context provides integrity protection"""

        return RequirementFlag.integrity in self._ctx.actual_flags

    @property
    def user(self):
        """Return user principal associated with this context"""

        return str(self._ctx.initiator_name)

    @property
    def host(self):
        """Return host principal associated with this context"""

        return str(self._ctx.target_name)

    def reset(self):
        """Reset GSS security context"""

        self._ctx = None

    def step(self, token=None):
        """Perform next step in GSS security exchange"""

        if not self._ctx:
            self._init_context()

        return self._ctx.step(token)

    def sign(self, data):
        """Sign a block of data"""

        return self._ctx.get_signature(data)

    def verify(self, data, sig):
        """Verify a signature for a block of data"""

        try:
            self._ctx.verify_signature(data, sig)
            return True
        except GSSError:
            return False


class GSSClient(_GSSBase):
    """GSS client"""

    def __init__(self, host, delegate_creds):
        super().__init__(host, 'initiate')

        flags = set((RequirementFlag.mutual_authentication,
                     RequirementFlag.integrity))

        if delegate_creds:
            flags.add(RequirementFlag.delegate_to_peer)

        self._flags = flags

    def _init_context(self):
        """Construct GSS client security context"""

        self._ctx = SecurityContext(name=self._host, creds=self._creds,
                                    flags=self._flags)


class GSSServer(_GSSBase):
    """GSS server"""

    def __init__(self, host):
        super().__init__(host, 'accept')

    def _init_context(self):
        """Construct GSS server security context"""

        self._ctx = SecurityContext(creds=self._creds)
