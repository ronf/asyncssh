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

"""GSSAPI error handler on systems where it isn't available"""


class GSSError(ValueError):
    """Stub class for reporting that GSSAPI is not available"""

    def __init__(self, maj_code=0, min_code=0, token=None):
        super().__init__('GSS not available')

        self.maj_code = maj_code
        self.min_code = min_code
        self.token = token


class Credentials:
    """Stub class for GSSAPI credentials"""

    pass


class Name:
    """Stub class for GSSAPI principal names"""

    def __init__(self, base, name_type=None):
        # pylint: disable=unused-argument

        raise GSSError(99, 99)


class NameType:
    """Stub class for GSS name types"""

    hostbased_service = 0


class RequirementFlag:
    """Stub class for GSSAPI requirement flags"""

    delegate_to_peer = 1
    integrity = 2
    mutual_authentication = 3


class SecurityContext:
    """Stub class for GSSAPI security contexts"""

    pass
