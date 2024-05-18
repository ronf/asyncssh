#!/usr/bin/env python3.6

# Copyright (c) 2013-2022 by Ron Frederick <ronf@timeheart.net> and others.
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

"""AsyncSSH: Asynchronous SSHv2 client and server library

AsyncSSH is a Python package which provides an asynchronous client and
server implementation of the SSHv2 protocol on top of the Python asyncio
framework. It requires Python 3.6 or later and the PyCA library for some
cryptographic functions.

"""

from os import path
from setuptools import setup

base_dir = path.abspath(path.dirname(__file__))

doclines = __doc__.split('\n', 1)

with open(path.join(base_dir, 'README.rst')) as desc:
    long_description = desc.read()

with open(path.join(base_dir, 'asyncssh', 'version.py')) as version:
    exec(version.read())

setup(name = 'asyncssh',
      version = __version__,
      author = __author__,
      author_email = __author_email__,
      url = __url__,
      project_urls = {
         'Documentation': 'https://asyncssh.readthedocs.io',
         'Source':        'https://github.com/ronf/asyncssh',
         'Tracker':       'https://github.com/ronf/asyncssh/issues'
      },
      license = 'Eclipse Public License v2.0',
      description = doclines[0],
      long_description = long_description,
      platforms = 'Any',
      python_requires = '>= 3.6',
      install_requires = [
          'cryptography >= 39.0',
          'typing_extensions >= 4.0.0'],
      extras_require = {
          'bcrypt':     ['bcrypt >= 3.1.3'],
          'fido2':      ['fido2 >= 0.9.2'],
          'gssapi':     ['gssapi >= 1.2.0'],
          'libnacl':    ['libnacl >= 1.4.2'],
          'pkcs11':     ['python-pkcs11 >= 0.7.0'],
          'pyOpenSSL':  ['pyOpenSSL >= 23.0.0'],
          'pywin32':    ['pywin32 >= 227']
      },
      packages = ['asyncssh', 'asyncssh.crypto'],
      package_data = {'asyncssh': ['py.typed']},
      scripts = [],
      test_suite = 'tests',
      classifiers = [
          'Development Status :: 5 - Production/Stable',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: OSI Approved',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: POSIX',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: 3.12',
          'Topic :: Internet',
          'Topic :: Security :: Cryptography',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Networking'])
