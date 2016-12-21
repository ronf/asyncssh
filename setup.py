#!/usr/bin/env python3.5

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

"""AsyncSSH: Asynchronous SSHv2 client and server library

AsyncSSH is a Python package which provides an asynchronous client and
server implementation of the SSHv2 protocol on top of the Python asyncio
framework. It requires Python 3.4 or later and either the PyCA library or
the PyCrypto library for some cryptographic functions.

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
      license = 'Eclipse Public License v1.0',
      description = doclines[0],
      long_description = long_description,
      platforms = 'Any',
      install_requires = ['cryptography >= 1.5'],
      extras_require = {
          'bcrypt':     ['bcrypt >= 3.0.0'],
          'libnacl':    ['libnacl >= 1.4.2'],
          'pypiwin32':  ['pypiwin32 >= 219']
      },
      packages = ['asyncssh', 'asyncssh.crypto', 'asyncssh.crypto.pyca'],
      scripts = [],
      test_suite = 'tests',
      classifiers = [
          'Development Status :: 5 - Production/Stable',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: OSI Approved',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: POSIX',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6',
          'Topic :: Internet',
          'Topic :: Security :: Cryptography',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Networking'])
