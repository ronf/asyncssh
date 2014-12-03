#!/usr/bin/env python3.4

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

"""AsyncSSH: Asynchronous SSHv2 client and server library

This package provides an asynchronous client and server implementation of
the SSHv2 protocol, based on the Python asyncio framework. It depends on
Python 3.4 or later and the PyCrypto library for some cryptographic functions.

"""
import os

from setuptools import setup, find_packages

__author__ = 'Ron Frederick'
__author_email__ = '<ronf@timeheart.net>'
__url__ = 'http://asyncssh.timeheart.net/'
__version__ = '0.9.1'

doclines = __doc__.split("\n", 1)

with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), "README.rst")) as desc:
    long_description = desc.read()

setup(name = 'asyncssh',
      version = __version__,
      author = __author__,
      author_email = __author_email__,
      url = __url__,
      download_url = __url__ + 'asyncssh-%s.tar.gz' % __version__,
      license = 'Eclipse Public License v1.0',
      description = doclines[0],
      long_description = long_description,
      platforms = 'Any',
      install_requires=["pycrypto"],
      extras_require = {
          'pycrypto': ['Crypto >= 2.6'],
          'pyca':     ['cryptography >= 0.6.1']
      },
      packages = ['asyncssh'],
      scripts = [],
      test_suite = 'tests',
      classifiers = [
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'License :: OSI Approved',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: POSIX',
          'Programming Language :: Python :: 3.4',
          'Topic :: Internet',
          'Topic :: Security :: Cryptography',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Networking'])
