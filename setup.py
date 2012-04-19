#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from setuptools import setup, Command
except ImportError:
    from distutils.core import setup, Command
import os
import sys
import unittest

#from cidrize import __version__
__version__ = '0.6.2'

if sys.version_info[:2] < (2, 4):
    print "This package requires Python 2.4+. Sorry!"
    sys.exit(-1)

class CleanCommand(Command):
    description = "cleans up non-package files. (dist, build, etc.)"
    user_options = []
    def initialize_options(self):
        self.files = None
    def finalize_options(self):
        self.files = './build ./dist ./MANIFEST ./*.pyc ./*.egg-info'
    def run(self):
        #files = './build ./dist ./MANIFEST ./*.pyc'
        print 'Cleaning: %s' % self.files
        os.system('rm -rf ' + self.files)

class TestCommand(Command):
    description = 'run unit tests'
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        args = [unittest.__file__]
        for root, dirs, files in os.walk('tests'):
            for file in files:
                if file.startswith('test') and file.endswith('py'):
                    args.append(file[:-3])
        sys.path.append('tests')
        unittest.main(None, None, args)

setup(
    name = 'cidrize',
    version = __version__,
    url = 'http://github.com/jathanism/cidrize/',
    license = 'BSD',
    description = "Cidrize parses IPv4/IPv6 addresses, CIDRs, ranges, and wildcard matches & attempts return a valid list of IP addresses",
    author = 'Jathan McCollum',
    author_email = 'jathan@gmail.com',
    py_modules = ['cidrize'],
    scripts = ['scripts/cidr'],
    install_requires=['netaddr>=0.7.6'],
    keywords = [
            'Networking', 'Systems Administration', 'IANA', 'IEEE', 'CIDR', 'IP',
            'IPv4', 'IPv6', 'IP Address', 'Firewalls', 'Security',
    ],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Plugins',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'Natural Language :: English',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.5',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Education :: Testing',
        'Topic :: Internet',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Firewalls',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: System :: Operating System',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
    cmdclass = {
        'clean': CleanCommand,
        'test': TestCommand,
    }
)
