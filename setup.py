#!/usr/bin/env python
# coding: utf-8
from os import chdir
from os.path import abspath, dirname

from setuptools import find_packages, setup

chdir(dirname(abspath(__file__)))

with open('README.rst') as f:
    readme = f.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    author='Brandon Davidson',
    author_email='brad@oatmail.org',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python',
    ],
    description='This package allows for Single-Sign On HTTP Negotiate authentication using the requests library on Windows.',
    include_package_data=True,
    install_requires=requirements,
    long_description=readme,
    name='requests-negotiate-sspi',
    packages=find_packages(exclude=('docs')),
    provides=['requests_negotiate_sspi'],
    url='https://github.com/brandond/requests-negotiate-sspi',
    version_command=('git describe --tags --dirty', 'pep440-git-full'),
)
