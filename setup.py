#!/usr/bin/env python
# coding: utf-8
from os import chdir
from os.path import abspath, dirname

from setuptools import setup, find_packages

chdir(dirname(abspath(__file__)))

with open('README.rst') as f:
    readme = f.read()

with open('LICENSE.txt') as f:
    license = f.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='requests-negotiate-sspi',
    version_command=('git describe --tags --dirty', 'pep440-git-full'),
    packages=find_packages(exclude=('docs')),
    install_requires=requirements,
    provides=['requests_negotiate_sspi'],
    author='Brandon Davidson',
    url='https://github.com/brandond/requests-negotiate-sspi',
    description='This package allows for Single-Sign On HTTP Negotiate authentication using the requests library on Windows.',
    long_description=readme,
    long_description_content_type='text/x-rst',
    license=license,
    include_package_data=True,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5'
    ],
    extras_require={
        'dev': [
            'setuptools-version-command',
        ]
    },
)
