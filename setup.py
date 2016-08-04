#!/usr/bin/env python
# coding: utf-8

from setuptools import setup, find_packages

version = {}

with open("requests_negotiate_sspi/version.py") as fp:
    exec(fp.read(), version)

with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='requests-negotiate-sspi',
    version=version['__version__'],
    packages=find_packages(exclude=('docs')),
    install_requires=requirements,
    provides=[ 'requests_negotiate_sspi' ],
    author='Brandon Davidson',
    url='https://github.com/brandond/requests-negotiate-sspi',
    download_url='https://github.com/brandond/requests-negotiate-sspi/tarball/{}'.format(version['__version__']),
    description='This package allows for Single-Sign On HTTP Negotiate authentication using the requests library on Windows.',
    long_description=readme,
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
)
