#!/usr/bin/env python
from setuptools import find_packages, setup

from django_x509 import get_version

setup(
    name="django-x509",
    version=get_version(),
    license="BSD",
    author="Federico Capoano",
    author_email="f.capoano@cineca.it",
    description="Reusable django app to generate and manage x509 certificates",
    long_description=open("README.rst").read(),
    url="https://github.com/openwisp/django-x509",
    download_url="https://github.com/openwisp/django-x509/releases",
    platforms=["Platform Indipendent"],
    keywords=["django", "x509", "pki", "PEM", "openwisp"],
    packages=find_packages(exclude=["tests", "docs"]),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        "openwisp-utils @ "
        "https://github.com/openwisp/openwisp-utils/archive/refs/heads/1.3.tar.gz",
        "pyopenssl>=25.3.0,<26.0.0",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Topic :: Internet :: WWW/HTTP",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Framework :: Django",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
    ],
)
