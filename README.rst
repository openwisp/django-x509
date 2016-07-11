django-x509
===========

.. image:: https://travis-ci.org/openwisp/django-x509.svg
   :target: https://travis-ci.org/openwisp/django-x509

.. image:: https://coveralls.io/repos/openwisp/django-x509/badge.svg
  :target: https://coveralls.io/r/openwisp/django-x509

.. image:: https://requires.io/github/openwisp/django-x509/requirements.svg?branch=master
   :target: https://requires.io/github/openwisp/django-x509/requirements/?branch=master
   :alt: Requirements Status

.. image:: https://badge.fury.io/py/django-x509.svg
   :target: http://badge.fury.io/py/django-x509

.. image:: https://img.shields.io/pypi/dm/django-x509.svg
   :target: https://pypi.python.org/pypi/django-x509

------------

Reusable django app implementing x509 PKI certificates management.

**Work in progress**.

------------

.. contents:: **Table of Contents**:
   :backlinks: none
   :depth: 3

------------

Current features
----------------

* TODO

Project goals
-------------

* TODO

Install stable version from pypi
--------------------------------

Install from pypi:

.. code-block:: shell

    pip install django-x509

Install development version
---------------------------

Install tarball:

.. code-block:: shell

    pip install https://github.com/openwisp/django-x509/tarball/master

Alternatively you can install via pip using git:

.. code-block:: shell

    pip install -e git+git://github.com/openwisp/django-x509#egg=django-x509

If you want to contribute, install your cloned fork:

.. code-block:: shell

    git clone git@github.com:<your_fork>/django-x509.git
    cd django-x509
    python setup.py develop

Setup (integrate in an existing django project)
-----------------------------------------------

Add ``django_x509`` to ``INSTALLED_APPS``:

.. code-block:: python

    INSTALLED_APPS = [
        # other apps
        'django_x509',
    ]

Then run:

.. code-block:: shell

    ./manage.py migrate

Installing for development
--------------------------

Install sqlite:

.. code-block:: shell

    sudo apt-get install sqlite3 libsqlite3-dev

Install your forked repo:

.. code-block:: shell

    git clone git://github.com/<your_fork>/django-x509
    cd django-x509/
    python setup.py develop

Install test requirements:

.. code-block:: shell

    pip install -r requirements-test.txt

Create database:

.. code-block:: shell

    cd tests/
    ./manage.py migrate
    ./manage.py createsuperuser

Launch development server:

.. code-block:: shell

    ./manage.py runserver

You can access the admin interface at http://127.0.0.1:8000/admin/.

Run tests with:

.. code-block:: shell

    ./runtests.py

Settings
--------

``DJANGO_X509_DEFAULT_CERT_VALIDITY``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+-------------+
| **type**:    | ``int``     |
+--------------+-------------+
| **default**: | ``365``     |
+--------------+-------------+

Default validity period (in days) when creating new x509 certificates.

``DJANGO_X509_DEFAULT_CA_VALIDITY``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+-------------+
| **type**:    | ``int``     |
+--------------+-------------+
| **default**: | ``3650``    |
+--------------+-------------+

Default validity period (in days) when creating new Certification Authorities.

``DJANGO_X509_CA_BASIC_CONSTRAINTS_CRITICAL``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+-----------+
| **type**:    | ``bool``  |
+--------------+-----------+
| **default**: | ``True``  |
+--------------+-----------+

Whether the ``basicConstraint`` x509 extension must be flagged as critical when creating new CAs.

``DJANGO_X509_CA_BASIC_CONSTRAINTS_PATHLEN``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+---------------------+
| **type**:    | ``int`` or ``None`` |
+--------------+---------------------+
| **default**: | ``0``               |
+--------------+---------------------+

Value of the ``pathLenConstraint`` of ``basicConstraint`` x509 extension used when creating new CAs.

When this value is a positive ``int`` it represents the maximum number of non-self-issued
intermediate certificates that may follow the generated certificate in a valid certification path.

Set this value to ``None`` to avoid imposing any limit.

``DJANGO_X509_CA_KEYUSAGE_CRITICAL``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+--------------------------+
| **type**:    | ``bool``                 |
+--------------+--------------------------+
| **default**: | ``True``                 |
+--------------+--------------------------+

Whether the ``keyUsage`` x509 extension should be flagged as "critical" for new CAs.

``DJANGO_X509_CA_KEYUSAGE_VALUE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+--------------------------+
| **type**:    | ``str``                  |
+--------------+--------------------------+
| **default**: | ``cRLSign, keyCertSign`` |
+--------------+--------------------------+

Value of the ``keyUsage`` x509 extension for new CAs.

``DJANGO_X509_CERT_KEYUSAGE_CRITICAL``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+--------------------------+
| **type**:    | ``bool``                 |
+--------------+--------------------------+
| **default**: | ``False``                |
+--------------+--------------------------+

Whether the ``keyUsage`` x509 extension should be flagged as "critical" for new
end-entity certificates.

``DJANGO_X509_CERT_KEYUSAGE_VALUE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+---------------------------------------+
| **type**:    | ``str``                               |
+--------------+---------------------------------------+
| **default**: | ``digitalSignature, keyEncipherment`` |
+--------------+---------------------------------------+

Value of the ``keyUsage`` x509 extension for new end-entity certificates.

Contributing
------------

1. Announce your intentions in the `OpenWISP Mailing List <https://groups.google.com/d/forum/openwisp>`_
2. Fork this repo and install it
3. Follow `PEP8, Style Guide for Python Code`_
4. Write code
5. Write tests for your code
6. Ensure all tests pass
7. Ensure test coverage does not decrease
8. Document your changes
9. Send pull request

.. _PEP8, Style Guide for Python Code: http://www.python.org/dev/peps/pep-0008/

Changelog
---------

See `CHANGES <https://github.com/openwisp/django-x509/blob/master/CHANGES.rst>`_.

License
-------

See `LICENSE <https://github.com/openwisp/django-x509/blob/master/LICENSE>`_.
