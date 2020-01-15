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

------------

Simple reusable django app implementing x509 PKI certificates management.

**Want to help OpenWISP?** `Find out how to help us grow here
<http://openwisp.io/docs/general/help-us.html>`_.

------------

.. contents:: **Table of Contents**:
   :backlinks: none
   :depth: 3

------------

Current features
----------------

* CA generation
* Import existing CAs
* End entity certificate generation
* Import existing certificates
* Certificate revocation
* CRL view (public or protected)
* Possibility to specify x509 extensions on each certificate
* Random serial numbers based on uuid4 integers (see `why is this a good idea
  <https://crypto.stackexchange.com/questions/257/unpredictability-of-x-509-serial-numbers>`_)
* Possibility to generate and import passphrase protected x509 certificates/CAs
* Passphrase protected x509 content will be shown encrypted in the web UI

Project goals
-------------

* provide a simple and reusable x509 PKI management django app
* provide abstract models that can be imported and extended in larger django projects

Dependencies
------------

* Python >= 3.6
* OpenSSL

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

Add the URLs to your main ``urls.py``:

.. code-block:: python

    from django.contrib import admin

    urlpatterns = [
        # ... other urls in your project ...

        url(r'admin/', admin.site.urls),
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

Install and run on docker
--------------------------

Build from docker file:

.. code-block:: shell

   sudo docker build -t openwisp/djangox509 .

Run the docker container:

.. code-block:: shell

   sudo docker run -it -p 8000:8000 openwisp/djangox509

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

``DJANGO_X509_DEFAULT_KEY_LENGTH``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+-------------+
| **type**:    | ``int``     |
+--------------+-------------+
| **default**: | ``2048``    |
+--------------+-------------+

Default key length for new CAs and new certificates.

Must be one of the following values:

* ``512``
* ``1024``
* ``2048``
* ``4096``

``DJANGO_X509_DEFAULT_DIGEST_ALGORITHM``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+-------------+
| **type**:    | ``str``     |
+--------------+-------------+
| **default**: | ``sha256``  |
+--------------+-------------+

Default digest algorithm for new CAs and new certificates.

Must be one of the following values:

* ``sha1``
* ``sha224``
* ``sha256``
* ``sha384``
* ``sha512``

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

``DJANGO_X509_CRL_PROTECTED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+-----------+
| **type**:    | ``bool``  |
+--------------+-----------+
| **default**: | ``False`` |
+--------------+-----------+

Whether the view for downloading Certificate Revocation Lists should
be protected with authentication or not.

Extending django-x509
---------------------

*django-x509* provides a set of models and admin classes which can be imported,
extended and reused by third party apps.

To extend *django-x509*, **you MUST NOT** add it to ``settings.INSTALLED_APPS``,
but you must create your own app (which goes into ``settings.INSTALLED_APPS``), import the
base classes from django-x509 and add your customizations.

In order to help django find the static files and templates of *django-x509*,
you need to perform the steps described below.

1. Install ``openwisp-utils``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Install (and add to the requirement of your project) `openwisp-utils
<https://github.com/openwisp/openwisp-utils>`_::

    pip install openwisp-utils

2. Add ``EXTENDED_APPS``
~~~~~~~~~~~~~~~~~~~~~~~~

Add the following to your ``settings.py``:

.. code-block:: python

    EXTENDED_APPS = ('django_x509',)

3. Add ``openwisp_utils.staticfiles.DependencyFinder``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add ``openwisp_utils.staticfiles.DependencyFinder`` to
``STATICFILES_FINDERS`` in your ``settings.py``:

.. code-block:: python

    STATICFILES_FINDERS = [
        'django.contrib.staticfiles.finders.FileSystemFinder',
        'django.contrib.staticfiles.finders.AppDirectoriesFinder',
        'openwisp_utils.staticfiles.DependencyFinder',
    ]

4. Add ``openwisp_utils.loaders.DependencyLoader``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add ``openwisp_utils.loaders.DependencyLoader`` to ``TEMPLATES`` in your ``settings.py``:

.. code-block:: python

    TEMPLATES = [
        {
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'OPTIONS': {
                'loaders': [
                    'django.template.loaders.filesystem.Loader',
                    'django.template.loaders.app_directories.Loader',
                    'openwisp_utils.loaders.DependencyLoader',
                ],
                'context_processors': [
                    'django.template.context_processors.debug',
                    'django.template.context_processors.request',
                    'django.contrib.auth.context_processors.auth',
                    'django.contrib.messages.context_processors.messages',
                ],
            },
        }
    ]

Extending models
~~~~~~~~~~~~~~~~

This example provides an example of how to extend the base models of
*django-x509* by adding a relation to another django model named `Organization`.

.. code-block:: python

    # models.py of your app
    from django.db import models
    from django_x509.base.models import AbstractCa, AbstractCert

    # the model ``organizations.Organization`` is omitted for brevity
    # if you are curious to see a real implementation, check out django-organizations


    class OrganizationMixin(models.Model):
        organization = models.ForeignKey('organizations.Organization')

        class Meta:
            abstract = True


    class Ca(OrganizationMixin, AbstractCa):
        class Meta(AbstractCa.Meta):
            abstract = False

        def clean(self):
            # your own validation logic here...
            pass


    class Cert(OrganizationMixin, AbstractCert):
        ca = models.ForeignKey(Ca)

        class Meta(AbstractCert.Meta):
            abstract = False

        def clean(self):
            # your own validation logic here...
            pass

Extending the admin
~~~~~~~~~~~~~~~~~~~

Following the previous `Organization` example, you can avoid duplicating the admin
code by importing the base admin classes and registering your models with.

.. code-block:: python

    # admin.py of your app
    from django.contrib import admin

    from django_x509.base.admin import CaAdmin as BaseCaAdmin
    from django_x509.base.admin import CertAdmin as BaseCertAdmin

    from .models import Ca, Cert


    class CaAdmin(BaseCaAdmin):
        # extend/modify the default behaviour here
        pass


    class CertAdmin(BaseCertAdmin):
        # extend/modify the default behaviour here
        pass


    admin.site.register(Ca, CaAdmin)
    admin.site.register(Cert, CertAdmin)

Contributing
------------

Please read the `OpenWISP contributing guidelines
<http://openwisp.io/docs/developer/contributing.html>`_
and also keep in mind the following:

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

Support
-------

See `OpenWISP Support Channels <http://openwisp.org/support.html>`_.
