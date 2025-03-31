django-x509
===========

.. image:: https://github.com/openwisp/django-x509/workflows/Django-x509%20Build/badge.svg?branch=master
    :target: https://github.com/openwisp/django-x509/actions?query=workflow%3A"Django-x509+Build%22"
    :alt: CI build status

.. image:: https://coveralls.io/repos/openwisp/django-x509/badge.svg
    :target: https://coveralls.io/r/openwisp/django-x509
    :alt: Test Coverage

.. image:: https://img.shields.io/librariesio/release/github/openwisp/django-x509
    :target: https://libraries.io/github/openwisp/django-x509#repository_dependencies
    :alt: Dependency monitoring

.. image:: https://img.shields.io/gitter/room/nwjs/nw.js.svg
    :target: https://gitter.im/openwisp/general
    :alt: chat

.. image:: https://badge.fury.io/py/django-x509.svg
    :target: http://badge.fury.io/py/django-x509
    :alt: Pypi Version

.. image:: https://pepy.tech/badge/django-x509
    :target: https://pepy.tech/project/django-x509
    :alt: downloads

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://pypi.org/project/black/
    :alt: code style: black

----

.. image:: https://github.com/openwisp/django-x509/raw/master/docs/demo_x509.gif
    :alt: demo

----

Simple reusable django app implementing x509 PKI certificates management.

**Want to help OpenWISP?** `Find out how to help us grow here
<http://openwisp.io/docs/general/help-us.html>`_.

.. image:: https://raw.githubusercontent.com/openwisp/openwisp2-docs/master/assets/design/openwisp-logo-black.svg
    :target: http://openwisp.org

----

.. contents:: **Table of Contents**:
    :backlinks: none
    :depth: 3

----

Current features
----------------

- CA generation
- Import existing CAs
- End entity certificate generation
- Import existing certificates
- Certificate revocation
- CRL view (public or protected)
- Possibility to specify x509 extensions on each certificate
- Random serial numbers based on uuid4 integers (see `why is this a good
  idea
  <https://crypto.stackexchange.com/questions/257/unpredictability-of-x-509-serial-numbers>`_)
- Possibility to generate and import passphrase protected x509
  certificates/CAs
- Passphrase protected x509 content will be shown encrypted in the web UI

Project goals
-------------

- provide a simple and reusable x509 PKI management django app
- provide abstract models that can be imported and extended in larger
  django projects

Dependencies
------------

- Python >= 3.9
- OpenSSL

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
        "django_x509",
    ]

Add the URLs to your main ``urls.py``:

.. code-block:: python

    from django.contrib import admin

    urlpatterns = [
        # ... other urls in your project ...
        url(r"admin/", admin.site.urls),
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
-------------------------

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

============ =======
**type**:    ``int``
**default**: ``365``
============ =======

Default validity period (in days) when creating new x509 certificates.

``DJANGO_X509_DEFAULT_CA_VALIDITY``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============ ========
**type**:    ``int``
**default**: ``3650``
============ ========

Default validity period (in days) when creating new Certification
Authorities.

``DJANGO_X509_DEFAULT_KEY_LENGTH``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============ ========
**type**:    ``int``
**default**: ``2048``
============ ========

Default key length for new CAs and new certificates.

Must be one of the following values:

- ``512``
- ``1024``
- ``2048``
- ``4096``

``DJANGO_X509_DEFAULT_DIGEST_ALGORITHM``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============ ==========
**type**:    ``str``
**default**: ``sha256``
============ ==========

Default digest algorithm for new CAs and new certificates.

Must be one of the following values:

- ``sha1``
- ``sha224``
- ``sha256``
- ``sha384``
- ``sha512``

``DJANGO_X509_CA_BASIC_CONSTRAINTS_CRITICAL``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============ ========
**type**:    ``bool``
**default**: ``True``
============ ========

Whether the ``basicConstraint`` x509 extension must be flagged as critical
when creating new CAs.

``DJANGO_X509_CA_BASIC_CONSTRAINTS_PATHLEN``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============ ===================
**type**:    ``int`` or ``None``
**default**: ``0``
============ ===================

Value of the ``pathLenConstraint`` of ``basicConstraint`` x509 extension
used when creating new CAs.

When this value is a positive ``int`` it represents the maximum number of
non-self-issued intermediate certificates that may follow the generated
certificate in a valid certification path.

Set this value to ``None`` to avoid imposing any limit.

``DJANGO_X509_CA_KEYUSAGE_CRITICAL``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============ ========
**type**:    ``bool``
**default**: ``True``
============ ========

Whether the ``keyUsage`` x509 extension should be flagged as "critical"
for new CAs.

``DJANGO_X509_CA_KEYUSAGE_VALUE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============ ========================
**type**:    ``str``
**default**: ``cRLSign, keyCertSign``
============ ========================

Value of the ``keyUsage`` x509 extension for new CAs.

``DJANGO_X509_CERT_KEYUSAGE_CRITICAL``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============ =========
**type**:    ``bool``
**default**: ``False``
============ =========

Whether the ``keyUsage`` x509 extension should be flagged as "critical"
for new end-entity certificates.

``DJANGO_X509_CERT_KEYUSAGE_VALUE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============ =====================================
**type**:    ``str``
**default**: ``digitalSignature, keyEncipherment``
============ =====================================

Value of the ``keyUsage`` x509 extension for new end-entity certificates.

``DJANGO_X509_CRL_PROTECTED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

============ =========
**type**:    ``bool``
**default**: ``False``
============ =========

Whether the view for downloading Certificate Revocation Lists should be
protected with authentication or not.

Extending django-x509
---------------------

One of the core values of the OpenWISP project is `Software Reusability
<http://openwisp.io/docs/general/values.html#software-reusability-means-long-term-sustainability>`_,
for this reason *django-x509* provides a set of base classes which can be
imported, extended and reused to create derivative apps.

In order to implement your custom version of *django-x509*, you need to
perform the steps described in this section.

When in doubt, the code in the `test project
<https://github.com/openwisp/django-x509/tree/master/tests/openwisp2/>`_
and the `sample app
<https://github.com/openwisp/django-x509/tree/master/tests/openwisp2/sample_x509/>`_
will serve you as source of truth: just replicate and adapt that code to
get a basic derivative of *django-x509* working.

**Premise**: if you plan on using a customized version of this module, we
suggest to start with it since the beginning, because migrating your data
from the default module to your extended version may be time consuming.

1. Initialize your custom module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The first thing you need to do is to create a new django app which will
contain your custom version of *django-x509*.

A django app is nothing more than a `python package
<https://docs.python.org/3/tutorial/modules.html#packages>`_ (a directory
of python scripts), in the following examples we'll call this django app
``myx509``, but you can name it how you want:

::

    django-admin startapp myx509

Keep in mind that the command mentioned above must be called from a
directory which is available in your `PYTHON_PATH
<https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH>`_ so that
you can then import the result into your project.

Now you need to add ``myx509`` to ``INSTALLED_APPS`` in your
``settings.py``, ensuring also that ``django_x509`` has been removed:

.. code-block:: python

    INSTALLED_APPS = [
        # ... other apps ...
        # 'django_x509'  <-- comment out or delete this line
        "myx509"
    ]

For more information about how to work with django projects and django
apps, please refer to the `django documentation
<https://docs.djangoproject.com/en/dev/intro/tutorial01/>`_.

2. Install ``django-x509`` & ``openwisp-utils``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Install (and add to the requirement of your project):

::

    pip install django-x509 openwisp-utils

3. Add ``EXTENDED_APPS``
~~~~~~~~~~~~~~~~~~~~~~~~

Add the following to your ``settings.py``:

.. code-block:: python

    EXTENDED_APPS = ["django_x509"]

4. Add ``openwisp_utils.staticfiles.DependencyFinder``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add ``openwisp_utils.staticfiles.DependencyFinder`` to
``STATICFILES_FINDERS`` in your ``settings.py``:

.. code-block:: python

    STATICFILES_FINDERS = [
        "django.contrib.staticfiles.finders.FileSystemFinder",
        "django.contrib.staticfiles.finders.AppDirectoriesFinder",
        "openwisp_utils.staticfiles.DependencyFinder",
    ]

5. Add ``openwisp_utils.loaders.DependencyLoader``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add ``openwisp_utils.loaders.DependencyLoader`` to ``TEMPLATES`` in your
``settings.py``:

.. code-block:: python

    TEMPLATES = [
        {
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "OPTIONS": {
                "loaders": [
                    "django.template.loaders.filesystem.Loader",
                    "django.template.loaders.app_directories.Loader",
                    "openwisp_utils.loaders.DependencyLoader",
                ],
                "context_processors": [
                    "django.template.context_processors.debug",
                    "django.template.context_processors.request",
                    "django.contrib.auth.context_processors.auth",
                    "django.contrib.messages.context_processors.messages",
                ],
            },
        }
    ]

6. Inherit the AppConfig class
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please refer to the following files in the sample app of the test project:

- `sample_x509/__init__.py
  <https://github.com/openwisp/django-x509/tree/master/tests/openwisp2/sample_x509/__init__.py>`_.
- `sample_x509/apps.py
  <https://github.com/openwisp/django-x509/tree/master/tests/openwisp2/sample_x509/apps.py>`_.

You have to replicate and adapt that code in your project.

For more information regarding the concept of ``AppConfig`` please refer
to the `"Applications" section in the django documentation
<https://docs.djangoproject.com/en/dev/ref/applications/>`_.

7. Create your custom models
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here we provide an example of how to extend the base models of
*django-x509*. We added a simple "details" field to the models for
demostration of modification:

.. code-block:: python

    from django.db import models
    from django_x509.base.models import AbstractCa, AbstractCert


    class DetailsModel(models.Model):
        details = models.CharField(max_length=64, blank=True, null=True)

        class Meta:
            abstract = True


    class Ca(DetailsModel, AbstractCa):
        """
        Concrete Ca model
        """

        class Meta(AbstractCa.Meta):
            abstract = False


    class Cert(DetailsModel, AbstractCert):
        """
        Concrete Cert model
        """

        class Meta(AbstractCert.Meta):
            abstract = False

You can add fields in a similar way in your ``models.py`` file.

**Note**: for doubts regarding how to use, extend or develop models please
refer to the `"Models" section in the django documentation
<https://docs.djangoproject.com/en/dev/topics/db/models/>`_.

8. Add swapper configurations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once you have created the models, add the following to your
``settings.py``:

.. code-block:: python

    # Setting models for swapper module
    DJANGO_X509_CA_MODEL = "myx509.Ca"
    DJANGO_X509_CERT_MODEL = "myx509.Cert"

Substitute ``myx509`` with the name you chose in step 1.

9. Create database migrations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create and apply database migrations:

::

    ./manage.py makemigrations
    ./manage.py migrate

For more information, refer to the `"Migrations" section in the django
documentation
<https://docs.djangoproject.com/en/dev/topics/migrations/>`_.

10. Create the admin
~~~~~~~~~~~~~~~~~~~~

Refer to the `admin.py file of the sample app
<https://github.com/openwisp/django-x509/tree/master/tests/openwisp2/sample_x509/admin.py>`_.

To introduce changes to the admin, you can do it in two main ways which
are described below.

**Note**: for more information regarding how the django admin works, or
how it can be customized, please refer to `"The django admin site" section
in the django documentation
<https://docs.djangoproject.com/en/dev/ref/contrib/admin/>`_.

1. Monkey patching
++++++++++++++++++

If the changes you need to add are relatively small, you can resort to
monkey patching.

For example:

.. code-block:: python

    from django_x509.admin import CaAdmin, CertAdmin

    CaAdmin.list_display.insert(
        1, "my_custom_field"
    )  # <-- your custom change example
    CertAdmin.list_display.insert(
        1, "my_custom_field"
    )  # <-- your custom change example

2. Inheriting admin classes
+++++++++++++++++++++++++++

If you need to introduce significant changes and/or you don't want to
resort to monkey patching, you can proceed as follows:

.. code-block:: python

    from django.contrib import admin
    from swapper import load_model

    from django_x509.base.admin import AbstractCaAdmin, AbstractCertAdmin

    Ca = load_model("django_x509", "Ca")
    Cert = load_model("django_x509", "Cert")


    class CertAdmin(AbstractCertAdmin):
        pass
        # add your changes here


    class CaAdmin(AbstractCaAdmin):
        pass
        # add your changes here


    admin.site.register(Ca, CaAdmin)
    admin.site.register(Cert, CertAdmin)

11. Create root URL configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please refer to the `urls.py
<https://github.com/openwisp/django-x509/tree/master/tests/openwisp2/urls.py>`_
file in the test project.

For more information about URL configuration in django, please refer to
the `"URL dispatcher" section in the django documentation
<https://docs.djangoproject.com/en/dev/topics/http/urls/>`_.

12. Import the automated tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When developing a custom application based on this module, it's a good
idea to import and run the base tests too, so that you can be sure the
changes you're introducing are not breaking some of the existing features
of *django-x509*.

In case you need to add breaking changes, you can overwrite the tests
defined in the base classes to test your own behavior.

.. code-block:: python

    from django.test import TestCase
    from django_x509.tests.base import TestX509Mixin
    from django_x509.tests.test_admin import (
        ModelAdminTests as BaseModelAdminTests,
    )
    from django_x509.tests.test_ca import TestCa as BaseTestCa
    from django_x509.tests.test_cert import TestCert as BaseTestCert


    class ModelAdminTests(BaseModelAdminTests):
        app_label = "myx509"


    class TestCert(BaseTestCert):
        pass


    class TestCa(BaseTestCa):
        pass


    del BaseModelAdminTests
    del BaseTestCa
    del BaseTestCert

Now, you can then run tests with:

::

    # the --parallel flag is optional
    ./manage.py test --parallel myx509

Substitute ``myx509`` with the name you chose in step 1.

For more information about automated tests in django, please refer to
`"Testing in Django"
<https://docs.djangoproject.com/en/dev/topics/testing/>`_.

Contributing
------------

Please refer to the `OpenWISP contributing guidelines
<http://openwisp.io/docs/developer/contributing.html>`_.

Support
-------

See `OpenWISP Support Channels <http://openwisp.org/support.html>`_.

Changelog
---------

See `CHANGES
<https://github.com/openwisp/django-x509/blob/master/CHANGES.rst>`_.

License
-------

See `LICENSE
<https://github.com/openwisp/django-x509/blob/master/LICENSE>`_.
