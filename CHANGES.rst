Changelog
=========

Version 0.6.0 [2020-01-15]
--------------------------

- Dropped support for python 2
- Added support for django 3.0

Version 0.5.1 [2019-12-23]
--------------------------

- [fix] Use ``self.pk`` instead of ``self.id`` to allow more
  flexible override of primary key
- Fixed jQuery init issue on django 2.2

Version 0.5.0 [2019-11-20]
--------------------------

* `#36 <https://github.com/openwisp/django-x509/issues/36>`_:
  [requirements] Added support for django 2.1
* `#44 <https://github.com/openwisp/django-x509/issues/44>`_:
  [models] Improved error message format #44
* `#61 <https://github.com/openwisp/django-x509/pull/61>`_:
  Bumped supported Django version to 2.2 and Python version to 3.7
* `#63 <https://github.com/openwisp/django-x509/pull/63>`_:
  [bug] Load model after registration in apps
* Bumped cryptography version to 2.8.0, pyopenssl to 19.0.0

Version 0.4.1 [2018-09-05]
--------------------------

* [admin] Fixed UI bug that prevented changing Cert and CA
* [requirements] cryptography>=2.3.0,<2.4.0
* [requirements] pyopenssl>=17.5.0,<18.1.0
* `#41 <https://github.com/openwisp/django-x509/pull/41>`_:
  [requirements] Added support for django 2.1
* [admin] Fixed involuntary permanent modification of field list

Version 0.4.0 [2018-02-19]
--------------------------

* `#24 <https://github.com/openwisp/django-x509/issues/24>`_:
  [qa] Added django 2.0 & dropped django 1.10
* `#25 <https://github.com/openwisp/django-x509/issues/25>`_:
  [admin] Automatically select ``certificate`` and ``private_key`` on click
* `#33 <https://github.com/openwisp/django-x509/issues/33>`_:
  [models] Added ``organizational_unit_name`` in ``Cert`` and ``Ca``

Version 0.3.4 [2017-12-20]
--------------------------

* [admin] Removed ``serial_number`` from certificate list

Version 0.3.3 [2017-12-20]
--------------------------

* [models] Reimplemented serial numbers as UUID integers
* [UX] Import vs New javascript switcher

Version 0.3.2 [2017-12-06]
--------------------------

* [requirements] upgraded pyopenssl to 17.5.0 and cryptography to 2.2.0
* [models] Fixed uncaught exception when imported
  PEM ``certificate`` or ``private_key`` is invalid

Version 0.3.1 [2017-12-01]
--------------------------

* temporarily downgraded cryptography and pyopenssl versions
  to avoid segmentation faults

Version 0.3.0 [2017-11-03]
--------------------------

* [models] Avoided possible double insertion in ``Base.save``
* [requirements] pyopenssl>=17.1.0,<17.4.0
* [admin] Fixed preformatted look of certificate and private-key fields
* [models] Allow importing certs with invalid country codes
* [models] Allow importing certificate with empty common name
* [tests] Updated data for import test to fix pyOpenSSL issue
* [models] Renamed ``organization`` field to ``organization_name``

Version 0.2.4 [2017-07-04]
--------------------------

* [models] added ``digest`` argument to ``CRL.export``
* [requirements] pyopenssl>=17.1.0,<17.2.0

Version 0.2.3 [2017-05-15]
--------------------------

* [migrations] Updated ``validity_start`` on ``Cert`` model

Version 0.2.2 [2017-05-11]
--------------------------

* [models] Set ``validity_start`` to 1 day before the current date (at 00:00)

Version 0.2.1 [2017-05-02]
--------------------------

* [django] added support for django 1.11

Version 0.2.0 [2017-01-11]
--------------------------

* [models] improved reusability by providing abstract models
* [admin] improved reusability by providing abstract admin classes
* [views] provided a base view that can be reused by third party apps
* [docs] documented how to extend models and admin
* [docs] documented hard dependencies

Version 0.1.3 [2016-09-22]
--------------------------

* [model] avoid import error if any imported field is ``NULL``
* [admin] added ``serial_number`` to ``list_display`` in ``Cert`` admin
* [model] avoid exception if x509 subject attributes are empty

Version 0.1.2 [2016-09-08]
--------------------------

* improved general ``verbose_name`` of the app
* added official compatibility with django 1.10
* [admin] show link to CA in cert admin
* [admin] added ``key_length`` and ``digest`` to available filters

Version 0.1.1 [2016-08-03]
--------------------------

* fixed x509 certificate version
* renamed ``public_key`` field to more appropiate ``certificate``
* show x509 text dump in admin when editing objects

Version 0.1 [2016-07-18]
------------------------

* CA and end entity certificate generation
* import existing certificates
* x509 extensions
* revocation
* CRL
