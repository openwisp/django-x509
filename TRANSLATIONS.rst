==============================
How to contribute translations
==============================

There are several things you can do to help us internationalize ``django-x509`` and provide a great experience for everybody

Providing a translation
=======================

We manage all of our translations using Transifex. Here's how you can get started:

*  `Create an account <https://www.transifex.com/signup/?join_project=openwisp>`_ with Transifex (it's free!)
* During the setup, it'll ask if you want to start your own project or join an existing project. Choose to join an existing project.
* Transifex will ask which languages you speak; filling this in is appreciated so that we have an accurate snapshot of the languages our contributors are familiar with.
* At this point, your account will be created and you can confirm your email.

At this point, you are ready to join and help with translations or you can request a language.

* Visit https://www.transifex.com/openwisp/django-x509/
* In the top right, you can click "Join team".
* You can specify the languages you speak OR request a language which is not currently provided.
* One of our contributors will be able to approve your access.

How does translated text get back into the GitHub repository?
=============================================================

We generally pull in all languages files at the time we cut a release. That allows us to keep everything up to date in a scalable way.

Making sure our code has all strings localized
==============================================

Besides providing the actual translations themselves, it's important that the code tokenizes all strings shown to the user.

Fixing existing known issues
============================

You can search our existing issues and find places to contribute here:
https://github.com/openwisp/django-x509/labels/l10n

Properly adding a new string
============================

When a new string is added, we'll add it for the `en_US` locale. You can find the .properties files here:
https://github.com/openwisp/django-x509/tree/master/app/extensions/django-x509/locales/en-US

The strings there are in camel-case a format like this:
tokenNameHere=Value in English here

Different files are used by different parts of the code. If you're not sure which file to edit, you do a search or grep using
another string in the same code you're looking at. For menu items and context menu items, you'll also have to add an entry here
