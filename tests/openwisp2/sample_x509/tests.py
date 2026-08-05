from datetime import datetime, timedelta, timezone

from django.test import TestCase

from django_x509.tests import TestX509Mixin
from django_x509.tests.test_admin import ModelAdminTests as BaseModelAdminTests
from django_x509.tests.test_ca import TestCa as BaseTestCa
from django_x509.tests.test_cert import TestCert as BaseTestCert

from .models import CustomCert


class TestCustomCert(TestX509Mixin, TestCase):
    def test_pk_field(self):
        """Test that a cert can be created without an AttributeError."""
        cert = self._create_cert(cert_model=CustomCert, fingerprint="123")
        self.assertEqual(cert.pk, cert.fingerprint)

    def test_ordering(self):
        ca = self._create_ca()
        old = CustomCert.objects.create(fingerprint="a", ca=ca)
        tied = CustomCert.objects.create(fingerprint="b", ca=ca)
        newest = CustomCert.objects.create(fingerprint="c", ca=ca)
        created = datetime(2026, 1, 1, tzinfo=timezone.utc)
        CustomCert.objects.filter(pk__in=[old.pk, tied.pk]).update(created=created)
        CustomCert.objects.filter(pk=newest.pk).update(
            created=created + timedelta(days=1)
        )

        self.assertEqual(CustomCert._meta.ordering, ("-created", "-pk"))
        self.assertEqual(
            list(CustomCert.objects.values_list("pk", flat=True)),
            [newest.pk, tied.pk, old.pk],
        )


class ModelAdminTests(BaseModelAdminTests):
    app_label = "sample_x509"


class TestCert(BaseTestCert):
    pass


class TestCa(BaseTestCa):
    pass


del BaseModelAdminTests
del BaseTestCa
del BaseTestCert
