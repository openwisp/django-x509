from django.test import TestCase

from django_x509.models import Ca
from django_x509.tests import TestX509Mixin

from .models import CustomCert


class TestCustomCert(TestX509Mixin, TestCase):
    """
    Tests for Custom Cert model with a custom primary_key field.
    """

    ca_model = Ca
    cert_model = CustomCert

    def test_pk_field(self):
        """Test that a cert can be created without an AttributeError."""
        cert = self._create_cert(fingerprint="123")
        self.assertEqual(cert.pk, cert.fingerprint)
