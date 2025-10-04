import zoneinfo
from datetime import datetime, timedelta

import cryptography.x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import NameAttribute, load_pem_x509_crl, Certificate
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from OpenSSL import crypto
from swapper import load_model

from .. import settings as app_settings
from ..base.models import datetime_to_string, generalized_time, utc_time
from . import TestX509Mixin

Ca = load_model("django_x509", "Ca")
Cert = load_model("django_x509", "Cert")


class TestCa(TestX509Mixin, TestCase):
    """
    tests for Ca model
    """

    app_label = Ca._meta.app_label

    def _prepare_revoked(self):
        ca = self._create_ca()
        crl = load_pem_x509_crl(ca.crl)
        self.assertEqual(len(crl), 0)
        cert = self._create_cert(ca=ca)
        cert.revoke()
        return ca, cert

    import_certificate = """
-----BEGIN CERTIFICATE-----
MIIDwTCCAqmgAwIBAgIDAeJAMA0GCSqGSIb3DQEBCwUAMHcxCzAJBgNVBAYTAlVT
MQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwE
QUNNRTEfMB0GCSqGSIb3DQEJARYQY29udGFjdEBhY21lLmNvbTETMBEGA1UEAwwK
aW1wb3J0dGVzdDAeFw0yNTEwMDMyMjAwMDBaFw0zNTEwMDIyMjAwMDBaMHcxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEN
MAsGA1UECgwEQUNNRTEfMB0GCSqGSIb3DQEJARYQY29udGFjdEBhY21lLmNvbTET
MBEGA1UEAwwKaW1wb3J0dGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAJgoX4hB2NkIdNwYrl++IsyVWw27LJBNnQG3pLk65XaW13aVnlaRLVAjGCeX
BCeK72aF45e4QuWverSsfzxWjzuZXQhf0B89AGSC63Xx48jcITiCdoinyWRLHabr
P7xAuNz8PWpOdV9TZd5jSp2N7sDTz3V7ahUz2KZ9AvDZ4ufg/wDzefctbLQ/G9es
XPUCJFCB31QGm0dZ23p10G9j+iYBmprIh7rV103ESSwZkBtbVu7rr0NP/OzgyRF1
bJ6MAkI2F66U98l+WVghToKXZgE0c79OpvS4QPjQH9HK+baQRAQfJr+1mYYR1+bX
JCXMRD0RBuFdOMN0/KzTFV5mfWMCAwEAAaNWMFQwEgYDVR0TAQH/BAgwBgEB/wIB
ADAOBgNVHQ8BAf8EBAMCAQYwDQYDVR0OBAYEBGhhc2gwHwYDVR0jBBgwFoAUiMhM
3Qtipq49Ic/oFMer1UjvIfQwDQYJKoZIhvcNAQELBQADggEBAFKe9Cq3eyv3aqMx
+5fL01mI3mSI8TEvutQ8ljtv2ddcS7urrwbSXbQp/yA2mugIl9e5ws9J573PYUiR
6Q6Ndtn07ssgKRmFLzxpmUAP4MkBJyHrka/8Vat+oRE9cxFx9zgT7ZNNZe5jaI8v
6NqtPX46sZfLU+0/qMT/+vR8/Ne1A87e+XZUGKiXvChF5I4PNqM4pgMFS2POwsO4
1dI1+4AevKmyu3ZLSt2vgVT70aK3NoMPgRzjDPGQ2hEYUaLZJbM1/YIMTvGGeldK
jH2iTxu8FCbllwTWfW8yZx8HvtLoQBJDCDFDuK9a/UFjkvSCoF1C9q1pUWuYVuVR
ok9Nbsc=
-----END CERTIFICATE-----
"""
    import_private_key = """
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCYKF+IQdjZCHTc
GK5fviLMlVsNuyyQTZ0Bt6S5OuV2ltd2lZ5WkS1QIxgnlwQniu9mheOXuELlr3q0
rH88Vo87mV0IX9AfPQBkgut18ePI3CE4gnaIp8lkSx2m6z+8QLjc/D1qTnVfU2Xe
Y0qdje7A0891e2oVM9imfQLw2eLn4P8A83n3LWy0PxvXrFz1AiRQgd9UBptHWdt6
ddBvY/omAZqayIe61ddNxEksGZAbW1bu669DT/zs4MkRdWyejAJCNheulPfJfllY
IU6Cl2YBNHO/Tqb0uED40B/Ryvm2kEQEHya/tZmGEdfm1yQlzEQ9EQbhXTjDdPys
0xVeZn1jAgMBAAECggEAOaCI1f1CWKiIQdejKyXC3kLu0luCfEC45y6bV4AD6g8l
GYd/CYBAbipseooKi8Nl+ilZUlv6Ei2MxqLSKZMK+mKSRpqrIzmiTW78KJZtU+Rz
PIjExeruLmr4lwBgCjdlDGUICZwfffQDD+ABIXzg4O0XlIIiYldZhWyxUXDkLDeI
AjftmxmTnKrz29kv9hKx+STYVYvv/GXJjeULqE4H5vgf/uXqFmZo5TCdMgnFhDd3
ga0a8ZmgtpvwBWOojWGaMv03XZLmeMnPTYXmAOiysyDjfw4XVEGxUKXiTVc3SPFf
GpQw+KjqfpOWjfpyeRA63DoA2mtptIocNeB0A07R6QKBgQDQo6lFmip5yVLfXUBz
M+dT8kVl5+PQbKRD9yAYhRJ/NOVmDi8NBVd2OlUSlkE/8ePlxiR/AGE1xJM49RuG
4xax+IZZcmuwCJRRtopx8gSSV3s/CxUZiyhQUWRdGJbza71w+BIZ2qC7sNBF+W6J
BxmMnyLKCNg5gDnndhHZP5iLPwKBgQC6snueuCx5tPHSJ6G+N4WFQQd/WUzONpO+
Bzjdaa/sCH3Llb+z3XRnFSwWNBSSO4wCvN5I/0H3WgJOfZ0yIwc/opuzG8iJMrl9
7XdY67hXoWTk4BqrNJm2MQv/QMtFTEVhO/n0Ke13Tu2AIVF0/qKrcR5MpGlFr6GY
QwLaSR+43QKBgFHSvYHkciANCok64xnLEz/i1cCfbsLAuLNG6bl0BssIjaa2jVFH
9QMS4WZGsxRG4x+r04hTN8yEaVB/H+qIiNAHLXlK3FzPIIvjUOxbA9v4nwcca4v2
/TpykS/Jgvm4GTWCtGabTUoOj7/BkM4AkM6LYnNlgJccaJkTvvA6drK1AoGAU11/
ddAni/EQShcIUjfYlzgCcQsfELWuIxx2d+fJdkwUX+PuRhKM97qshP2cce/FBTPw
zgetHRZEEWhl2Q1rHy8s9z1gvmK4EVMIB9y54+dddhXb0rcaLBCamtAD9F2qXVC6
vBw8vRmxU5WNGgDaAlPwg6immUdjkOnbTD16vMECgYBVuNU6w5C2YnM6yCu7ZIvy
Zq6SAaQuFirRg5Zclwh8h+iIU6a6RHXZcebdVy2rUiUZafopwm/dRJF9gc8mQdZ8
R2+F8EKcVuQ9rBipfZshVgi/WK4UtH0adywTWgfLWMAWB2vu8Ne/flppTzQroLZc
dyHJt/vDaHYzpjqmAWHFrQ==
-----END PRIVATE KEY-----
"""

    def get_attribute_for_oid(self, name: cryptography.x509.Name, oid: ObjectIdentifier) -> NameAttribute:
        attributes = name.get_attributes_for_oid(oid)
        self.assertEqual(len(attributes), 1)
        return attributes[0]

    def test_new(self):
        ca = self._create_ca()
        self.assertNotEqual(ca.certificate, "")
        self.assertNotEqual(ca.private_key, "")
        cert = cryptography.x509.load_pem_x509_certificate(ca.certificate.encode("utf-8"))
        self.assertEqual(int(cert.serial_number), int(ca.serial_number))
        subject = cert.subject
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.COUNTRY_NAME).value, ca.country_code)
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.STATE_OR_PROVINCE_NAME).value, ca.state)
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.LOCALITY_NAME).value, ca.city)
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.ORGANIZATION_NAME).value, ca.organization_name)
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.EMAIL_ADDRESS).value, ca.email)
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.COMMON_NAME).value, ca.common_name)
        issuer = cert.issuer
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.COUNTRY_NAME).value, ca.country_code)
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.STATE_OR_PROVINCE_NAME).value, ca.state)
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.LOCALITY_NAME).value, ca.city)
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.ORGANIZATION_NAME).value, ca.organization_name)
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.EMAIL_ADDRESS).value, ca.email)
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.COMMON_NAME).value, ca.common_name)
        # ensure version is 3
        self.assertEqual(cert.version.value, 2)
        # basic constraints
        e = cert.extensions.get_extension_for_class(cryptography.x509.extensions.BasicConstraints)
        self.assertEqual(e.critical, True)
        self.assertEqual(e.value.public_bytes(), b"0\x06\x01\x01\xff\x02\x01\x00")

    def test_x509_property(self):
        ca = self._create_ca()
        cert = cryptography.x509.load_pem_x509_certificate(ca.certificate.encode("utf-8"))
        self.assertEqual(ca.x509.subject, cert.subject)
        self.assertEqual(ca.x509.issuer, cert.issuer)

    def test_x509_property_none(self):
        self.assertIsNone(Ca().x509)

    def test_pkey_property(self):
        ca = self._create_ca()
        self.assertIsInstance(ca.pkey, RSAPrivateKey)

    def test_pkey_property_none(self):
        self.assertIsNone(Ca().pkey)

    def test_default_validity_end(self):
        ca = Ca()
        self.assertEqual(ca.validity_end.year, datetime.now().year + 10)

    def test_default_validity_start(self):
        ca = Ca()
        expected = datetime.now() - timedelta(days=1)
        self.assertEqual(ca.validity_start.year, expected.year)
        self.assertEqual(ca.validity_start.month, expected.month)
        self.assertEqual(ca.validity_start.day, expected.day)
        self.assertEqual(ca.validity_start.hour, 0)
        self.assertEqual(ca.validity_start.minute, 0)
        self.assertEqual(ca.validity_start.second, 0)

    def test_import_ca(self):
        ca = Ca(name="ImportTest")
        ca.certificate = self.import_certificate
        ca.private_key = self.import_private_key
        ca.full_clean()
        ca.save()
        cert = ca.x509
        # verify attributes
        self.assertEqual(cert.serial_number, 123456)
        subject = cert.subject
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.COUNTRY_NAME).value, "US")
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.STATE_OR_PROVINCE_NAME).value, "CA")
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.LOCALITY_NAME).value, "San Francisco")
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.ORGANIZATION_NAME).value, "ACME")
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.EMAIL_ADDRESS).value, "contact@acme.com")
        self.assertEqual(self.get_attribute_for_oid(subject, NameOID.COMMON_NAME).value, "importtest")
        issuer = cert.issuer
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.COUNTRY_NAME).value, "US")
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.STATE_OR_PROVINCE_NAME).value, "CA")
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.LOCALITY_NAME).value, "San Francisco")
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.ORGANIZATION_NAME).value, "ACME")
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.EMAIL_ADDRESS).value, "contact@acme.com")
        self.assertEqual(self.get_attribute_for_oid(issuer, NameOID.COMMON_NAME).value, "importtest")
        # verify field attributes
        self.assertEqual(ca.key_length, "2048")
        self.assertEqual(ca.digest, "sha256WithRSAEncryption")
        start = timezone.make_aware(
            datetime.strptime("20251003220000Z", generalized_time),
            timezone=zoneinfo.ZoneInfo("utc")
        )
        self.assertEqual(ca.validity_start, start)
        end = timezone.make_aware(
            datetime.strptime("20351002220000Z", generalized_time),
            timezone=zoneinfo.ZoneInfo("utc")
        )
        self.assertEqual(ca.validity_end, end)
        self.assertEqual(ca.country_code, "US")
        self.assertEqual(ca.state, "CA")
        self.assertEqual(ca.city, "San Francisco")
        self.assertEqual(ca.organization_name, "ACME")
        self.assertEqual(ca.email, "contact@acme.com")
        self.assertEqual(ca.common_name, "importtest")
        self.assertEqual(ca.name, "ImportTest")
        self.assertEqual(int(ca.serial_number), 123456)
        # ensure version is 3
        self.assertEqual(cert.version.value, 2)
        ca.delete()
        # test auto name
        ca = Ca(
            certificate=self.import_certificate, private_key=self.import_private_key
        )
        ca.full_clean()
        ca.save()
        self.assertEqual(ca.name, "importtest")

    def test_import_private_key_empty(self):
        ca = Ca(name="ImportTest")
        ca.certificate = self.import_certificate
        try:
            ca.full_clean()
        except ValidationError as e:
            # verify error message
            self.assertIn("importing an existing certificate", str(e))
        else:
            self.fail("ValidationError not raised")

    def test_basic_constraints_not_critical(self):
        setattr(app_settings, "CA_BASIC_CONSTRAINTS_CRITICAL", False)
        ca = self._create_ca()
        e = ca.x509.extensions.get_extension_for_class(cryptography.x509.extensions.BasicConstraints)
        # Reset the setting before a possible panic might happen.
        setattr(app_settings, "CA_BASIC_CONSTRAINTS_CRITICAL", True)
        self.assertEqual(e.critical, False)

    def test_basic_constraints_pathlen(self):
        setattr(app_settings, "CA_BASIC_CONSTRAINTS_PATHLEN", 2)
        ca = self._create_ca()
        e = ca.x509.extensions.get_extension_for_class(cryptography.x509.extensions.BasicConstraints)
        # Reset the setting before a possible panic might happen.
        setattr(app_settings, "CA_BASIC_CONSTRAINTS_PATHLEN", 0)
        self.assertEqual(e.value.public_bytes(), b"0\x06\x01\x01\xff\x02\x01\x02")

    def test_basic_constraints_pathlen_none(self):
        setattr(app_settings, "CA_BASIC_CONSTRAINTS_PATHLEN", None)
        ca = self._create_ca()
        e = ca.x509.extensions.get_extension_for_class(cryptography.x509.extensions.BasicConstraints)
        # Reset the setting before a possible panic might happen.
        setattr(app_settings, "CA_BASIC_CONSTRAINTS_PATHLEN", 0)
        self.assertEqual(e.value.public_bytes(), b"0\x03\x01\x01\xff")

    def test_keyusage(self):
        ca = self._create_ca()
        e = ca.x509.extensions.get_extension_for_class(cryptography.x509.extensions.KeyUsage)
        self.assertEqual(e.critical, True)
        self.assertEqual(e.value.public_bytes(), b"\x03\x02\x01\x06")

    def test_keyusage_not_critical(self):
        setattr(app_settings, "CA_KEYUSAGE_CRITICAL", False)
        ca = self._create_ca()
        e = ca.x509.extensions.get_extension_for_class(cryptography.x509.extensions.KeyUsage)
        # Reset the setting before a possible panic might happen.
        setattr(app_settings, "CA_KEYUSAGE_CRITICAL", True)
        self.assertEqual(e.critical, False)

    def test_keyusage_value(self):
        setattr(app_settings, "CA_KEYUSAGE_VALUE", {
            "digital_signature": False,
            "content_commitment": False,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": True,
            "key_cert_sign": True,
            "crl_sign": True,
            "encipher_only": False,
            "decipher_only": False,
        })
        ca = self._create_ca()
        e = ca.x509.extensions.get_extension_for_class(cryptography.x509.extensions.KeyUsage)
        self.assertEqual(e.value.public_bytes(), b"\x03\x02\x01\x0e")
        setattr(app_settings, "CA_KEYUSAGE_VALUE", {
            "digital_signature": False,
            "content_commitment": False,
            "key_encipherment": False,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": True,
            "crl_sign": True,
            "encipher_only": False,
            "decipher_only": False,
        })

    def test_subject_key_identifier(self):
        ca = self._create_ca()
        e = ca.x509.extensions.get_extension_for_class(cryptography.x509.extensions.SubjectKeyIdentifier)
        self.assertEqual(e.critical, False)
        self.assertEqual(e.value.public_bytes(), b'\x04\x04hash')

    def test_authority_key_identifier(self):
        ca = self._create_ca()
        e = ca.x509.extensions.get_extension_for_class(cryptography.x509.extensions.AuthorityKeyIdentifier)
        self.assertEqual(e.critical, False)
        authority_key_identifier = cryptography.x509.extensions.AuthorityKeyIdentifier.from_issuer_public_key(
            ca.pkey.public_key()
        )
        self.assertEqual(e.value, authority_key_identifier)

    def test_extensions(self):
        extensions = [
            {
                "name": "1.3.6.1.4.1.99999.1",
                "critical": False,
                "value": "CA - autogenerated Certificate",
            }
        ]
        ca = self._create_ca(extensions=extensions)
        e1 = ca.x509.extensions.get_extension_for_oid(ObjectIdentifier("1.3.6.1.4.1.99999.1"))
        self.assertEqual(e1.critical, False)
        self.assertEqual(e1.value.public_bytes(), b"\x0c\x0bCA - autogenerated Certificate")

    def test_extensions_error1(self):
        extensions = {}
        try:
            self._create_ca(extensions=extensions)
        except ValidationError as e:
            # verify error message
            self.assertIn("Extension format invalid", str(e.message_dict["__all__"][0]))
        else:
            self.fail("ValidationError not raised")

    def test_extensions_error2(self):
        extensions = [{"wrong": "wrong"}]
        try:
            self._create_ca(extensions=extensions)
        except ValidationError as e:
            # verify error message
            self.assertIn("Extension format invalid", str(e.message_dict["__all__"][0]))
        else:
            self.fail("ValidationError not raised")

    def test_get_revoked_certs(self):
        ca = self._create_ca()
        c1 = self._create_cert(ca=ca)
        c2 = self._create_cert(ca=ca)
        self._create_cert(ca=ca)
        self.assertEqual(ca.get_revoked_certs().count(), 0)
        c1.revoke()
        self.assertEqual(ca.get_revoked_certs().count(), 1)
        c2.revoke()
        self.assertEqual(ca.get_revoked_certs().count(), 2)
        now = timezone.now()
        # expired certificates are not counted
        start = now - timedelta(days=6650)
        end = now - timedelta(days=6600)
        c4 = self._create_cert(ca=ca, validity_start=start, validity_end=end)
        c4.revoke()
        self.assertEqual(ca.get_revoked_certs().count(), 2)
        # inactive not counted yet
        start = now + timedelta(days=2)
        end = now + timedelta(days=365)
        c5 = self._create_cert(ca=ca, validity_start=start, validity_end=end)
        c5.revoke()
        self.assertEqual(ca.get_revoked_certs().count(), 2)

    def test_crl(self):
        ca, cert = self._prepare_revoked()
        crl = load_pem_x509_crl(ca.crl)
        self.assertEqual(len(crl), 1)
        self.assertEqual(int(crl[0].serial_number), cert.serial_number)

    def test_crl_view(self):
        ca, cert = self._prepare_revoked()
        path = reverse("admin:crl", args=[ca.pk])
        self.assertEqual(path, f"/admin/{self.app_label}/ca/{ca.pk}.crl")
        deprecated_path = reverse("admin:deprecated_crl", args=[ca.pk])
        self.assertEqual(
            deprecated_path, f"/admin/{self.app_label}/ca/x509/ca/{ca.pk}.crl"
        )
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        crl = load_pem_x509_crl(response.content)
        self.assertEqual(len(crl), 1)
        self.assertEqual(crl[0].serial_number, int(cert.serial_number))

    def test_crl_view_403(self):
        setattr(app_settings, "CRL_PROTECTED", True)
        ca, _ = self._prepare_revoked()
        response = self.client.get(reverse("admin:crl", args=[ca.pk]))
        self.assertEqual(response.status_code, 403)
        setattr(app_settings, "CRL_PROTECTED", False)

    def test_crl_view_404(self):
        self._prepare_revoked()
        response = self.client.get(reverse("admin:crl", args=[10]))
        self.assertEqual(response.status_code, 404)

    def test_x509_import_exception_fixed(self):
        certificate = """-----BEGIN CERTIFICATE-----
MIIEBTCCAu2gAwIBAgIBATANBgkqhkiG9w0BAQUFADBRMQswCQYDVQQGEwJJVDEL
MAkGA1UECAwCUk0xDTALBgNVBAcMBFJvbWExDzANBgNVBAoMBkNpbmVjYTEVMBMG
A1UEAwwMUHJvdmEgQ2luZWNhMB4XDTE2MDkyMTA5MDQyOFoXDTM2MDkyMTA5MDQy
OFowUTELMAkGA1UEBhMCSVQxCzAJBgNVBAgMAlJNMQ0wCwYDVQQHDARSb21hMQ8w
DQYDVQQKDAZDaW5lY2ExFTATBgNVBAMMDFByb3ZhIENpbmVjYTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMV26pysBdm3OqhyyZjbWZ3ThmH6QTIDScTj
+1y3nGgnIwgpHWJmZiO/XrwYburLttE+NP7qwgtRcVoxTJFnhuunSei8vE9lyooD
l1wRUU0qMZSWB/Q3OF+S+FhRMtymx+H6a46yC5Wqxk0apNlvAJ1avuBtZjvipQHS
Z3ub5iHpHr0LZKYbqq2yXna6SbGUjnGjVieIXTilbi/9yjukhNvoHC1fSXciV8hO
8GFuR5bUF/6kQFFMZsk3vXNTsKVx5ef7+zpN6n8lGmNAC8D28EqBxar4YAhuu8Jw
+gvguEOji5BsF8pTu4NVBXia0xWjD1DKLmueVLu9rd4l2HGxsA0CAwEAAaOB5zCB
5DAMBgNVHRMEBTADAQH/MC0GCWCGSAGG+EIBDQQgFh5DQSAtIGF1dG9nZW5lcmF0
ZWQgQ2VydGlmaWNhdGUwCwYDVR0PBAQDAgEGMB0GA1UdDgQWBBQjUcBhP7i26o7R
iaVbmRStMVsggTB5BgNVHSMEcjBwgBQjUcBhP7i26o7RiaVbmRStMVsggaFVpFMw
UTELMAkGA1UEBhMCSVQxCzAJBgNVBAgMAlJNMQ0wCwYDVQQHDARSb21hMQ8wDQYD
VQQKDAZDaW5lY2ExFTATBgNVBAMMDFByb3ZhIENpbmVjYYIBATANBgkqhkiG9w0B
AQUFAAOCAQEAg0yQ8CGHGl4p2peALn63HxkAxKzxc8bD/bCItXHq3QFJAYRe5nuu
eGBMdlVvlzh+N/xW1Jcl3+dg9UOlB5/eFr0BWXyk/0vtnJoMKjc4eVAcOlcbgk9s
c0J4ZACrfjbBH9bU7OgYy4NwVXWQFbQqDZ4/beDnuA8JZcGV5+gK3H85pqGBndev
4DUTCrYk+kRLMyWLfurH7dSyw/9DXAmOVPB6SMkTK6sqkhwUmT6hEdADFUBTujes
AjGrlOCMA8XDvvxVEl5nA6JjoPAQ8EIjYvxMykZE+nk0ZO4mqMG5DWCp/2ggodAD
tnpHdm8yeMsoFPm+yZVDHDXjAirS6MX28w==
-----END CERTIFICATE-----"""
        private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxXbqnKwF2bc6qHLJmNtZndOGYfpBMgNJxOP7XLecaCcjCCkd
YmZmI79evBhu6su20T40/urCC1FxWjFMkWeG66dJ6Ly8T2XKigOXXBFRTSoxlJYH
9Dc4X5L4WFEy3KbH4fprjrILlarGTRqk2W8AnVq+4G1mO+KlAdJne5vmIekevQtk
phuqrbJedrpJsZSOcaNWJ4hdOKVuL/3KO6SE2+gcLV9JdyJXyE7wYW5HltQX/qRA
UUxmyTe9c1OwpXHl5/v7Ok3qfyUaY0ALwPbwSoHFqvhgCG67wnD6C+C4Q6OLkGwX
ylO7g1UFeJrTFaMPUMoua55Uu72t3iXYcbGwDQIDAQABAoIBAD2pWa/c4+LNncqW
Na++52gqcm9MB2nHrxSFoKueRoAboIve0uc0VLba/ok8E/7L6GXEyCXGRxvjrcLd
XCyXqIET9zdvIFqmza11W6GLYtj20Q62Hvu69qaZrWVezcQrbIV7fnTL0mRFNLFF
Ha8sQ4Pfn3VTlDYlGyPLgTcPQrjZlwD5OlzRNEbko/LkdNXZ3pvf4q17pjsxP3E7
XqD+d+dny+pBZL748Hp1RmNo/XfhF2Y4iIV4+3/CyBiTlnn8sURqQCeuoA42iCIH
y28SBz0WS2FD/yVNbH0c4ZU+/R3Fwz5l7sHfaBieJeTFeqr5kuRU7Rro0EfFpa41
rT3fTz0CgYEA9/XpNsMtRLoMLqb01zvylgLO1cKNkAmoVFhAnh9nH1n3v55Vt48h
K9NkHUPbVwSIVdQxDzQy+YXw9IEjieVCBOPHTxRHfX90Azup5dFVXznw6qs1GiW2
mXK+fLToVoTSCi9sHIbIkCAnKS7B5hzKxu+OicKKvouo7UM/NWiSGpsCgYEAy93i
gN8leZPRSGXgS5COXOJ7zf8mqYWbzytnD5wh3XjWA2SNap93xyclCB7rlMfnOAXy
9rIgjrDEBBW7BwUyrYcB8M/qLvFfuf3rXgdhVzvA2OctdUdyzGERXObhiRopa2kq
jFj4QyRa5kv7VTe85t9Ap2bqpE2nVD1wxRdaFncCgYBN0M+ijvfq5JQkI+MclMSZ
jUIJ1WeFt3IrHhMRTHuZXCui5/awh2t6jHmTsZLpKRP8E35d7hy9L+qhYNGdWeQx
Eqaey5dv7AqlZRj5dYtcOhvAGYCttv4qA9eB3Wg4lrAv4BgGj8nraRvBEdpp88kz
S0SpOPM/vyaBZyQ0B6AqVwKBgQCvDvV03Cj94SSRGooj2RmmQQU2uqakYwqMNyTk
jpm16BE+EJYuvIjKBp8R/hslQxMVVGZx2DuEy91F9LMJMDl4MLpF4wOhE7uzpor5
zzSTB8htePXcA2Jche227Ls2U7TFeyUCJ1Pns8wqfYxwfNBFH+gQ15sdQ2EwQSIY
3BiLuQKBgGG+yqKnBceb9zybnshSAVdGt933XjEwRUbaoXGnHjnCxsTtSGa0JkCT
2yrYrwM4KOr7LrKtvz703ApicJf+oRO+vW27+N5t0pyLCjsYJyL55RpM0KWJhKhT
KQV8C/ciDV+lIw2yBmlCNvUmy7GAsHSZM+C8y29+GFR7an6WV+xa
-----END RSA PRIVATE KEY-----"""
        ca = Ca(name="ImportTest error")
        ca.certificate = certificate
        ca.private_key = private_key
        ca.full_clean()
        ca.save()
        self.assertEqual(ca.email, "")

    # this certificate has an invalid country code
    problematic_certificate = """-----BEGIN CERTIFICATE-----
MIIEjzCCA3egAwIBAgIBATANBgkqhkiG9w0BAQUFADB9MQ8wDQYDVQQGEwZJdGFs
aWExFjAUBgNVBAgMDUxhbWV6aWEgVGVybWUxFjAUBgNVBAcMDUxhbWV6aWEgVGVy
bWUxIDAeBgNVBAoMF0NvbXVuZSBkaSBMYW1lemlhIFRlcm1lMRgwFgYDVQQDDA9M
YW1lemlhZnJlZXdpZmkwHhcNMTIwMjE3MTQzMzAyWhcNMjIwMjE3MTQzMzAyWjB9
MQ8wDQYDVQQGEwZJdGFsaWExFjAUBgNVBAgMDUxhbWV6aWEgVGVybWUxFjAUBgNV
BAcMDUxhbWV6aWEgVGVybWUxIDAeBgNVBAoMF0NvbXVuZSBkaSBMYW1lemlhIFRl
cm1lMRgwFgYDVQQDDA9MYW1lemlhZnJlZXdpZmkwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDBsEbRkpsgl9PZO+eb6M+2XDuENaDKIWxzEqhlQWqfivM5
SJNpIBij9n8vIgRu2ie7DmomBkU93tQWwL5EcZcSuqAnBgzkNmko5bsk9w7v6Apq
V4UckIhtie7KRDCrG1XJaZ/0V4uYcW7+d1fYTCfMcgchpzMQsHAdjikyzRXc5TJn
noV6eZf76zQGSaZllwl90VwQvEVe3VCKSja+zpYxsOjQgnKgrDx1O0l/RGxtCWGG
fY9bizlD01nH4WuMT9ObO9F1YqnBc7pWtmRm4DfArr3yW5LKxkRrilwV1UCgQ80z
yMYSeEIufChexzo1JBzrL7aEKnSm5fDvt3iJV3OlAgMBAAGjggEYMIIBFDAMBgNV
HRMEBTADAQH/MC0GCWCGSAGG+EIBDQQgFh5DQSAtIGF1dG9nZW5lcmF0ZWQgQ2Vy
dGlmaWNhdGUwCwYDVR0PBAQDAgEGMB0GA1UdDgQWBBSsrs2asN5B2nSL36P72EBR
MOLgijCBqAYDVR0jBIGgMIGdgBSsrs2asN5B2nSL36P72EBRMOLgiqGBgaR/MH0x
DzANBgNVBAYTBkl0YWxpYTEWMBQGA1UECAwNTGFtZXppYSBUZXJtZTEWMBQGA1UE
BwwNTGFtZXppYSBUZXJtZTEgMB4GA1UECgwXQ29tdW5lIGRpIExhbWV6aWEgVGVy
bWUxGDAWBgNVBAMMD0xhbWV6aWFmcmVld2lmaYIBATANBgkqhkiG9w0BAQUFAAOC
AQEAf6qG2iFfTv31bOWeE2GBO5VyT1l2MjB/waAXT4vPE2P3RVMoZguBZLc3hmbx
nF6L5JlG7VbRqEE8wJMS5WeURuJe94CVftXJhzcd8ZnsISoGAh0IiRCLuTmpa/5q
3eWjgUwr3KldEJ77Sts72qSzRAD6C6RCMxnZTvcQzEjpomLLj1ID82lTrlrYl/in
MDl+i5LuDRMlgj6PQhUgV+WoRESnZ/jL2MMxA/hcFPzfDDw6A2Kzgz4wzS5FMyHM
iOCe57IN5gNeO2FAL351FHBONYQMtqeEEL82eSc53oFcLKCJf3E2yo1w6p5HB08H
IuRFwXXuD2zUkZtldBcYeAa2oA==
-----END CERTIFICATE-----"""
    problematic_private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAwbBG0ZKbIJfT2Tvnm+jPtlw7hDWgyiFscxKoZUFqn4rzOUiT
aSAYo/Z/LyIEbtonuw5qJgZFPd7UFsC+RHGXErqgJwYM5DZpKOW7JPcO7+gKaleF
HJCIbYnuykQwqxtVyWmf9FeLmHFu/ndX2EwnzHIHIaczELBwHY4pMs0V3OUyZ56F
enmX++s0BkmmZZcJfdFcELxFXt1Qiko2vs6WMbDo0IJyoKw8dTtJf0RsbQlhhn2P
W4s5Q9NZx+FrjE/TmzvRdWKpwXO6VrZkZuA3wK698luSysZEa4pcFdVAoEPNM8jG
EnhCLnwoXsc6NSQc6y+2hCp0puXw77d4iVdzpQIDAQABAoIBAQCvQLPjftbUV+x8
++ImRTJkm/HSP7/8BOAfAvvRmq5CK7TF2TBgh4UkHq6X1BzUvJoEfBd5zmSqhcu7
xqyiO3FppemxRZ02hTEDq1J5MP6X/oomDIjJ/tEi5BJne+nZeMNXmjX8HZaW2dSH
dS7L7KR6LZbcUXA4Ip1fcLlAWSb2Fe0bcuSLPaZZSmiA1Q3B/Q6nIOqPXDWq1/yz
Vs7doSfniAt8CQse+NeWybevAHhaLjHIbqtvmAqmq91ehEiy87Cyj9VA5l4ggM8n
O6DcmjSaiXfkLgJlrMQ50Ddxoqf35pf+vzebwFdYmyt3fGlIP1OaeVsfIGbkNFZG
NQkdjEwhAoGBAObDqy8HMv070U+EXSdbv2x1A1glkA2ZUI1Ki+zXIrNV8ohZ4w71
/v2UsAAXxTCtx28EMFo923dHGk9OXM3EhmyNqYBRX97rB5V7Gt5FxmJs75punYaB
IfMvo83Hn8mrBUUb74pQhhJ2TVVv/N3nefuElys6lMwyVgUBsu0xPt1pAoGBANbe
qKouEl+lKdhfABbLCsgCp5yXhFEgNMuGArj5Op/mw/RWOYs4TuN35WmzpmsQZ2PD
+cr+/oN+eJ7zgyStDJmMkeG4vtUVJ5F4wWFWgwgY7zU1J3tu0e/EvgaaLkqWtLRE
xGJ0zc0qHQdOGGxnQPUy49yvMsdrVwHT/RQiJdDdAoGAAnxlIbKQKA426QZiAoSI
gWCZUp/E94CJT5xX+YsvwoLQhAuD2Ktpvc2WP8oBw857cYS4CKDV9mj7rZMIiObv
E8hK5Sj7QWmCwWd8GJzj0DegNSev5r0JYpdGyna2D/QZsG7mm7TWXOiNWLhGHxXZ
SI5bGoodBD4ekxs7lDaNmNECgYEAoVVd3ynosdgZq1TphDPATJ1xrKo3t5IvEgH1
WV4JHrbuuy9i1Z3Z3gHQR6WUdx9CAi7MCBeekq0LdI3zEj69Dy30+z70Spovs5Kv
4J5MlG/kbFcU5iE3kIhxBhQOXgL6e8CGlEaPoFTWpv2EaSC+LV2gqbsCralzEvRR
OiTJsCECgYEAzdFUEea4M6Uavsd36mBbCLAYkYvhMMYUcrebFpDFwZUFaOrNV0ju
5YkQTn0EQuwQWKcfs+Z+HRiqMmqj5RdgxQs6pCQG9nfp0uVSflZATOiweshGjn6f
wZWuZRQLPPTAdiW+drs3gz8w0u3Y9ihgvHQqFcGJ1+j6ANJ0XdE/D5Y=
-----END RSA PRIVATE KEY-----"""

    def test_ca_invalid_country(self):
        ca = self._create_ca(
            name="ImportTest error",
            certificate=self.problematic_certificate,
            private_key=self.problematic_private_key,
        )
        self.assertEqual(ca.country_code, "")

    def test_import_ca_cert_validation_error(self):
        certificate = self.import_certificate[20:]
        private_key = self.import_private_key
        ca = Ca(name="TestCaCertValidation")
        try:
            ca.certificate = certificate
            ca.private_key = private_key
            ca.full_clean()
        except ValidationError as e:
            error_msg = str(e.message_dict["certificate"][0])
            self.assertTrue(error_msg.endswith("MalformedFraming"))
        else:
            self.fail("ValidationError not raised")

    def test_import_ca_key_validation_error(self):
        certificate = self.import_certificate
        private_key = self.import_private_key[20:]
        ca = Ca(name="TestCaKeyValidation")
        try:
            ca.certificate = certificate
            ca.private_key = private_key
            ca.full_clean()
            ca.save()
        except ValidationError as e:
            error_msg = str(e.message_dict["private_key"][0])
            self.assertTrue(error_msg.endswith("unsupported"))
        else:
            self.fail("ValidationError not raised")

    def test_create_old_serial_ca(self):
        ca = self._create_ca(serial_number=3)
        self.assertEqual(int(ca.serial_number), 3)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca.certificate)
        self.assertEqual(int(cert.get_serial_number()), int(ca.serial_number))

    def test_bad_serial_number_ca(self):
        try:
            self._create_ca(serial_number="notIntegers")
        except ValidationError as e:
            self.assertEqual(
                "Serial number must be an integer",
                str(e.message_dict["serial_number"][0]),
            )

    def test_import_ca_key_with_passphrase(self):
        ca = Ca(name="ImportTest")
        ca.certificate = """-----BEGIN CERTIFICATE-----
MIICrzCCAhigAwIBAgIJANCybYj5LwUWMA0GCSqGSIb3DQEBCwUAMG8xCzAJBgNV
BAYTAklOMQwwCgYDVQQIDANhc2QxDDAKBgNVBAcMA2FzZDEMMAoGA1UECgwDYXNk
MQwwCgYDVQQLDANhc2QxDDAKBgNVBAMMA2FzZDEaMBgGCSqGSIb3DQEJARYLYXNk
QGFzZC5hc2QwHhcNMTgwODI5MjExMDQ1WhcNMTkwODI5MjExMDQ1WjBvMQswCQYD
VQQGEwJJTjEMMAoGA1UECAwDYXNkMQwwCgYDVQQHDANhc2QxDDAKBgNVBAoMA2Fz
ZDEMMAoGA1UECwwDYXNkMQwwCgYDVQQDDANhc2QxGjAYBgkqhkiG9w0BCQEWC2Fz
ZEBhc2QuYXNkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBuDdlU20Ydie8
tmbq2hn8Ski6aSH2IyVVMxUj3+i6QZmoJ4sZzcAMCLPIkCAxby5pP0V6/DSqjxTL
ShYy/7QMCovmj3O+23eYR/JGNAfsk6uDsWJL6OLHTNdx19mL0NioeFNEUJt14Cbz
uqUizT7UdONLer0UK4uP2sE09Eo4cQIDAQABo1MwUTAdBgNVHQ4EFgQURUEc1+ho
on8xaoSU+HU6CRkn0/owHwYDVR0jBBgwFoAURUEc1+hoon8xaoSU+HU6CRkn0/ow
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQB2zU8qtkXVM25yrL9s
FC5oSqTky2c9KI/hwdsSronSvwaMoASgfl7UjzXlovq9FWZpNSVZ06wetkJVjq5N
Xn3APftPSmKw0J1tzUfZuvq8Z8q6uXQ4B2+BsiCkG/PwXizbKDc29yzXsXTL4+cQ
J7RrWKwDUi/GKVvqc+JjgsQ/nA==
-----END CERTIFICATE-----

        """
        ca.private_key = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,D7DDAD38C7462384

CUEPD7buBQqv/uipFz/tXYURNcQrY5HKU904IVsKbM233KPA6qU6IaRF6RRxxUtE
ejrmY2es9ZmU63gO/G/16E0CxzWhm3G2pOBsWHsBGGYcMpqZ842E3NoWimfQuRyO
E7TtMKW+Jdl6mzkw8s/KkSeGkGvZFKrclSN37CtkexRn4cXQkhNgPztyeRaQjIBM
SveP2qbODU+lr8g2oUjx05Ftcv1zJin85tzifJlQyaQz8ozKYtHA/RSpLEFZ19HG
mXn4Rvvai8r2zhdqfT/0/G6dABDrhQLxQhPE2MrY0hAlr7DnDrYNQQ/QyGoiAdcR
ee7QUDNfDnjzU6k/EjYPU1827/Kw8R4al8yDtVcUqfDuEsKabot+krEx4IZ5LOk9
PkcSW8UR0cIm7QE2BzQEzaZKQIpVwjSsSKm+RcFktiCKVun3Sps+GtXBr+AmF5Na
r6xeg+j9kz8lT8F5lnpFTk6c8cD8GDCRiLsFzPo652BQ24dAEPvsSbYmKwr1gEe8
tfsARqOuvSafQNzqBYFV7abFr8DFiE1Kghk6d6x2u7qVREvOh0RYHRWqsTRf4MMn
WlEnL9zfYST9Ur3gJgBOH2WHboDlQZu1k7yoLMfiGTQSQ2/xg1zS+5IWxt4tg029
B+f39N5zyDjuGFYcf3J6J4zybHmvdSAa62qxnkeDIbLz4axTU8+hNNOWxIsAh5vs
OO8quCk6DE4j4u3Yzk7810dkJtliwboQiTlitEbCjiyjkOrabIICKMte8nhylZX6
BxZA3knyYRiB0FNYSxI6YuCIqTjr0AoBvNHdkdjkv2VFomYNBd8ruA==
-----END RSA PRIVATE KEY-----
        """
        ca.passphrase = "test123"
        ca.full_clean()
        ca.save()
        self.assertIsInstance(ca.pkey, RSAPrivateKey)

    def test_import_ca_key_with_incorrect_passphrase(self):
        ca = Ca(name="ImportTest")
        ca.certificate = """-----BEGIN CERTIFICATE-----
MIICrzCCAhigAwIBAgIJANCybYj5LwUWMA0GCSqGSIb3DQEBCwUAMG8xCzAJBgNV
BAYTAklOMQwwCgYDVQQIDANhc2QxDDAKBgNVBAcMA2FzZDEMMAoGA1UECgwDYXNk
MQwwCgYDVQQLDANhc2QxDDAKBgNVBAMMA2FzZDEaMBgGCSqGSIb3DQEJARYLYXNk
QGFzZC5hc2QwHhcNMTgwODI5MjExMDQ1WhcNMTkwODI5MjExMDQ1WjBvMQswCQYD
VQQGEwJJTjEMMAoGA1UECAwDYXNkMQwwCgYDVQQHDANhc2QxDDAKBgNVBAoMA2Fz
ZDEMMAoGA1UECwwDYXNkMQwwCgYDVQQDDANhc2QxGjAYBgkqhkiG9w0BCQEWC2Fz
ZEBhc2QuYXNkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBuDdlU20Ydie8
tmbq2hn8Ski6aSH2IyVVMxUj3+i6QZmoJ4sZzcAMCLPIkCAxby5pP0V6/DSqjxTL
ShYy/7QMCovmj3O+23eYR/JGNAfsk6uDsWJL6OLHTNdx19mL0NioeFNEUJt14Cbz
uqUizT7UdONLer0UK4uP2sE09Eo4cQIDAQABo1MwUTAdBgNVHQ4EFgQURUEc1+ho
on8xaoSU+HU6CRkn0/owHwYDVR0jBBgwFoAURUEc1+hoon8xaoSU+HU6CRkn0/ow
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQB2zU8qtkXVM25yrL9s
FC5oSqTky2c9KI/hwdsSronSvwaMoASgfl7UjzXlovq9FWZpNSVZ06wetkJVjq5N
Xn3APftPSmKw0J1tzUfZuvq8Z8q6uXQ4B2+BsiCkG/PwXizbKDc29yzXsXTL4+cQ
J7RrWKwDUi/GKVvqc+JjgsQ/nA==
-----END CERTIFICATE-----

        """
        ca.private_key = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,D7DDAD38C7462384

CUEPD7buBQqv/uipFz/tXYURNcQrY5HKU904IVsKbM233KPA6qU6IaRF6RRxxUtE
ejrmY2es9ZmU63gO/G/16E0CxzWhm3G2pOBsWHsBGGYcMpqZ842E3NoWimfQuRyO
E7TtMKW+Jdl6mzkw8s/KkSeGkGvZFKrclSN37CtkexRn4cXQkhNgPztyeRaQjIBM
SveP2qbODU+lr8g2oUjx05Ftcv1zJin85tzifJlQyaQz8ozKYtHA/RSpLEFZ19HG
mXn4Rvvai8r2zhdqfT/0/G6dABDrhQLxQhPE2MrY0hAlr7DnDrYNQQ/QyGoiAdcR
ee7QUDNfDnjzU6k/EjYPU1827/Kw8R4al8yDtVcUqfDuEsKabot+krEx4IZ5LOk9
PkcSW8UR0cIm7QE2BzQEzaZKQIpVwjSsSKm+RcFktiCKVun3Sps+GtXBr+AmF5Na
r6xeg+j9kz8lT8F5lnpFTk6c8cD8GDCRiLsFzPo652BQ24dAEPvsSbYmKwr1gEe8
tfsARqOuvSafQNzqBYFV7abFr8DFiE1Kghk6d6x2u7qVREvOh0RYHRWqsTRf4MMn
WlEnL9zfYST9Ur3gJgBOH2WHboDlQZu1k7yoLMfiGTQSQ2/xg1zS+5IWxt4tg029
B+f39N5zyDjuGFYcf3J6J4zybHmvdSAa62qxnkeDIbLz4axTU8+hNNOWxIsAh5vs
OO8quCk6DE4j4u3Yzk7810dkJtliwboQiTlitEbCjiyjkOrabIICKMte8nhylZX6
BxZA3knyYRiB0FNYSxI6YuCIqTjr0AoBvNHdkdjkv2VFomYNBd8ruA==
-----END RSA PRIVATE KEY-----
        """
        try:
            ca.passphrase = "incorrect_passphrase"
            ca.full_clean()
            ca.save()
        except ValidationError as e:
            self.assertIn("Incorrect Passphrase", str(e.message_dict["passphrase"][0]))
        else:
            self.fail("ValidationError not raised")

    def test_generate_ca_with_passphrase(self):
        ca = self._create_ca(passphrase="123")
        ca.full_clean()
        ca.save()
        self.assertIsInstance(ca.pkey, RSAPrivateKey)

    def test_datetime_to_string(self):
        generalized_datetime = datetime(2050, 1, 1, 0, 0, 0, 0)
        utc_datetime = datetime(2049, 12, 31, 0, 0, 0, 0)
        self.assertEqual(
            datetime_to_string(generalized_datetime),
            generalized_datetime.strftime(generalized_time),
        )
        self.assertEqual(
            datetime_to_string(utc_datetime), utc_datetime.strftime(utc_time)
        )

    def test_renew(self):
        ca = self._create_ca()
        cert1 = self._create_cert(ca=ca, name="cert1")
        cert2 = self._create_cert(ca=ca, name="cert2")
        old_ca_cert = ca.certificate
        old_ca_key = ca.private_key
        old_ca_end = ca.validity_end
        old_ca_serial_number = ca.serial_number
        old_cert1_cert = cert1.certificate
        old_cert1_key = cert1.private_key
        old_cert1_serial_number = cert1.serial_number
        old_cert1_end = cert1.validity_end
        old_cert2_cert = cert2.certificate
        old_cert2_key = cert2.private_key
        old_cert2_serial_number = cert2.serial_number
        old_cert2_end = cert2.validity_end
        ca.renew()
        cert1.refresh_from_db()
        cert2.refresh_from_db()
        self.assertNotEqual(old_ca_cert, ca.certificate)
        self.assertNotEqual(old_ca_key, ca.private_key)
        self.assertLess(old_ca_end, ca.validity_end)
        self.assertNotEqual(old_ca_serial_number, ca.serial_number)
        self.assertNotEqual(old_cert1_cert, cert1.certificate)
        self.assertNotEqual(old_cert1_key, cert1.private_key)
        self.assertLess(old_cert1_end, cert1.validity_end)
        self.assertNotEqual(old_cert1_serial_number, cert1.serial_number)
        self.assertNotEqual(old_cert2_cert, cert2.certificate)
        self.assertNotEqual(old_cert2_key, cert2.private_key)
        self.assertLess(old_cert2_end, cert2.validity_end)
        self.assertNotEqual(old_cert2_serial_number, cert2.serial_number)

    def test_ca_common_name_length(self):
        common_name = (
            "this is a very very very very very very"
            " very very very very very very long name"
        )
        with self.assertRaises(ValidationError) as context_manager:
            self._create_ca(common_name=common_name)

        msg = (
            f"Ensure this value has at most 64 characters (it has {len(common_name)})."
        )
        message_dict = context_manager.exception.message_dict
        self.assertIn("common_name", message_dict)
        self.assertEqual(message_dict["common_name"][0], msg)

    def test_ca_without_key_length_and_digest_algo(self):
        try:
            self._create_ca(key_length="", digest="")
        except ValidationError as e:
            self.assertIn("digest", e.error_dict)
        except Exception as e:
            self.fail(f"Got exception: {e}")
        else:
            self.fail("ValidationError not raised as expected")
