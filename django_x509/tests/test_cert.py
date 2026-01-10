from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.core.exceptions import ValidationError
from django.test import TestCase
from openwisp_utils.tests import AssertNumQueriesSubTestMixin

from .. import settings as app_settings
from . import Ca, Cert, TestX509Mixin


class TestCert(AssertNumQueriesSubTestMixin, TestX509Mixin, TestCase):
    """
    tests for Cert model
    """

    import_certificate = """
-----BEGIN CERTIFICATE-----
MIICMTCCAdugAwIBAgIDAeJAMA0GCSqGSIb3DQEBBQUAMGgxETAPBgNVBAoMCE9w
ZW5XSVNQMQswCQYDVQQGEwJJVDEMMAoGA1UEAwwDb3cyMQ0wCwYDVQQHDARSb21l
MRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tMQswCQYDVQQIDAJSTTAiGA8y
MDE1MTEwMTAwMDAwMFoYDzIxMTgxMTAyMTgwMDI1WjAAMFwwDQYJKoZIhvcNAQEB
BQADSwAwSAJBANh0Y7oG5JUl9cCBs6E11cJ2xLul6zw8cEoD1L7NazrPXG/NGTLt
OF2TOEUob24aQ+YagMD6HLbejV0baTXwXakCAwEAAaOB0TCBzjAJBgNVHRMEAjAA
MAsGA1UdDwQEAwIFoDAdBgNVHQ4EFgQUpcvUDhxzJFpMvjlTQjBaCjQI/3QwgZQG
A1UdIwSBjDCBiYAUwfnP0B5rF3xo7yDRAda+1nj6QqahbKRqMGgxETAPBgNVBAoM
CE9wZW5XSVNQMQswCQYDVQQGEwJJVDEMMAoGA1UEAwwDb3cyMQ0wCwYDVQQHDARS
b21lMRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tMQswCQYDVQQIDAJSTYID
AeJAMA0GCSqGSIb3DQEBBQUAA0EAUKog+BPsM8j34Clec2BAACcuyJlwX41vQ3kG
FqQS2KfO7YIk5ITWhX8y0P//u+ENWRlnVTRQma9d5tYYJvL8+Q==
-----END CERTIFICATE-----
"""
    import_private_key = """
-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA2HRjugbklSX1wIGz
oTXVwnbEu6XrPDxwSgPUvs1rOs9cb80ZMu04XZM4RShvbhpD5hqAwPoctt6NXRtp
NfBdqQIDAQABAkEAx9M7NcOjRqXSqDOU92DRxEMNAAb+kY9iQpIi1zqgoZqWduVK
tq0X0ous54j2ItqKDHxqEbbBzlo/BxMn5zkdOQIhAPIlngBgjgM0FFt+4bw6+5mW
VvjxIQoVHkmd1HsfHkPvAiEA5NZ+Zqbbv6T7oLgixye1nbcJ3mQ5+IUuamGp7dVq
/+cCIQDpxVNCffTcNt0ob9gyRqc74Z5Ze0EwYK761zqZGrO3VQIgYp0UZ4QsWo/s
Z7wyMISqPUbtl8q1OKWb9PgVVIqNy60CIEpi865urZNSIz4SRrxn4r+WV9Mxlfxs
1xtxYxSjiqrj
-----END PRIVATE KEY-----

"""
    import_ca_certificate = """
-----BEGIN CERTIFICATE-----
MIICpTCCAk+gAwIBAgIDAeJAMA0GCSqGSIb3DQEBBQUAMGgxETAPBgNVBAoMCE9w
ZW5XSVNQMQswCQYDVQQGEwJJVDEMMAoGA1UEAwwDb3cyMQ0wCwYDVQQHDARSb21l
MRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29tMQswCQYDVQQIDAJSTTAiGA8y
MDE1MTEwMTAwMDAwMFoYDzIxMjcxMDMxMTc1OTI1WjBoMREwDwYDVQQKDAhPcGVu
V0lTUDELMAkGA1UEBhMCSVQxDDAKBgNVBAMMA293MjENMAsGA1UEBwwEUm9tZTEc
MBoGCSqGSIb3DQEJARYNdGVzdEB0ZXN0LmNvbTELMAkGA1UECAwCUk0wXDANBgkq
hkiG9w0BAQEFAANLADBIAkEAsz5ORGAkryOe3bHRsuBJjCbwvPh4peSfpdrRV9CS
iz7HQWq1s+wdzHONvc8pin+lmnB+RhGm0LrZDOWRyfzjMwIDAQABo4HdMIHaMBIG
A1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTB+c/Q
HmsXfGjvINEB1r7WePpCpjCBlAYDVR0jBIGMMIGJgBTB+c/QHmsXfGjvINEB1r7W
ePpCpqFspGowaDERMA8GA1UECgwIT3BlbldJU1AxCzAJBgNVBAYTAklUMQwwCgYD
VQQDDANvdzIxDTALBgNVBAcMBFJvbWUxHDAaBgkqhkiG9w0BCQEWDXRlc3RAdGVz
dC5jb20xCzAJBgNVBAgMAlJNggMB4kAwDQYJKoZIhvcNAQEFBQADQQAeHppFPgUx
TPJ0Vv9oZHcaOTww6S2p/X/F6yCHZMYq83B+cVxcJ4v+MVxRLg7DBVAIA8gOEFy2
sKMLWX3IKJmh
-----END CERTIFICATE-----
"""
    import_ca_private_key = """
-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAsz5ORGAkryOe3bHR
suBJjCbwvPh4peSfpdrRV9CSiz7HQWq1s+wdzHONvc8pin+lmnB+RhGm0LrZDOWR
yfzjMwIDAQABAkEAnG5ICEyQN3my8HB8PsyX44UonQOM59s7qZfrE+SnwHU2ywhE
k9Y1S1C9VB0YsDZTeZUggJNSDN4YrKjIevYZQQIhAOWec6vngM/PlI1adrFndd3d
2WlyfnXwE/RFzVDOfOcrAiEAx9Y1ZbtTr2AL6wsf+wpRbkq9dPEiWi4C+0ms3Uw2
8BkCIGRctohLnqS2QWLrSHfQFdeM0StizN11uvMI023fYv6TAiEAxujn85/3V1wh
4M4NAiMuFLseQ5V1XQ/pddjK0Od405kCIC2ezclTgDBbRkHXKFtKnoj3/pGUsa3K
5XIa5rp5Is47
-----END PRIVATE KEY-----
"""

    def test_new(self):
        with self.assertNumQueries(3):
            cert = self._create_cert()
        self.assertNotEqual(cert.certificate, "")
        self.assertNotEqual(cert.private_key, "")
        x509_obj = cert.x509
        self.assertEqual(x509_obj.serial_number, int(cert.serial_number))
        # ensure version is 3
        self.assertEqual(x509_obj.version, x509.Version.v3)

        def get_attr(name_obj, oid):
            attrs = name_obj.get_attributes_for_oid(oid)
            return str(attrs[0].value) if attrs else ""

        # check subject
        mapping = {
            NameOID.COUNTRY_NAME: cert.country_code,
            NameOID.STATE_OR_PROVINCE_NAME: cert.state,
            NameOID.LOCALITY_NAME: cert.city,
            NameOID.ORGANIZATION_NAME: cert.organization_name,
            NameOID.EMAIL_ADDRESS: cert.email,
            NameOID.COMMON_NAME: cert.common_name,
        }
        for oid, expected_val in mapping.items():
            self.assertEqual(get_attr(x509_obj.subject, oid), expected_val)
        # check issuer
        self.assertEqual(x509_obj.issuer, cert.ca.x509.subject)
        self.assertEqual(
            get_attr(x509_obj.issuer, NameOID.COMMON_NAME), cert.ca.common_name
        )
        # check signature
        cert._verify_ca()
        # basic constraints
        ext = x509_obj.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertFalse(ext.critical)
        self.assertFalse(ext.value.ca)

    def test_x509_property(self):
        cert = self._create_cert()
        cert_from_pem = x509.load_pem_x509_certificate(cert.certificate.encode())
        self.assertEqual(cert.x509.subject, cert_from_pem.subject)
        self.assertEqual(cert.x509.issuer, cert_from_pem.issuer)

    def test_x509_property_none(self):
        self.assertIsNone(Cert().x509)

    def test_pkey_property(self):
        cert = self._create_cert()
        self.assertIsInstance(cert.pkey, rsa.RSAPrivateKey)

    def test_pkey_property_none(self):
        self.assertIsNone(Cert().pkey)

    def test_default_validity_end(self):
        cert = Cert()
        self.assertEqual(cert.validity_end.year, datetime.now().year + 1)

    def test_default_validity_start(self):
        cert = Cert()
        expected = datetime.now() - timedelta(days=1)
        self.assertEqual(cert.validity_start.year, expected.year)
        self.assertEqual(cert.validity_start.month, expected.month)
        self.assertEqual(cert.validity_start.day, expected.day)
        self.assertEqual(cert.validity_start.hour, 0)
        self.assertEqual(cert.validity_start.minute, 0)
        self.assertEqual(cert.validity_start.second, 0)

    def test_import_cert(self):
        ca = Ca(name="ImportTest")
        ca.certificate = self.import_ca_certificate
        ca.private_key = self.import_ca_private_key
        ca.full_clean()
        ca.save()
        cert = Cert(
            name="ImportCertTest",
            ca=ca,
            certificate=self.import_certificate,
            private_key=self.import_private_key,
        )
        cert.full_clean()
        cert.save()
        x509_obj = cert.x509
        # verify attributes
        self.assertEqual(x509_obj.serial_number, 123456)
        # verify issuer (using CA subject for comparison)
        self.assertEqual(x509_obj.issuer, ca.x509.subject)
        # verify field attributes
        self.assertEqual(cert.key_length, "512")
        self.assertEqual(cert.digest, "sha1")
        self.assertEqual(int(cert.serial_number), 123456)

        self.assertEqual(cert.country_code, "")
        self.assertEqual(cert.common_name, "")
        start = datetime(2015, 11, 1, 0, 0, 0, tzinfo=dt_timezone.utc)
        end = datetime(2118, 11, 2, 18, 0, 25, tzinfo=dt_timezone.utc)
        self.assertEqual(cert.validity_start, start)
        self.assertEqual(cert.validity_end, end)
        # ensure version is 3
        self.assertEqual(x509_obj.version, x509.Version.v3)
        cert.delete()
        # test auto name
        cert = Cert(
            certificate=self.import_certificate,
            private_key=self.import_private_key,
            ca=ca,
        )
        cert.full_clean()
        cert.save()
        self.assertEqual(cert.name, "123456")

    def test_import_private_key_empty(self):
        ca = self._create_ca()
        cert = Cert(name="ImportTest", ca=ca)
        cert.certificate = self.import_certificate
        with self.assertRaises(ValidationError) as cm:
            cert.full_clean()
        self.assertIn("importing an existing certificate", str(cm.exception))

    def test_import_wrong_ca(self):
        ca = self._create_ca()
        # test auto name
        cert = Cert(
            certificate=self.import_certificate,
            private_key=self.import_private_key,
            ca=ca,
        )
        with self.assertRaises(ValidationError) as cm:
            cert.full_clean()
        self.assertIn("The Certificate Issuer does not match", str(cm.exception))

    def test_keyusage(self):
        cert = self._create_cert()
        ext = cert.x509.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertFalse(ext.critical)
        self.assertTrue(ext.value.digital_signature)
        self.assertTrue(ext.value.key_encipherment)

    def test_keyusage_critical(self):
        setattr(app_settings, "CERT_KEYUSAGE_CRITICAL", True)
        cert = self._create_cert()
        ext = cert.x509.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(ext.critical)
        setattr(app_settings, "CERT_KEYUSAGE_CRITICAL", False)

    def test_keyusage_value(self):
        setattr(app_settings, "CERT_KEYUSAGE_VALUE", "digitalSignature")
        cert = self._create_cert()
        ext = cert.x509.extensions.get_extension_for_class(x509.KeyUsage)
        self.assertTrue(ext.value.digital_signature)
        self.assertFalse(ext.value.key_encipherment)
        setattr(
            app_settings, "CERT_KEYUSAGE_VALUE", "digitalSignature, keyEncipherment"
        )

    def test_subject_key_identifier(self):
        cert = self._create_cert()
        ext = cert.x509.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        self.assertFalse(ext.critical)
        expected_ski = x509.SubjectKeyIdentifier.from_public_key(cert.pkey.public_key())
        self.assertEqual(ext.value, expected_ski)

    def test_authority_key_identifier(self):
        cert = self._create_cert()
        ext = cert.x509.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        self.assertFalse(ext.critical)
        ca_ski = cert.ca.x509.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        )
        self.assertEqual(ext.value.key_identifier, ca_ski.value.digest)

    def test_extensions(self):
        extensions = [
            {"name": "nsCertType", "critical": False, "value": "client"},
            {
                "name": "extendedKeyUsage",
                "critical": True,  # critical just for testing purposes
                "value": "clientAuth",
            },
        ]
        cert = self._create_cert(extensions=extensions)
        x509_obj = cert.x509
        ns_oid = x509.ObjectIdentifier("2.16.840.1.113730.1.1")
        e1 = cert.x509.extensions.get_extension_for_oid(ns_oid)
        self.assertFalse(e1.critical)
        self.assertEqual(e1.value.value, b"\x03\x02\x07\x80")
        e2 = x509_obj.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertTrue(e2.critical)
        self.assertIn(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, e2.value)

    def test_extensions_error1(self):
        extensions = {}
        try:
            self._create_cert(extensions=extensions)
        except ValidationError as e:
            msg = e.message_dict.get("__all__", [str(e)])[0]
            self.assertIn("Extension format invalid", str(msg))
        else:
            self.fail("ValidationError not raised")

    def test_extensions_error2(self):
        extensions = [{"wrong": "wrong"}]
        try:
            self._create_cert(extensions=extensions)
        except ValidationError as e:
            msg = e.message_dict.get("__all__", [str(e)])[0]
            self.assertIn("Extension format invalid", str(msg))
        else:
            self.fail("ValidationError not raised")

    def test_revoke(self):
        cert = self._create_cert()
        self.assertFalse(cert.revoked)
        self.assertIsNone(cert.revoked_at)
        cert.revoke()
        self.assertTrue(cert.revoked)
        self.assertIsNotNone(cert.revoked_at)

    def test_x509_text(self):
        cert = self._create_cert()
        text = cert.x509_text
        self.assertIsNotNone(text)
        self.assertIn(f"Subject: CN={cert.common_name}", text)
        self.assertIn(f"Serial Number: {cert.serial_number}", text)
        new_cert = Cert()
        self.assertIsNone(new_cert.x509_text)

    def test_get_subject_None_attrs(self):
        ca = self._create_ca()
        cert = Cert(name="test", ca=ca, common_name="test")
        subject = cert._get_subject()
        cn_attrs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        self.assertEqual(len(cn_attrs), 1)
        self.assertEqual(cn_attrs[0].value, "test")
        self.assertEqual(len(subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)), 0)
        self.assertEqual(
            len(subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)), 0
        )
        cert.country_code = "IT"
        subject_updated = cert._get_subject()
        self.assertEqual(
            len(subject_updated.get_attributes_for_oid(NameOID.COUNTRY_NAME)), 1
        )
        self.assertEqual(
            subject_updated.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value, "IT"
        )

    def test_cert_create(self):
        ca = Ca(name="Test CA")
        ca.full_clean()
        ca.save()

        Cert.objects.create(ca=ca, common_name="TestCert1", name="TestCert1")

    def test_import_cert_validation_error(self):
        certificate = self.import_certificate[20:]
        private_key = self.import_private_key
        ca = self._create_ca()
        try:
            cert = Cert(
                name="TestCertValidation",
                ca=ca,
                certificate=certificate,
                private_key=private_key,
            )
            cert.full_clean()
        except ValidationError as e:
            error_msg = str(e.message_dict["certificate"][0])
            self.assertIn("Invalid certificate", error_msg)
        else:
            self.fail("ValidationError not raised")

    def test_import_key_validation_error(self):
        certificate = self.import_certificate
        private_key = self.import_private_key[20:]
        ca = self._create_ca()
        try:
            cert = Cert(
                name="TestKeyValidation",
                ca=ca,
                certificate=certificate,
                private_key=private_key,
            )
            cert.full_clean()
        except ValidationError as e:
            error_msg = str(e.message_dict["private_key"][0])
            self.assertIn("Invalid private key", error_msg)
        else:
            self.fail("ValidationError not raised")

    def test_create_old_serial_certificate(self):
        cert = self._create_cert(serial_number=3)
        self.assertEqual(int(cert.serial_number), 3)
        x509_obj = cert.x509
        self.assertEqual(x509_obj.serial_number, 3)

    def test_bad_serial_number_cert(self):
        try:
            self._create_cert(serial_number="notIntegers")
        except ValidationError as e:
            self.assertEqual(
                "Serial number must be an integer",
                str(e.message_dict["serial_number"][0]),
            )

    def test_serial_number_clash(self):
        ca = Ca(name="TestSerialClash")
        ca.certificate = self.import_ca_certificate
        ca.private_key = self.import_ca_private_key
        ca.save()
        cert = self._create_cert(serial_number=123456, ca=ca)
        cert.full_clean()
        cert.save()
        _cert = Cert(
            name="TestClash",
            ca=ca,
            certificate=self.import_certificate,
            private_key=self.import_private_key,
        )
        try:
            _cert.full_clean()
        except ValidationError as e:
            self.assertEqual(
                "Certificate with this CA and Serial number already exists.",
                str(e.message_dict["__all__"][0]),
            )
        else:
            self.fail("ValidationError not raised for serial clash")

    def test_import_cert_with_passphrase(self):
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
        self.assertIsInstance(ca.pkey, rsa.RSAPrivateKey)

    def test_generate_ca_with_passphrase(self):
        ca = self._create_ca(passphrase="123")
        ca.full_clean()
        ca.save()
        self.assertIsInstance(ca.pkey, rsa.RSAPrivateKey)

    def test_renew(self):
        cert = self._create_cert()
        old_cert = cert.certificate
        old_key = cert.private_key
        old_end = cert.validity_end
        old_serial_number = cert.serial_number
        ca = cert.ca
        old_ca_cert = ca.certificate
        old_ca_key = ca.private_key
        old_ca_end = ca.validity_end
        old_ca_serial_number = str(cert.ca.serial_number)
        cert.renew()
        self.assertNotEqual(old_cert, cert.certificate)
        self.assertNotEqual(old_key, cert.private_key)
        self.assertGreater(cert.validity_end, old_end)
        self.assertNotEqual(old_serial_number, cert.serial_number)
        ca = cert.ca
        ca.refresh_from_db()
        self.assertEqual(old_ca_cert, ca.certificate)
        self.assertEqual(old_ca_key, ca.private_key)
        self.assertEqual(old_ca_end, ca.validity_end)
        self.assertEqual(old_ca_serial_number, ca.serial_number)

    def test_cert_common_name_length(self):
        common_name = "a" * 65
        with self.assertRaises(ValidationError) as context_manager:
            self._create_cert(common_name=common_name)
        msg = (
            f"Ensure this value has at most 64 characters (it has {len(common_name)})."
        )
        message_dict = context_manager.exception.message_dict
        self.assertIn("common_name", message_dict)
        self.assertEqual(message_dict["common_name"][0], msg)
