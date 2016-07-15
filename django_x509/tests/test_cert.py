from datetime import datetime

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from OpenSSL import crypto

from .. import settings as app_settings
from ..models import Ca, Cert
from ..models.base import generalized_time


class TestCert(TestCase):
    """
    tests for Cert model
    """
    def _create_ca(self):
        ca = Ca(name='newcert',
                key_length='2048',
                digest='sha256',
                country_code='IT',
                state='RM',
                city='Rome',
                organization='OpenWISP',
                email='test@test.com',
                common_name='openwisp.org')
        ca.full_clean()
        ca.save()
        return ca

    def _create_cert(self, ext=[]):
        cert = Cert(name='testcert',
                    ca=self._create_ca(),
                    key_length='1024',
                    digest='sha1',
                    country_code='IT',
                    state='RM',
                    city='Rome',
                    organization='Prova',
                    email='test@test2.com',
                    common_name='test.org',
                    extensions=ext)
        cert.full_clean()
        cert.save()
        return cert

    import_public_key = """
-----BEGIN CERTIFICATE-----
MIICJzCCAdGgAwIBAwIDEtaHMA0GCSqGSIb3DQEBDgUAMHcxCzAJBgNVBAYTAlVT
MQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwE
QUNNRTEfMB0GCSqGSIb3DQEJARYQY29udGFjdEBhY21lLmNvbTETMBEGA1UEAwwK
aW1wb3J0dGVzdDAiGA8yMDE2MDcwMTE0MTgwOVoYDzIwMTkwNzA3MTQxODA5WjB3
MQswCQYDVQQGEwJJVDELMAkGA1UECAwCTUkxDjAMBgNVBAcMBU1pbGFuMRIwEAYD
VQQKDAlBQ01FLXRlc3QxHDAaBgkqhkiG9w0BCQEWDXVuaXRAdGVzdC5jb20xGTAX
BgNVBAMMEGltcG9ydC1jZXJ0LXRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
AoGBALgaNcjebrIyJGx3YGo5SWoAzTyw9sbiUZuthK9I5P5mzkzJz5YlRTDkjR9W
F9l68ZibY+/yT/+BdHWydCqM//3wtRxLFMf5+WNjQ/I2IXO7l0pDL3OooMytP3eQ
yo3eIuIHtEWgmLIP1+uu/9PDr4HOOZWB08+bBi3hF2SuPJfvAgMBAAEwDQYJKoZI
hvcNAQEOBQADQQClCDugAsjCMPkLx4FJEYwxLI0fwcjmOzvFTfWPyaaFZlc+0HD1
7h5Kt1NszHoqdVyBME/5jhPQCCZ+7hge1YyJ
-----END CERTIFICATE-----
"""
    import_private_key = """
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALgaNcjebrIyJGx3
YGo5SWoAzTyw9sbiUZuthK9I5P5mzkzJz5YlRTDkjR9WF9l68ZibY+/yT/+BdHWy
dCqM//3wtRxLFMf5+WNjQ/I2IXO7l0pDL3OooMytP3eQyo3eIuIHtEWgmLIP1+uu
/9PDr4HOOZWB08+bBi3hF2SuPJfvAgMBAAECgYEAl42MBSWGvs6kSV4kUo2CL+8l
BPcwzxxzzdITzjAVwo9i+LeRWaqowM0El21KCNA6nkQdCuPQkydAdbtIAdc8y6ul
tn00ffK9+1fl6fiWCLkkOrc2wWXNJcbgrQU9kxFTta2xKlhaMwH9urWnd2aNmIrg
RnV8COLaaik6UgM8OXECQQDc4swTDgk65X4cB8aFOSKEhf3fZQY59EoDm09S9Mab
FR7GREh9rCj1KgBClnPeoccHtmRbMptAGzk71A5OjJglAkEA1V53CggnV5/nt8PC
PgcbYXcvxRGI/7h17TW1vem02yQgYu8hOICTyhM0uEHLj86ryb6pQsj1HgWlny1v
/Xi5gwJAGuqAF6pUMZsZfOztofpOXHu/beNvmMxN4JaiWed99BPkxiA3/ShnbUiK
85JF2FE6YZQ2Mm6+QFeQ59t1StkTCQJAFGP1rlC/KcGPTGF506GsPTE9sHCPjhib
tHKYjrCh5vtZ2PqPSy4GcZ5KQH2RLYoLorkExewceKUDgeW+uRNrbwJBAKv3NDC5
2t2eLEfQzyiFig5VUvgy+4pTG+5qImm8/9sGs/LPAMepAPGx3CWrevIV/zkyoY+v
b56wRkkyq2kMxFY=
-----END PRIVATE KEY-----
"""

    import_ca_public_key = """
-----BEGIN CERTIFICATE-----
MIIB4zCCAY2gAwIBAwIDAeJAMA0GCSqGSIb3DQEBBQUAMHcxCzAJBgNVBAYTAlVT
MQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwE
QUNNRTEfMB0GCSqGSIb3DQEJARYQY29udGFjdEBhY21lLmNvbTETMBEGA1UEAwwK
aW1wb3J0dGVzdDAiGA8yMDE1MDEwMTAwMDAwMFoYDzIwMjAwMTAxMDAwMDAwWjB3
MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lz
Y28xDTALBgNVBAoMBEFDTUUxHzAdBgkqhkiG9w0BCQEWEGNvbnRhY3RAYWNtZS5j
b20xEzARBgNVBAMMCmltcG9ydHRlc3QwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA
v42Y9u9pYUiFRb36lwqdLmG8hCjl0g0HlMo2WqvHCTLk2CJvprBEuggSnaRCAmG9
ipCIds/ggaJ/w4KqJabNQQIDAQABMA0GCSqGSIb3DQEBBQUAA0EAAfEPPqbY1TLw
6IXNVelAXKxUp2f8FYCnlb0pQ3tswvefpad3h3oHrI2RGkIsM70axo7dAEk05Tj0
Zt3jXRLGAQ==
-----END CERTIFICATE-----
"""
    import_ca_private_key = """
-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAv42Y9u9pYUiFRb36
lwqdLmG8hCjl0g0HlMo2WqvHCTLk2CJvprBEuggSnaRCAmG9ipCIds/ggaJ/w4Kq
JabNQQIDAQABAkEAqpB3CEqeVxWwNi24GQ5Gb6pvpm6UVblsary0MYCLtk+jK6fg
KCptUIryQ4cblZF54y3+wrLzJ9LUOStkk10DwQIhAPItbg5PqSZTCE/Ql20jUggo
BHpXO7FI157oMxXnBJtVAiEAynx4ocYpgVtmJ9iSooZRtPp9ullEdUtU2pedSgY6
oj0CIHtcBs6FZ20dKIO3hhrSvgtnjvhejQp+R08rijIi7ibNAiBUOhR/zosjSN6k
gnz0aAUC0BOOeWV1mQFR8DE4QoEPTQIhAIdGrho1hsZ3Cs7mInJiLLhh4zwnndQx
WRyKPvMvJzWT
-----END PRIVATE KEY-----
"""

    def test_new(self):
        cert = self._create_cert()
        self.assertNotEqual(cert.public_key, '')
        self.assertNotEqual(cert.private_key, '')
        x509 = cert.x509
        self.assertEqual(x509.get_serial_number(), cert.id)
        subject = x509.get_subject()
        # check subject
        self.assertEqual(subject.countryName, cert.country_code)
        self.assertEqual(subject.stateOrProvinceName, cert.state)
        self.assertEqual(subject.localityName, cert.city)
        self.assertEqual(subject.organizationName, cert.organization)
        self.assertEqual(subject.emailAddress, cert.email)
        self.assertEqual(subject.commonName, cert.common_name)
        # check issuer
        issuer = x509.get_issuer()
        ca = cert.ca
        self.assertEqual(issuer.countryName, ca.country_code)
        self.assertEqual(issuer.stateOrProvinceName, ca.state)
        self.assertEqual(issuer.localityName, ca.city)
        self.assertEqual(issuer.organizationName, ca.organization)
        self.assertEqual(issuer.emailAddress, ca.email)
        self.assertEqual(issuer.commonName, ca.common_name)
        # check signature
        store = crypto.X509Store()
        store.add_cert(ca.x509)
        store_ctx = crypto.X509StoreContext(store, cert.x509)
        store_ctx.verify_certificate()
        # ensure version is 3
        self.assertEqual(x509.get_version(), 3)
        # basic constraints
        e = cert.x509.get_extension(0)
        self.assertEqual(e.get_critical(), 0)
        self.assertEqual(e.get_short_name().decode(), 'basicConstraints')
        self.assertEqual(e.get_data(), b'0\x00')

    def test_x509_property(self):
        cert = self._create_cert()
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert.public_key)
        self.assertEqual(cert.x509.get_subject(), x509.get_subject())
        self.assertEqual(cert.x509.get_issuer(), x509.get_issuer())

    def test_x509_property_none(self):
        self.assertIsNone(Cert().x509)

    def test_pkey_property(self):
        cert = self._create_cert()
        self.assertIsInstance(cert.pkey, crypto.PKey)

    def test_pkey_property_none(self):
        self.assertIsNone(Cert().pkey)

    def test_default_validity(self):
        cert = Cert()
        self.assertEqual(cert.validity_end.year, datetime.now().year + 1)

    def test_import_cert(self):
        ca = Ca(name='ImportTest')
        ca.public_key = self.import_ca_public_key
        ca.private_key = self.import_ca_private_key
        ca.full_clean()
        ca.save()
        cert = Cert(name='ImportCertTest',
                    ca=ca,
                    public_key=self.import_public_key,
                    private_key=self.import_private_key)
        cert.full_clean()
        cert.save()
        x509 = cert.x509
        # verify attributes
        self.assertEqual(x509.get_serial_number(), 1234567)
        subject = x509.get_subject()
        self.assertEqual(subject.countryName, 'IT')
        self.assertEqual(subject.stateOrProvinceName, 'MI')
        self.assertEqual(subject.localityName, 'Milan')
        self.assertEqual(subject.organizationName, 'ACME-test')
        self.assertEqual(subject.emailAddress, 'unit@test.com')
        self.assertEqual(subject.commonName, 'import-cert-test')
        issuer = x509.get_issuer()
        self.assertEqual(issuer.countryName, 'US')
        self.assertEqual(issuer.stateOrProvinceName, 'CA')
        self.assertEqual(issuer.localityName, 'San Francisco')
        self.assertEqual(issuer.organizationName, 'ACME')
        self.assertEqual(issuer.emailAddress, 'contact@acme.com')
        self.assertEqual(issuer.commonName, 'importtest')
        # verify field attribtues
        self.assertEqual(cert.key_length, '1024')
        self.assertEqual(cert.digest, 'sha224')
        start = timezone.make_aware(datetime.strptime('20160701141809Z', generalized_time))
        self.assertEqual(cert.validity_start, start)
        end = timezone.make_aware(datetime.strptime('20190707141809Z', generalized_time))
        self.assertEqual(cert.validity_end, end)
        self.assertEqual(cert.country_code, 'IT')
        self.assertEqual(cert.state, 'MI')
        self.assertEqual(cert.city, 'Milan')
        self.assertEqual(cert.organization, 'ACME-test')
        self.assertEqual(cert.email, 'unit@test.com')
        self.assertEqual(cert.common_name, 'import-cert-test')
        self.assertEqual(cert.serial_number, 1234567)
        # ensure version is 3
        self.assertEqual(x509.get_version(), 3)
        cert.delete()
        # test auto name
        cert = Cert(public_key=self.import_public_key,
                    private_key=self.import_private_key,
                    ca=ca)
        cert.full_clean()
        cert.save()
        self.assertEqual(cert.name, 'import-cert-test')

    def test_import_private_key_empty(self):
        ca = Ca(name='ImportTest')
        ca.public_key = self.import_ca_public_key
        ca.private_key = self.import_ca_private_key
        ca.full_clean()
        ca.save()
        cert = Cert(name='ImportTest',
                    ca=ca)
        cert.public_key = self.import_public_key
        try:
            cert.full_clean()
        except ValidationError as e:
            # verify error message
            self.assertIn('importing an existing certificate', str(e))
        else:
            self.fail('ValidationError not raised')

    def test_import_wrong_ca(self):
        # test auto name
        cert = Cert(public_key=self.import_public_key,
                    private_key=self.import_private_key,
                    ca=self._create_ca())
        try:
            cert.full_clean()
        except ValidationError as e:
            # verify error message
            self.assertIn('CA doesn\'t match', str(e.message_dict['__all__'][0]))
        else:
            self.fail('ValidationError not raised')

    def test_keyusage(self):
        cert = self._create_cert()
        e = cert.x509.get_extension(1)
        self.assertEqual(e.get_short_name().decode(), 'keyUsage')
        self.assertEqual(e.get_critical(), False)
        self.assertEqual(e.get_data(), b'\x03\x02\x05\xa0')

    def test_keyusage_critical(self):
        setattr(app_settings, 'CERT_KEYUSAGE_CRITICAL', True)
        cert = self._create_cert()
        e = cert.x509.get_extension(1)
        self.assertEqual(e.get_short_name().decode(), 'keyUsage')
        self.assertEqual(e.get_critical(), True)
        setattr(app_settings, 'CERT_KEYUSAGE_CRITICAL', False)

    def test_keyusage_value(self):
        setattr(app_settings, 'CERT_KEYUSAGE_VALUE', 'digitalSignature')
        cert = self._create_cert()
        e = cert.x509.get_extension(1)
        self.assertEqual(e.get_short_name().decode(), 'keyUsage')
        self.assertEqual(e.get_data(), b'\x03\x02\x07\x80')
        setattr(app_settings, 'CERT_KEYUSAGE_VALUE', 'digitalSignature, keyEncipherment')

    def test_subject_key_identifier(self):
        cert = self._create_cert()
        e = cert.x509.get_extension(2)
        self.assertEqual(e.get_short_name().decode(), 'subjectKeyIdentifier')
        self.assertEqual(e.get_critical(), False)
        e2 = crypto.X509Extension(b'subjectKeyIdentifier',
                                  False,
                                  b'hash',
                                  subject=cert.x509)
        self.assertEqual(e.get_data(), e2.get_data())

    def test_authority_key_identifier(self):
        cert = self._create_cert()
        e = cert.x509.get_extension(3)
        self.assertEqual(e.get_short_name().decode(), 'authorityKeyIdentifier')
        self.assertEqual(e.get_critical(), False)
        e2 = crypto.X509Extension(b'authorityKeyIdentifier',
                                  False,
                                  b'keyid:always,issuer:always',
                                  issuer=cert.ca.x509)
        self.assertEqual(e.get_data(), e2.get_data())

    def test_extensions(self):
        extensions = [
            {
                "name": "nsCertType",
                "critical": False,
                "value": "client"
            },
            {
                "name": "extendedKeyUsage",
                "critical": True,  # critical just for testing purposes
                "value": "clientAuth"
            }
        ]
        cert = self._create_cert(ext=extensions)
        e1 = cert.x509.get_extension(4)
        self.assertEqual(e1.get_short_name().decode(), 'nsCertType')
        self.assertEqual(e1.get_critical(), False)
        self.assertEqual(e1.get_data(), b'\x03\x02\x07\x80')
        e2 = cert.x509.get_extension(5)
        self.assertEqual(e2.get_short_name().decode(), 'extendedKeyUsage')
        self.assertEqual(e2.get_critical(), True)
        self.assertEqual(e2.get_data(), b'0\n\x06\x08+\x06\x01\x05\x05\x07\x03\x02')

    def test_extensions_error1(self):
        extensions = {}
        try:
            self._create_cert(ext=extensions)
        except ValidationError as e:
            # verify error message
            self.assertIn('Extension format invalid', str(e.message_dict['__all__'][0]))
        else:
            self.fail('ValidationError not raised')

    def test_extensions_error2(self):
        extensions = [
            {"wrong": "wrong"}
        ]
        try:
            self._create_cert(ext=extensions)
        except ValidationError as e:
            # verify error message
            self.assertIn('Extension format invalid', str(e.message_dict['__all__'][0]))
        else:
            self.fail('ValidationError not raised')

    def test_revoke(self):
        cert = self._create_cert()
        self.assertFalse(cert.revoked)
        self.assertIsNone(cert.revoked_at)
        cert.revoke()
        self.assertTrue(cert.revoked)
        self.assertIsNotNone(cert.revoked_at)
