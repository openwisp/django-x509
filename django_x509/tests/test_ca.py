from datetime import datetime, timedelta

from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from django.test import TestCase
from django.utils import timezone
from OpenSSL import crypto

from .. import settings as app_settings
from ..models import Ca, Cert
from ..models.base import generalized_time


class TestCa(TestCase):
    """
    tests for Ca model
    """
    def _create_ca(self, ext=[]):
        ca = Ca(name='newcert',
                key_length='2048',
                digest='sha256',
                country_code='IT',
                state='RM',
                city='Rome',
                organization='OpenWISP',
                email='test@test.com',
                common_name='openwisp.org',
                extensions=ext)
        ca.full_clean()
        ca.save()
        return ca

    def _create_cert(self, ca=None, ext=[],
                     validity_start=None,
                     validity_end=None):
        if not ca:
            ca = self._create_ca()
        cert = Cert(name='testcert',
                    ca=ca,
                    key_length='1024',
                    digest='sha1',
                    country_code='IT',
                    state='RM',
                    city='Rome',
                    organization='Prova',
                    email='test@test2.com',
                    common_name='test.org',
                    extensions=ext)
        if validity_start:
            cert.validity_start = validity_start
        if validity_end:
            cert.validity_end = validity_end
        cert.full_clean()
        cert.save()
        return cert

    def _prepare_revoked(self):
        ca = self._create_ca()
        crl = crypto.load_crl(crypto.FILETYPE_PEM, ca.crl)
        self.assertIsNone(crl.get_revoked())
        cert = self._create_cert(ca=ca)
        cert.revoke()
        return (ca, cert)

    import_public_key = """
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
    import_private_key = """
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
        ca = self._create_ca()
        self.assertNotEqual(ca.public_key, '')
        self.assertNotEqual(ca.private_key, '')
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca.public_key)
        self.assertEqual(cert.get_serial_number(), ca.id)
        subject = cert.get_subject()
        self.assertEqual(subject.countryName, ca.country_code)
        self.assertEqual(subject.stateOrProvinceName, ca.state)
        self.assertEqual(subject.localityName, ca.city)
        self.assertEqual(subject.organizationName, ca.organization)
        self.assertEqual(subject.emailAddress, ca.email)
        self.assertEqual(subject.commonName, ca.common_name)
        issuer = cert.get_issuer()
        self.assertEqual(issuer.countryName, ca.country_code)
        self.assertEqual(issuer.stateOrProvinceName, ca.state)
        self.assertEqual(issuer.localityName, ca.city)
        self.assertEqual(issuer.organizationName, ca.organization)
        self.assertEqual(issuer.emailAddress, ca.email)
        self.assertEqual(issuer.commonName, ca.common_name)
        # ensure version is 3
        self.assertEqual(cert.get_version(), 3)
        # basic constraints
        e = cert.get_extension(0)
        self.assertEqual(e.get_critical(), 1)
        self.assertEqual(e.get_short_name().decode(), 'basicConstraints')
        self.assertEqual(e.get_data(), b'0\x06\x01\x01\xff\x02\x01\x00')

    def test_x509_property(self):
        ca = self._create_ca()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca.public_key)
        self.assertEqual(ca.x509.get_subject(), cert.get_subject())
        self.assertEqual(ca.x509.get_issuer(), cert.get_issuer())

    def test_x509_property_none(self):
        self.assertIsNone(Ca().x509)

    def test_pkey_property(self):
        ca = self._create_ca()
        self.assertIsInstance(ca.pkey, crypto.PKey)

    def test_pkey_property_none(self):
        self.assertIsNone(Ca().pkey)

    def test_default_validity(self):
        ca = Ca()
        self.assertEqual(ca.validity_end.year, datetime.now().year + 10)

    def test_import_ca(self):
        ca = Ca(name='ImportTest')
        ca.public_key = self.import_public_key
        ca.private_key = self.import_private_key
        ca.full_clean()
        ca.save()
        cert = ca.x509
        # verify attributes
        self.assertEqual(cert.get_serial_number(), 123456)
        subject = cert.get_subject()
        self.assertEqual(subject.countryName, 'US')
        self.assertEqual(subject.stateOrProvinceName, 'CA')
        self.assertEqual(subject.localityName, 'San Francisco')
        self.assertEqual(subject.organizationName, 'ACME')
        self.assertEqual(subject.emailAddress, 'contact@acme.com')
        self.assertEqual(subject.commonName, 'importtest')
        issuer = cert.get_issuer()
        self.assertEqual(issuer.countryName, 'US')
        self.assertEqual(issuer.stateOrProvinceName, 'CA')
        self.assertEqual(issuer.localityName, 'San Francisco')
        self.assertEqual(issuer.organizationName, 'ACME')
        self.assertEqual(issuer.emailAddress, 'contact@acme.com')
        self.assertEqual(issuer.commonName, 'importtest')
        # verify field attribtues
        self.assertEqual(ca.key_length, '512')
        self.assertEqual(ca.digest, 'sha1')
        start = timezone.make_aware(datetime.strptime('20150101000000Z', generalized_time))
        self.assertEqual(ca.validity_start, start)
        end = timezone.make_aware(datetime.strptime('20200101000000Z', generalized_time))
        self.assertEqual(ca.validity_end, end)
        self.assertEqual(ca.country_code, 'US')
        self.assertEqual(ca.state, 'CA')
        self.assertEqual(ca.city, 'San Francisco')
        self.assertEqual(ca.organization, 'ACME')
        self.assertEqual(ca.email, 'contact@acme.com')
        self.assertEqual(ca.common_name, 'importtest')
        self.assertEqual(ca.name, 'ImportTest')
        self.assertEqual(ca.serial_number, 123456)
        # ensure version is 3
        self.assertEqual(cert.get_version(), 3)
        ca.delete()
        # test auto name
        ca = Ca(public_key=self.import_public_key,
                private_key=self.import_private_key)
        ca.full_clean()
        ca.save()
        self.assertEqual(ca.name, 'importtest')

    def test_import_private_key_empty(self):
        ca = Ca(name='ImportTest')
        ca.public_key = self.import_public_key
        try:
            ca.full_clean()
        except ValidationError as e:
            # verify error message
            self.assertIn('importing an existing certificate', str(e))
        else:
            self.fail('ValidationError not raised')

    def test_basic_constraints_not_critical(self):
        setattr(app_settings, 'CA_BASIC_CONSTRAINTS_CRITICAL', False)
        ca = self._create_ca()
        e = ca.x509.get_extension(0)
        self.assertEqual(e.get_critical(), 0)
        setattr(app_settings, 'CA_BASIC_CONSTRAINTS_CRITICAL', True)

    def test_basic_constraints_pathlen(self):
        setattr(app_settings, 'CA_BASIC_CONSTRAINTS_PATHLEN', 2)
        ca = self._create_ca()
        e = ca.x509.get_extension(0)
        self.assertEqual(e.get_data(), b'0\x06\x01\x01\xff\x02\x01\x02')
        setattr(app_settings, 'CA_BASIC_CONSTRAINTS_PATHLEN', 0)

    def test_basic_constraints_pathlen_none(self):
        setattr(app_settings, 'CA_BASIC_CONSTRAINTS_PATHLEN', None)
        ca = self._create_ca()
        e = ca.x509.get_extension(0)
        self.assertEqual(e.get_data(), b'0\x03\x01\x01\xff')
        setattr(app_settings, 'CA_BASIC_CONSTRAINTS_PATHLEN', 0)

    def test_keyusage(self):
        ca = self._create_ca()
        e = ca.x509.get_extension(1)
        self.assertEqual(e.get_short_name().decode(), 'keyUsage')
        self.assertEqual(e.get_critical(), True)
        self.assertEqual(e.get_data(), b'\x03\x02\x01\x06')

    def test_keyusage_not_critical(self):
        setattr(app_settings, 'CA_KEYUSAGE_CRITICAL', False)
        ca = self._create_ca()
        e = ca.x509.get_extension(1)
        self.assertEqual(e.get_short_name().decode(), 'keyUsage')
        self.assertEqual(e.get_critical(), False)
        setattr(app_settings, 'CA_KEYUSAGE_CRITICAL', True)

    def test_keyusage_value(self):
        setattr(app_settings, 'CA_KEYUSAGE_VALUE', 'cRLSign, keyCertSign, keyAgreement')
        ca = self._create_ca()
        e = ca.x509.get_extension(1)
        self.assertEqual(e.get_short_name().decode(), 'keyUsage')
        self.assertEqual(e.get_data(), b'\x03\x02\x01\x0e')
        setattr(app_settings, 'CA_KEYUSAGE_VALUE', 'cRLSign, keyCertSign')

    def test_subject_key_identifier(self):
        ca = self._create_ca()
        e = ca.x509.get_extension(2)
        self.assertEqual(e.get_short_name().decode(), 'subjectKeyIdentifier')
        self.assertEqual(e.get_critical(), False)
        e2 = crypto.X509Extension(b'subjectKeyIdentifier',
                                  False,
                                  b'hash',
                                  subject=ca.x509)
        self.assertEqual(e.get_data(), e2.get_data())

    def test_authority_key_identifier(self):
        ca = self._create_ca()
        e = ca.x509.get_extension(3)
        self.assertEqual(e.get_short_name().decode(), 'authorityKeyIdentifier')
        self.assertEqual(e.get_critical(), False)
        e2 = crypto.X509Extension(b'authorityKeyIdentifier',
                                  False,
                                  b'keyid:always,issuer:always',
                                  issuer=ca.x509)
        self.assertEqual(e.get_data(), e2.get_data())

    def test_extensions(self):
        extensions = [
            {
                "name": "nsComment",
                "critical": False,
                "value": "CA - autogenerated Certificate"
            }
        ]
        ca = self._create_ca(ext=extensions)
        e1 = ca.x509.get_extension(4)
        self.assertEqual(e1.get_short_name().decode(), 'nsComment')
        self.assertEqual(e1.get_critical(), False)
        self.assertEqual(e1.get_data(), b'\x16\x1eCA - autogenerated Certificate')

    def test_extensions_error1(self):
        extensions = {}
        try:
            self._create_ca(ext=extensions)
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
            self._create_ca(ext=extensions)
        except ValidationError as e:
            # verify error message
            self.assertIn('Extension format invalid', str(e.message_dict['__all__'][0]))
        else:
            self.fail('ValidationError not raised')

    def test_get_revoked_certs(self):
        ca = self._create_ca()
        c1 = self._create_cert(ca=ca)
        c2 = self._create_cert(ca=ca)
        c3 = self._create_cert(ca=ca)  # noqa
        self.assertEqual(ca.get_revoked_certs().count(), 0)
        c1.revoke()
        self.assertEqual(ca.get_revoked_certs().count(), 1)
        c2.revoke()
        self.assertEqual(ca.get_revoked_certs().count(), 2)
        now = timezone.now()
        # expired certificates are not counted
        start = now - timedelta(days=6650)
        end = now - timedelta(days=6600)
        c4 = self._create_cert(ca=ca,
                               validity_start=start,
                               validity_end=end)
        c4.revoke()
        self.assertEqual(ca.get_revoked_certs().count(), 2)
        # inactive not counted yet
        start = now + timedelta(days=2)
        end = now + timedelta(days=365)
        c5 = self._create_cert(ca=ca,
                               validity_start=start,
                               validity_end=end)
        c5.revoke()
        self.assertEqual(ca.get_revoked_certs().count(), 2)

    def test_crl(self):
        ca, cert = self._prepare_revoked()
        crl = crypto.load_crl(crypto.FILETYPE_PEM, ca.crl)
        revoked_list = crl.get_revoked()
        self.assertIsNotNone(revoked_list)
        self.assertEqual(len(revoked_list), 1)
        self.assertEqual(int(revoked_list[0].get_serial()), cert.serial_number)

    def test_crl_view(self):
        ca, cert = self._prepare_revoked()
        response = self.client.get(reverse('x509:crl', args=[ca.pk]))
        self.assertEqual(response.status_code, 200)
        crl = crypto.load_crl(crypto.FILETYPE_PEM, response.content)
        revoked_list = crl.get_revoked()
        self.assertIsNotNone(revoked_list)
        self.assertEqual(len(revoked_list), 1)
        self.assertEqual(int(revoked_list[0].get_serial()), cert.serial_number)

    def test_crl_view_403(self):
        setattr(app_settings, 'CRL_PROTECTED', True)
        ca, cert = self._prepare_revoked()
        response = self.client.get(reverse('x509:crl', args=[ca.pk]))
        self.assertEqual(response.status_code, 403)
        setattr(app_settings, 'CRL_PROTECTED', False)
