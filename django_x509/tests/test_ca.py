from datetime import datetime, timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from OpenSSL import crypto
from swapper import load_model

from .. import settings as app_settings
from ..base.models import datetime_to_string, generalized_time, utc_time
from . import TestX509Mixin

Ca = load_model('django_x509', 'Ca')
Cert = load_model('django_x509', 'Cert')


class TestCa(TestX509Mixin, TestCase):
    """
    tests for Ca model
    """

    def _prepare_revoked(self):
        ca = self._create_ca()
        crl = crypto.load_crl(crypto.FILETYPE_PEM, ca.crl)
        self.assertIsNone(crl.get_revoked())
        cert = self._create_cert(ca=ca)
        cert.revoke()
        return (ca, cert)

    import_certificate = """
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
        self.assertNotEqual(ca.certificate, '')
        self.assertNotEqual(ca.private_key, '')
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca.certificate)
        self.assertEqual(int(cert.get_serial_number()), int(ca.serial_number))
        subject = cert.get_subject()
        self.assertEqual(subject.countryName, ca.country_code)
        self.assertEqual(subject.stateOrProvinceName, ca.state)
        self.assertEqual(subject.localityName, ca.city)
        self.assertEqual(subject.organizationName, ca.organization_name)
        self.assertEqual(subject.emailAddress, ca.email)
        self.assertEqual(subject.commonName, ca.common_name)
        issuer = cert.get_issuer()
        self.assertEqual(issuer.countryName, ca.country_code)
        self.assertEqual(issuer.stateOrProvinceName, ca.state)
        self.assertEqual(issuer.localityName, ca.city)
        self.assertEqual(issuer.organizationName, ca.organization_name)
        self.assertEqual(issuer.emailAddress, ca.email)
        self.assertEqual(issuer.commonName, ca.common_name)
        # ensure version is 3
        self.assertEqual(cert.get_version(), 2)
        # basic constraints
        e = cert.get_extension(0)
        self.assertEqual(e.get_critical(), 1)
        self.assertEqual(e.get_short_name().decode(), 'basicConstraints')
        self.assertEqual(e.get_data(), b'0\x06\x01\x01\xff\x02\x01\x00')

    def test_x509_property(self):
        ca = self._create_ca()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca.certificate)
        self.assertEqual(ca.x509.get_subject(), cert.get_subject())
        self.assertEqual(ca.x509.get_issuer(), cert.get_issuer())

    def test_x509_property_none(self):
        self.assertIsNone(Ca().x509)

    def test_pkey_property(self):
        ca = self._create_ca()
        self.assertIsInstance(ca.pkey, crypto.PKey)

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
        ca = Ca(name='ImportTest')
        ca.certificate = self.import_certificate
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
        start = timezone.make_aware(
            datetime.strptime('20150101000000Z', generalized_time)
        )
        self.assertEqual(ca.validity_start, start)
        end = timezone.make_aware(
            datetime.strptime('20200101000000Z', generalized_time)
        )
        self.assertEqual(ca.validity_end, end)
        self.assertEqual(ca.country_code, 'US')
        self.assertEqual(ca.state, 'CA')
        self.assertEqual(ca.city, 'San Francisco')
        self.assertEqual(ca.organization_name, 'ACME')
        self.assertEqual(ca.email, 'contact@acme.com')
        self.assertEqual(ca.common_name, 'importtest')
        self.assertEqual(ca.name, 'ImportTest')
        self.assertEqual(int(ca.serial_number), 123456)
        # ensure version is 3
        self.assertEqual(cert.get_version(), 3)
        ca.delete()
        # test auto name
        ca = Ca(
            certificate=self.import_certificate, private_key=self.import_private_key
        )
        ca.full_clean()
        ca.save()
        self.assertEqual(ca.name, 'importtest')

    def test_import_private_key_empty(self):
        ca = Ca(name='ImportTest')
        ca.certificate = self.import_certificate
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
        e2 = crypto.X509Extension(
            b'subjectKeyIdentifier', False, b'hash', subject=ca.x509
        )
        self.assertEqual(e.get_data(), e2.get_data())

    def test_authority_key_identifier(self):
        ca = self._create_ca()
        e = ca.x509.get_extension(3)
        self.assertEqual(e.get_short_name().decode(), 'authorityKeyIdentifier')
        self.assertEqual(e.get_critical(), False)
        e2 = crypto.X509Extension(
            b'authorityKeyIdentifier',
            False,
            b'keyid:always,issuer:always',
            issuer=ca.x509,
        )
        self.assertEqual(e.get_data(), e2.get_data())

    def test_extensions(self):
        extensions = [
            {
                'name': 'nsComment',
                'critical': False,
                'value': 'CA - autogenerated Certificate',
            }
        ]
        ca = self._create_ca(extensions=extensions)
        e1 = ca.x509.get_extension(4)
        self.assertEqual(e1.get_short_name().decode(), 'nsComment')
        self.assertEqual(e1.get_critical(), False)
        self.assertEqual(e1.get_data(), b'\x16\x1eCA - autogenerated Certificate')

    def test_extensions_error1(self):
        extensions = {}
        try:
            self._create_ca(extensions=extensions)
        except ValidationError as e:
            # verify error message
            self.assertIn('Extension format invalid', str(e.message_dict['__all__'][0]))
        else:
            self.fail('ValidationError not raised')

    def test_extensions_error2(self):
        extensions = [{'wrong': 'wrong'}]
        try:
            self._create_ca(extensions=extensions)
        except ValidationError as e:
            # verify error message
            self.assertIn('Extension format invalid', str(e.message_dict['__all__'][0]))
        else:
            self.fail('ValidationError not raised')

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
        crl = crypto.load_crl(crypto.FILETYPE_PEM, ca.crl)
        revoked_list = crl.get_revoked()
        self.assertIsNotNone(revoked_list)
        self.assertEqual(len(revoked_list), 1)
        self.assertEqual(int(revoked_list[0].get_serial()), cert.serial_number)

    def test_crl_view(self):
        ca, cert = self._prepare_revoked()
        response = self.client.get(reverse('admin:crl', args=[ca.pk]))
        self.assertEqual(response.status_code, 200)
        crl = crypto.load_crl(crypto.FILETYPE_PEM, response.content)
        revoked_list = crl.get_revoked()
        self.assertIsNotNone(revoked_list)
        self.assertEqual(len(revoked_list), 1)
        self.assertEqual(int(revoked_list[0].get_serial()), cert.serial_number)

    def test_crl_view_403(self):
        setattr(app_settings, 'CRL_PROTECTED', True)
        ca, _ = self._prepare_revoked()
        response = self.client.get(reverse('admin:crl', args=[ca.pk]))
        self.assertEqual(response.status_code, 403)
        setattr(app_settings, 'CRL_PROTECTED', False)

    def test_crl_view_404(self):
        self._prepare_revoked()
        response = self.client.get(reverse('admin:crl', args=[10]))
        self.assertEqual(response.status_code, 404)

    def test_x509_text(self):
        ca = self._create_ca()
        text = crypto.dump_certificate(crypto.FILETYPE_TEXT, ca.x509)
        self.assertEqual(ca.x509_text, text.decode('utf-8'))

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
        ca = Ca(name='ImportTest error')
        ca.certificate = certificate
        ca.private_key = private_key
        ca.full_clean()
        ca.save()
        self.assertEqual(ca.email, '')

    def test_fill_subject_non_strings(self):
        ca1 = self._create_ca()
        ca2 = Ca(name='ca', organization_name=ca1)
        x509 = crypto.X509()
        subject = ca2._fill_subject(x509.get_subject())
        self.assertEqual(subject.organizationName, 'Test CA')

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
            name='ImportTest error',
            certificate=self.problematic_certificate,
            private_key=self.problematic_private_key,
        )
        self.assertEqual(ca.country_code, '')

    def test_import_ca_cert_validation_error(self):
        certificate = self.import_certificate[20:]
        private_key = self.import_private_key
        ca = Ca(name='TestCaCertValidation')
        try:
            ca.certificate = certificate
            ca.private_key = private_key
            ca.full_clean()
        except ValidationError as e:
            # cryptography 2.4 and 2.6 have different error message formats
            error_msg = str(e.message_dict['certificate'][0])
            self.assertTrue(
                "('PEM routines', 'PEM_read_bio', 'no start line')"
                in error_msg  # cryptography 2.4+
                or "('PEM routines', 'get_name', 'no start line')"
                in error_msg  # cryptography 2.6+
            )
        else:
            self.fail('ValidationError not raised')

    def test_import_ca_key_validation_error(self):
        certificate = self.import_certificate
        private_key = self.import_private_key[20:]
        ca = Ca(name='TestCaKeyValidation')
        try:
            ca.certificate = certificate
            ca.private_key = private_key
            ca.full_clean()
            ca.save()
        except ValidationError as e:
            # cryptography 2.4 and 2.6 have different error message formats
            error_msg = str(e.message_dict['private_key'][0])
            self.assertTrue(
                "('PEM routines', 'PEM_read_bio', 'no start line')"
                in error_msg  # cryptography 2.4+
                or "('PEM routines', 'get_name', 'no start line')"
                in error_msg  # cryptography 2.6+
            )
        else:
            self.fail('ValidationError not raised')

    def test_create_old_serial_ca(self):
        ca = self._create_ca(serial_number=3)
        self.assertEqual(int(ca.serial_number), 3)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca.certificate)
        self.assertEqual(int(cert.get_serial_number()), int(ca.serial_number))

    def test_bad_serial_number_ca(self):
        try:
            self._create_ca(serial_number='notIntegers')
        except ValidationError as e:
            self.assertEqual(
                'Serial number must be an integer',
                str(e.message_dict['serial_number'][0]),
            )

    def test_import_ca_key_with_passphrase(self):
        ca = Ca(name='ImportTest')
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
        ca.passphrase = 'test123'
        ca.full_clean()
        ca.save()
        self.assertIsInstance(ca.pkey, crypto.PKey)

    def test_import_ca_key_with_incorrect_passphrase(self):
        ca = Ca(name='ImportTest')
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
            ca.passphrase = 'incorrect_passphrase'
            ca.full_clean()
            ca.save()
        except ValidationError as e:
            self.assertIn('Incorrect Passphrase', str(e.message_dict['passphrase'][0]))
        else:
            self.fail('ValidationError not raised')

    def test_generate_ca_with_passphrase(self):
        ca = self._create_ca(passphrase='123')
        ca.full_clean()
        ca.save()
        self.assertIsInstance(ca.pkey, crypto.PKey)

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
        cert1 = self._create_cert(ca=ca, name='cert1')
        cert2 = self._create_cert(ca=ca, name='cert2')
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
            'this is a very very very very very very'
            ' very very very very very very long name'
        )
        with self.assertRaises(ValidationError) as context_manager:
            self._create_ca(common_name=common_name)

        msg = (
            f'Ensure this value has at most 64 characters (it has {len(common_name)}).'
        )
        message_dict = context_manager.exception.message_dict
        self.assertIn('common_name', message_dict)
        self.assertEqual(message_dict['common_name'][0], msg)

    def test_ca_without_key_length_and_digest_algo(self):
        try:
            self._create_ca(key_length='', digest='')
        except ValidationError as e:
            self.assertIn('key_length', e.error_dict)
            self.assertIn('digest', e.error_dict)
        except Exception as e:
            self.fail(f'Got exception: {e}')
        else:
            self.fail('ValidationError not raised as expected')
