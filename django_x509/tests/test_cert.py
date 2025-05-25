from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.extensions import BasicConstraints, SubjectKeyIdentifier, \
    AuthorityKeyIdentifier, KeyUsage
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from openwisp_utils.tests import AssertNumQueriesSubTestMixin
from swapper import load_model

from .. import settings as app_settings
from ..base.models import generalized_time
from . import TestX509Mixin

Ca = load_model('django_x509', 'Ca')
Cert = load_model('django_x509', 'Cert')


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
        self.assertNotEqual(cert.certificate, '')
        self.assertNotEqual(cert.private_key, '')
        self.assertEqual(cert.x509.serial_number, cert.serial_number)
        
        # check subject
        self.assertEqual(
            cert.x509.subject.rfc4514_string(),
            cert._fill_subject().rfc4514_string(),
        )
        
        # check issuer
        self.assertEqual(
            cert.x509.issuer.rfc4514_string(),
            cert.ca._fill_subject().rfc4514_string(),
        )
        
        # check signature
        cert.x509.verify_directly_issued_by(cert.ca.x509)
        
        # ensure version is 3 (indexed 0 based counting)
        self.assertEqual(cert.x509.version.value, 2)
        
        # basic constraints
        basic_constraints_ext = cert.x509.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
        self.assertFalse(basic_constraints_ext.critical)
        self.assertEqual(basic_constraints_ext.oid._name, 'basicConstraints')
        self.assertIsInstance(
            obj=basic_constraints_ext.value,
            cls=BasicConstraints,
        )
        self.assertEqual(basic_constraints_ext.value, BasicConstraints(
            ca=False,
            path_length=None,
        ))

    def test_x509_property(self):
        # not entirely sure if this test is necessary
        cert = self._create_cert()
        x509_cert = x509.load_pem_x509_certificate(
            cert.certificate.encode('utf-8'),
        )
        self.assertEqual(cert.x509.subject.rfc4514_string(), x509_cert.subject.rfc4514_string())
        self.assertEqual(cert.x509.issuer.rfc4514_string(), x509_cert.issuer.rfc4514_string())

    def test_x509_property_none(self):
        self.assertIsNone(Cert().x509)

    def test_pkey_property(self):
        cert = self._create_cert()
        self.assertIsInstance(cert.pkey, RSAPrivateKey)

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
        ca = Ca(name='ImportTest')
        ca.certificate = self.import_ca_certificate
        ca.private_key = self.import_ca_private_key
        ca.full_clean()
        ca.save()
        cert = Cert(
            name='ImportCertTest',
            ca=ca,
            certificate=self.import_certificate,
            private_key=self.import_private_key,
        )
        cert.full_clean()
        cert.save()
        # verify attributes
        self.assertEqual(int(cert.x509.serial_number), 123456)
        self.assertEqual('', cert.x509.subject.rfc4514_string())
        self.assertEqual('ST=RM,1.2.840.113549.1.9.1=test@test.com,L=Rome,CN=ow2,C=IT,O=OpenWISP', cert.x509.issuer.rfc4514_string())
        
        # verify field attribtues
        self.assertEqual(cert.key_length, '512')
        self.assertEqual(cert.digest, 'sha1')
        start = timezone.make_aware(
            datetime.strptime('20151101000000Z', generalized_time)
        )
        self.assertEqual(cert.validity_start, start)
        end = timezone.make_aware(
            datetime.strptime('21181102180025Z', generalized_time)
        )
        self.assertEqual(cert.validity_end, end)
        self.assertEqual(cert.country_code, '')
        self.assertEqual(cert.state, '')
        self.assertEqual(cert.city, '')
        self.assertEqual(cert.organization_name, '')
        self.assertEqual(cert.email, '')
        self.assertEqual(cert.common_name, '')
        self.assertEqual(int(cert.serial_number), 123456)
        # ensure version is 3 (indexed 0 based counting)
        self.assertEqual(cert.x509.version.value, 2)
        cert.delete()
        # test auto name
        cert = Cert(
            certificate=self.import_certificate,
            private_key=self.import_private_key,
            ca=ca,
        )
        cert.full_clean()
        cert.save()
        self.assertEqual(cert.name, '123456')

    def test_import_private_key_empty(self):
        ca = Ca(name='ImportTest')
        ca.certificate = self.import_ca_certificate
        ca.private_key = self.import_ca_private_key
        ca.full_clean()
        ca.save()
        cert = Cert(name='ImportTest', ca=ca)
        cert.certificate = self.import_certificate
        try:
            cert.full_clean()
        except ValidationError as e:
            # verify error message
            self.assertIn('importing an existing certificate', str(e))
        else:
            self.fail('ValidationError not raised')

    def test_import_wrong_ca(self):
        # test auto name
        cert = Cert(
            certificate=self.import_certificate,
            private_key=self.import_private_key,
            ca=self._create_ca(),
        )
        try:
            cert.full_clean()
        except ValidationError as e:
            # verify error message
            self.assertIn("CA doesn't match", str(e.message_dict['__all__'][0]))
        else:
            self.fail('ValidationError not raised')

    def test_keyusage(self):
        cert = self._create_cert()
        
        key_usage_ext = cert.x509.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
        self.assertFalse(key_usage_ext.critical)
        self.assertEqual(key_usage_ext.oid._name, 'keyUsage')
        self.assertIsInstance(
            obj=key_usage_ext.value,
            cls=KeyUsage,
        )

    def test_keyusage_critical(self):
        setattr(app_settings, 'CERT_KEYUSAGE_CRITICAL', True)
        try:
            cert = self._create_cert()
            
            key_usage_ext = cert.x509.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
            self.assertTrue(key_usage_ext.critical)
            self.assertEqual(key_usage_ext.oid._name, 'keyUsage')
            self.assertIsInstance(
                obj=key_usage_ext.value,
                cls=KeyUsage,
            )
        finally:
            setattr(app_settings, 'CERT_KEYUSAGE_CRITICAL', False)

    def test_keyusage_value(self):
        setattr(
            app_settings, 'CERT_KEYUSAGE_VALUE', 'digitalSignature',
        )
        try:
            cert = self._create_cert()
            
            key_usage_ext = cert.x509.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
            self.assertFalse(key_usage_ext.critical)
            self.assertEqual(key_usage_ext.oid._name, 'keyUsage')
            self.assertIsInstance(
                obj=key_usage_ext.value,
                cls=KeyUsage,
            )
            self.assertEqual(key_usage_ext.value, KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ))
        finally:
            setattr(
                app_settings, 'CERT_KEYUSAGE_VALUE', 'digitalSignature, keyEncipherment',
            )

    def test_subject_key_identifier(self):
        cert = self._create_cert()
        subject_key_identifier_ext = cert.x509.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        
        self.assertFalse(subject_key_identifier_ext.critical)
        self.assertEqual(subject_key_identifier_ext.oid._name, 'subjectKeyIdentifier')
        self.assertIsInstance(
            obj=subject_key_identifier_ext.value,
            cls=SubjectKeyIdentifier,
        )
        self.assertEqual(
            subject_key_identifier_ext.value,
            SubjectKeyIdentifier.from_public_key(cert.x509.public_key())
        )

    def test_authority_key_identifier(self):
        cert = self._create_cert()
        
        authority_key_identifier_ext = cert.x509.extensions.get_extension_for_oid(
            x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        
        self.assertFalse(authority_key_identifier_ext.critical)
        self.assertEqual(authority_key_identifier_ext.oid._name, 'authorityKeyIdentifier')
        self.assertIsInstance(
            obj=authority_key_identifier_ext.value,
            cls=AuthorityKeyIdentifier,
        )
        
        self.assertEqual(
            authority_key_identifier_ext.value,
            AuthorityKeyIdentifier.from_issuer_public_key(cert.ca.x509.public_key())
        )

    def test_extensions(self):
        """
        @todo: I'm not sure named extensions will work with cryptography
            as ObjectIdentifier expects a dotted-string identifier
        """
        extensions = [
            {
                'name': 'nsCertType', # 2.16.840.1.113730.1.1
                'critical': False,
                'value': 'client',
            },
            {
                'name': 'extendedKeyUsage', # 2.5.29.37
                'critical': True,  # critical just for testing purposes
                'value': 'clientAuth',
            },
        ]
        cert = self._create_cert(extensions=extensions)
        ns_cert_type_ext = cert.x509.extensions.get_extension_for_oid(
            '2.16.840.1.113730.1.1'
        )
        self.assertEqual(ns_cert_type_ext.oid._name, 'nsCertType')
        self.assertFalse(ns_cert_type_ext.critical)
        #self.assertEqual(e1.get_data(), b'\x03\x02\x07\x80')
        
        return
        e2 = cert.x509.get_extension(5)
        self.assertEqual(e2.get_short_name().decode(), 'extendedKeyUsage')
        self.assertEqual(e2.get_critical(), True)
        self.assertEqual(e2.get_data(), b'0\n\x06\x08+\x06\x01\x05\x05\x07\x03\x02')

    def test_extensions_error1(self):
        extensions = {}
        try:
            self._create_cert(extensions=extensions)
        except ValidationError as e:
            # verify error message
            self.assertIn('Extension format invalid', str(e.message_dict['__all__'][0]))
        else:
            self.fail('ValidationError not raised')

    def test_extensions_error2(self):
        extensions = [{'wrong': 'wrong'}]
        try:
            self._create_cert(extensions=extensions)
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

    def test_x509_text(self):
        cert = self._create_cert()
        self.assertIn(
            member=f'Subject: {cert.x509.subject.rfc4514_string()}\n',
            container=cert.x509_text,
        )
        self.assertIn(
            member=f'Issuer: {cert.x509.issuer.rfc4514_string()}\n',
            container=cert.x509_text,
        )
        self.assertIn(
            member=f'Serial Number: {cert.x509.serial_number}\n',
            container=cert.x509_text,
        )
        self.assertIn(
            member=f'Not Before: {cert.x509.not_valid_before_utc}\n',
            container=cert.x509_text,
        )
        self.assertIn(
            member=f'Not After: {cert.x509.not_valid_after_utc}\n',
            container=cert.x509_text,
        )
        self.assertIn(
            member=f'Signature Algorithm: {cert.x509.signature_hash_algorithm.name}\n',
            container=cert.x509_text,
        )
        self.assertIn(
            member=f'Extensions:\n',
            container=cert.x509_text,
        )

    def test_fill_subject_None_attrs(self):
        # ensure no exception raised if model attrs are set to None
        cert = Cert(name='test', ca=self._create_ca())
        cert._fill_subject()
        self.country_code = 'IT'
        cert._fill_subject()
        self.state = 'RM'
        cert._fill_subject()
        self.city = 'Rome'
        cert._fill_subject()
        self.organization_name = 'OpenWISP'
        cert._fill_subject()
        self.email = 'test@test.com'
        cert._fill_subject()

    def test_cert_create(self):
        ca = Ca(name='Test CA')
        ca.full_clean()
        ca.save()

        Cert.objects.create(ca=ca, common_name='TestCert1', name='TestCert1')

    def test_import_cert_validation_error(self):
        certificate = self.import_certificate[20:]
        private_key = self.import_private_key
        ca = Ca(name='TestImportCertValidation')
        ca.certificate = self.import_ca_certificate
        ca.private_key = self.import_ca_private_key
        ca.full_clean()
        ca.save()
        try:
            cert = Cert(
                name='TestCertValidation',
                ca=ca,
                certificate=certificate,
                private_key=private_key,
            )
            cert.full_clean()
        except ValidationError as e:
            self.assertIn(
                member="Unable to load PEM file.",
                container=str(e.message_dict['certificate'][0]),
            )
        else:
            self.fail('ValidationError not raised')

    def test_import_key_validation_error(self):
        certificate = self.import_certificate
        private_key = self.import_private_key[20:]
        ca = Ca(name='TestImportKeyValidation')
        ca.certificate = self.import_certificate
        ca.private_key = self.import_private_key
        ca.full_clean()
        ca.save()
        try:
            cert = Cert(
                name='TestKeyValidation',
                ca=ca,
                certificate=certificate,
                private_key=private_key,
            )
            cert.full_clean()
        except ValidationError as e:
            self.assertIn(
                member='Could not deserialize key data.',
                container=e.message_dict.get('passphrase', ['', ])[0],
            )
        else:
            self.fail('ValidationError not raised')

    def test_create_old_serial_certificate(self):
        cert = self._create_cert(serial_number=3)
        self.assertEqual(int(cert.serial_number), 3)
        x509 = cert.x509
        self.assertEqual(int(x509.serial_number), 3)

    def test_bad_serial_number_cert(self):
        try:
            self._create_cert(serial_number='notIntegers')
        except ValidationError as e:
            self.assertEqual(
                'Serial number must be an integer',
                str(e.message_dict['serial_number'][0]),
            )

    def test_serial_number_clash(self):
        ca = Ca(name='TestSerialClash')
        ca.certificate = self.import_ca_certificate
        ca.private_key = self.import_ca_private_key
        ca.save()
        cert = self._create_cert(serial_number=123456, ca=ca)
        cert.full_clean()
        cert.save()
        _cert = Cert(
            name='TestClash',
            ca=ca,
            certificate=self.import_certificate,
            private_key=self.import_private_key,
        )
        try:
            _cert.full_clean()
        except ValidationError as e:
            self.assertEqual(
                'Certificate with this CA and Serial number already exists.',
                str(e.message_dict['__all__'][0]),
            )

    def test_import_cert_with_passphrase(self):
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
        self.assertIsInstance(ca.pkey, RSAPrivateKey)

    def test_generate_ca_with_passphrase(self):
        ca = self._create_ca(passphrase='123')
        ca.full_clean()
        ca.save()
        self.assertIsInstance(ca.pkey, RSAPrivateKey)

    def test_renew(self):
        cert = self._create_cert()
        old_cert = cert.certificate
        old_key = cert.private_key
        old_end = cert.validity_end
        old_serial_number = cert.serial_number
        old_ca_cert = cert.ca.certificate
        old_ca_key = cert.ca.private_key
        old_ca_end = cert.ca.validity_end
        old_ca_serial_number = cert.ca.serial_number
        cert.renew()
        self.assertNotEqual(old_cert, cert.certificate)
        self.assertNotEqual(old_key, cert.private_key)
        self.assertLess(old_end, cert.validity_end)
        self.assertNotEqual(old_serial_number, cert.serial_number)
        self.assertEqual(old_ca_cert, cert.ca.certificate)
        self.assertEqual(old_ca_key, cert.ca.private_key)
        self.assertEqual(old_ca_end, cert.ca.validity_end)
        self.assertEqual(old_ca_serial_number, cert.ca.serial_number)

    def test_cert_common_name_length(self):
        common_name = (
            'this is a very very very very very very'
            ' very very very very very very long name'
        )
        with self.assertRaises(ValidationError) as context_manager:
            self._create_cert(common_name=common_name)

        msg = (
            f'Ensure this value has at most 64 characters (it has {len(common_name)}).'
        )
        message_dict = context_manager.exception.message_dict
        self.assertIn('common_name', message_dict)
        self.assertEqual(message_dict['common_name'][0], msg)
