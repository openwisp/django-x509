from django.contrib.admin.sites import AdminSite
from django.test import TestCase

from ..admin import CaAdmin, CertAdmin
from ..models import Ca, Cert
from .test_helpers import MessagingRequest


class MockSuperUser:
    def has_perm(self, perm):
        return True


request = MessagingRequest()
request.user = MockSuperUser()

ca_fields = ['operation_type',
             'name',
             'notes',
             'key_length',
             'digest',
             'validity_start',
             'validity_end',
             'country_code',
             'state',
             'city',
             'organization_name',
             'organizational_unit_name',
             'email',
             'common_name',
             'extensions',
             'serial_number',
             'certificate',
             'private_key',
             'passphrase']

cert_fields = ['operation_type',
               'name',
               'ca',
               'notes',
               'key_length',
               'digest',
               'validity_start',
               'validity_end',
               'country_code',
               'state',
               'city',
               'organization_name',
               'organizational_unit_name',
               'email',
               'common_name',
               'extensions',
               'serial_number',
               'certificate',
               'private_key',
               'passphrase']

ca_readonly = ['key_length',
               'digest',
               'validity_start',
               'validity_end',
               'country_code',
               'state',
               'city',
               'organization_name',
               'organizational_unit_name',
               'email',
               'common_name',
               'serial_number',
               'certificate',
               'private_key',
               'created',
               'modified']

cert_readonly = ['revoked',
                 'revoked_at',
                 'created',
                 'modified',
                 'created',
                 'modified',
                 'created',
                 'modified',
                 'created',
                 'modified',
                 'created',
                 'modified',
                 'created',
                 'modified']


class ModelAdminTests(TestCase):

    def setUp(self):
        self.ca = Ca.objects.create()
        self.cert = Cert.objects.create(ca_id=self.ca.pk)
        self.cert.ca = self.ca
        self.site = AdminSite()

    def test_modeladmin_str_ca(self):
        ma = CaAdmin(Ca, self.site)
        self.assertEqual(str(ma), 'django_x509.CaAdmin')

    def test_modeladmin_str_certr(self):
        ma = CertAdmin(Cert, self.site)
        self.assertEqual(str(ma), 'django_x509.CertAdmin')

    def test_default_fields_ca(self):
        ma = CaAdmin(Ca, self.site)
        self.assertEqual(list(ma.get_form(request).base_fields), ca_fields)
        ca_fields.insert(len(ca_fields), 'created')
        ca_fields.insert(len(ca_fields), 'modified')
        self.assertEqual(list(ma.get_fields(request)), ca_fields)
        index = ca_fields.index('extensions')
        pass_index = ca_fields.index('passphrase')
        ca_fields.remove('extensions')
        ca_fields.remove('passphrase')
        self.assertEqual(list(ma.get_fields(request, self.ca)), ca_fields)
        ca_fields.insert(index, 'extensions')
        ca_fields.insert(pass_index, 'passphrase')

    def test_default_fields_cert(self):
        ma = CertAdmin(Cert, self.site)
        self.assertEqual(list(ma.get_form(request).base_fields), cert_fields)
        cert_fields.insert(4, 'revoked')
        cert_fields.insert(5, 'revoked_at')
        cert_fields.insert(len(cert_fields), 'created')
        cert_fields.insert(len(cert_fields), 'modified')
        self.assertEqual(list(ma.get_fields(request)), cert_fields)
        index = cert_fields.index('extensions')
        pass_index = cert_fields.index('passphrase')
        cert_fields.remove('extensions')
        cert_fields.remove('passphrase')
        self.assertEqual(list(ma.get_fields(request, self.cert)), cert_fields)
        cert_fields.insert(index, 'extensions')
        cert_fields.insert(pass_index, 'passphrase')

    def test_default_fieldsets_ca(self):
        ma = CaAdmin(Ca, self.site)
        self.assertEqual(ma.get_fieldsets(request), [(None, {'fields': ca_fields})])

    def test_default_fieldsets_cert(self):
        ma = CertAdmin(Cert, self.site)
        self.assertEqual(ma.get_fieldsets(request), [(None, {'fields': cert_fields})])

    def test_readonly_fields_Ca(self):
        ma = CaAdmin(Ca, self.site)
        self.assertEqual(ma.get_readonly_fields(request), ('created', 'modified'))
        self.assertEqual(ma.get_readonly_fields(request, self.ca), tuple(ca_readonly))
        ca_readonly.remove('created')
        ca_readonly.remove('modified')

    def test_readonly_fields_Cert(self):
        ma = CertAdmin(Cert, self.site)
        self.assertEqual(ma.get_readonly_fields(request), cert_readonly)
        ca_readonly.append('ca')
        self.assertEqual(ma.get_readonly_fields(request, self.cert), tuple(ca_readonly + cert_readonly))

    def test_ca_url(self):
        ma = CertAdmin(Cert, self.site)
        self.assertEqual(ma.ca_url(self.cert), "<a href='/admin/django_x509/ca/1/change/'></a>")

    def test_revoke_action(self):
        ma = CertAdmin(Cert, self.site)
        ma.revoke_action(request, [self.cert])
        m = list(request.get_messages())
        self.assertEqual(len(m), 1)
        self.assertEqual(str(m[0]), '1 certificate was revoked.')
