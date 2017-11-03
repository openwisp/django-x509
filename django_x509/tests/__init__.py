"""
test utilities shared among test classes
these mixins are reused also in openwisp2
change with care.
"""


class TestX509Mixin(object):
    def _create_ca(self, **kwargs):
        options = dict(name='Test CA',
                       key_length='2048',
                       digest='sha256',
                       country_code='IT',
                       state='RM',
                       city='Rome',
                       organization_name='OpenWISP',
                       email='test@test.com',
                       common_name='openwisp.org',
                       extensions=[])
        options.update(kwargs)
        ca = self.ca_model(**options)
        ca.full_clean()
        ca.save()
        return ca

    def _create_cert(self, **kwargs):
        options = dict(name='TestCert',
                       ca=None,
                       key_length='2048',
                       digest='sha256',
                       country_code='IT',
                       state='RM',
                       city='Rome',
                       organization_name='Test',
                       email='test@test.com',
                       common_name='openwisp.org',
                       extensions=[])
        options.update(kwargs)
        # auto create CA if not supplied
        if not options.get('ca'):
            options['ca'] = self._create_ca()
        cert = self.cert_model(**options)
        cert.full_clean()
        cert.save()
        return cert
