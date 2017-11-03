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
        ca = self._create_ca(name='ImportTest error',
                             certificate=self.problematic_certificate,
                             private_key=self.problematic_private_key)
        self.assertEqual(ca.country_code, '')
