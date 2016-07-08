from django.conf import settings

DEFAULT_CERT_VALIDITY = getattr(settings, 'DJANGO_X509_DEFAULT_CERT_VALIDITY', 365)
DEFAULT_CA_VALIDITY = getattr(settings, 'DJANGO_X509_DEFAULT_CA_VALIDITY', 3650)
