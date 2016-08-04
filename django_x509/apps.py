from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _


class DjangoX509Config(AppConfig):
    name = 'django_x509'
    verbose_name = _('x509 Certificates')
