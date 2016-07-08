from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _

from .base import AbstractX509


@python_2_unicode_compatible
class Cert(AbstractX509):
    """
    Concrete Cert model
    """
    ca = models.ForeignKey('django_x509.Ca', verbose_name=_('CA'))

    class Meta:
        verbose_name = _('certificate')
        verbose_name_plural = _('certificates')
        unique_together = ('ca', 'serial_number')
