from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from .base import AbstractX509


class AbstractCert(AbstractX509):
    """
    Abstract Cert model
    """
    ca = models.ForeignKey('django_x509.Ca', verbose_name=_('CA'))
    revoked = models.BooleanField(_('revoked'),
                                  default=False)
    revoked_at = models.DateTimeField(_('revoked at'),
                                      blank=True,
                                      null=True,
                                      default=None)

    def __str__(self):
        return self.name

    class Meta:
        abstract = True
        verbose_name = _('certificate')
        verbose_name_plural = _('certificates')
        unique_together = ('ca', 'serial_number')

    def revoke(self):
        """
        * flag certificate as revoked
        * fill in revoked_at DateTimeField
        """
        now = timezone.now()
        self.revoked = True
        self.revoked_at = now
        self.save()


class Cert(AbstractCert):
    """
    Concrete Cert model
    """
Cert.Meta.abstract = False
