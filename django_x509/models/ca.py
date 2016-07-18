from datetime import timedelta

from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from OpenSSL import crypto

from .. import settings as app_settings
from ..utils import bytes_compat
from .base import AbstractX509, generalized_time


def default_ca_validity_end():
    """
    returns the default value for validity_end field
    """
    delta = timedelta(days=app_settings.DEFAULT_CA_VALIDITY)
    return timezone.now() + delta


class AbstractCa(AbstractX509):
    """
    Abstract Ca model (for reuse)
    """
    class Meta:
        abstract = True
        verbose_name = _('CA')
        verbose_name_plural = _('CAs')

    def get_revoked_certs(self):
        """
        Returns revoked certificates of this CA
        (does not include expired certificates)
        """
        now = timezone.now()
        return self.cert_set.filter(revoked=True,
                                    validity_start__lte=now,
                                    validity_end__gte=now)

    @property
    def crl(self):
        """
        Returns up to date CRL of this CA
        """
        revoked_certs = self.get_revoked_certs()
        crl = crypto.CRL()
        now_str = timezone.now().strftime(generalized_time)
        for cert in revoked_certs:
            revoked = crypto.Revoked()
            revoked.set_serial(bytes_compat(cert.serial_number))
            revoked.set_reason(b'unspecified')
            revoked.set_rev_date(bytes_compat(now_str))
            crl.add_revoked(revoked)
        return crl.export(self.x509, self.pkey, days=1)

AbstractCa._meta.get_field('validity_end').default = default_ca_validity_end


class Ca(AbstractCa):
    """
    Concrete CA model
    """
Ca.Meta.abstract = False
