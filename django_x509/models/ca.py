from datetime import timedelta

from django.utils import timezone
from django.utils.encoding import python_2_unicode_compatible
from django.utils.translation import ugettext_lazy as _

from ..settings import DEFAULT_CA_VALIDITY
from .base import AbstractX509


def default_ca_validity_end():
    """
    returns the default value for validity_end field
    """
    delta = timedelta(days=DEFAULT_CA_VALIDITY)
    return timezone.now() + delta


@python_2_unicode_compatible
class Ca(AbstractX509):
    """
    Concrete Ca model
    """
    class Meta:
        verbose_name = _('CA')
        verbose_name_plural = _('CAs')

Ca._meta.get_field('validity_end').default = default_ca_validity_end
