from django.http import HttpResponse
from django.utils.translation import ugettext_lazy as _

from . import settings as app_settings
from .models import Ca


def crl(request, pk):
    """
    returns CRL of a CA
    """
    if app_settings.CRL_PROTECTED and not request.user.is_authenticated():
        return HttpResponse(_('Forbidden'),
                            status=403,
                            content_type='text/plain')
    ca = Ca.objects.get(pk=pk)
    return HttpResponse(ca.crl,
                        status=200,
                        content_type='application/x-pem-file')
