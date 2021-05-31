from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.translation import ugettext_lazy as _

from django_x509 import settings as app_settings


class CrlDownloadMixin:
    def crl_view(self, request, pk):
        authenticated = request.user.is_authenticated
        authenticated = authenticated() if callable(authenticated) else authenticated
        if app_settings.CRL_PROTECTED or not authenticated:
            return HttpResponse(_('Forbidden'), status=403, content_type='text/plain')
        instance = get_object_or_404(self.model, pk=pk)
        response = HttpResponse(
            instance.crl, status=200, content_type='application/x-pem-file'
        )
        response['Content-Disposition'] = f'attachment; filename={pk}.crl'
        return response
