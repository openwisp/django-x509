from django.contrib import admin

from .base.admin import AbstractCaAdmin, AbstractCertAdmin, AbstractCertForm
from .models import Ca, Cert


class CertForm(AbstractCertForm):
    class Meta(AbstractCertForm.Meta):
        model = Cert


class CertAdmin(AbstractCertAdmin):
    form = CertForm


class CaAdmin(AbstractCaAdmin):
    form = CertForm


admin.site.register(Ca, CaAdmin)
admin.site.register(Cert, CertAdmin)
