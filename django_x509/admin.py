from django.contrib import admin

from .base.admin import AbstractCaAdmin, AbstractCertAdmin, AbstractX509Form
from .models import Ca, Cert


class X509Form(AbstractX509Form):
    class Meta(AbstractX509Form.Meta):
        model = Cert


class CertAdmin(AbstractCertAdmin):
    form = X509Form


class CaAdmin(AbstractCaAdmin):
    form = X509Form


admin.site.register(Ca, CaAdmin)
admin.site.register(Cert, CertAdmin)
