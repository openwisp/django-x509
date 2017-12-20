from django.contrib import admin

from .base.admin import AbstractCaAdmin, AbstractCertAdmin
from .models import Ca, Cert


class CertAdmin(AbstractCertAdmin):
    pass


class CaAdmin(AbstractCaAdmin):
    pass


admin.site.register(Ca, CaAdmin)
admin.site.register(Cert, CertAdmin)
