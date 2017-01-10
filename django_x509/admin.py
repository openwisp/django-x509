from django.contrib import admin

from .base.admin import CaAdmin, CertAdmin
from .models import Ca, Cert

admin.site.register(Ca, CaAdmin)
admin.site.register(Cert, CertAdmin)
