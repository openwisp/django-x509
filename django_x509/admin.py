from django.contrib import admin
from django.contrib.admin import ModelAdmin as BaseAdmin

from .models import Ca, Cert


class AbstractAdmin(BaseAdmin):
    """
    ModelAdmin for TimeStampedEditableModel
    """
    list_display = ['name',
                    'key_length',
                    'digest',
                    'created',
                    'modified']
    search_fields = ('name', 'serial_number', 'common_name')
    actions_on_bottom = True
    save_on_top = True

    def __init__(self, *args, **kwargs):
        self.readonly_fields += ('created', 'modified',)
        super(AbstractAdmin, self).__init__(*args, **kwargs)


class CaAdmin(AbstractAdmin):
    pass


class CertAdmin(AbstractAdmin):
    list_filter = ('ca', 'created',)
    fields = ['name',
              'ca',
              'notes',
              'key_length',
              'digest',
              'validity_start',
              'validity_end',
              'country_code',
              'state',
              'city',
              'organization',
              'email',
              'common_name',
              'serial_number',
              'public_key',
              'private_key',
              'created',
              'modified']

CertAdmin.list_display = AbstractAdmin.list_display[:]
CertAdmin.list_display.insert(1, 'ca')


admin.site.register(Ca, CaAdmin)
admin.site.register(Cert, CertAdmin)
