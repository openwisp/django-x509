from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class DjangoX509Config(AppConfig):
    name = "django_x509"
    verbose_name = _("x509 Certificates")
    default_auto_field = "django.db.models.AutoField"

    def ready(self):
        from .handlers import notify_x509_objects_expired, notify_x509_objects_expiring
        from .signals import x509_objects_expired, x509_objects_expiring

        x509_objects_expiring.connect(
            notify_x509_objects_expiring,
            dispatch_uid="django_x509.notify_x509_objects_expiring",
        )
        x509_objects_expired.connect(
            notify_x509_objects_expired,
            dispatch_uid="django_x509.notify_x509_objects_expired",
        )
