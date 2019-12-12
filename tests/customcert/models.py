from django.db import models

from django_x509.base.models import AbstractCert


class CustomCert(AbstractCert):
    """
    Custom Cert model
    """

    fingerprint = models.CharField(
        primary_key=True, max_length=64, unique=True
    )

    class Meta(AbstractCert.Meta):
        abstract = False
