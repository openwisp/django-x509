from .base.models import AbstractCa, AbstractCert


class Ca(AbstractCa):
    """
    Concrete Ca model
    """
    class Meta(AbstractCa.Meta):
        abstract = False


class Cert(AbstractCert):
    """
    Concrete Cert model
    """
    class Meta(AbstractCert.Meta):
        abstract = False
