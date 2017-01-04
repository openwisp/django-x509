from .base.models import AbstractCa, AbstractCert


class Ca(AbstractCa):
    """
    Concrete Ca model
    """


Ca.Meta.abstract = False


class Cert(AbstractCert):
    """
    Concrete Cert model
    """


Cert.Meta.abstract = False
