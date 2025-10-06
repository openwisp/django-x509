from django.conf import settings

DEFAULT_CERT_VALIDITY = getattr(settings, "DJANGO_X509_DEFAULT_CERT_VALIDITY", 365)
DEFAULT_CA_VALIDITY = getattr(settings, "DJANGO_X509_DEFAULT_CA_VALIDITY", 3650)
DEFAULT_KEY_LENGTH = str(getattr(settings, "DJANGO_X509_DEFAULT_KEY_LENGTH", "2048"))
DEFAULT_DIGEST_ALGORITHM = getattr(
    settings, "DJANGO_X509_DEFAULT_DIGEST_ALGORITHM", "sha256WithRSAEncryption"
)
CA_BASIC_CONSTRAINTS_CRITICAL = getattr(
    settings, "DJANGO_X509_CA_BASIC_CONSTRAINTS_CRITICAL", True
)
CA_BASIC_CONSTRAINTS_PATHLEN = getattr(
    settings, "DJANGO_X509_CA_BASIC_CONSTRAINTS_PATHLEN", 0
)
CA_KEYUSAGE_CRITICAL = getattr(settings, "DJANGO_X509_CA_KEYUSAGE_CRITICAL", True)
CA_KEYUSAGE_VALUE = getattr(
    settings, "DJANGO_X509_CA_KEYUSAGE_VALUE", {
        "digital_signature": False,
        "content_commitment": False,
        "key_encipherment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": True,
        "crl_sign": True,
        "encipher_only": False,
        "decipher_only": False,
    }
)
CERT_KEYUSAGE_CRITICAL = getattr(settings, "DJANGO_X509_CERT_KEYUSAGE_CRITICAL", False)
CERT_KEYUSAGE_VALUE = getattr(
    settings, "DJANGO_X509_CERT_KEYUSAGE_VALUE", {
        "digital_signature": True,
        "content_commitment": False,
        "key_encipherment": True,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "encipher_only": False,
        "decipher_only": False,
    }
)  # noqa
CRL_PROTECTED = getattr(settings, "DJANGO_X509_CRL_PROTECTED", False)
