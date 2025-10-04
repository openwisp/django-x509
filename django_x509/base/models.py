import collections
import enum
import textwrap
import uuid
from datetime import datetime, timedelta
from typing import Union, Optional, List

import cryptography.x509
import swapper
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat._oid import NameOID, SignatureAlgorithmOID
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, rsa, dsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1, ECDSA
from cryptography.hazmat.primitives.hashes import SHA224, SHA256, SHA384, SHA512, SHA1
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate, load_pem_x509_certificate
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from jsonfield import JSONField
from model_utils.fields import AutoCreatedField, AutoLastModifiedField

from .. import settings as app_settings


# We hardcode the public RSA exponent to a frequently used one.
RSA_PUBLIC_EXPONENT = 65537


class SupportedDigests(enum.Enum):
    """Supported certificate digest algorithm combinations."""

    Sha1WithRSAEncryption = "sha1WithRSAEncryption"
    Sha224WithRSAEncryption = "sha224WithRSAEncryption"
    Sha256WithRSAEncryption = "sha256WithRSAEncryption"
    Sha384WithRSAEncryption = "sha384WithRSAEncryption"
    Sha512WithRSAEncryption = "sha512WithRSAEncryption"
    EcdsaWithSHA256 = "ecdsa-with-SHA256"
    EcdsaWithSHA384 = "ecdsa-with-SHA384"
    EcdsaWithSHA512 = "ecdsa-with-SHA512"
    DsaWithSHA1 = "dsaWithSHA1"
    DsaWithSHA256 = "dsaWithSHA256"
    Ed25519 = "Ed25519"
    Ed448 = "Ed448"

    @property
    def is_rsa(self) -> bool:
        return self == SupportedDigests.Sha1WithRSAEncryption or self == SupportedDigests.Sha224WithRSAEncryption or self == SupportedDigests.Sha256WithRSAEncryption or self == SupportedDigests.Sha384WithRSAEncryption or self == SupportedDigests.Sha512WithRSAEncryption

    @property
    def is_ecdsa(self) -> bool:
        return self == SupportedDigests.EcdsaWithSHA256 or self == SupportedDigests.EcdsaWithSHA384 or self == SupportedDigests.EcdsaWithSHA512

    @property
    def is_dsa(self) -> bool:
        return self == SupportedDigests.DsaWithSHA1 or self == SupportedDigests.DsaWithSHA256

    @property
    def is_ed(self) -> bool:
        return self == SupportedDigests.Ed25519 or self == SupportedDigests.Ed448

    @staticmethod
    def from_object_identifier(oid: ObjectIdentifier) -> "SupportedDigests":
        """Convert an ObjectIdentifier to a SupportedDigest object."""
        if oid == SignatureAlgorithmOID.RSA_WITH_SHA1:
            return SupportedDigests.Sha1WithRSAEncryption
        if oid == SignatureAlgorithmOID.RSA_WITH_SHA224:
            return SupportedDigests.Sha224WithRSAEncryption
        if oid == SignatureAlgorithmOID.RSA_WITH_SHA256:
            return SupportedDigests.Sha256WithRSAEncryption
        if oid == SignatureAlgorithmOID.RSA_WITH_SHA384:
            return SupportedDigests.Sha384WithRSAEncryption
        if oid == SignatureAlgorithmOID.RSA_WITH_SHA512:
            return SupportedDigests.Sha512WithRSAEncryption
        if oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256:
            return SupportedDigests.EcdsaWithSHA256
        if oid == SignatureAlgorithmOID.ECDSA_WITH_SHA384:
            return SupportedDigests.EcdsaWithSHA384
        if oid == SignatureAlgorithmOID.ECDSA_WITH_SHA512:
            return SupportedDigests.EcdsaWithSHA512
        if oid == SignatureAlgorithmOID.DSA_WITH_SHA1:
            return SupportedDigests.DsaWithSHA1
        if oid == SignatureAlgorithmOID.DSA_WITH_SHA256:
            return SupportedDigests.DsaWithSHA256
        if oid == SignatureAlgorithmOID.ED25519:
            return SupportedDigests.Ed25519
        if oid == SignatureAlgorithmOID.ED448:
            return SupportedDigests.Ed448

        raise ValueError("The signature algorithm with OID '{}' (common name '{}') is not supported".format(oid, oid._name))


    def requires_key_length(self) -> bool:
        """Check if a digest algorithm needs a key length to generate a new private key."""
        return self.is_rsa or self.is_dsa

    def generate_private_key(self, key_size: Optional[int] = None) -> Union[ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey, rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey]:
        """Generate a private key for the selected digest algorithm."""
        if self == SupportedDigests.Sha1WithRSAEncryption or self == SupportedDigests.Sha224WithRSAEncryption or self == SupportedDigests.Sha256WithRSAEncryption or self == SupportedDigests.Sha384WithRSAEncryption or self == SupportedDigests.Sha512WithRSAEncryption:
            if key_size is None:
                raise ValueError(f"A key size must be specified when using the digest algorithm: '{self}'")
            return rsa.generate_private_key(RSA_PUBLIC_EXPONENT, key_size)

        if self == SupportedDigests.EcdsaWithSHA256:
            return ec.generate_private_key(SECP256R1())
        if self == SupportedDigests.EcdsaWithSHA384:
            return ec.generate_private_key(SECP384R1())
        if self == SupportedDigests.EcdsaWithSHA512:
            return ec.generate_private_key(SECP521R1())

        if self == SupportedDigests.DsaWithSHA1 or self == SupportedDigests.DsaWithSHA256:
            if key_size is None:
                raise ValueError(f"A key size must be specified when using the digest algorithm: '{self}'")

            return dsa.generate_private_key(key_size)

        if self == SupportedDigests.Ed25519:
            return ed25519.Ed25519PrivateKey.generate()

        return ed448.Ed448PrivateKey.generate()

    def get_hashing_algorithm_instance(self) -> Union[SHA1, SHA224, SHA256, SHA384, SHA512] | None:
        """Get an instance of the hashing algorithm used."""
        if self == SupportedDigests.Sha1WithRSAEncryption:
            return SHA1()
        if self == SupportedDigests.Sha224WithRSAEncryption:
            return SHA224()
        if self == SupportedDigests.Sha256WithRSAEncryption:
            return SHA256()
        if self == SupportedDigests.Sha384WithRSAEncryption:
            return SHA384()
        if self == SupportedDigests.Sha512WithRSAEncryption:
            return SHA512()
        if self == SupportedDigests.EcdsaWithSHA256:
            return SHA256()
        if self == SupportedDigests.EcdsaWithSHA384:
            return SHA384()
        if self == SupportedDigests.EcdsaWithSHA512:
            return SHA512()
        if self == SupportedDigests.DsaWithSHA1:
            return SHA1()
        if self == SupportedDigests.DsaWithSHA256:
            return SHA256()
        if self == SupportedDigests.Ed25519:
            return None

        return None

    def get_private_key_serialization_format(self):
        """Retrieve the serialization format for the private key."""
        return serialization.PrivateFormat.PKCS8

    def __str__(self) -> str:
        """Convert this object to a string."""
        if self == SupportedDigests.Sha1WithRSAEncryption:
            return "SHA1 with RSA signature"
        if self == SupportedDigests.Sha224WithRSAEncryption:
            return "SHA224 with RSA signature"
        if self == SupportedDigests.Sha256WithRSAEncryption:
            return "SHA256 with RSA signature"
        if self == SupportedDigests.Sha384WithRSAEncryption:
            return "SHA384 with RSA signature"
        if self == SupportedDigests.Sha512WithRSAEncryption:
            return "SHA512 with RSA signature"
        if self == SupportedDigests.EcdsaWithSHA256:
            return "SHA256 with ECDSA signature"
        if self == SupportedDigests.EcdsaWithSHA384:
            return "SHA384 with ECDSA signature"
        if self == SupportedDigests.EcdsaWithSHA512:
            return "SHA512 with ECDSA signature"
        if self == SupportedDigests.DsaWithSHA1:
            return "SHA1 with DSA signature"
        if self == SupportedDigests.DsaWithSHA256:
            return "SHA256 with DSA signature"
        if self == SupportedDigests.Ed25519:
            return "Edwards-Curve Digital Signature Algorithm with 25519 curve"

        return "Edwards-Curve Digital Signature with 448 curve"

generalized_time = "%Y%m%d%H%M%SZ"
utc_time = "%y%m%d%H%M%SZ"

KEY_LENGTH_CHOICES = (
    (None, "---"),
    ("512", "512"),
    ("1024", "1024"),
    ("2048", "2048"),
    ("4096", "4096"),
)

DIGEST_CHOICES = [
    (x.value, str(x)) for x in SupportedDigests
]


def cert_to_text(cert: cryptography.x509.Certificate) -> str:
    lines = []
    lines.append("Certificate:")
    lines.append("    Data:")
    lines.append(f"        Version: {cert.version.name} ({cert.version.value})")
    lines.append(f"        Serial Number: {cert.serial_number}")
    if cert.signature_hash_algorithm is not None:
        lines.append(f"        Signature Algorithm: {cert.signature_hash_algorithm.name}")
    lines.append("        Issuer: " + cert.issuer.rfc4514_string())
    lines.append("        Validity")
    lines.append(f"            Not Before: {cert.not_valid_before_utc}")
    lines.append(f"            Not After : {cert.not_valid_after_utc}")
    lines.append("        Subject: " + cert.subject.rfc4514_string())
    lines.append("        Subject Public Key Info:")
    pubkey = cert.public_key()
    if hasattr(pubkey, "key_size"):
        lines.append(f"            Public Key Algorithm: {pubkey.__class__.__name__}")
        lines.append(f"                Public-Key: ({pubkey.key_size} bit)")
    else:
        lines.append(f"            Public Key Algorithm: {pubkey.__class__.__name__}")

    lines.append("    X509v3 extensions:")
    for ext in cert.extensions:
        lines.append(f"        {ext.oid._name or ext.oid.dotted_string}:")
        value = str(ext.value)
        for line in textwrap.wrap(value, width=70):
            lines.append(f"            {line}")

    lines.append("Signature:")
    sig_hex = cert.signature.hex()
    for line in textwrap.wrap(sig_hex, width=48):
        lines.append(f"    {line}")

    return "\n".join(lines)


def datetime_to_string(datetime_):
    """
    Converts datetime.datetime object to UTCTime/GeneralizedTime string
    following RFC5280. (Returns string encoded in UTCtime for dates through year
    2049, otherwise in GeneralizedTime format)
    """
    if datetime_.year < 2050:
        return datetime_.strftime(utc_time)
    return datetime_.strftime(generalized_time)


def default_validity_start():
    """
    Sets validity_start field to 1 day before the current date
    (avoids "certificate not valid yet" edge case).

    In some cases, because of timezone differences, when certificates
    were just created they were considered valid in a timezone (eg: Europe)
    but not yet valid in another timezone (eg: US).

    This function intentionally returns naive datetime (not timezone aware),
    so that certificates are valid from 00:00 AM in all timezones.
    """
    start = datetime.now() - timedelta(days=1)
    return start.replace(hour=0, minute=0, second=0, microsecond=0)


def default_ca_validity_end():
    """
    returns the default value for validity_end field
    """
    delta = timedelta(days=app_settings.DEFAULT_CA_VALIDITY)
    return timezone.now() + delta


def default_cert_validity_end():
    """
    returns the default value for validity_end field
    """
    delta = timedelta(days=app_settings.DEFAULT_CERT_VALIDITY)
    return timezone.now() + delta


def default_key_length():
    """
    returns default value for key_length field
    (this avoids to set the exact default value in the database migration)
    """
    return app_settings.DEFAULT_KEY_LENGTH


def default_digest_algorithm():
    """
    returns default value for digest field
    (this avoids to set the exact default value in the database migration)
    """
    return app_settings.DEFAULT_DIGEST_ALGORITHM


class BaseX509(models.Model):
    """
    Abstract Cert class, shared between Ca and Cert
    """

    name = models.CharField(max_length=64)
    notes = models.TextField(blank=True)
    # A key_length only needs to be set for specific algorithms.
    key_length = models.CharField(
        _("key length"),
        help_text=_("bits"),
        choices=KEY_LENGTH_CHOICES,
        default=default_key_length,
        max_length=6,
        blank=True,
        null=True,
    )
    digest = models.CharField(
        _("digest algorithm"),
        help_text=_("The digest algorithm to use for computing the digest. This is a combination of a hashing algorithm"
                    " and a signature algorithm. For Edwards-Curves, the hashing algorithm is already baked into the"
                    " signature."),
        choices=DIGEST_CHOICES,
        default=default_digest_algorithm,
        max_length=23,
    )
    validity_start = models.DateTimeField(
        blank=True, null=True, default=default_validity_start
    )
    validity_end = models.DateTimeField(
        blank=True, null=True, default=default_cert_validity_end
    )
    country_code = models.CharField(max_length=2, blank=True)
    state = models.CharField(_("state or province"), max_length=64, blank=True)
    city = models.CharField(_("city"), max_length=64, blank=True)
    organization_name = models.CharField(_("organization"), max_length=64, blank=True)
    organizational_unit_name = models.CharField(
        _("organizational unit name"), max_length=64, blank=True
    )
    email = models.EmailField(_("email address"), blank=True)
    common_name = models.CharField(_("common name"), max_length=64, blank=True)
    extensions = JSONField(
        _("extensions"),
        default=list,
        blank=True,
        help_text=_("Additional x509 certificate extensions"),
        load_kwargs={"object_pairs_hook": collections.OrderedDict},
        dump_kwargs={"indent": 4},
    )
    # serial_number is set to CharField as a UUID integer is too big for a
    # PositiveIntegerField and an IntegerField on SQLite
    serial_number = models.CharField(
        _("serial number"),
        help_text=_("Leave blank to determine automatically"),
        blank=True,
        null=True,
        max_length=48,
    )
    certificate = models.TextField(
        blank=True, help_text="Certificate in X.509 PEM format"
    )
    private_key = models.TextField(
        blank=True, help_text="Private key in X.509 PEM format"
    )
    created = AutoCreatedField(_("created"), editable=True)
    modified = AutoLastModifiedField(_("modified"), editable=True)
    passphrase = models.CharField(
        max_length=64,
        blank=True,
        help_text=_("Passphrase for the private key, if present"),
    )

    class Meta:
        abstract = True

    def __str__(self):
        return self.name

    def clean_fields(self, *args, **kwargs):
        # importing existing certificate
        # must be done here in order to validate imported fields
        # and fill private and public key before validation fails
        if self._state.adding and self.certificate and self.private_key:
            self._validate_pem()
            self._import()
        super().clean_fields(*args, **kwargs)

    def clean(self):
        super().clean()
        if self._should_generate_certificate():
            if self.digest:
                digest_algorithm_combination = SupportedDigests(self.digest)
                if digest_algorithm_combination.requires_key_length() and not self.key_length:
                    raise ValidationError(
                        _(
                            "The selected Digest algorithm requires the Key length to be set"
                        )
                    )

                if not digest_algorithm_combination.requires_key_length() and self.key_length:
                    raise ValidationError(
                        _(
                            "The selected Digest algorithm requires the Key length to be empty"
                        )
                    )
        else:
            # when importing, both public and private must be present
            if (self.certificate and not self.private_key) or (
                    self.private_key and not self.certificate
            ):
                raise ValidationError(
                    _(
                        "When importing an existing certificate, both "
                        "keys (private and public) must be present"
                    )
                )


        if self.serial_number:
            self._validate_serial_number()

        self._verify_extension_format()


    def _should_generate_certificate(self):
        return self._state.adding and not self.certificate and not self.private_key

    def save(self, *args, **kwargs):
        if self._should_generate_certificate():
            # auto generate serial number
            if not self.serial_number:
                self.serial_number = BaseX509._generate_serial_number()
            self._generate()
        super().save(*args, **kwargs)

    @cached_property
    def x509(self) -> Certificate | None:
        """Retrieve the certificate as an object, if set."""
        if self.certificate:
            return cryptography.x509.load_pem_x509_certificate(self.certificate.encode("utf-8"))

        return None

    @cached_property
    def x509_text(self) -> str | None:
        """Retrieve a raw encoding of the certificate (as a text dump)."""
        if self.x509 is not None:
            return cert_to_text(self.x509)

        return None

    @cached_property
    def pkey(self) -> Union[ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey, rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey] | None:
        """Retrieve the private key as an object, if set."""
        if self.private_key:
            return serialization.load_pem_private_key(
                self.private_key.encode("utf-8"),
                password=self.passphrase.encode("utf-8") if self.passphrase else None,
            )

        return None

    @staticmethod
    def _extract_openssl_error_from_private_key_error(error: ValueError):
        """Extract an OpenSSLError from a ValueError if it exists."""
        if len(error.args) > 1:
            maybe_openssl_errors = error.args[1]
            if isinstance(maybe_openssl_errors, list) and len(maybe_openssl_errors) > 0:
                maybe_openssl_error = maybe_openssl_errors[0]
                if isinstance(maybe_openssl_error, cryptography.hazmat.bindings._rust.openssl.OpenSSLError):
                    return maybe_openssl_error

        return None

    def _validate_pem(self):
        """Validate the certificate and private key."""
        errors = {}

        if self.private_key:
            try:
                load_pem_private_key(self.private_key.encode("utf-8"), password=self.passphrase.encode("utf-8") if self.passphrase else None)
            except ValueError as e:
                openssl_error = self._extract_openssl_error_from_private_key_error(e)
                if openssl_error is None:
                    errors["private_key"] = ValidationError(
                        f"Decoding of the private key failed: {e}. This might be because of a password that is incorrect.")
                else:
                    error = "OpenSSL error: <br>{}".format(openssl_error.reason_text.decode("utf-8"))
                    if "bad decrypt" in error:
                        error = "<b>Incorrect Passphrase</b> <br>" + error
                        errors["passphrase"] = ValidationError(_(mark_safe(error)))
                    errors["private_key"] = ValidationError(_(mark_safe(error)))

        if self.certificate:
            try:
                load_pem_x509_certificate(self.certificate.encode("utf-8"))
            except cryptography.x509.base.InvalidVersion as e:
                errors["certificate"] = ValidationError(str(e))
            except ValueError as e:
                openssl_error = self._extract_openssl_error_from_private_key_error(e)
                if openssl_error is None:
                    errors["certificate"] = ValidationError(f"Decoding of the certificate failed: {e}")
                else:
                    error = "OpenSSL error: <br>{0}".format(
                        str(e.args[0]).replace("), ", "), <br>").strip("[]")
                    )
                    errors["certificate"] = ValidationError(_(mark_safe(error)))

        if len(errors) > 0:
            raise ValidationError(errors)

    def _validate_serial_number(self):
        """
        (internal use only)
        validates serial number if set manually
        """
        try:
            int(self.serial_number)
        except ValueError:
            raise ValidationError(
                {"serial_number": _("Serial number must be an integer")}
            )

    def _generate(self):
        """
        Generate a new X509 certificate.

        This function is used when a new certificate is generated on the admin dashboard. It's used for both CA and
        end-entity ceritifcates.
        """
        subject = self._get_subject()
        digest_algorithm_combination = SupportedDigests(self.digest)
        private_key = digest_algorithm_combination.generate_private_key(int(self.key_length) if self.key_length is not None else None)

        certificate = (
            cryptography.x509.CertificateBuilder()
                .subject_name(subject)
                .serial_number(int(self.serial_number))
                .not_valid_before(self.validity_start)
                .not_valid_after(self.validity_end)
        )

        if hasattr(self, "ca"):
            # Generate a certificate issued by a CA.
            issuer = self.ca.x509.subject
            issuer_key = self.ca.pkey
        else:
            # Generate a certificate for a CA.
            issuer = subject
            issuer_key = private_key

        certificate = certificate.issuer_name(issuer)
        certificate = certificate.public_key(private_key.public_key())
        certificate = self._add_extensions(certificate)
        signed_certificate = certificate.sign(issuer_key, digest_algorithm_combination.get_hashing_algorithm_instance())
        self.certificate = signed_certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        if self.passphrase:
            encryption_algorithm = serialization.BestAvailableEncryption(self.passphrase.encode("utf-8"))
        else:
            encryption_algorithm = serialization.NoEncryption()

        self.private_key = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=digest_algorithm_combination.get_private_key_serialization_format(), encryption_algorithm=encryption_algorithm).decode("utf-8")

    def _get_subject(self) -> cryptography.x509.Name:
        """Convert the information in this model to a Name object for use in certificates."""
        attributes = []

        if self.country_code:
            attributes.append(
                cryptography.x509.NameAttribute(
                    NameOID.COUNTRY_NAME,
                    self.country_code,
                )
            )

        if self.state:
            attributes.append(
                cryptography.x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME,
                    self.state,
                )
            )

        if self.city:
            attributes.append(
                cryptography.x509.NameAttribute(
                    NameOID.LOCALITY_NAME,
                    self.city,
                )
            )

        if self.organization_name:
            attributes.append(
                cryptography.x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME,
                    self.organization_name,
                )
            )

        if self.organizational_unit_name:
            attributes.append(
                cryptography.x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME,
                    self.organizational_unit_name,
                )
            )

        if self.email:
            attributes.append(
                cryptography.x509.NameAttribute(
                    NameOID.EMAIL_ADDRESS,
                    self.email,
                )
            )

        if self.common_name:
            attributes.append(
                cryptography.x509.NameAttribute(
                    NameOID.COMMON_NAME,
                    self.common_name,
                )
            )

        return cryptography.x509.Name(attributes)

    def _import(self):
        """
        (internal use only)
        imports existing x509 certificates
        """
        certificate = self.x509
        if certificate is None:
            raise ValidationError("When importing, the certificate must be set")

        try:
            digest_signature_algorithms = SupportedDigests.from_object_identifier(certificate.signature_algorithm_oid)
        except ValueError as e:
            raise ValidationError(f"Unsupported signature algorithm: {e}")

        if hasattr(self, "ca"):
            # Verify an end entity certificate with the CA when importing.
            ca_certificate: Certificate = self.ca.x509
            ca_certificate_digest_signature_algorithms = SupportedDigests.from_object_identifier(ca_certificate.signature_algorithm_oid)
            ca_public_key = ca_certificate.public_key()
            try:
                if ca_certificate_digest_signature_algorithms.is_rsa:
                    ca_public_key.verify(
                        signature=self.x509.signature,
                        data=self.x509.tbs_certificate_bytes,
                        padding=padding.PKCS1v15(),
                        algorithm=digest_signature_algorithms.get_hashing_algorithm_instance(),
                    )
                elif ca_certificate_digest_signature_algorithms.is_ecdsa:
                    ca_public_key.verify(
                        signature=self.x509.signature,
                        data=self.x509.tbs_certificate_bytes,
                        signature_algorithm=ECDSA(certificate.signature_hash_algorithm),
                    )
                elif ca_certificate_digest_signature_algorithms.is_dsa:
                    ca_public_key.verify(
                        signature=self.x509.signature,
                        data=self.x509.tbs_certificate_bytes,
                        algorithm=certificate.signature_hash_algorithm,
                    )
                else:
                    ca_public_key.verify(
                        signature=self.x509.signature,
                        data=self.x509.tbs_certificate_bytes,
                    )
            except InvalidSignature:
                raise ValidationError(f"Validation of the certificate signature failed, the CA did not match the certificate")

        if digest_signature_algorithms.requires_key_length():
            self.key_length = str(certificate.public_key().key_size)
        else:
            self.key_length = None

        self.digest = digest_signature_algorithms.value

        self.validity_start = certificate.not_valid_before_utc
        self.validity_end = certificate.not_valid_after_utc

        subject = certificate.subject

        country = subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        self.country_code = country[0].value if len(country) > 0 else ""
        # allow importing from legacy systems which use invalid country codes
        if len(self.country_code) > 2:
            self.country_code = ""

        state = subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
        self.state = state[0].value if len(state) > 0 else ""

        city = subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
        self.city = city[0].value if len(city) > 0 else ""

        organization_name = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        self.organization_name = organization_name[0].value if len(organization_name) > 0 else ""

        organizational_unit_name = subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        self.organizational_unit_name = organizational_unit_name[0].value if len(organizational_unit_name) > 0 else ""

        email = subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        self.email = email[0].value if len(email) > 0 else ""

        common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        self.common_name = common_name[0].value if len(common_name) > 0 else ""

        self.serial_number = certificate.serial_number

        if not self.name:
            self.name = self.common_name or str(self.serial_number)

    def _verify_extension_format(self):
        """
        (internal use only)
        verifies the format of ``self.extension`` is correct
        """
        msg = "Extension format invalid"
        if not isinstance(self.extensions, list):
            raise ValidationError(msg)
        for ext in self.extensions:
            if not isinstance(ext, dict):
                raise ValidationError(msg)
            if not ("name" in ext and "critical" in ext and "value" in ext):
                raise ValidationError(msg)

            oid = str(ext.get("name"))

            try:
                ObjectIdentifier(oid)
            except ValueError:
                raise ValidationError(f"Invalid object identifier '{oid}'")

    def _add_extensions(self, certificate: cryptography.x509.CertificateBuilder) -> cryptography.x509.CertificateBuilder:
        """Add extensions to a certificate."""
        if hasattr(self, "ca"):
            # Extensions for normal certificates signed by a different Certificate Authority.
            certificate = certificate.add_extension(
                cryptography.x509.extensions.BasicConstraints(False, None),
                False
            )
            certificate = certificate.add_extension(
                cryptography.x509.extensions.KeyUsage(
                    **app_settings.CERT_KEYUSAGE_VALUE
                ),
                app_settings.CERT_KEYUSAGE_CRITICAL
            )
            issuer_public_key = self.ca.x509.public_key()
        else:
            # Extensions for Certificate Authority.
            path_length = app_settings.CA_BASIC_CONSTRAINTS_PATHLEN
            certificate = certificate.add_extension(
                cryptography.x509.extensions.BasicConstraints(True, path_length),
                app_settings.CA_BASIC_CONSTRAINTS_CRITICAL
            )
            certificate = certificate.add_extension(
                cryptography.x509.extensions.KeyUsage(**app_settings.CA_KEYUSAGE_VALUE),
                app_settings.CA_KEYUSAGE_CRITICAL
            )
            issuer_public_key = certificate._public_key

        certificate = certificate.add_extension(
            cryptography.x509.extensions.SubjectKeyIdentifier(b"hash"),
            False
        )
        # authorityKeyIdentifier must be added after the other extensions have been already added
        certificate = certificate.add_extension(
            cryptography.x509.extensions.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_public_key
            ),
            False
        )

        for extension in self.extensions:
            certificate = certificate.add_extension(
                cryptography.x509.extensions.UnrecognizedExtension(
                    ObjectIdentifier(str(extension["name"])),
                    b'\x0c\x0b' + bytes(str(extension["value"]), "utf-8")
                ),
                bool(extension["critical"]),
            )

        return certificate

    def renew(self):
        """Renew a certificate."""
        self._generate()
        self.serial_number = BaseX509._generate_serial_number()
        self.validity_end = self.__class__().validity_end
        self.save()

    @staticmethod
    def _generate_serial_number():
        """Generate a new serial number."""
        return uuid.uuid4().int


class AbstractCa(BaseX509):
    """
    Abstract Ca model
    """

    class Meta:
        abstract = True
        verbose_name = _("CA")
        verbose_name_plural = _("CAs")

    def get_revoked_certs(self) -> List[cryptography.x509.Certificate]:
        """
        Returns revoked certificates of this CA
        (does not include expired certificates)
        """
        now = timezone.now()
        return self.cert_set.filter(
            revoked=True, validity_start__lte=now, validity_end__gte=now
        )

    def renew(self):
        """
        Renew the certificate, private key and
        validity end date of a CA
        """
        super().renew()
        for cert in self.cert_set.all():
            cert.renew()

    @property
    def crl(self):
        """
        Returns up to date CRL of this CA
        """
        now = timezone.now()
        revoked_certs = self.get_revoked_certs()
        builder = (x509.CertificateRevocationListBuilder()
                   .issuer_name(self.x509.subject)
                   .last_update(now - timedelta(days=1))
                   .next_update(now + timedelta(days=1)))

        for cert in revoked_certs:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(cert.serial_number))
                .revocation_date(now)
                .add_extension(
                    x509.CRLReason(x509.ReasonFlags.unspecified),
                    critical=False
                )
                .build()
            )

            builder = builder.add_revoked_certificate(revoked_cert)

        return builder.sign(self.pkey, SHA256()).public_bytes(serialization.Encoding.PEM)

AbstractCa._meta.get_field("validity_end").default = default_ca_validity_end


class AbstractCert(BaseX509):
    """
    Abstract Cert model
    """

    ca = models.ForeignKey(
        swapper.get_model_name("django_x509", "Ca"),
        on_delete=models.CASCADE,
        verbose_name=_("CA"),
    )
    revoked = models.BooleanField(_("revoked"), default=False)
    revoked_at = models.DateTimeField(
        _("revoked at"), blank=True, null=True, default=None
    )

    def __str__(self):
        return self.name

    class Meta:
        abstract = True
        verbose_name = _("certificate")
        verbose_name_plural = _("certificates")
        unique_together = ("ca", "serial_number")

    def revoke(self):
        """
        * flag certificate as revoked
        * fill in revoked_at DateTimeField
        """
        now = timezone.now()
        self.revoked = True
        self.revoked_at = now
        self.save()
