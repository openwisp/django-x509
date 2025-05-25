import collections
import uuid
from datetime import datetime, timedelta

import swapper
from cryptography import x509
from cryptography.exceptions import InvalidKey, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
)
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    CertificateBuilder,
    CertificateRevocationListBuilder,
    Extension,
    ExtensionNotFound,
    ExtensionOID,
    ExtensionType,
    KeyUsage,
    Name,
    NameAttribute,
    NameOID,
    RevokedCertificateBuilder,
    SubjectKeyIdentifier,
)
from cryptography.x509.oid import CRLEntryExtensionOID, ExtensionOID, NameOID
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from jsonfield import JSONField
from model_utils.fields import AutoCreatedField, AutoLastModifiedField

from .. import settings as app_settings

generalized_time = '%Y%m%d%H%M%SZ'
utc_time = '%y%m%d%H%M%SZ'

KEY_LENGTH_CHOICES = (
    ('512', '512'),
    ('1024', '1024'),
    ('2048', '2048'),
    ('4096', '4096'),
)

DIGEST_CHOICES = (
    ('sha1', 'SHA1'),
    ('sha224', 'SHA224'),
    ('sha256', 'SHA256'),
    ('sha384', 'SHA384'),
    ('sha512', 'SHA512'),
)

SIGNATURE_MAPPING = {
    'sha1WithRSAEncryption': 'sha1',
    'sha224WithRSAEncryption': 'sha224',
    'sha256WithRSAEncryption': 'sha256',
    'sha384WithRSAEncryption': 'sha384',
    'sha512WithRSAEncryption': 'sha512',
}


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
    key_length = models.CharField(
        _('key length'),
        help_text=_('bits'),
        choices=KEY_LENGTH_CHOICES,
        default=default_key_length,
        max_length=6,
    )
    digest = models.CharField(
        _('digest algorithm'),
        help_text=_('bits'),
        choices=DIGEST_CHOICES,
        default=default_digest_algorithm,
        max_length=8,
    )
    validity_start = models.DateTimeField(
        blank=True, null=True, default=default_validity_start
    )
    validity_end = models.DateTimeField(
        blank=True, null=True, default=default_cert_validity_end
    )
    country_code = models.CharField(max_length=2, blank=True)
    state = models.CharField(_('state or province'), max_length=64, blank=True)
    city = models.CharField(_('city'), max_length=64, blank=True)
    organization_name = models.CharField(_('organization'), max_length=64, blank=True)
    organizational_unit_name = models.CharField(
        _('organizational unit name'), max_length=64, blank=True
    )
    email = models.EmailField(_('email address'), blank=True)
    common_name = models.CharField(_('common name'), max_length=64, blank=True)
    extensions = JSONField(
        _('extensions'),
        default=list,
        blank=True,
        help_text=_('additional x509 certificate extensions'),
        load_kwargs={'object_pairs_hook': collections.OrderedDict},
        dump_kwargs={'indent': 4},
    )
    # serial_number is set to CharField as a UUID integer is too big for a
    # PositiveIntegerField and an IntegerField on SQLite
    serial_number = models.CharField(
        _('serial number'),
        help_text=_('leave blank to determine automatically'),
        blank=True,
        null=True,
        max_length=48,
    )
    certificate = models.TextField(
        blank=True, help_text='certificate in X.509 PEM format'
    )
    private_key = models.TextField(
        blank=True, help_text='private key in X.509 PEM format'
    )
    created = AutoCreatedField(_('created'), editable=True)
    modified = AutoLastModifiedField(_('modified'), editable=True)
    passphrase = models.CharField(
        max_length=64,
        blank=True,
        help_text=_('Passphrase for the private key, if present'),
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
        # when importing, both public and private must be present
        if (self.certificate and not self.private_key) or (
            self.private_key and not self.certificate
        ):
            raise ValidationError(
                _(
                    'When importing an existing certificate, both '
                    'keys (private and public) must be present'
                )
            )
        if self.serial_number:
            self._validate_serial_number()
        self._verify_extension_format()

    def save(self, *args, **kwargs):
        if self._state.adding and not self.certificate and not self.private_key:
            # auto generate serial number
            if not self.serial_number:
                self.serial_number = self._generate_serial_number()
            self._generate()
        super().save(*args, **kwargs)

    @cached_property
    def x509(self):
        """
        Returns an instance of cryptography.x509.Certificate
        """
        if self.certificate:
            return x509.load_pem_x509_certificate(
                self.certificate.encode('utf-8'), backend=default_backend()
            )

    @cached_property
    def x509_text(self):
        """
        Returns a text dump of the information
        contained in the x509 certificate
        """
        if not self.certificate:
            return None

        cert = self.x509
        lines = [
            f'Subject: {cert.subject.rfc4514_string()}',
            f'Issuer: {cert.issuer.rfc4514_string()}',
            f'Serial Number: {cert.serial_number}',
            f'Not Before: {cert.not_valid_before_utc}',
            f'Not After: {cert.not_valid_after_utc}',
            f'Signature Algorithm: {cert.signature_hash_algorithm.name}',
            'Extensions:',
        ]

        for ext in cert.extensions:
            lines.append(f'  - {ext.oid._name or ext.oid.dotted_string}: {ext.value}')

        return '\n'.join(lines)

    @cached_property
    def pkey(self):
        """
        Returns an instance of cryptography private key
        """
        if self.private_key:
            return serialization.load_pem_private_key(
                self.private_key.encode('utf-8'),
                password=getattr(self, 'passphrase', None).encode('utf-8') or None,
                backend=default_backend(),
            )

    def _validate_pem(self):
        """
        (internal use only)
        validates certificate and private key
        """
        errors = {}
        # Validate certificate
        try:
            x509.load_pem_x509_certificate(self.certificate.encode('utf-8'))
        except Exception as e:
            errors['certificate'] = ValidationError(
                _(mark_safe(f'Certificate error:<br>{str(e)}'))
            )

        # Validate private key
        try:
            serialization.load_pem_private_key(
                self.private_key.encode('utf-8'),
                password=getattr(self, 'passphrase', None).encode('utf-8')
                if getattr(self, 'passphrase', None)
                else None,
            )
        except ValueError as e:
            error = f'<b>Incorrect Passphrase</b><br>{str(e)}'
            errors['passphrase'] = ValidationError(_(mark_safe(error)))
        except (InvalidKey, UnsupportedAlgorithm) as e:
            errors['private_key'] = ValidationError(
                _(mark_safe(f'Private key error:<br>{str(e)}'))
            )
        if errors:
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
                {'serial_number': _('Serial number must be an integer')}
            )

    def _generate(self):
        """
        (internal use only)
        generates a new x509 certificate (CA or end-entity)
        """
        # Generate RSA private key
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=int(self.key_length)
        )
        public_key = key.public_key()

        # Fill subject and issuer
        subject = self._fill_subject()
        if not hasattr(self, 'ca'):
            issuer = subject
            issuer_key = key
        else:
            issuer = self.ca.x509.issuer
            issuer_key = self.ca.pkey

        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(public_key)
        builder = builder.serial_number(int(self.serial_number))
        builder = builder.not_valid_before(self.validity_start)
        builder = builder.not_valid_after(self.validity_end)
        builder = self._build_extensions(
            builder, public_key, self.ca.x509 if hasattr(self, 'ca') else None
        )

        # Sign certificate
        cert = builder.sign(
            private_key=issuer_key, algorithm=getattr(hashes, self.digest.upper())()
        )

        # Store PEM-encoded certificate
        self.certificate = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        # Store PEM-encoded private key
        if self.passphrase:
            encryption = BestAvailableEncryption(self.passphrase.encode('utf-8'))
        else:
            encryption = NoEncryption()
        self.private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption,
        ).decode('utf-8')

    def _fill_subject(self):
        """
        (internal use only)
        returns a cryptography.x509.Name object
        """
        attr_map = {
            'country_code': NameOID.COUNTRY_NAME,
            'state': NameOID.STATE_OR_PROVINCE_NAME,
            'city': NameOID.LOCALITY_NAME,
            'organization_name': NameOID.ORGANIZATION_NAME,
            'organizational_unit_name': NameOID.ORGANIZATIONAL_UNIT_NAME,
            'email': NameOID.EMAIL_ADDRESS,
            'common_name': NameOID.COMMON_NAME,
        }

        name_attributes = []
        for model_attr, oid in attr_map.items():
            value = getattr(self, model_attr)
            if value:
                name_attributes.append(x509.NameAttribute(oid, str(value)))

        return x509.Name(name_attributes)

    def _import(self):
        """
        (internal use only)
        imports existing x509 certificates
        """
        cert = self.x509
        # when importing an end entity certificate
        if hasattr(self, 'ca'):
            self._verify_ca()

        # Use cryptography to extract the public key and key length
        public_key = cert.public_key()  # This gets the public key from the certificate
        if isinstance(public_key, rsa.RSAPublicKey):
            self.key_length = public_key.key_size
        else:
            raise ValueError("Unsupported key type")

        # The signature algorithm handling remains the same
        algorithm = cert.signature_algorithm_oid._name  # Use the cryptography API for signature algorithm
        self.digest = SIGNATURE_MAPPING.get(algorithm)

        # Handle validity period
        not_before = cert.not_valid_before
        self.validity_start = timezone.make_aware(not_before)
        not_after = cert.not_valid_after
        self.validity_end = timezone.make_aware(not_after)

        def get_attr_for_oid(attr):
            attr_list = subject.get_attributes_for_oid(attr)
            return attr_list[0].value if attr_list else ''

        # Extract subject details
        subject = cert.subject
        self.country_code = get_attr_for_oid(NameOID.COUNTRY_NAME)
        if len(self.country_code) > 2:
            self.country_code = ''
        self.state = get_attr_for_oid(NameOID.STATE_OR_PROVINCE_NAME)
        self.city = get_attr_for_oid(NameOID.LOCALITY_NAME)
        self.organization_name = get_attr_for_oid(NameOID.ORGANIZATION_NAME)
        self.organizational_unit_name = get_attr_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        self.email = get_attr_for_oid(NameOID.EMAIL_ADDRESS)
        self.common_name = get_attr_for_oid(NameOID.COMMON_NAME)
        self.serial_number = cert.serial_number

        if not self.name:
            self.name = self.common_name or str(self.serial_number)

    def _verify_ca(self):
        """
        (internal use only)
        verifies the current x509 is signed
        by the associated CA
        """
        cert = self.x509
        ca_cert = self.ca.x509

        try:
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception as e:
            raise ValidationError(
                _("CA doesn't match, certificate verification failed: “%s”") % str(e)
            )

    def _verify_extension_format(self):
        """
        (internal use only)
        verifies the format of ``self.extension`` is correct
        """
        msg = 'Extension format invalid'
        if not isinstance(self.extensions, list):
            raise ValidationError(msg)
        for ext in self.extensions:
            if not isinstance(ext, dict):
                raise ValidationError(msg)
            if not ('name' in ext and 'critical' in ext and 'value' in ext):
                raise ValidationError(msg)

    def _build_extensions(self, cert_builder, public_key, issuer_cert=None):
        """
        (internal use only)
        returns a list of extensions to be
        added to the certificate builder
        """
        extensions = []

        # CA or EE?
        is_ca = not hasattr(self, 'ca')
        pathlen = app_settings.CA_BASIC_CONSTRAINTS_PATHLEN if is_ca else None

        # basicConstraints
        basic_constraints = BasicConstraints(ca=is_ca, path_length=pathlen)
        critical = app_settings.CA_BASIC_CONSTRAINTS_CRITICAL if is_ca else False
        extensions.append((basic_constraints, critical))

        # keyUsage
        key_usage_value = (
            app_settings.CA_KEYUSAGE_VALUE
            if is_ca
            else app_settings.CERT_KEYUSAGE_VALUE
        )
        key_usage_critical = (
            app_settings.CA_KEYUSAGE_CRITICAL
            if is_ca
            else app_settings.CERT_KEYUSAGE_CRITICAL
        )

        key_usage = KeyUsage(
            digital_signature='digitalSignature' in key_usage_value,
            key_encipherment='keyEncipherment' in key_usage_value,
            content_commitment='nonRepudiation' in key_usage_value,
            data_encipherment='dataEncipherment' in key_usage_value,
            key_agreement='keyAgreement' in key_usage_value,
            key_cert_sign='keyCertSign' in key_usage_value,
            crl_sign='cRLSign' in key_usage_value,
            encipher_only=False,
            decipher_only=False,
        )
        extensions.append((key_usage, key_usage_critical))

        # subjectKeyIdentifier
        ski = SubjectKeyIdentifier.from_public_key(public_key)
        extensions.append((ski, False))

        # authorityKeyIdentifier
        if issuer_cert:
            authority_key_id = AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_cert.public_key()
            )
            extensions.append((authority_key_id, False))

        # Custom extensions defined in self.extensions
        for ext in self.extensions:
            ext_oid = ExtensionOID._map.get(ext['name']) or ext['name']
            extensions.append(
                (
                    x509.UnrecognizedExtension(
                        x509.ObjectIdentifier(ext_oid),
                        str(ext['value']).encode('utf-8'),
                    ),
                    bool(ext['critical']),
                )
            )

        # Add to the builder
        for ext_value, is_critical in extensions:
            cert_builder = cert_builder.add_extension(ext_value, critical=is_critical)

        return cert_builder

    def renew(self):
        self._generate()
        self.serial_number = self._generate_serial_number()
        self.validity_end = self.__class__().validity_end
        self.save()

    def _generate_serial_number(self):
        return uuid.uuid4().int


class AbstractCa(BaseX509):
    """
    Abstract Ca model
    """

    class Meta:
        abstract = True
        verbose_name = _('CA')
        verbose_name_plural = _('CAs')

    def get_revoked_certs(self):
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
        Returns up-to-date CRL of this CA using cryptography
        """
        now = timezone.now()
        builder = CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.x509.subject)
        builder = builder.last_update(now)
        builder = builder.next_update(now + timedelta(days=1))

        for cert in self.get_revoked_certs():
            revoked_cert = (
                RevokedCertificateBuilder()
                .serial_number(int(cert.serial_number))
                .revocation_date(now)
                .add_extension(
                    x509.CRLReason(x509.ReasonFlags.unspecified),
                    critical=False,
                )
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(private_key=self.pkey, algorithm=hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.PEM).decode("utf-8")


AbstractCa._meta.get_field('validity_end').default = default_ca_validity_end


class AbstractCert(BaseX509):
    """
    Abstract Cert model
    """

    ca = models.ForeignKey(
        swapper.get_model_name('django_x509', 'Ca'),
        on_delete=models.CASCADE,
        verbose_name=_('CA'),
    )
    revoked = models.BooleanField(_('revoked'), default=False)
    revoked_at = models.DateTimeField(
        _('revoked at'), blank=True, null=True, default=None
    )

    def __str__(self):
        return self.name

    class Meta:
        abstract = True
        verbose_name = _('certificate')
        verbose_name_plural = _('certificates')
        unique_together = ('ca', 'serial_number')

    def revoke(self):
        """
        * flag certificate as revoked
        * fill in revoked_at DateTimeField
        """
        now = timezone.now()
        self.revoked = True
        self.revoked_at = now
        self.save()
