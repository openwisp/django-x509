import collections
import uuid
from datetime import datetime, timedelta

import OpenSSL
import swapper
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from jsonfield import JSONField
from model_utils.fields import AutoCreatedField, AutoLastModifiedField
from OpenSSL import crypto

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
                    'When importing an existing certificate, both'
                    'keys (private and public) must be present'
                )
            )
        if self.serial_number:
            self._validate_serial_number()
        self._verify_extension_format()

    def save(self, *args, **kwargs):
        generate = False
        if not self.pk and not self.certificate and not self.private_key:
            generate = True
        super().save(*args, **kwargs)
        if generate:
            # automatically determine serial number
            if not self.serial_number:
                self.serial_number = self._generate_serial_number()
            self._generate()
            kwargs['force_insert'] = False
            super().save(*args, **kwargs)

    @cached_property
    def x509(self):
        """
        returns an instance of OpenSSL.crypto.X509
        """
        if self.certificate:
            return crypto.load_certificate(crypto.FILETYPE_PEM, self.certificate)

    @cached_property
    def x509_text(self):
        """
        returns a text dump of the information
        contained in the x509 certificate
        """
        if self.certificate:
            text = crypto.dump_certificate(crypto.FILETYPE_TEXT, self.x509)
            return text.decode('utf-8')

    @cached_property
    def pkey(self):
        """
        returns an instance of OpenSSL.crypto.PKey
        """
        if self.private_key:
            return crypto.load_privatekey(
                crypto.FILETYPE_PEM,
                self.private_key,
                passphrase=getattr(self, 'passphrase').encode('utf-8'),
            )

    def _validate_pem(self):
        """
        (internal use only)
        validates certificate and private key
        """
        errors = {}
        for field in ['certificate', 'private_key']:
            method_name = 'load_{0}'.format(field.replace('_', ''))
            load_pem = getattr(crypto, method_name)
            try:
                args = (crypto.FILETYPE_PEM, getattr(self, field))
                kwargs = {}
                if method_name == 'load_privatekey':
                    kwargs['passphrase'] = getattr(self, 'passphrase').encode('utf8')
                load_pem(*args, **kwargs)
            except OpenSSL.crypto.Error as e:
                error = 'OpenSSL error: <br>{0}'.format(
                    str(e.args[0]).replace('), ', '), <br>').strip('[]')
                )
                if 'bad decrypt' in error:
                    error = '<b>Incorrect Passphrase</b> <br>' + error
                    errors['passphrase'] = ValidationError(_(mark_safe(error)))
                    continue
                errors[field] = ValidationError(_(mark_safe(error)))
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
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, int(self.key_length))
        cert = crypto.X509()
        subject = self._fill_subject(cert.get_subject())
        cert.set_version(0x2)  # version 3 (0 indexed counting)
        cert.set_subject(subject)
        cert.set_serial_number(int(self.serial_number))
        cert.set_notBefore(bytes(str(datetime_to_string(self.validity_start)), 'utf8'))
        cert.set_notAfter(bytes(str(datetime_to_string(self.validity_end)), 'utf8'))
        # generating certificate for CA
        if not hasattr(self, 'ca'):
            issuer = cert.get_subject()
            issuer_key = key
        # generating certificate issued by a CA
        else:
            issuer = self.ca.x509.get_subject()
            issuer_key = self.ca.pkey
        cert.set_issuer(issuer)
        cert.set_pubkey(key)
        cert = self._add_extensions(cert)
        cert.sign(issuer_key, str(self.digest))
        self.certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode(
            'utf-8'
        )
        key_args = (crypto.FILETYPE_PEM, key)
        key_kwargs = {}
        if self.passphrase:
            key_kwargs['passphrase'] = self.passphrase.encode('utf-8')
            key_kwargs['cipher'] = 'DES-EDE3-CBC'
        self.private_key = crypto.dump_privatekey(*key_args, **key_kwargs).decode(
            'utf-8'
        )

    def _fill_subject(self, subject):
        """
        (internal use only)
        fills OpenSSL.crypto.X509Name object
        """
        attr_map = {
            'country_code': 'countryName',
            'state': 'stateOrProvinceName',
            'city': 'localityName',
            'organization_name': 'organizationName',
            'organizational_unit_name': 'organizationalUnitName',
            'email': 'emailAddress',
            'common_name': 'commonName',
        }
        # set x509 subject attributes only if not empty strings
        for model_attr, subject_attr in attr_map.items():
            value = getattr(self, model_attr)
            if value:
                # coerce value to string, allow these fields to be redefined
                # as foreign keys by subclasses without losing compatibility
                setattr(subject, subject_attr, str(value))
        return subject

    def _import(self):
        """
        (internal use only)
        imports existing x509 certificates
        """
        cert = self.x509
        # when importing an end entity certificate
        if hasattr(self, 'ca'):
            self._verify_ca()
        self.key_length = str(cert.get_pubkey().bits())
        # this line might fail if a certificate with
        # an unsupported signature algorithm is imported
        algorithm = cert.get_signature_algorithm().decode('utf8')
        self.digest = SIGNATURE_MAPPING[algorithm]
        not_before = cert.get_notBefore().decode('utf8')
        self.validity_start = datetime.strptime(not_before, generalized_time)
        self.validity_start = timezone.make_aware(self.validity_start)
        not_after = cert.get_notAfter().decode('utf8')
        self.validity_end = datetime.strptime(not_after, generalized_time)
        self.validity_end.replace(tzinfo=timezone.tzinfo())
        self.validity_end = timezone.make_aware(self.validity_end)
        subject = cert.get_subject()
        self.country_code = subject.countryName or ''
        # allow importing from legacy systems which use invalid country codes
        if len(self.country_code) > 2:
            self.country_code = ''
        self.state = subject.stateOrProvinceName or ''
        self.city = subject.localityName or ''
        self.organization_name = subject.organizationName or ''
        self.organizational_unit_name = subject.organizationalUnitName or ''
        self.email = subject.emailAddress or ''
        self.common_name = subject.commonName or ''
        self.serial_number = cert.get_serial_number()
        if not self.name:
            self.name = self.common_name or str(self.serial_number)

    def _verify_ca(self):
        """
        (internal use only)
        verifies the current x509 is signed
        by the associated CA
        """
        store = crypto.X509Store()
        store.add_cert(self.ca.x509)
        store_ctx = crypto.X509StoreContext(store, self.x509)
        try:
            store_ctx.verify_certificate()
        except crypto.X509StoreContextError as e:
            raise ValidationError(
                _("CA doesn't match, got the " 'following error from pyOpenSSL: "%s"')
                % e.args[0][2]
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

    def _add_extensions(self, cert):
        """
        (internal use only)
        adds x509 extensions to ``cert``
        """
        ext = []
        # prepare extensions for CA
        if not hasattr(self, 'ca'):
            pathlen = app_settings.CA_BASIC_CONSTRAINTS_PATHLEN
            ext_value = 'CA:TRUE'
            if pathlen is not None:
                ext_value = '{0}, pathlen:{1}'.format(ext_value, pathlen)
            ext.append(
                crypto.X509Extension(
                    b'basicConstraints',
                    app_settings.CA_BASIC_CONSTRAINTS_CRITICAL,
                    bytes(str(ext_value), 'utf8'),
                )
            )
            ext.append(
                crypto.X509Extension(
                    b'keyUsage',
                    app_settings.CA_KEYUSAGE_CRITICAL,
                    bytes(str(app_settings.CA_KEYUSAGE_VALUE), 'utf8'),
                )
            )
            issuer_cert = cert
        # prepare extensions for end-entity certs
        else:
            ext.append(crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'))
            ext.append(
                crypto.X509Extension(
                    b'keyUsage',
                    app_settings.CERT_KEYUSAGE_CRITICAL,
                    bytes(str(app_settings.CERT_KEYUSAGE_VALUE), 'utf8'),
                )
            )
            issuer_cert = self.ca.x509
        ext.append(
            crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert)
        )
        cert.add_extensions(ext)
        # authorityKeyIdentifier must be added after
        # the other extensions have been already added
        cert.add_extensions(
            [
                crypto.X509Extension(
                    b'authorityKeyIdentifier',
                    False,
                    b'keyid:always,issuer:always',
                    issuer=issuer_cert,
                )
            ]
        )
        for ext in self.extensions:
            cert.add_extensions(
                [
                    crypto.X509Extension(
                        bytes(str(ext['name']), 'utf8'),
                        bool(ext['critical']),
                        bytes(str(ext['value']), 'utf8'),
                    )
                ]
            )
        return cert

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
        Returns up to date CRL of this CA
        """
        revoked_certs = self.get_revoked_certs()
        crl = crypto.CRL()
        now_str = datetime_to_string(timezone.now())
        for cert in revoked_certs:
            revoked = crypto.Revoked()
            revoked.set_serial(bytes(str(cert.serial_number), 'utf8'))
            revoked.set_reason(b'unspecified')
            revoked.set_rev_date(bytes(str(now_str), 'utf8'))
            crl.add_revoked(revoked)
        return crl.export(self.x509, self.pkey, days=1, digest=b'sha256')


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
