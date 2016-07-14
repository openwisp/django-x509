from datetime import datetime, timedelta

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.translation import ugettext_lazy as _
from model_utils.fields import AutoCreatedField, AutoLastModifiedField
from OpenSSL import crypto

from .. import settings as app_settings
from ..utils import bytes_compat

generalized_time = '%Y%m%d%H%M%SZ'

KEY_LENGTH_CHOICES = (
    ('', ''),
    ('512', '512'),
    ('1024', '1024'),
    ('2048', '2048'),
    ('4096', '4096')
)

DIGEST_CHOICES = (
    ('', ''),
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


def default_cert_validity_end():
    """
    returns the default value for validity_end field
    """
    delta = timedelta(days=app_settings.DEFAULT_CERT_VALIDITY)
    return timezone.now() + delta


class AbstractX509(models.Model):
    """
    Abstract Cert class, shared between Ca and Cert
    """
    name = models.CharField(max_length=64)
    notes = models.TextField(blank=True)
    key_length = models.CharField(_('key length'),
                                  help_text=_('bits'),
                                  blank=True,
                                  choices=KEY_LENGTH_CHOICES,
                                  max_length=6)
    digest = models.CharField(_('digest algorithm'),
                              help_text=_('bits'),
                              blank=True,
                              choices=DIGEST_CHOICES,
                              max_length=8)
    validity_start = models.DateTimeField(blank=True,
                                          null=True,
                                          default=timezone.now)
    validity_end = models.DateTimeField(blank=True,
                                        null=True,
                                        default=default_cert_validity_end)
    country_code = models.CharField(max_length=2, blank=True)
    state = models.CharField(_('state or province'), max_length=64, blank=True)
    city = models.CharField(_('city'), max_length=64, blank=True)
    organization = models.CharField(_('organization'), max_length=64, blank=True)
    email = models.EmailField(_('email address'), blank=True)
    common_name = models.CharField(_('common name'), max_length=63, blank=True)
    serial_number = models.PositiveIntegerField(_('serial number'),
                                                help_text=_('leave blank to determine automatically'),
                                                blank=True,
                                                null=True)
    public_key = models.TextField(blank=True, help_text='Certificate in X.509 PEM format')
    private_key = models.TextField(blank=True, help_text='Private key in X.509 PEM format')
    created = AutoCreatedField(_('created'), editable=True)
    modified = AutoLastModifiedField(_('modified'), editable=True)

    class Meta:
        abstract = True

    def clean_fields(self, *args, **kwargs):
        # importing existing certificate
        if self.public_key and self.private_key and (
            not self.key_length or
            not self.digest or
            not self.validity_start or
            not self.validity_end or
            not self.country_code or
            not self.state or
            not self.city or
            not self.organization or
            not self.email or
            not self.common_name or
            not self.serial_number
        ):
            self._import()
        super(AbstractX509, self).clean_fields(*args, **kwargs)

    def clean(self):
        # when importing, both public and private must be present
        if (
            (self.public_key and not self.private_key) or
            (self.private_key and not self.public_key)
        ):
            raise ValidationError(_('When importing an existing certificate, both'
                                    'keys (private and public) must be present'))

    def save(self, *args, **kwargs):
        generate = False
        if not self.id and not self.public_key and not self.private_key:
            generate = True
        super(AbstractX509, self).save(*args, **kwargs)
        if generate:
            # automatically determine serial number
            if not self.serial_number:
                self.serial_number = self.id
            self._generate()
            super(AbstractX509, self).save(*args, **kwargs)

    @cached_property
    def x509(self):
        """
        returns an instance of OpenSSL.crypto.X509
        """
        if self.public_key:
            return crypto.load_certificate(crypto.FILETYPE_PEM, self.public_key)

    @cached_property
    def pkey(self):
        """
        returns an instance of OpenSSL.crypto.PKey
        """
        if self.private_key:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, self.private_key)

    def _generate(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, int(self.key_length))
        ext = []
        cert = crypto.X509()
        subject = self._fill_subject(cert.get_subject())
        cert.set_version(3)
        cert.set_subject(subject)
        cert.set_serial_number(self.serial_number)
        cert.set_notBefore(bytes_compat(self.validity_start.strftime(generalized_time)))
        cert.set_notAfter(bytes_compat(self.validity_end.strftime(generalized_time)))
        # generating certificate for CA
        if not hasattr(self, 'ca'):
            issuer = subject
            issuer_key = key
        # generating certificate issued by a CA
        else:
            issuer = self.ca.x509.get_subject()
            issuer_key = self.ca.pkey
        cert.set_issuer(issuer)
        cert.set_pubkey(key)
        self._add_extensions(cert)
        cert.sign(issuer_key, self.digest)
        self.public_key = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        self.private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    def _fill_subject(self, subject):
        subject.countryName = self.country_code
        subject.stateOrProvinceName = self.state
        subject.localityName = self.city
        subject.organizationName = self.organization
        subject.emailAddress = self.email
        subject.commonName = self.common_name
        return subject

    def _import(self):
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
        self.validity_start = datetime.strptime(not_before,
                                                generalized_time)
        self.validity_start = timezone.make_aware(self.validity_start)
        not_after = cert.get_notAfter().decode('utf8')
        self.validity_end = datetime.strptime(not_after,
                                              generalized_time)
        self.validity_end.replace(tzinfo=timezone.tzinfo())
        self.validity_end = timezone.make_aware(self.validity_end)
        subject = cert.get_subject()
        self.country_code = subject.countryName
        self.state = subject.stateOrProvinceName
        self.city = subject.localityName
        self.organization = subject.organizationName
        self.email = subject.emailAddress
        self.common_name = subject.commonName
        self.serial_number = cert.get_serial_number()
        if not self.name:
            self.name = self.common_name

    def _verify_ca(self):
        store = crypto.X509Store()
        store.add_cert(self.ca.x509)
        store_ctx = crypto.X509StoreContext(store, self.x509)
        try:
            store_ctx.verify_certificate()
        except crypto.X509StoreContextError as e:
            raise ValidationError(_("CA doesn't match, got the"
                                    "following error from pyOpenSSL: \"%s\"") % e.args[0][2])

    def _add_extensions(self, cert):
        ext = []
        # prepare extensions for CA
        if not hasattr(self, 'ca'):
            pathlen = app_settings.CA_BASIC_CONSTRAINTS_PATHLEN
            ext_value = 'CA:TRUE'
            if pathlen is not None:
                ext_value = '{0}, pathlen:{1}'.format(ext_value, pathlen)
            ext.append(crypto.X509Extension(b'basicConstraints',
                                            app_settings.CA_BASIC_CONSTRAINTS_CRITICAL,
                                            bytes_compat(ext_value)))
            ext.append(crypto.X509Extension(b'keyUsage',
                                            app_settings.CA_KEYUSAGE_CRITICAL,
                                            bytes_compat(app_settings.CA_KEYUSAGE_VALUE)))
            issuer_cert = cert
        # prepare extensions for end-entity certs
        else:
            ext.append(crypto.X509Extension(b'basicConstraints',
                                            False,
                                            b'CA:FALSE'))
            ext.append(crypto.X509Extension(b'keyUsage',
                                            app_settings.CERT_KEYUSAGE_CRITICAL,
                                            bytes_compat(app_settings.CERT_KEYUSAGE_VALUE)))
            issuer_cert = self.ca.x509
        ext.append(crypto.X509Extension(b'subjectKeyIdentifier',
                                        False,
                                        b'hash',
                                        subject=cert))
        cert.add_extensions(ext)
        # authorityKeyIdentifier must be added after
        # the other extensions have been already added
        cert.add_extensions([
            crypto.X509Extension(b'authorityKeyIdentifier',
                                 False,
                                 b'keyid:always,issuer:always',
                                 issuer=issuer_cert)
        ])
