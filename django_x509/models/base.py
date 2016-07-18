import collections
from datetime import datetime, timedelta

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.encoding import python_2_unicode_compatible
from django.utils.functional import cached_property
from django.utils.translation import ugettext_lazy as _
from jsonfield import JSONField
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


@python_2_unicode_compatible
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
                                  default=default_key_length,
                                  max_length=6)
    digest = models.CharField(_('digest algorithm'),
                              help_text=_('bits'),
                              blank=True,
                              choices=DIGEST_CHOICES,
                              default=default_digest_algorithm,
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
    extensions = JSONField(_('extensions'),
                           default=list,
                           blank=True,
                           help_text=_('additional x509 certificate extensions'),
                           load_kwargs={'object_pairs_hook': collections.OrderedDict},
                           dump_kwargs={'indent': 4})
    serial_number = models.PositiveIntegerField(_('serial number'),
                                                help_text=_('leave blank to determine automatically'),
                                                blank=True,
                                                null=True)
    public_key = models.TextField(blank=True, help_text='certificate in X.509 PEM format')
    private_key = models.TextField(blank=True, help_text='private key in X.509 PEM format')
    created = AutoCreatedField(_('created'), editable=True)
    modified = AutoLastModifiedField(_('modified'), editable=True)

    class Meta:
        abstract = True

    def __str__(self):
        return self.name

    def clean_fields(self, *args, **kwargs):
        # importing existing certificate
        # must be done here in order to validate imported fields
        # and fill private and public key before validation fails
        if not self.pk and self.public_key and self.private_key:
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
        self._verify_extension_format()

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
        """
        (internal use only)
        generates a new x509 certificate (CA or end-entity)
        """
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, int(self.key_length))
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
        cert = self._add_extensions(cert)
        cert.sign(issuer_key, self.digest)
        self.public_key = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        self.private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    def _fill_subject(self, subject):
        """
        (internal use only)
        fills OpenSSL.crypto.X509Name object
        """
        subject.countryName = self.country_code
        subject.stateOrProvinceName = self.state
        subject.localityName = self.city
        subject.organizationName = self.organization
        subject.emailAddress = self.email
        subject.commonName = self.common_name
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
            raise ValidationError(_("CA doesn't match, got the"
                                    "following error from pyOpenSSL: \"%s\"") % e.args[0][2])

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
        for ext in self.extensions:
            cert.add_extensions([
                crypto.X509Extension(bytes_compat(ext['name']),
                                     bool(ext['critical']),
                                     bytes_compat(ext['value']))
            ])
        return cert
