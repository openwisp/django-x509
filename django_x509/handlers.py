from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import mail_admins, mail_managers, send_mass_mail
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .base.models import AutoRenewChoices


def _format_datetime(value):
    return timezone.localtime(value).strftime("%Y-%m-%d %H:%M:%S %Z")


def _admin_url(instance):
    try:
        return reverse(
            "admin:{0}_{1}_change".format(
                instance._meta.app_label, instance._meta.model_name
            ),
            args=[instance.pk],
        )
    except Exception:
        return ""


def _render_instance(instance, extra_text=""):
    line = _(
        "- %(name)s (expires on %(validity_end)s, admin: %(admin_url)s)%(extra)s"
    ) % {
        "name": instance.name,
        "validity_end": _format_datetime(instance.validity_end),
        "admin_url": _admin_url(instance) or _("unavailable"),
        "extra": f" {extra_text}" if extra_text else "",
    }
    return line


def _render_failed_instance(entry):
    instance = entry["instance"]
    return _render_instance(
        instance,
        _("automatic renewal failed: %(error)s")
        % {"error": entry.get("error", _("unknown error"))},
    )


def _send_notification_email(subject, body):
    sent_messages = 0
    if getattr(settings, "ADMINS", ()):
        mail_admins(subject, body)
        sent_messages += 1
    if getattr(settings, "MANAGERS", ()):
        mail_managers(subject, body)
        sent_messages += 1
    if sent_messages:
        return True
    recipients = list(
        get_user_model()
        .objects.filter(is_superuser=True)
        .exclude(email="")
        .values_list("email", flat=True)
        .distinct()
    )
    if not recipients:
        return False
    send_mass_mail(
        (
            (
                subject,
                body,
                getattr(
                    settings,
                    "DEFAULT_FROM_EMAIL",
                    getattr(settings, "SERVER_EMAIL", None),
                ),
                recipients,
            ),
        )
    )
    return True


def notify_x509_objects_expiring(
    sender, expiring_cas, expiring_certs, notice_days, **kwargs
):
    manual_cas = [ca for ca in expiring_cas if not ca.can_auto_renew_ca]
    auto_cas = [ca for ca in expiring_cas if ca.can_auto_renew_ca]
    manual_certs = [cert for cert in expiring_certs if not cert.can_auto_renew]
    auto_certs = [cert for cert in expiring_certs if cert.can_auto_renew]
    if not any([manual_cas, auto_cas, manual_certs, auto_certs]):
        return False
    subject = _(
        "django-x509 expiration notice: %(ca_count)d CAs "
        "and %(cert_count)d certificates"
    ) % {
        "ca_count": len(expiring_cas),
        "cert_count": len(expiring_certs),
    }
    lines = [
        _("The following x509 objects will expire in %(notice_days)d day(s).")
        % {"notice_days": notice_days}
    ]
    if manual_cas:
        lines.append("")
        lines.append(_("Certificate authorities requiring manual action:"))
        lines.extend(
            _render_instance(
                ca,
                _("enable '%(choice)s' if you want automatic renewal")
                % {
                    "choice": AutoRenewChoices.CA_AND_CERTIFICATES.label,
                },
            )
            for ca in manual_cas
        )
    if auto_cas:
        lines.append("")
        lines.append(_("Certificate authorities with automatic renewal enabled:"))
        lines.extend(
            _render_instance(ca, _("no manual action is required")) for ca in auto_cas
        )
    if manual_certs:
        lines.append("")
        lines.append(_("Certificates requiring manual action:"))
        lines.extend(
            _render_instance(
                cert,
                _("update automatic renewal on CA %(ca_name)s: %(ca_url)s")
                % {
                    "ca_name": cert.ca.name,
                    "ca_url": _admin_url(cert.ca) or _("unavailable"),
                },
            )
            for cert in manual_certs
        )
    if auto_certs:
        lines.append("")
        lines.append(_("Certificates with automatic renewal enabled:"))
        lines.extend(
            _render_instance(
                cert,
                _("automatic renewal is enabled on CA %(ca_name)s")
                % {"ca_name": cert.ca.name},
            )
            for cert in auto_certs
        )
    return _send_notification_email(
        str(subject), "\n".join(str(line) for line in lines)
    )


def notify_x509_objects_expired(
    sender,
    expired_cas,
    expired_certs,
    renewed_cas,
    renewed_certs,
    failed_cas,
    failed_certs,
    **kwargs,
):
    if not any(
        [
            expired_cas,
            expired_certs,
            renewed_cas,
            renewed_certs,
            failed_cas,
            failed_certs,
        ]
    ):
        return False
    subject = _(
        "django-x509 expiration report: %(ca_count)d CAs "
        "and %(cert_count)d certificates"
    ) % {
        "ca_count": len(expired_cas) + len(renewed_cas) + len(failed_cas),
        "cert_count": len(expired_certs) + len(renewed_certs) + len(failed_certs),
    }
    lines = [_("The daily x509 expiration check detected the following events.")]
    if renewed_cas:
        lines.append("")
        lines.append(_("Renewed certificate authorities:"))
        lines.extend(
            _render_instance(
                ca,
                _("automatic renewal completed successfully"),
            )
            for ca in renewed_cas
        )
    if renewed_certs:
        lines.append("")
        lines.append(_("Renewed certificates:"))
        lines.extend(
            _render_instance(
                cert,
                _("automatic renewal completed successfully"),
            )
            for cert in renewed_certs
        )
    if expired_cas:
        lines.append("")
        lines.append(_("Expired certificate authorities requiring manual action:"))
        lines.extend(
            _render_instance(
                ca,
                _("enable '%(choice)s' if you want automatic renewal")
                % {"choice": AutoRenewChoices.CA_AND_CERTIFICATES.label},
            )
            for ca in expired_cas
        )
    if expired_certs:
        lines.append("")
        lines.append(_("Expired certificates requiring manual action:"))
        lines.extend(
            _render_instance(
                cert,
                _("update automatic renewal on CA %(ca_name)s: %(ca_url)s")
                % {
                    "ca_name": cert.ca.name,
                    "ca_url": _admin_url(cert.ca) or _("unavailable"),
                },
            )
            for cert in expired_certs
        )
    if failed_cas:
        lines.append("")
        lines.append(_("Certificate authorities whose automatic renewal failed:"))
        lines.extend(_render_failed_instance(entry) for entry in failed_cas)
    if failed_certs:
        lines.append("")
        lines.append(_("Certificates whose automatic renewal failed:"))
        lines.extend(_render_failed_instance(entry) for entry in failed_certs)
    return _send_notification_email(
        str(subject), "\n".join(str(line) for line in lines)
    )
