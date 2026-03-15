from datetime import datetime, time, timedelta

from celery import shared_task
from django.db.models import Q
from django.utils import timezone
from swapper import load_model

from . import settings as app_settings
from .signals import x509_objects_expired, x509_objects_expiring


def _get_day_window(days_from_today):
    target_day = timezone.localdate() + timedelta(days=days_from_today)
    start = timezone.make_aware(
        datetime.combine(target_day, time.min),
        timezone.get_current_timezone(),
    )
    return start, start + timedelta(days=1)


def _get_signal_success(signal, **kwargs):
    responses = signal.send_robust(sender=check_x509_expiration, **kwargs)
    success = False
    for _receiver, response in responses:
        if isinstance(response, Exception):
            return False
        success = success or bool(response)
    return success


def _mark_expired_objects_notified(instances):
    if not instances:
        return
    model = instances[0].__class__
    model.objects.filter(pk__in=[instance.pk for instance in instances]).update(
        expire_notified=True
    )


@shared_task
def check_x509_expiration():
    Ca = load_model("django_x509", "Ca")
    Cert = load_model("django_x509", "Cert")
    now = timezone.now()
    expiring_cas = []
    expiring_certs = []
    if app_settings.EXPIRATION_NOTICE_DAYS >= 0:
        start, end = _get_day_window(app_settings.EXPIRATION_NOTICE_DAYS)
        expiring_cas = list(
            Ca.objects.filter(
                validity_end__gt=now, validity_end__gte=start, validity_end__lt=end
            ).order_by("validity_end", "pk")
        )
        expiring_certs = list(
            Cert.objects.select_related("ca")
            .filter(
                revoked=False,
                validity_end__gt=now,
                validity_end__gte=start,
                validity_end__lt=end,
            )
            .order_by("validity_end", "pk")
        )
        if expiring_cas or expiring_certs:
            _get_signal_success(
                x509_objects_expiring,
                expiring_cas=expiring_cas,
                expiring_certs=expiring_certs,
                notice_days=app_settings.EXPIRATION_NOTICE_DAYS,
            )
    expired_cas = list(
        Ca.objects.filter(validity_end__lte=now)
        .filter(Q(expire_notified__isnull=True) | Q(expire_notified=False))
        .order_by("validity_end", "pk")
    )
    expired_certs = list(
        Cert.objects.select_related("ca")
        .filter(revoked=False, validity_end__lte=now)
        .filter(Q(expire_notified__isnull=True) | Q(expire_notified=False))
        .order_by("validity_end", "pk")
    )
    expired_ca_ids = {ca.pk for ca in expired_cas}
    renewed_cas = []
    renewed_certs = []
    failed_cas = []
    failed_certs = []
    manual_expired_cas = []
    manual_expired_certs = []
    for ca in expired_cas:
        if ca.can_auto_renew_ca:
            try:
                ca.renew()
                renewed_cas.append(ca)
            except Exception as exc:
                failed_cas.append({"instance": ca, "error": str(exc)})
        else:
            manual_expired_cas.append(ca)
    renewed_ca_ids = {ca.pk for ca in renewed_cas}
    for cert in expired_certs:
        if cert.ca_id in renewed_ca_ids:
            continue
        if cert.can_auto_renew and cert.ca_id not in expired_ca_ids:
            try:
                cert.renew()
                renewed_certs.append(cert)
            except Exception as exc:
                failed_certs.append({"instance": cert, "error": str(exc)})
        else:
            manual_expired_certs.append(cert)
    if not any(
        [
            manual_expired_cas,
            manual_expired_certs,
            renewed_cas,
            renewed_certs,
            failed_cas,
            failed_certs,
        ]
    ):
        return {
            "expiring_cas": len(expiring_cas),
            "expiring_certs": len(expiring_certs),
        }
    notified = _get_signal_success(
        x509_objects_expired,
        expired_cas=manual_expired_cas,
        expired_certs=manual_expired_certs,
        renewed_cas=renewed_cas,
        renewed_certs=renewed_certs,
        failed_cas=failed_cas,
        failed_certs=failed_certs,
    )
    if notified:
        _mark_expired_objects_notified(manual_expired_cas)
        _mark_expired_objects_notified(manual_expired_certs)
        _mark_expired_objects_notified([entry["instance"] for entry in failed_cas])
        _mark_expired_objects_notified([entry["instance"] for entry in failed_certs])
    return {
        "expiring_cas": len(expiring_cas),
        "expiring_certs": len(expiring_certs),
        "expired_cas": len(manual_expired_cas),
        "expired_certs": len(manual_expired_certs),
        "renewed_cas": len(renewed_cas),
        "renewed_certs": len(renewed_certs),
        "failed_cas": len(failed_cas),
        "failed_certs": len(failed_certs),
        "notified": notified,
    }
