from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from django.utils import timezone

from django_x509.base.models import AutoRenewChoices
from django_x509.handlers import (
    notify_x509_objects_expired,
    notify_x509_objects_expiring,
)
from django_x509.signals import x509_objects_expired, x509_objects_expiring
from django_x509.tasks import check_x509_expiration

from . import TestX509Mixin

User = get_user_model()


@override_settings(DJANGO_X509_EXPIRATION_NOTICE_DAYS=3)
class TestExpirationTasks(TestX509Mixin, TestCase):
    def _set_validity_end(self, instance, delta):
        instance.validity_end = timezone.now() + delta
        instance.save(update_fields=["validity_end"])
        return instance

    def test_check_x509_expiration_uses_superusers_as_fallback(self):
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="openwisp"
        )
        cert = self._set_validity_end(
            self._create_cert(name="expiring-cert"), timedelta(days=3)
        )

        check_x509_expiration()

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("expiring-cert", mail.outbox[0].body)
        self.assertEqual(mail.outbox[0].to, ["admin@example.com"])
        cert.refresh_from_db()
        self.assertIsNone(cert.expire_notified)

    @override_settings(
        ADMINS=[("Admin", "admin@example.com")],
        MANAGERS=[("Manager", "manager@example.com")],
        SERVER_EMAIL="server@example.com",
    )
    def test_check_x509_expiration_prefers_admins_and_managers(self):
        cert = self._set_validity_end(
            self._create_cert(name="expiring-cert"), timedelta(days=3)
        )

        check_x509_expiration()

        self.assertEqual(len(mail.outbox), 2)
        recipients = sorted(message.to[0] for message in mail.outbox)
        self.assertEqual(recipients, ["admin@example.com", "manager@example.com"])
        self.assertTrue(all("expiring-cert" in message.body for message in mail.outbox))
        cert.refresh_from_db()
        self.assertIsNone(cert.expire_notified)

    def test_check_x509_expiration_marks_expired_objects_as_notified(self):
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="openwisp"
        )
        cert = self._create_cert(name="expired-cert")
        cert.expire_notified = None
        cert.save(update_fields=["expire_notified"])
        self._set_validity_end(cert, timedelta(days=-1))

        check_x509_expiration()

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("expired-cert", mail.outbox[0].body)
        cert.refresh_from_db()
        self.assertTrue(cert.expire_notified)
        mail.outbox = []

        check_x509_expiration()

        self.assertEqual(mail.outbox, [])

    def test_check_x509_expiration_marks_expired_cas_as_notified(self):
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="openwisp"
        )
        ca = self._create_ca(name="expired-ca")
        self._set_validity_end(ca, timedelta(days=-1))

        check_x509_expiration()

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("expired-ca", mail.outbox[0].body)
        ca.refresh_from_db()
        self.assertTrue(ca.expire_notified)
        mail.outbox = []

        check_x509_expiration()

        self.assertEqual(mail.outbox, [])

    def test_check_x509_expiration_auto_renews_expired_certificates(self):
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="openwisp"
        )
        cert = self._create_cert(name="expired-cert")
        cert.ca.auto_renew = AutoRenewChoices.CERTIFICATES_ONLY
        cert.ca.save(update_fields=["auto_renew"])
        self._set_validity_end(cert, timedelta(days=-1))
        old_validity_end = cert.validity_end
        old_serial = cert.serial_number

        check_x509_expiration()

        cert.refresh_from_db()
        self.assertGreater(cert.validity_end, old_validity_end)
        self.assertNotEqual(cert.serial_number, old_serial)
        self.assertIsNone(cert.expire_notified)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("expired-cert", mail.outbox[0].body)
        self.assertIn("renewed", mail.outbox[0].body.lower())

    def test_check_x509_expiration_auto_renews_expired_cas(self):
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="openwisp"
        )
        ca = self._create_ca(
            name="expired-ca", auto_renew=AutoRenewChoices.CA_AND_CERTIFICATES
        )
        cert = self._create_cert(name="ca-child-cert", ca=ca)
        self._set_validity_end(ca, timedelta(days=-1))
        self._set_validity_end(cert, timedelta(days=-1))
        old_ca_validity_end = ca.validity_end
        old_cert_validity_end = cert.validity_end

        check_x509_expiration()

        ca.refresh_from_db()
        cert.refresh_from_db()
        self.assertGreater(ca.validity_end, old_ca_validity_end)
        self.assertGreater(cert.validity_end, old_cert_validity_end)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("expired-ca", mail.outbox[0].body)
        self.assertIn("renewed", mail.outbox[0].body.lower())

    def test_check_x509_expiration_auto_renew_ca_skips_revoked_certificates(self):
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="openwisp"
        )
        ca = self._create_ca(
            name="expired-ca", auto_renew=AutoRenewChoices.CA_AND_CERTIFICATES
        )
        active_cert = self._create_cert(name="active-child-cert", ca=ca)
        revoked_cert = self._create_cert(name="revoked-child-cert", ca=ca)
        revoked_cert.revoke()
        self._set_validity_end(ca, timedelta(days=-1))
        old_active_serial = active_cert.serial_number
        old_revoked_serial = str(revoked_cert.serial_number)
        old_revoked_certificate = revoked_cert.certificate

        check_x509_expiration()

        active_cert.refresh_from_db()
        revoked_cert.refresh_from_db()
        self.assertNotEqual(active_cert.serial_number, old_active_serial)
        self.assertEqual(revoked_cert.serial_number, old_revoked_serial)
        self.assertEqual(revoked_cert.certificate, old_revoked_certificate)
        self.assertTrue(revoked_cert.revoked)

    def test_check_x509_expiration_failed_auto_renew_is_attempted_on_next_run(self):
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="openwisp"
        )
        cert = self._create_cert(name="expired-cert")
        cert.ca.auto_renew = AutoRenewChoices.CERTIFICATES_ONLY
        cert.ca.save(update_fields=["auto_renew"])
        self._set_validity_end(cert, timedelta(days=-1))

        with patch.object(cert.__class__, "renew", side_effect=Exception("boom")):
            check_x509_expiration()

        cert.refresh_from_db()
        self.assertIsNone(cert.expire_notified)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("automatic renewal failed", mail.outbox[0].body.lower())
        mail.outbox = []

        check_x509_expiration()

        cert.refresh_from_db()
        self.assertIsNone(cert.expire_notified)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("renewed", mail.outbox[0].body.lower())

    def test_check_x509_expiration_failed_ca_auto_renew_is_attempted_on_next_run(
        self,
    ):
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="openwisp"
        )
        ca = self._create_ca(
            name="expired-ca", auto_renew=AutoRenewChoices.CA_AND_CERTIFICATES
        )
        self._set_validity_end(ca, timedelta(days=-1))

        with patch.object(ca.__class__, "renew", side_effect=Exception("boom")):
            check_x509_expiration()

        ca.refresh_from_db()
        self.assertIsNone(ca.expire_notified)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("automatic renewal failed", mail.outbox[0].body.lower())
        mail.outbox = []

        check_x509_expiration()

        ca.refresh_from_db()
        self.assertIsNone(ca.expire_notified)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("renewed", mail.outbox[0].body.lower())

    def test_check_x509_expiration_ca_auto_renew_rolls_back_partial_failures(self):
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="openwisp"
        )
        ca = self._create_ca(
            name="expired-ca", auto_renew=AutoRenewChoices.CA_AND_CERTIFICATES
        )
        healthy_cert = self._create_cert(name="healthy-child-cert", ca=ca)
        failing_cert = self._create_cert(name="failing-child-cert", ca=ca)
        self._set_validity_end(ca, timedelta(days=-1))
        self._set_validity_end(healthy_cert, timedelta(days=-1))
        self._set_validity_end(failing_cert, timedelta(days=-1))
        old_ca_serial = str(ca.serial_number)
        old_ca_certificate = ca.certificate
        old_healthy_serial = str(healthy_cert.serial_number)
        old_healthy_certificate = healthy_cert.certificate
        old_failing_serial = str(failing_cert.serial_number)
        old_failing_certificate = failing_cert.certificate
        original_renew = healthy_cert.__class__.renew

        def renew_with_failure(instance):
            if instance.name == "failing-child-cert":
                raise Exception("boom")
            return original_renew(instance)

        with patch.object(
            healthy_cert.__class__,
            "renew",
            autospec=True,
            side_effect=renew_with_failure,
        ):
            check_x509_expiration()

        ca.refresh_from_db()
        healthy_cert.refresh_from_db()
        failing_cert.refresh_from_db()
        self.assertEqual(str(ca.serial_number), old_ca_serial)
        self.assertEqual(ca.certificate, old_ca_certificate)
        self.assertEqual(str(healthy_cert.serial_number), old_healthy_serial)
        self.assertEqual(healthy_cert.certificate, old_healthy_certificate)
        self.assertEqual(str(failing_cert.serial_number), old_failing_serial)
        self.assertEqual(failing_cert.certificate, old_failing_certificate)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("automatic renewal failed", mail.outbox[0].body.lower())
        self.assertIn("expired-ca", mail.outbox[0].body)

    def test_check_x509_expiration_does_not_mark_expired_objects_without_recipients(
        self,
    ):
        cert = self._create_cert(name="expired-cert")
        self._set_validity_end(cert, timedelta(days=-1))

        check_x509_expiration()

        self.assertEqual(mail.outbox, [])
        cert.refresh_from_db()
        self.assertIsNone(cert.expire_notified)

    def test_expiring_signal_can_be_overridden(self):
        cert = self._set_validity_end(
            self._create_cert(name="expiring-cert"), timedelta(days=3)
        )
        captured = {}

        def receiver(sender, expiring_cas, expiring_certs, notice_days, **kwargs):
            captured["notice_days"] = notice_days
            captured["ca_ids"] = [ca.pk for ca in expiring_cas]
            captured["cert_ids"] = [item.pk for item in expiring_certs]
            return True

        x509_objects_expiring.disconnect(
            dispatch_uid="django_x509.notify_x509_objects_expiring"
        )
        x509_objects_expiring.connect(receiver, dispatch_uid="test_expiring_receiver")
        try:
            check_x509_expiration()
        finally:
            x509_objects_expiring.disconnect(dispatch_uid="test_expiring_receiver")
            x509_objects_expiring.connect(
                notify_x509_objects_expiring,
                dispatch_uid="django_x509.notify_x509_objects_expiring",
            )

        self.assertEqual(captured["notice_days"], 3)
        self.assertEqual(captured["ca_ids"], [])
        self.assertEqual(captured["cert_ids"], [cert.pk])
        self.assertEqual(mail.outbox, [])

    def test_expired_signal_can_be_overridden(self):
        cert = self._create_cert(name="expired-cert")
        self._set_validity_end(cert, timedelta(days=-1))
        captured = {}

        def receiver(
            sender,
            expired_cas,
            expired_certs,
            renewed_cas,
            renewed_certs,
            failed_cas,
            failed_certs,
            **kwargs,
        ):
            captured["expired_cert_ids"] = [item.pk for item in expired_certs]
            captured["renewed_cert_ids"] = [item.pk for item in renewed_certs]
            captured["failed_cert_ids"] = [item["instance"].pk for item in failed_certs]
            return True

        x509_objects_expired.disconnect(
            dispatch_uid="django_x509.notify_x509_objects_expired"
        )
        x509_objects_expired.connect(receiver, dispatch_uid="test_expired_receiver")
        try:
            check_x509_expiration()
        finally:
            x509_objects_expired.disconnect(dispatch_uid="test_expired_receiver")
            x509_objects_expired.connect(
                notify_x509_objects_expired,
                dispatch_uid="django_x509.notify_x509_objects_expired",
            )

        self.assertEqual(captured["expired_cert_ids"], [cert.pk])
        self.assertEqual(captured["renewed_cert_ids"], [])
        self.assertEqual(captured["failed_cert_ids"], [])
        self.assertEqual(mail.outbox, [])

    def test_expired_signal_exception_does_not_mark_objects_notified(self):
        cert = self._create_cert(name="expired-cert")
        self._set_validity_end(cert, timedelta(days=-1))

        def receiver(sender, **kwargs):
            raise RuntimeError("boom")

        x509_objects_expired.disconnect(
            dispatch_uid="django_x509.notify_x509_objects_expired"
        )
        x509_objects_expired.connect(receiver, dispatch_uid="test_expired_exception")
        try:
            result = check_x509_expiration()
        finally:
            x509_objects_expired.disconnect(dispatch_uid="test_expired_exception")
            x509_objects_expired.connect(
                notify_x509_objects_expired,
                dispatch_uid="django_x509.notify_x509_objects_expired",
            )

        cert.refresh_from_db()
        self.assertFalse(result["notified"])
        self.assertIsNone(cert.expire_notified)
        self.assertEqual(mail.outbox, [])

    def test_notify_x509_objects_expiring_returns_false_without_objects(self):
        self.assertFalse(
            notify_x509_objects_expiring(
                sender=self.__class__,
                expiring_cas=[],
                expiring_certs=[],
                notice_days=3,
            )
        )

    def test_notify_x509_objects_expired_returns_false_without_events(self):
        self.assertFalse(
            notify_x509_objects_expired(
                sender=self.__class__,
                expired_cas=[],
                expired_certs=[],
                renewed_cas=[],
                renewed_certs=[],
                failed_cas=[],
                failed_certs=[],
            )
        )

    def test_notify_x509_objects_expiring_includes_manual_and_auto_ca_sections(self):
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="openwisp"
        )
        manual_ca = self._set_validity_end(
            self._create_ca(name="manual-ca"), timedelta(days=3)
        )
        auto_ca = self._set_validity_end(
            self._create_ca(
                name="auto-ca", auto_renew=AutoRenewChoices.CA_AND_CERTIFICATES
            ),
            timedelta(days=3),
        )
        auto_cert = self._set_validity_end(
            self._create_cert(name="auto-cert", ca=auto_ca), timedelta(days=3)
        )

        with patch("django_x509.handlers.reverse", side_effect=Exception("boom")):
            result = notify_x509_objects_expiring(
                sender=self.__class__,
                expiring_cas=[manual_ca, auto_ca],
                expiring_certs=[auto_cert],
                notice_days=3,
            )

        self.assertTrue(result)
        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        self.assertIn("Certificate authorities requiring manual action:", body)
        self.assertIn("Certificate authorities with automatic renewal enabled:", body)
        self.assertIn("Certificates with automatic renewal enabled:", body)
        self.assertIn("manual-ca", body)
        self.assertIn("auto-ca", body)
        self.assertIn("auto-cert", body)
        self.assertIn("unavailable", body)
