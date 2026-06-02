from copy import deepcopy

from cryptography import x509
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.test import TestCase
from swapper import load_model

from django_x509 import settings as app_settings
from django_x509.schemas import (
    DEFAULT_CA_EXTENSIONS_SCHEMA,
    DEFAULT_CERT_EXTENSIONS_SCHEMA,
)

from . import TestX509Mixin

Cert = load_model("django_x509", "Cert")


class ExtensionsSchemaTests(TestX509Mixin, TestCase):
    ns_comment_oid = x509.ObjectIdentifier("2.16.840.1.113730.1.13")

    def test_default_ca_schema_rejects_cert_only_extension(self):
        with self.assertRaises(ValidationError) as context:
            self._create_ca(
                extensions=[
                    {
                        "name": "extendedKeyUsage",
                        "critical": True,
                        "value": ["clientAuth"],
                    }
                ]
            )
        self.assertIn("extensions", context.exception.message_dict)

    def test_default_cert_schema_accepts_list_values(self):
        cert = self._create_cert(
            extensions=[
                {"name": "nsCertType", "critical": False, "value": ["client"]},
                {
                    "name": "extendedKeyUsage",
                    "critical": True,
                    "value": ["clientAuth", "serverAuth"],
                },
            ]
        )
        ns_oid = x509.ObjectIdentifier("2.16.840.1.113730.1.1")
        ns_cert_type = cert.x509.extensions.get_extension_for_oid(ns_oid)
        eku = cert.x509.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        self.assertEqual(cert.extensions[0]["value"], ["client"])
        self.assertEqual(cert.extensions[1]["value"], ["clientAuth", "serverAuth"])
        self.assertEqual(ns_cert_type.value.value, b"\x03\x02\x07\x80")
        self.assertIn(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, eku.value)
        self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, eku.value)

    def test_invalid_extension_payloads_raise_field_errors(self):
        with self.assertRaises(ValidationError) as context:
            self._create_cert(
                extensions=[
                    {
                        "name": "extendedKeyUsage",
                        "critical": True,
                        "value": ["notSupported"],
                    }
                ]
            )
        self.assertIn("extensions", context.exception.message_dict)

    def test_duplicate_extensions_raise_field_errors(self):
        with self.assertRaises(ValidationError) as context:
            self._create_cert(
                extensions=[
                    {"name": "nsComment", "critical": False, "value": "first"},
                    {"name": "nsComment", "critical": False, "value": "second"},
                ]
            )
        self.assertIn("extensions", context.exception.message_dict)
        self.assertIn(
            "Duplicate extension is not allowed: nsComment",
            str(context.exception.message_dict["extensions"][0]),
        )

    def test_legacy_string_values_are_normalized(self):
        cert = self._create_cert(
            extensions=[
                {"name": "nsCertType", "critical": False, "value": "client, server"},
                {
                    "name": "extendedKeyUsage",
                    "critical": True,
                    "value": "clientAuth, serverAuth",
                },
            ]
        )
        self.assertEqual(cert.extensions[0]["value"], ["client", "server"])
        self.assertEqual(cert.extensions[1]["value"], ["clientAuth", "serverAuth"])

    def test_missing_critical_defaults_to_false(self):
        cert = self._create_cert(
            extensions=[{"name": "nsComment", "value": "comment without critical"}]
        )
        ns_comment = cert.x509.extensions.get_extension_for_oid(self.ns_comment_oid)
        self.assertFalse(cert.extensions[0].get("critical", False))
        self.assertFalse(ns_comment.critical)

    def test_nscomment_rejects_values_over_255_utf8_bytes(self):
        with self.assertRaises(ValidationError) as context:
            self._create_cert(extensions=[{"name": "nsComment", "value": "é" * 128}])
        self.assertIn("extensions", context.exception.message_dict)
        self.assertIn(
            "nsComment value exceeds maximum length of 255 bytes",
            str(context.exception.message_dict["extensions"][0]),
        )

    def test_nscomment_uses_long_form_der_length_for_128_bytes(self):
        cert = self._create_cert(extensions=[{"name": "nsComment", "value": "a" * 128}])
        ns_comment = cert.x509.extensions.get_extension_for_oid(self.ns_comment_oid)
        self.assertEqual(ns_comment.value.value[:3], b"\x16\x81\x80")
        self.assertEqual(ns_comment.value.value[3:], b"a" * 128)

    def test_ca_schema_setting_override(self):
        schema = deepcopy(DEFAULT_CA_EXTENSIONS_SCHEMA)
        schema["items"]["oneOf"][0]["properties"]["value"]["minLength"] = 20
        with self.settings(DJANGO_X509_CA_EXTENSIONS_SCHEMA=schema):
            with self.assertRaises(ValidationError) as context:
                self._create_ca(
                    extensions=[
                        {
                            "name": "nsComment",
                            "critical": False,
                            "value": "short comment",
                        }
                    ]
                )
            self.assertIn("extensions", context.exception.message_dict)
            ca = self._create_ca(
                extensions=[
                    {
                        "name": "nsComment",
                        "critical": False,
                        "value": "comment long enough for schema",
                    }
                ]
            )
        self.assertEqual(ca.extensions[0]["value"], "comment long enough for schema")

    def test_schema_override_still_rejects_unsupported_extension_names(self):
        schema = deepcopy(DEFAULT_CERT_EXTENSIONS_SCHEMA)
        schema["items"]["oneOf"].append(
            {
                "title": "Custom extension",
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "name": {"const": "customExt"},
                    "critical": {"type": "boolean", "default": False},
                    "value": {"type": "string", "minLength": 1},
                },
                "required": ["name", "critical", "value"],
            }
        )
        with self.settings(DJANGO_X509_CERT_EXTENSIONS_SCHEMA=schema):
            with self.assertRaises(ValidationError) as context:
                self._create_cert(
                    extensions=[
                        {"name": "customExt", "critical": False, "value": "abc"}
                    ]
                )
        self.assertIn("extensions", context.exception.message_dict)
        self.assertIn(
            "Unsupported extension: customExt",
            str(context.exception.message_dict["extensions"][0]),
        )

    def test_schema_override_still_rejects_incompatible_nscomment_shape(self):
        schema = deepcopy(DEFAULT_CERT_EXTENSIONS_SCHEMA)
        schema["items"]["oneOf"][0]["properties"]["value"] = {"type": "integer"}
        with self.settings(DJANGO_X509_CERT_EXTENSIONS_SCHEMA=schema):
            with self.assertRaises(ValidationError) as context:
                self._create_cert(
                    extensions=[{"name": "nsComment", "critical": False, "value": 7}]
                )
        self.assertIn("extensions", context.exception.message_dict)
        self.assertIn(
            "nsComment extension requires a string value.",
            str(context.exception.message_dict["extensions"][0]),
        )

    def test_invalid_schema_override_raises_improperly_configured(self):
        with self.settings(DJANGO_X509_CA_EXTENSIONS_SCHEMA={"type": "madeup"}):
            with self.assertRaises(ImproperlyConfigured):
                app_settings.get_ca_extensions_schema()

    def test_normalize_extensions_none_becomes_empty_list(self):
        cert = Cert()
        cert.extensions = None
        cert._normalize_extensions(DEFAULT_CERT_EXTENSIONS_SCHEMA)
        self.assertEqual(cert.extensions, [])

    def test_normalize_extensions_keeps_non_dict_entries(self):
        cert = Cert()
        cert.extensions = ["invalid-entry"]
        cert._normalize_extensions(DEFAULT_CERT_EXTENSIONS_SCHEMA)
        self.assertEqual(cert.extensions, ["invalid-entry"])

    def test_get_extension_values_returns_empty_list_for_unexpected_types(self):
        self.assertEqual(Cert()._get_extension_values({"unexpected": "mapping"}), [])

    def test_raise_extensions_validation_error_without_path(self):
        with self.assertRaises(ValidationError) as context:
            Cert()._raise_extensions_validation_error("", "bad data")
        self.assertEqual(
            str(context.exception.message_dict["extensions"][0]),
            "Extensions data: bad data",
        )

    def test_validate_supported_extensions_rejects_non_boolean_critical(self):
        cert = Cert()
        cert.extensions = [{"name": "nsComment", "critical": "yes", "value": "ok"}]
        with self.assertRaises(ValidationError) as context:
            cert._validate_supported_extensions()
        self.assertIn("extensions", context.exception.message_dict)
        self.assertIn(
            "Critical flag must be a boolean value.",
            str(context.exception.message_dict["extensions"][0]),
        )

    def test_validate_supported_extensions_rejects_empty_nscomment_value(self):
        cert = Cert()
        cert.extensions = [{"name": "nsComment", "critical": False, "value": ""}]
        with self.assertRaises(ValidationError) as context:
            cert._validate_supported_extensions()
        self.assertIn("extensions", context.exception.message_dict)
        self.assertIn(
            "nsComment extension requires a value.",
            str(context.exception.message_dict["extensions"][0]),
        )

    def test_validate_supported_extensions_rejects_empty_extended_key_usage(self):
        cert = Cert()
        cert.extensions = [{"name": "extendedKeyUsage", "critical": False, "value": []}]
        with self.assertRaises(ValidationError) as context:
            cert._validate_supported_extensions()
        self.assertIn("extensions", context.exception.message_dict)
        self.assertIn(
            "extendedKeyUsage extension requires at least one valid value.",
            str(context.exception.message_dict["extensions"][0]),
        )

    def test_validate_supported_extensions_rejects_empty_ns_cert_type(self):
        cert = Cert()
        cert.extensions = [{"name": "nsCertType", "critical": False, "value": []}]
        with self.assertRaises(ValidationError) as context:
            cert._validate_supported_extensions()
        self.assertIn("extensions", context.exception.message_dict)
        self.assertIn(
            "nsCertType extension requires at least one valid type.",
            str(context.exception.message_dict["extensions"][0]),
        )
