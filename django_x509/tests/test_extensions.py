from copy import deepcopy

from cryptography import x509
from django.core.exceptions import ValidationError
from django.test import TestCase

from django_x509.schemas import (
    DEFAULT_CA_EXTENSIONS_SCHEMA,
    DEFAULT_CERT_EXTENSIONS_SCHEMA,
)

from . import TestX509Mixin


class ExtensionsSchemaTests(TestX509Mixin, TestCase):
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
