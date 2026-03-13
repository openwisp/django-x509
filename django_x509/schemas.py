import copy

import jsonschema
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def _build_extension_schema(name, title, description, value_schema):
    return {
        "title": title,
        "description": description,
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "name": {"const": name},
            "critical": {"type": "boolean", "default": False},
            "value": value_schema,
        },
        "required": ["name", "critical", "value"],
    }


def _build_multi_value_schema(title, description, choices):
    return {
        "title": title,
        "description": description,
        "type": "array",
        "items": {"type": "string", "enum": choices},
        "minItems": 1,
        "uniqueItems": True,
    }


DEFAULT_CA_EXTENSIONS_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "CA extensions",
    "type": "array",
    "default": [],
    "items": {
        "oneOf": [
            _build_extension_schema(
                "nsComment",
                "Netscape comment",
                "Store a short human readable comment in the certificate.",
                {
                    "type": "string",
                    "title": "Comment",
                    "minLength": 1,
                    "maxLength": 255,
                },
            ),
            _build_extension_schema(
                "nsCertType",
                "Netscape certificate type",
                "Mark the certificate with CA-oriented Netscape certificate type bits.",
                _build_multi_value_schema(
                    "Certificate types",
                    "Select one or more certificate type flags.",
                    ["sslca", "emailca", "objca"],
                ),
            ),
        ]
    },
}

DEFAULT_CERT_EXTENSIONS_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Certificate extensions",
    "type": "array",
    "default": [],
    "items": {
        "oneOf": [
            _build_extension_schema(
                "nsComment",
                "Netscape comment",
                "Store a short human readable comment in the certificate.",
                {
                    "type": "string",
                    "title": "Comment",
                    "minLength": 1,
                    "maxLength": 255,
                },
            ),
            _build_extension_schema(
                "nsCertType",
                "Netscape certificate type",
                "Mark the certificate with end-entity Netscape certificate type bits.",
                _build_multi_value_schema(
                    "Certificate types",
                    "Select one or more certificate type flags.",
                    ["client", "server", "email", "objsign"],
                ),
            ),
            _build_extension_schema(
                "extendedKeyUsage",
                "Extended key usage",
                "Select one or more extended key usage values.",
                _build_multi_value_schema(
                    "Extended key usages",
                    "Select one or more extended key usage values.",
                    ["clientAuth", "serverAuth", "codeSigning", "emailProtection"],
                ),
            ),
        ]
    },
}


def get_schema_item_options(schema):
    options = {}
    for branch in schema.get("items", {}).get("oneOf", []):
        properties = branch.get("properties", {})
        name = properties.get("name", {}).get("const")
        if name:
            options[name] = branch
    return options


def _validate_schema(setting_name, schema):
    try:
        validator_cls = jsonschema.validators.validator_for(schema)
        validator_cls.check_schema(schema)
    except jsonschema.exceptions.SchemaError as error:
        raise ImproperlyConfigured(
            f"{setting_name} contains an invalid JSON schema: {error.message}"
        ) from error


def _get_extensions_schema(setting_name, default_schema):
    schema = copy.deepcopy(getattr(settings, setting_name, default_schema))
    _validate_schema(setting_name, schema)
    return schema


def get_ca_extensions_schema():
    return _get_extensions_schema(
        "DJANGO_X509_CA_EXTENSIONS_SCHEMA", DEFAULT_CA_EXTENSIONS_SCHEMA
    )


def get_cert_extensions_schema():
    return _get_extensions_schema(
        "DJANGO_X509_CERT_EXTENSIONS_SCHEMA", DEFAULT_CERT_EXTENSIONS_SCHEMA
    )
