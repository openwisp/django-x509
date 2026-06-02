import json

from django import forms
from django.contrib.admin.widgets import AdminTextareaWidget
from django.template.loader import get_template


class ExtensionsWidget(AdminTextareaWidget):
    def __init__(self, schema, attrs=None):
        self.schema = schema
        attrs = attrs or {}
        css_classes = attrs.get("class", "").split()
        for css_class in ("vLargeTextField", "x509-extensions-raw-input"):
            if css_class not in css_classes:
                css_classes.append(css_class)
        attrs["class"] = " ".join(filter(None, css_classes))
        super().__init__(attrs)

    @property
    def media(self):
        return forms.Media(
            js=["django-x509/js/extensions-widget.js"],
            css={"all": ["django-x509/css/extensions-widget.css"]},
        )

    def render(self, name, value, attrs=None, renderer=None):
        template = get_template("django_x509/widgets/extensions.html")
        context = {
            "schema": json.dumps(self.schema),
            "textarea": super().render(name, value, attrs, renderer),
        }
        return template.render(context)
