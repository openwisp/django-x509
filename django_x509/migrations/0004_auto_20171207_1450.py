# -*- coding: utf-8 -*-
# Generated by Django 1.11.8 on 2017-12-07 13:50
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("django_x509", "0003_rename_organization_field")]

    operations = [
        migrations.AlterField(
            model_name="ca",
            name="serial_number",
            field=models.CharField(
                blank=True,
                help_text="leave blank to determine automatically",
                max_length=39,
                null=True,
                verbose_name="serial number",
            ),
        ),
        migrations.AlterField(
            model_name="cert",
            name="serial_number",
            field=models.CharField(
                blank=True,
                help_text="leave blank to determine automatically",
                max_length=39,
                null=True,
                verbose_name="serial number",
            ),
        ),
    ]
