# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-12-19 00:41
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('auth_api', '0005_auto_20171219_0020'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='InvitationLink',
            new_name='Membership',
        ),
    ]
