# Generated by Django 4.2.7 on 2023-11-13 04:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pages', '0020_user_email_hash'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='email_hash',
        ),
        migrations.AddField(
            model_name='user',
            name='encrypted_email',
            field=models.TextField(blank=True, null=True),
        ),
    ]
