# Generated by Django 4.2.7 on 2023-11-13 10:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pages', '0023_user_iv_user_key'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='tag',
            field=models.CharField(default=0, max_length=30),
            preserve_default=False,
        ),
    ]