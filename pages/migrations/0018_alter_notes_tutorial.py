# Generated by Django 3.2.12 on 2022-03-03 08:47

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('pages', '0017_auto_20220228_1228'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notes',
            name='tutorial',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notes', to='pages.tutorial'),
        ),
    ]
