# Generated by Django 3.2 on 2021-04-28 08:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0006_auto_20210426_1237'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='client',
            name='logopath',
        ),
        migrations.AddField(
            model_name='client',
            name='logoname',
            field=models.CharField(blank=True, max_length=100),
        ),
    ]
