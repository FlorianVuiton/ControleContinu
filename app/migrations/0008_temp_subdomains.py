# Generated by Django 3.2 on 2021-06-28 09:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0007_auto_20210428_1011'),
    ]

    operations = [
        migrations.CreateModel(
            name='temp_subdomains',
            fields=[
                ('id_temp_subdomains', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('ip', models.CharField(max_length=100)),
            ],
        ),
    ]
