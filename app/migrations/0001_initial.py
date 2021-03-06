# Generated by Django 3.2 on 2021-04-21 12:24

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Asset',
            fields=[
                ('id_asset', models.AutoField(primary_key=True, serialize=False)),
                ('name_asset', models.CharField(max_length=100)),
                ('data_type', models.CharField(choices=[('ip', 'publicIP'), ('dom', 'domain'), ('subdom', 'subdomain')], max_length=6)),
                ('list_status', models.CharField(choices=[('none', 'none'), ('base', 'base_list'), ('ban', 'ban_list'), ('delta', 'delta_list')], max_length=5)),
                ('data_output', models.BooleanField()),
            ],
        ),
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id_client', models.AutoField(primary_key=True, serialize=False)),
                ('name_client', models.CharField(max_length=100)),
                ('description', models.CharField(blank=True, max_length=500)),
                ('logopath', models.URLField(blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id_scan', models.AutoField(primary_key=True, serialize=False)),
                ('date', models.DateField(auto_now_add=True)),
                ('id_client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.client')),
            ],
        ),
        migrations.CreateModel(
            name='Port',
            fields=[
                ('id_port', models.AutoField(primary_key=True, serialize=False)),
                ('num', models.IntegerField()),
                ('protocol', models.CharField(max_length=100)),
                ('id_asset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.asset')),
            ],
        ),
        migrations.CreateModel(
            name='Log',
            fields=[
                ('id_log', models.AutoField(primary_key=True, serialize=False)),
                ('list_from', models.CharField(choices=[('none', 'none'), ('base', 'base_list'), ('ban', 'ban_list'), ('delta', 'delta_list')], max_length=5)),
                ('list_to', models.CharField(choices=[('none', 'none'), ('base', 'base_list'), ('ban', 'ban_list'), ('delta', 'delta_list')], max_length=5)),
                ('date', models.DateField(auto_now=True)),
                ('id_asset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.asset')),
            ],
        ),
        migrations.AddField(
            model_name='asset',
            name='id_scan',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.scan'),
        ),
    ]
