# Generated by Django 4.2.1 on 2023-06-14 15:59

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0002_rename_uservisitor_customuser_shopyme'),
    ]

    operations = [
        migrations.CreateModel(
            name='Tag',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tag', models.CharField(max_length=100)),
                ('host', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.host')),
            ],
        ),
    ]
