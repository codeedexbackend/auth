# Generated by Django 3.2.10 on 2024-02-08 07:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0013_alter_user_mobile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='mobile',
            field=models.IntegerField(null=True, unique=True),
        ),
    ]
