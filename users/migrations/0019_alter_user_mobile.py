# Generated by Django 3.2.10 on 2024-02-08 07:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0018_user_details'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='mobile',
            field=models.CharField(max_length=12, null=True, unique=True),
        ),
    ]
