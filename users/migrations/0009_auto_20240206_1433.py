# Generated by Django 3.2.10 on 2024-02-06 09:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_rename_otp_secret_key_user_otp'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='username',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='product',
            name='Price',
            field=models.IntegerField(null=True),
        ),
    ]
