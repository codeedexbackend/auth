# Generated by Django 3.2.10 on 2024-02-08 09:24

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0026_rename_userdetail_user_details'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='user_details',
            new_name='UserDetails',
        ),
    ]
