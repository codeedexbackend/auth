# Generated by Django 3.2.10 on 2024-02-08 09:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0023_delete_user_details'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user_detail',
            name='profile_picture',
            field=models.ImageField(blank=True, null=True, upload_to='profile_pics'),
        ),
    ]