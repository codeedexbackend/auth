# Generated by Django 3.2.10 on 2024-02-08 08:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0020_alter_user_mobile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user_details',
            name='address',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='user_details',
            name='phone_number',
            field=models.CharField(max_length=15),
        ),
        migrations.AlterField(
            model_name='user_details',
            name='profile_picture',
            field=models.ImageField(blank=True, null=True, upload_to='profile_pics/'),
        ),
    ]
