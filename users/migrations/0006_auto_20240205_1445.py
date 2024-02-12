# Generated by Django 3.2.10 on 2024-02-05 09:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0005_product'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='mobile',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='password2',
            field=models.CharField(default='********', max_length=200),
        ),
    ]
