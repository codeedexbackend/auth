# Generated by Django 3.2.10 on 2024-02-02 10:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0004_auto_20240202_1523'),
    ]

    operations = [
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Product_Name', models.CharField(max_length=100)),
                ('Description', models.CharField(max_length=100)),
                ('Product_Image', models.ImageField(upload_to='profile')),
                ('Product_Category', models.CharField(max_length=100)),
                ('Price', models.IntegerField(max_length=100)),
                ('Size', models.CharField(default='size', max_length=100)),
            ],
        ),
    ]
