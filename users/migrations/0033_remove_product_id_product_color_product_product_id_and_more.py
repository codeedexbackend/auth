# Generated by Django 5.0.1 on 2024-02-14 11:13

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0032_user_otp_secret_key'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='product',
            name='id',
        ),
        migrations.AddField(
            model_name='product',
            name='Color',
            field=models.CharField(choices=[('red', 'Red'), ('blue', 'Blue'), ('green', 'Green'), ('yellow', 'Yellow')], default='red', max_length=20),
        ),
        migrations.AddField(
            model_name='product',
            name='product_id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='product',
            name='Product_Category',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='users.category'),
        ),
        migrations.AlterField(
            model_name='product',
            name='Size',
            field=models.CharField(choices=[('small', 'Small'), ('medium', 'Medium'), ('large', 'Large'), ('xl', 'XL')], max_length=10),
        ),
    ]
