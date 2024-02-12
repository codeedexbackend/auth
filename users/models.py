from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class User(AbstractUser):
    DoesNotExist = None
    name = models.CharField(max_length=200)
    email = models.CharField(max_length=200,unique=True)
    password = models.CharField(max_length=200)
    password2 = models.CharField(max_length=200, default='********')
    mobile = models.IntegerField(null=True, unique=True, default=None)
    otp = models.CharField(max_length=32, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    username = models.CharField(max_length=200,null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']



class Category(models.Model):
    Category_Name = models.CharField(max_length=100)

class Product(models.Model):
    Product_Name = models.CharField(max_length=100)
    Description = models.CharField(max_length=100)
    Product_Image = models.ImageField(upload_to="profile")
    Product_Category = models.CharField(max_length=100)
    Price = models.IntegerField(null=True)
    Size = models.CharField(max_length=100,default='size')


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, blank=True, null=True)

class carousel(models.Model):
    carousel_image = models.ImageField(upload_to="profile")




class UserDetails(models.Model):
    objects = None
    profile_picture = models.ImageField(upload_to='profile_pics', blank=True, null=True)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)
    address = models.TextField()
    city = models.CharField(max_length=255)
    pincode = models.CharField(max_length=10)




