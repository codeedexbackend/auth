from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission,BaseUserManager,AbstractBaseUser,PermissionsMixin
from django.utils.translation import gettext_lazy as _


# Create your models here.
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class PasswordResetUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    otp_secret_key = models.CharField(max_length=32, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    groups = models.ManyToManyField(Group, related_name='passwordresetuser_set', blank=True, verbose_name=_('groups'))
    user_permissions = models.ManyToManyField(Permission, related_name='passwordresetuser_set', blank=True, verbose_name=_('user permissions'))

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=200)
    password2 = models.CharField(max_length=200, default='********')
    mobile = models.IntegerField(null=True, unique=True, default=None)
    otp = models.CharField(max_length=32, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    username = models.CharField(max_length=200, unique=True, null=True)
    groups = models.ManyToManyField(Group, related_name='user_set', blank=True, verbose_name=_('groups'))
    user_permissions = models.ManyToManyField(Permission, related_name='user_set', blank=True, verbose_name=_('user permissions'))
    otp_secret_key = models.CharField(max_length=32, blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []



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




