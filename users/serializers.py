from requests import Response
from rest_framework import serializers, status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.views import APIView

from .models import User, Category, Product, UserProfile, carousel, UserDetails

# from django.contrib.auth.forms import PasswordChangeForm,PasswordResetConfirmForm
from twilio.rest import Client



class UserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)
    mobile = serializers.CharField(write_only=True, required=True)
    otp = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'password', 'password2', 'mobile', 'otp']
        extra_kwargs = {
            'password': {'write_only': True},
            'password2': {'write_only': True},
        }

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise serializers.ValidationError({"Error": "Passwords do not match"})

        return data

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        password2 = validated_data.pop('password2', None)
        otp = validated_data.pop('otp', None)
        instance = self.Meta.model(**validated_data)

        if password is not None:
            instance.set_password(password)



        instance.save()
        return instance

class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(write_only=True)

    def validate(self, data):
        otp_entered = data.get('otp')

        if not otp_entered:
            raise serializers.ValidationError('OTP is required for verification.')

        email = self.context.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")


        stored_otp = user.profile.otp

        if not stored_otp:
            raise serializers.ValidationError("Stored OTP is missing. Please complete the registration process.")

        if otp_entered != stored_otp:
            raise serializers.ValidationError("Invalid OTP.")

        return data
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['Category_Name']

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['product_id','Product_Name', 'Description', 'Product_Image', 'Product_Category', 'Price', 'Size','Color']



class ProductByCategorySerializer(serializers.ModelSerializer):
    Product_Category = serializers.StringRelatedField()

    class Meta:
        model = Product
        fields = ['Product_Name', 'Description', 'Product_Image', 'Product_Category', 'Price', 'Size', 'Color']




class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class ResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class carouselserializer(serializers.ModelSerializer):
    class Meta:
        model = carousel
        fields = ['carousel_image']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDetails

        fields = ['profile_picture', 'name', 'email', 'phone_number', 'address', 'city','pincode']


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']


class PasswordOTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(min_length=6, write_only=True)

    def validate(self, attrs):
        try:
            otp = attrs.get('otp')

            # Check if the provided OTP matches the one sent to the user
            if self.context['request'].user.profile.otp != otp:
                raise AuthenticationFailed('Invalid OTP', 401)

            # OTP is valid, you might want to perform additional actions here if needed

            return {'message': 'OTP verified successfully'}
        except Exception as e:
            raise AuthenticationFailed('Invalid request', 401)