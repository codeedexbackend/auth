import os

import boto3
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import default_token_generator
from django.db import IntegrityError
from django.shortcuts import render, redirect,get_object_or_404
from django.utils.crypto import get_random_string
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, DjangoUnicodeDecodeError, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.csrf import csrf_exempt
# from django_rest_passwordreset.views import ResetPasswordRequestToken
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from django.utils.encoding import force_bytes, DjangoUnicodeDecodeError, force_str
# from django_otp.plugins.otp_totp.models import TOTPDevice

from rest_framework.response import Response
from django.core.mail import send_mail
from rest_framework import status, generics,permissions
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer, CategorySerializer, ProductSerializer, OTPVerificationSerializer,carouselserializer, UserProfileSerializer, PasswordResetSerializer,PassOTPVerificationSerializer,ChangePasswordSerializer,ProductByCategorySerializer,CartItemSerializer
from .models import User, Category, Product, carousel, UserDetails


from django.conf import settings
from django.contrib.auth.views import PasswordChangeView
from django.contrib.auth import update_session_auth_hash, get_user_model
# from .serializers import PasswordUpdateSerializer
from django.urls import reverse, reverse_lazy
import random
import jwt
import datetime
from django.views import View
from django.http import Http404, HttpResponseRedirect

from .utils import generate_otp, send_otp_email
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from .filters import ProductFilter
from .permissions import IsOwnerOrReadOnly


# Create your views here.

def generate_otp():
    return str(random.randint(1000, 9999))


class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = generate_otp()
            send_otp_email(email, otp)


            request.session['registration_otp'] = otp
            request.session['registration_data'] = serializer.validated_data

            return Response({"message": "OTP sent successfully.", "status": True}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_otp_email(self, to_email, otp):
        pass

class OTPVerificationView(APIView):
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)

        if serializer.is_valid():
            stored_otp = request.session.get('registration_otp')
            stored_data = request.session.get('registration_data')


            if serializer.validated_data['otp'] == stored_otp:
                user_model = get_user_model()
                username = stored_data.get('email', None)
                user = user_model.objects.create_user(username=username, **stored_data)



                user.save()


                del request.session['registration_otp']
                del request.session['registration_data']

                return Response({"message": "Registration successful.", "status": True}, status=status.HTTP_200_OK)

            return Response({"message": "Invalid OTP.", "status": False}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class EmailVerificationView(View):
    def get(self, request, token):
        try:

            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = decoded_token['user_id']

            user = User.objects.get(id=user_id)
            user.is_active = True
            user.save()


            return redirect('success-page')

        except jwt.ExpiredSignatureError:
            raise Http404('Verification link has expired.')

        except jwt.DecodeError:
            raise Http404('Invalid verification link.')

class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!', 400)

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!', 400)

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'token': token,
            'message': 'Login successful',
            'status': True
        }
        return response

class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!', 400)

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!', 400)

        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response({
            'message': 'User authenticated',
            'status': True,
            'user_data': serializer.data
        })

class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'Logout successful',
            'status': True
        }
        return response


class CategoryView(APIView):
    def get(self,request):
        categories = Category.objects.all()
        serializer = CategorySerializer(categories,many=True)
        return Response(serializer.data)

    def post(self,request):
        serializer = CategorySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)



class CustomPageNumberPagination(PageNumberPagination):
    page_size = 10  # Number of items per page
    page_size_query_param = 'page_size'
    max_page_size = 1000


class ProductView(APIView):
    pagination_class = CustomPageNumberPagination  # Add this line for pagination

    def get(self, request):
        product = Product.objects.all()
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(product, request)
        serializer = ProductSerializer(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def post(self, request):
        serializer = ProductSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

class ProductByCategoryView(generics.ListAPIView):
    serializer_class = ProductByCategorySerializer
    pagination_class = CustomPageNumberPagination  # Add this line for pagination

    def get_queryset(self):
        category_id = self.kwargs['category_id']
        return Product.objects.filter(Product_Category=category_id)

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(queryset, request)
        serializer = self.serializer_class(result_page, many=True)
        return paginator.get_paginated_response(serializer.data)


class ProductSearchView(generics.ListAPIView):
    serializer_class = ProductSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = ProductFilter

    def get_queryset(self):
        return Product.objects.all()

class carouselview(APIView):
    def post(self,request):
        serilaizer = carouselserializer(data=request.data)
        serilaizer.is_valid(raise_exception=True)
        serilaizer.save()
        return Response(serilaizer.data)

    def get(self,request):
        caro_usel = carousel.objects.all()
        serializer = carouselserializer(caro_usel, many=True)
        return Response(serializer.data)

class user_detail_view(APIView):
    def post(self, request):
        serializer = UserProfileSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User Profile Updated Successfully.','status':True}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



    def get(self,request):
        user_details = UserDetails.objects.all()
        serializer = UserProfileSerializer(user_details,many=True)
        return Response(serializer.data)




User = get_user_model()

class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        email = request.data.get('email', None)
        user = User.objects.filter(email=email).first()

        if user:
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])

            user.otp_secret_key = otp
            user.save()

            email_subject = 'Password Reset OTP'
            email_body = f'Your OTP for password reset is: {otp}'
            to_email = [user.email] 
            send_mail(email_subject, email_body, from_email=None, recipient_list=to_email)


            return Response({'detail': 'OTP sent successfully.','status':True}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'User not found.','status':False}, status=status.HTTP_404_NOT_FOUND)
        
User = get_user_model()

class PassOTPVerificationView(generics.GenericAPIView):
    serializer_class = PassOTPVerificationSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email', None)
        otp = serializer.validated_data.get('otp', None)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': f'User with email {email} not found.', 'status': False}, status=status.HTTP_404_NOT_FOUND)

        if not self.verify_otp(user.otp_secret_key, otp):
            return Response({'detail': 'Invalid OTP.', 'status': False}, status=status.HTTP_400_BAD_REQUEST)

        user.otp_secret_key = None
        user.save()

        return Response({'detail': 'OTP verification successful. Proceed to reset password.', 'status': True}, status=status.HTTP_200_OK)

    def verify_otp(self, secret_key, otp):

        return secret_key == otp



class ChangePasswordView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')
        new_password = serializer.validated_data.get('new_password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': f'User with email {email} not found.', 'status': False}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()

        return Response({'detail': 'Password changed successfully.', 'status': True}, status=status.HTTP_200_OK)

    
class CartItemCreateView(generics.CreateAPIView):
    serializer_class = CartItemSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
 