import os

import boto3
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import default_token_generator
from django.db import IntegrityError
from django.shortcuts import render, redirect,get_object_or_404
from django.utils.crypto import get_random_string
from django.utils.decorators import method_decorator
from django.utils.encoding import force_text, force_bytes, DjangoUnicodeDecodeError, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.csrf import csrf_exempt
from django_rest_passwordreset.views import ResetPasswordRequestToken
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.mail import send_mail
from rest_framework import status, generics
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer, CategorySerializer, ProductSerializer, OTPVerificationSerializer,carouselserializer, UserProfileSerializer, ResetPasswordEmailRequestSerializer,PasswordOTPVerificationSerializer
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


class ProductView(APIView):
    def get(self,request):
        product = Product.objects.all()
        serializer = ProductSerializer(product,many=True)
        return Response(serializer.data)


    def post(self,request):
        serilaizer = ProductSerializer(data=request.data)
        serilaizer.is_valid(raise_exception=True)
        serilaizer.save()
        return Response(serilaizer.data)


# class ChangePasswordView(APIView):
#     permission_classes = [IsAuthenticated]
#
#     def post(self, request):
#         serializer = ChangePasswordSerializer(data=request.data)
#         if serializer.is_valid():
#             user = request.user
#             if user.check_password(serializer.data.get('old_password')):
#                 user.set_password(serializer.data.get('new_password'))
#                 user.save()
#                 update_session_auth_hash(request, user)  # To update session after password change
#                 return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
#             return Response({'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#
class CustomResetPasswordRequestToken(View):
    template_name = 'custom_reset_password_request_token.html'
    success_url = reverse_lazy('password_reset_done')

    @method_decorator(csrf_exempt)  # Disable CSRF protection for this view
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        # Customize the behavior if needed
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        try:
            token = kwargs.get('token', '')  # Assuming 'token' is still part of the URL
            user = get_user_model().objects.get(id=request.user.id)  # Directly use request.user

            # Custom OTP validation logic
            otp = request.POST.get('otp')  # Adjust this based on how OTP is sent from Flutter
            if self.validate_otp(user, otp):
                return redirect(self.success_url)
            else:
                return CustomRedirect(
                    settings.FRONTEND_URL + '?otp_valid=False&message=Invalid OTP'
                )
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            raise Http404

    def validate_otp(self, user, otp):
        # Implement your OTP validation logic here
        # Return True if OTP is valid, False otherwise
        return True
#
# class PasswordResetConfirm(APIView):
#     # Implement your password reset confirmation logic here
#     pass

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


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data.get('email')

            # Check if user exists with the provided email
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({'error': 'No user found with this email address', 'status': False},
                                status=status.HTTP_400_BAD_REQUEST)

            # Generate OTP
            otp = get_random_string(length=4, allowed_chars='0123456789')

            # Send OTP via email
            subject = 'Password Reset OTP'
            message = f'Your OTP for password reset is: {otp}'
            from_email = 'praveen.codeedex@gmail.com'  # Update with your email
            to_email = [user.email]
            send_mail(subject, message, from_email, to_email)

            # You may also choose to save the OTP in the database or session for verification

            return Response({'success': 'We have sent you an OTP to reset your password', 'status': True},
                            status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomRedirect(HttpResponseRedirect):
    allowed_schemes = ['http', 'https']


# class PasswordTokenCheckAPI(APIView):
#     serializer_class = OTPVerificationSerializer
#
#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#
#         if serializer.is_valid():
#             stored_otp = request.session.get('password-change-otp')
#             stored_data = request.session.get('registration_data')
#
#             # redirect_url = request.data.get('redirect_url')
#             # otp = request.data.get('otp')
#
#             try:
#                 # Check if the user is authenticated
#                 if request.user.is_authenticated:
#                     # Check if the provided OTP matches the one sent to the user
#                     if hasattr(request.user, 'profile') and request.user.profile.otp == otp:
#                         # OTP is valid, redirect to the page to set a new password
#                         if redirect_url and len(redirect_url) > 3:
#                             return CustomRedirect(redirect_url + '?otp_valid=True&message=OTP verified successfully')
#                         else:
#                             return CustomRedirect(
#                                 os.environ.get('FRONTEND_URL', '') + '?otp_valid=False&message=Invalid OTP')
#                     else:
#                         # Handling invalid OTP
#                         if redirect_url and len(redirect_url) > 3:
#                             return CustomRedirect(redirect_url + '?otp_valid=False&message=Invalid OTP')
#                         else:
#                             return CustomRedirect(
#                                 os.environ.get('FRONTEND_URL', '') + '?otp_valid=False&message=Invalid OTP')
#                 else:
#                     # Handle the case where the user is anonymous
#                     # You might want to redirect them to a login page or handle it differently
#                     return CustomRedirect(os.environ.get('FRONTEND_URL', '') + '?otp_valid=False&message=Invalid OTP')
#
#             except DjangoUnicodeDecodeError as identifier:
#                 return Response({'error': 'Invalid user ID'}, status=status.HTTP_400_BAD_REQUEST)
#         else:
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)






class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = OTPVerificationSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


