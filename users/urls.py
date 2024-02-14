from django.urls import path
from .views import RegisterView, LoginView, UserView, LogoutView, CategoryView, ProductView, OTPVerificationView, \
    carouselview, user_detail_view, PassOTPVerificationView,PasswordResetView,ChangePasswordView

# from users import views

urlpatterns = [
    path('register/',RegisterView.as_view()),
    path('login/',LoginView.as_view()),
    path('user/',UserView.as_view()),
    path('logout/',LogoutView.as_view()),
    path('CategoryView/',CategoryView.as_view()),
    path('ProductView/',ProductView.as_view()),
    path('carousel/',carouselview.as_view()),
    path('VerifyOTPView/', OTPVerificationView.as_view()),
    # path('change_password/', ChangePasswordView.as_view(), name='change-password'),
    path('user_details/', user_detail_view.as_view(), name='user_details'),

    # path('request-reset-email/', RequestPasswordResetEmail.as_view(),name="request-reset-email"),
    # path('password-change-otp/', CustomResetPasswordRequestToken.as_view(), name='password-change-otp')
    path('password-reset/', PasswordResetView.as_view(), name='password-reset'),
    path('otp-verification/', PassOTPVerificationView.as_view(), name='otp-verification'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    # path('delivery-zones/', DeliveryZoneListAPIView.as_view(), name='delivery-zone-list'),



]



