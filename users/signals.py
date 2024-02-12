# users/signals.py

from django.core.mail import EmailMultiAlternatives
from django.dispatch import receiver
from django.template.loader import render_to_string
from django.urls import reverse
from django.http import HttpResponseBadRequest

from django_rest_passwordreset.signals import reset_password_token_created
from django.contrib.auth import get_user_model

class PasswordResetSignalHandler:
    @classmethod
    def send_reset_email(cls, reset_password_token):
        try:
            if hasattr(reset_password_token, 'user'):
                # This is a ResetPasswordToken object
                user = reset_password_token.user
            elif hasattr(reset_password_token, 'user_id'):
                # This is a ResetPasswordRequestToken object
                user = get_user_model().objects.get(pk=reset_password_token.user_id)
            else:
                raise ValueError("Invalid token type")

            context = {
                'current_user': user,
                'username': user.username,
                'email': user.email,
                'reset_password_url': "{}?token={}".format(
                    reset_password_token.request.build_absolute_uri(reverse('password_reset:reset-password-confirm')),
                    reset_password_token.key)
            }

            # render email text
            email_html_message = render_to_string('email/password_reset_email.html', context)
            email_plaintext_message = render_to_string('email/password_reset_email.txt', context)

            msg = EmailMultiAlternatives(
                "Password Reset for {title}".format(title="Your Website Title"),
                email_plaintext_message,
                "noreply@yourdomain.com",
                [user.email]
            )
            msg.attach_alternative(email_html_message, "text/html")
            msg.send()

        except ValueError as e:
            # Log the error or handle it as needed
            pass


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    PasswordResetSignalHandler.send_reset_email(instance)

    context = {
        'current_user': reset_password_token.user,
        'username': reset_password_token.user.username,
        'email': reset_password_token.user.email,
        'reset_password_url': "{}?token={}".format(
            instance.request.build_absolute_uri(reverse('password_reset:reset-password-confirm')),
            reset_password_token.key)
    }
