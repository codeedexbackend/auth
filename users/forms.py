

# forms.py
from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import authenticate

class CustomPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(
        label='Old Password',
        widget=forms.PasswordInput(attrs={'autofocus': True}),
    )

    def clean_old_password(self):
        old_password = self.cleaned_data.get('old_password')
        user = self.user
        if not authenticate(username=user.username, password=old_password):
            raise forms.ValidationError('Invalid old password.')
        return old_password