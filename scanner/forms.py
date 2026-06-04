"""Foydalanuvchi ro'yxatdan o'tish va kirish formalari.

Email (Gmail) asosiy identifikator sifatida ishlatiladi: foydalanuvchi
email kiritadi, u Django User modelida `username` sifatida ham saqlanadi.
"""
from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.validators import validate_email


class RegisterForm(forms.Form):
    """Email + parol orqali ro'yxatdan o'tish."""

    email = forms.EmailField(
        label="Email (Gmail)",
        widget=forms.EmailInput(
            attrs={"placeholder": "siz@gmail.com", "autocomplete": "email"}
        ),
    )
    password1 = forms.CharField(
        label="Parol",
        min_length=6,
        widget=forms.PasswordInput(
            attrs={"placeholder": "Kamida 6 ta belgi", "autocomplete": "new-password"}
        ),
    )
    password2 = forms.CharField(
        label="Parolni tasdiqlang",
        widget=forms.PasswordInput(
            attrs={"placeholder": "Parolni qayta kiriting", "autocomplete": "new-password"}
        ),
    )

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        validate_email(email)
        if User.objects.filter(username__iexact=email).exists() or User.objects.filter(
            email__iexact=email
        ).exists():
            raise forms.ValidationError("Bu email allaqachon ro'yxatdan o'tgan.")
        return email

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1")
        p2 = cleaned.get("password2")
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Parollar mos kelmadi.")
        return cleaned

    def save(self) -> User:
        email = self.cleaned_data["email"]
        password = self.cleaned_data["password1"]
        # username = email — foydalanuvchi email bilan kiradi
        user = User.objects.create_user(username=email, email=email, password=password)
        return user


class LoginForm(forms.Form):
    """Email + parol orqali kirish."""

    email = forms.EmailField(
        label="Email (Gmail)",
        widget=forms.EmailInput(
            attrs={"placeholder": "siz@gmail.com", "autocomplete": "email"}
        ),
    )
    password = forms.CharField(
        label="Parol",
        widget=forms.PasswordInput(
            attrs={"placeholder": "Parolingiz", "autocomplete": "current-password"}
        ),
    )

    def __init__(self, *args, request=None, **kwargs):
        self.request = request
        self.user = None
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned = super().clean()
        email = (cleaned.get("email") or "").strip().lower()
        password = cleaned.get("password")
        if email and password:
            # username = email asosida autentifikatsiya
            user = authenticate(self.request, username=email, password=password)
            if user is None:
                raise forms.ValidationError("Email yoki parol noto'g'ri.")
            if not user.is_active:
                raise forms.ValidationError("Hisob faol emas.")
            self.user = user
        return cleaned
