"""Asosiy URL marshrutlari."""
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("scanner.urls")),
    path("bot/", include("bot.urls")),
]
