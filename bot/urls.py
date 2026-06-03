"""Bot URL marshrutlari."""
from django.urls import path

from .views import WebhookView

app_name = "bot"

urlpatterns = [
    path("webhook/", WebhookView.as_view(), name="webhook"),
]
