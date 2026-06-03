"""Scanner URL marshrutlari."""
from django.urls import path

from . import views

app_name = "scanner"

urlpatterns = [
    path("", views.HomeView.as_view(), name="home"),
    path("scan/", views.ScanView.as_view(), name="scan"),
    path("result/<int:scan_id>/", views.ScanResultView.as_view(), name="result"),
    path("history/", views.HistoryView.as_view(), name="history"),
    path("api/stats/", views.StatsAPIView.as_view(), name="stats_api"),
]
