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
    # --- Autentifikatsiya ---
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("dashboard/", views.DashboardView.as_view(), name="dashboard"),
]
