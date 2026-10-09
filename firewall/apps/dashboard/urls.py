from __future__ import annotations

from django.urls import path

from apps.dashboard import views

app_name = "dashboard"

urlpatterns = [
    path("", views.overview, name="overview"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("logs/", views.logs, name="logs"),
    path("logs/<int:pk>/", views.log_detail, name="log_detail"),
    path("rules/", views.rules, name="rules"),
    path("rules/upload/", views.policy_upload, name="policy_upload"),
    path("rules/policies/<int:pk>/", views.policy_preview, name="policy_preview"),
    path("rules/policies/select/", views.policy_switch, name="policy_switch"),
    path("analytics/", views.analytics, name="analytics"),
    path("tester/", views.tester, name="tester"),
]
