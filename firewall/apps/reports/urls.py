from __future__ import annotations

from django.urls import path

from apps.reports import views

app_name = "reports"

urlpatterns = [
    path("logs/<int:pk>/pdf/", views.log_pdf, name="log_pdf"),
]
