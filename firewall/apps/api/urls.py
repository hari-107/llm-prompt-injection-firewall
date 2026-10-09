from __future__ import annotations

from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from apps.api.gateway import GatewayInputView, GatewayOutputView

from apps.api.views import (
    AnalyticsView,
    BatchScanView,
    FirewallConfigView,
    HealthView,
    LogListView,
    PromptScanView,
    ResponseScanView,
    RuleViewSet,
)

router = DefaultRouter()
router.register("rules", RuleViewSet, basename="rule")

urlpatterns = [
    path("gateway/input/", GatewayInputView.as_view(), name="gateway-input"),
    path("gateway/output/", GatewayOutputView.as_view(), name="gateway-output"),
    path("health/", HealthView.as_view(), name="api-health"),
    path("scan/prompt/", PromptScanView.as_view(), name="api-scan-prompt"),
    path("scan/response/", ResponseScanView.as_view(), name="api-scan-response"),
    path("scan/batch/", BatchScanView.as_view(), name="api-scan-batch"),
    path("config/", FirewallConfigView.as_view(), name="api-config"),
    path("logs/", LogListView.as_view(), name="api-logs"),
    path("analytics/", AnalyticsView.as_view(), name="api-analytics"),
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("", include(router.urls)),
]
