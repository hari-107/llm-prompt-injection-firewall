"""API-key authentication for DRF.

Clients send `Authorization: Api-Key pifw_...` (or `X-API-Key: pifw_...`). We
resolve the SHA-256 hash to an APIKey row and authenticate as its owning user.
JWT and session auth are handled by DRF's built-in classes alongside this one.
"""

from __future__ import annotations

from django.utils import timezone
from rest_framework import authentication, exceptions


class APIKeyAuthentication(authentication.BaseAuthentication):
    keyword = "Api-Key"

    def authenticate(self, request):
        raw = self._extract(request)
        if not raw:
            return None  # fall through to other authenticators

        from apps.accounts.models import APIKey

        api_key = APIKey.resolve(raw)
        if api_key is None:
            raise exceptions.AuthenticationFailed("Invalid or inactive API key.")

        api_key.last_used_at = timezone.now()
        api_key.save(update_fields=["last_used_at"])
        request.api_key = api_key
        return (api_key.user, api_key)

    def authenticate_header(self, request):
        return self.keyword

    def _extract(self, request) -> str | None:
        header = request.META.get("HTTP_X_API_KEY")
        if header:
            return header.strip()
        auth = request.META.get("HTTP_AUTHORIZATION", "")
        if auth.lower().startswith(self.keyword.lower() + " "):
            return auth[len(self.keyword) + 1 :].strip()
        return None
