"""Role-based DRF permissions.

Roles (see accounts.models.Role): admin > analyst > auditor > readonly.
- readonly / auditor: read-only access to scan + read endpoints.
- analyst: may manage rules and run scans.
- admin: everything, including user/API-key management.

A request authenticated via an APIKey inherits its owner's role. Requests with
no profile (e.g. a bare superuser created before signals ran) are treated as
admin if `is_superuser`, else readonly.
"""

from __future__ import annotations

from rest_framework.permissions import SAFE_METHODS, BasePermission

from apps.accounts.models import Role


def role_of(user) -> str | None:
    if user is None or not user.is_authenticated:
        return None
    profile = getattr(user, "profile", None)
    if profile is not None:
        return profile.role
    return Role.ADMIN if user.is_superuser else Role.READONLY


class HasRole(BasePermission):
    """Base: subclasses set `allowed_roles` (and optionally `write_roles`)."""

    allowed_roles: set[str] = set()
    write_roles: set[str] = set()

    def has_permission(self, request, view) -> bool:
        role = role_of(request.user)
        if role is None:
            return False
        if request.method in SAFE_METHODS:
            return role in self.allowed_roles or role in self.write_roles
        return role in self.write_roles


class CanScan(HasRole):
    allowed_roles = {Role.READONLY, Role.AUDITOR}
    write_roles = {Role.ANALYST, Role.ADMIN}


class CanManageRules(HasRole):
    allowed_roles = {Role.AUDITOR, Role.READONLY, Role.ANALYST, Role.ADMIN}
    write_roles = {Role.ANALYST, Role.ADMIN}


class CanViewLogs(HasRole):
    allowed_roles = {Role.AUDITOR, Role.ANALYST, Role.ADMIN}
    write_roles = {Role.ADMIN}


class IsAdmin(HasRole):
    allowed_roles = {Role.ADMIN}
    write_roles = {Role.ADMIN}
