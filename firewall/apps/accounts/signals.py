from __future__ import annotations

from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.accounts.models import Profile, Role


@receiver(post_save, sender=User)
def ensure_profile(sender, instance: User, created: bool, **kwargs) -> None:
    """Every user gets a Profile. Superusers default to the admin role."""
    if not created:
        return
    role = Role.ADMIN if instance.is_superuser else Role.READONLY
    Profile.objects.get_or_create(user=instance, defaults={"role": role})
