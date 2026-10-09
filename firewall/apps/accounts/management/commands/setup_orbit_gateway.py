from __future__ import annotations

from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from apps.accounts.models import APIKey, Profile, Role


class Command(BaseCommand):
    help = "Create the limited Orbit chatbot account and configure its local firewall API key."

    def handle(self, *args, **options):
        chatbot_dir = Path(__file__).resolve().parents[4].parent / "chatbot"
        if not chatbot_dir.is_dir():
            raise CommandError(f"Expected a sibling chatbot folder at {chatbot_dir}.")
        env_file = chatbot_dir / ".env"
        values: dict[str, str] = {}
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    name, value = line.split("=", 1)
                    values[name.strip()] = value.strip()

        username = "orbit_firewall_gateway"
        user, _ = get_user_model().objects.get_or_create(username=username)
        user.is_active = True
        user.is_staff = False
        user.is_superuser = False
        user.set_unusable_password()
        user.save()
        profile, _ = Profile.objects.get_or_create(user=user)
        profile.role = Role.ANALYST
        profile.save(update_fields=["role"])

        raw_key = values.get("FIREWALL_API_KEY", "")
        api_key = APIKey.resolve(raw_key) if raw_key else None
        if api_key is None or api_key.user_id != user.pk:
            APIKey.objects.filter(user=user, name="Orbit local chatbot gateway").update(active=False)
            _, raw_key = APIKey.generate(name="Orbit local chatbot gateway", user=user)

        values.update({
            "CHATBOT_HOST": values.get("CHATBOT_HOST", "127.0.0.1"),
            "CHATBOT_PORT": values.get("CHATBOT_PORT", "3000"),
            "FIREWALL_URL": values.get("FIREWALL_URL", "http://127.0.0.1:8000"),
            "FIREWALL_API_KEY": raw_key,
            "OLLAMA_BASE_URL": values.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
            "OLLAMA_MODEL": values.get("OLLAMA_MODEL", "phi3"),
            "OLLAMA_TIMEOUT_SECONDS": values.get("OLLAMA_TIMEOUT_SECONDS", "180"),
        })
        env_file.write_text(
            "# Local Orbit settings; do not commit or share this file.\n"
            + "".join(f"{name}={value}\n" for name, value in values.items()),
            encoding="utf-8",
        )
        self.stdout.write(self.style.SUCCESS(
            "Orbit gateway account and local API key are configured; the key was not displayed."
        ))
