"""Import threat-intel signatures and jailbreak samples from a JSON file.

Defaults to data/attack_corpus.json. Idempotent by signature_id / sample text.
"""

from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.threatintel.models import JailbreakSample, ThreatSignature


class Command(BaseCommand):
    help = "Import threat signatures and jailbreak samples from a JSON dataset."

    def add_arguments(self, parser):
        parser.add_argument("--path", default=str(Path(settings.BASE_DIR) / "data" / "attack_corpus.json"))

    def handle(self, *args, **opts):
        path = Path(opts["path"])
        if not path.exists():
            self.stderr.write(self.style.ERROR(f"Dataset not found: {path}"))
            return
        data = json.loads(path.read_text(encoding="utf-8"))

        sig_created = 0
        for sig in data.get("signatures", []):
            _, created = ThreatSignature.objects.get_or_create(
                signature_id=sig["signature_id"],
                defaults=dict(
                    kind=sig.get("kind", "regex"), pattern=sig["pattern"],
                    category=sig["category"], severity=sig.get("severity", "medium"),
                    description=sig.get("description", ""), source=sig.get("source", ""),
                    atlas=sig.get("atlas", ""),
                ),
            )
            sig_created += int(created)

        sample_created = 0
        for s in data.get("samples", []):
            _, created = JailbreakSample.objects.get_or_create(
                text=s["text"],
                defaults=dict(
                    category=s["category"], is_attack=s.get("is_attack", True),
                    source=s.get("source", ""), notes=s.get("notes", ""),
                ),
            )
            sample_created += int(created)

        self.stdout.write(self.style.SUCCESS(
            f"Imported {sig_created} new signatures ({ThreatSignature.objects.count()} total), "
            f"{sample_created} new samples ({JailbreakSample.objects.count()} total)."
        ))
