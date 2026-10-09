"""Text normalization and layered decoding.

Attackers hide instructions behind encodings and invisible characters. Before
any detector runs we normalize the text and surface decoded layers so the rule
engine and classifier see the *effective* instruction, not the obfuscation.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

# Zero-width / invisible / directional-control characters used to smuggle text
# past human review while remaining tokenizable by a model.
_INVISIBLE_CHARS = (
    "​‌‍‎‏‪‫‬‭‮"
    "⁠⁡⁢⁣⁤﻿­᠎؜"
)
_INVISIBLE_RE = re.compile(f"[{_INVISIBLE_CHARS}]")

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){8,}")
_URL_ENC = re.compile(r"%[0-9a-fA-F]{2}")
_UNICODE_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{4}")


@dataclass
class NormalizedText:
    """Result of normalizing/decoding a raw prompt.

    - normalized: NFKC-folded text with invisible characters stripped.
    - decoded_layers: any text recovered from base64/hex/url/rot13/unicode.
    - flags: obfuscation signals observed (fed into risk scoring).
    - combined: normalized + all decoded layers, what detectors scan.
    """

    raw: str
    normalized: str
    decoded_layers: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    @property
    def combined(self) -> str:
        if not self.decoded_layers:
            return self.normalized
        return self.normalized + "\n" + "\n".join(self.decoded_layers)


def _strip_invisible(text: str) -> tuple[str, int]:
    count = len(_INVISIBLE_RE.findall(text))
    return _INVISIBLE_RE.sub("", text), count


def _try_base64(run: str) -> str | None:
    try:
        raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=False)
        decoded = raw.decode("utf-8", errors="strict")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if _printable_ratio(decoded) < 0.85 or len(decoded) < 4:
        return None
    return decoded


def _try_hex(run: str) -> str | None:
    cleaned = re.sub(r"[\s:]", "", run)
    if len(cleaned) % 2 != 0 or len(cleaned) < 8:
        return None
    try:
        decoded = bytes.fromhex(cleaned).decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    if _printable_ratio(decoded) < 0.85:
        return None
    return decoded


def _try_url(run: str) -> str | None:
    try:
        decoded = urllib.parse.unquote(run, errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if decoded != run else None


def _try_unicode_escape(run: str) -> str | None:
    try:
        return codecs.decode(run, "unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return None


def _try_rot13(text: str) -> str | None:
    """ROT13 only makes sense to surface if it reveals injection keywords."""
    decoded = codecs.decode(text, "rot_13")
    if _INJECTION_HINT.search(decoded) and not _INJECTION_HINT.search(text):
        return decoded
    return None


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for c in s if c.isprintable() or c.isspace())
    return printable / len(s)


# Keywords that, if they appear only *after* decoding, strongly imply the
# encoding was used to hide an instruction.
_INJECTION_HINT = re.compile(
    r"ignore|disregard|forget|system\s*prompt|instruction|bypass|reveal|"
    r"jailbreak|developer\s*mode|sudo|api[_\s-]*key|password|secret",
    re.IGNORECASE,
)


def normalize(text: str, *, max_decode_layers: int = 12) -> NormalizedText:
    """Normalize + decode a prompt. Safe on arbitrary input."""
    if text is None:
        text = ""

    flags: list[str] = []

    stripped, invisible_count = _strip_invisible(text)
    if invisible_count:
        flags.append(f"invisible-chars:{invisible_count}")

    normalized = unicodedata.normalize("NFKC", stripped)
    if normalized != stripped:
        flags.append("unicode-normalized")

    decoded_layers: list[str] = []
    seen: set[str] = {normalized}

    def _add(layer: str | None, flag: str) -> None:
        if not layer:
            return
        layer = layer.strip()
        layer, count = _strip_invisible(layer)
        if count and "decoded-invisible-chars" not in flags:
            flags.append("decoded-invisible-chars")
        layer = unicodedata.normalize("NFKC", layer)
        if not layer or layer in seen or len(decoded_layers) >= max_decode_layers:
            return
        seen.add(layer)
        decoded_layers.append(layer)
        if flag not in flags:
            flags.append(flag)

    # Decode complete URL/unicode text to preserve words split by sparse escapes,
    # and inspect recovered layers too. The layer cap bounds nested decoding.
    index = 0
    while index <= len(decoded_layers) and index <= max_decode_layers:
        current = normalized if index == 0 else decoded_layers[index - 1]
        for run in _B64_RUN.findall(current):
            _add(_try_base64(run), "base64-decoded")
        for run in _HEX_RUN.findall(current):
            _add(_try_hex(run), "hex-decoded")
        if _URL_ENC.search(current):
            _add(_try_url(current), "url-decoded")
        if _UNICODE_ESCAPE.search(current):
            _add(_UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(0)[2:], 16)), current),
                 "unicode-escape-decoded")
        _add(_try_rot13(current), "rot13-decoded")
        index += 1

    return NormalizedText(
        raw=text,
        normalized=normalized,
        decoded_layers=decoded_layers,
        flags=flags,
    )
