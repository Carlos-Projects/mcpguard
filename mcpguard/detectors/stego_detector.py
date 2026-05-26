from __future__ import annotations

import math
import re
from typing import Any

from mcpguard.detectors.base import DetectionPlugin, registry
from mcpguard.main import SecurityEvent

ZW_CHARS = re.compile(
    "[\u200b\u200c\u200d\u2060\ufeff\u180e\u2061\u2062\u2063\u2064]"
)

INVISIBLE_CHARS = re.compile(
    "[\u3164\u2800\U000E0000-\U000E007F]"
)

BIDI_OVERRIDES = re.compile(
    "[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]"
)

VARIATION_SELECTORS = re.compile(
    "[\ufe00-\ufe0f\U000E0100-\U000E01EF]"
)

ZALGO = re.compile(
    "[\u0300-\u036f\u0483-\u0489\u0591-\u05bd\u05bf\u05c1\u05c2\u05c4\u05c5\u05c7"
    "\u0610-\u061a\u064b-\u065f\u0670\u06d6-\u06dc\u06df-\u06e4\u06e7\u06e8\u06ea"
    "\u06eb\u06ec\u06ed\u0711\u0730-\u074a\u07a6-\u07b0\u07eb-\u07f3\u0816-\u0819"
    "\u081b-\u0823\u0825-\u0827\u0829-\u082d\u0859-\u085b\u08d4-\u08e1\u08e3-\u0902"
    "\u093a\u093c\u0941-\u0948\u094d\u0951-\u0957\u0962\u0963\u0981\u09bc\u09be"
    "\u09c1-\u09c4\u09cd\u09d7\u09e2\u09e3\u0a01\u0a02\u0a3c\u0a41\u0a42\u0a47"
    "\u0a48\u0a4b-\u0a4d\u0a51\u0a70\u0a71\u0a75\u0a81\u0a82\u0abc\u0ac1-\u0ac5"
    "\u0ac7\u0ac8\u0acd\u0ae2\u0ae3\u0b01\u0b3c\u0b3f\u0b41-\u0b44\u0b4d\u0b56"
    "\u0b57\u0b62\u0b63\u0b82\u0bbe\u0bc0\u0bcd\u0bd7\u0c00\u0c3e-\u0c40\u0c46"
    "\u0c47\u0c48\u0c4a-\u0c4d\u0c55\u0c56\u0c62\u0c63\u0c81\u0cbc\u0cbf\u0cc6"
    "\u0ccc\u0ccd\u0ce2\u0ce3\u0d01\u0d3e\u0d41-\u0d44\u0d4d\u0d57\u0d62\u0d63"
    "\u0dca\u0dcf\u0dd2-\u0dd4\u0dd6\u0ddf\u0e31\u0e34-\u0e3a\u0e47-\u0e4e\u0eb1"
    "\u0eb4-\u0eb9\u0ebb\u0ebc\u0ec8-\u0ecd\ufb1e\ufe00-\ufe0f\ufe20-\ufe26"
    "\uff9e\uff9f]"
)

CONFUSABLE_WHITESPACE = re.compile(
    "[\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u00a0\u1680\u3000]"
)

BASE64_OR_HEX_IN_TEXT = re.compile(r"\b(?:[A-Za-z0-9+/]{40,}={0,2}|[A-Fa-f0-9]{32,})\b")

ST3GG_MARKERS = re.compile(
    r"(?:ST3GG\{[^}]*\}|STEG|I'?VE BEEN PWNED|LOVE PLINY|Plinian\s*divider|"
    r"ignore.the.image|decode.the.hidden|LSB.steg|developer.mode.activated)", re.IGNORECASE
)

PUNYCODE = re.compile(r"xn--[a-z0-9]{4,}", re.IGNORECASE)

MATH_ALPHANUM = re.compile("[\U0001d400-\U0001d7ff]")

EMOJI_SKIN_TONES = re.compile("[\U0001f3fb-\U0001f3ff]")


CYRILLIC_LOOKALIKES: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u04bb": "h", "\u04e9": "o", "\u051b": "e", "\u0432": "b",
    "\u043a": "k", "\u043d": "h", "\u043c": "m", "\u0442": "t",
    "\u0437": "3",
}

CYRILLIC_PATTERN = re.compile(
    "[" + "".join(CYRILLIC_LOOKALIKES.keys()) + "]"
)

SUSPICIOUS_ARG_NAMES = {"prompt", "code", "command", "instructions", "input", "message", "text", "query"}
ENTROPY_THRESHOLD = 4.0


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for c in data:
        freq[ord(c)] = freq.get(ord(c), 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values() if count > 0)


class StegoDetectorPlugin(DetectionPlugin):
    name = "stego_detector"

    def inspect_request(self, msg: dict[str, Any]) -> SecurityEvent | None:
        if msg.get("method") != "tools/call":
            return None
        params = msg.get("params", {})
        if not isinstance(params, dict):
            return None
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return None

        tool = params.get("name", "unknown")
        alerts: list[str] = []
        details: dict[str, Any] = {"tool": tool}

        text_chunks = self._extract_text(arguments)
        for chunk in text_chunks:
            if len(chunk) < 5:
                continue

            alerts.extend(self._check_zero_width(chunk, details))
            alerts.extend(self._check_invisible(chunk, details))
            alerts.extend(self._check_bidi(chunk, details))
            alerts.extend(self._check_variation_selectors(chunk, details))
            alerts.extend(self._check_zalgo(chunk, details))
            alerts.extend(self._check_confusable_whitespace(chunk, details))
            alerts.extend(self._check_st3gg_markers(chunk, details))
            alerts.extend(self._check_punycode(chunk, details))
            alerts.extend(self._check_math_alphanum(chunk, details))
            alerts.extend(self._check_emoji_skin_tones(chunk, details))
            alerts.extend(self._check_cyrillic_lookalikes(chunk, details))
            alerts.extend(self._check_base64_in_arg(chunk, arguments, details))
            alerts.extend(self._check_high_entropy(chunk, details))

        if alerts:
            return SecurityEvent(
                event_type="stego_detection",
                severity="high" if any(
                    a.startswith("[CRIT]") for a in alerts
                ) else "medium",
                message=f"Steganographic indicators: {len(alerts)} signal(s)",
                details={
                    "tool": tool,
                    "alerts": alerts,
                    "evidence": {k: v for k, v in details.items() if k != "tool"},
                },
                blocked=True,
            )
        return None

    def inspect_sse_event(self, event_type: str, data: dict[str, Any]) -> SecurityEvent | None:
        text_chunks = self._extract_text(data)
        alerts: list[str] = []
        details: dict[str, Any] = {}

        for chunk in text_chunks:
            if len(chunk) < 5:
                continue
            alerts.extend(self._check_zero_width(chunk, details))
            alerts.extend(self._check_invisible(chunk, details))
            alerts.extend(self._check_bidi(chunk, details))
            alerts.extend(self._check_zalgo(chunk, details))
            alerts.extend(self._check_st3gg_markers(chunk, details))

        if alerts:
            return SecurityEvent(
                event_type="stego_detection_sse",
                severity="high",
                message=f"Steganographic indicators in SSE: {len(alerts)} signal(s)",
                details={"alerts": alerts, "evidence": details},
                blocked=True,
            )
        return None

    def _check_zero_width(self, text: str, details: dict) -> list[str]:
        matches = ZW_CHARS.findall(text)
        if matches:
            counts: dict[str, int] = {}
            for m in matches:
                name = {
                    "\u200b": "ZWSP", "\u200c": "ZWNJ", "\u200d": "ZWJ",
                    "\u2060": "WJ", "\ufeff": "BOM", "\u180e": "MVS",
                }.get(m, f"U+{ord(m):04X}")
                counts[name] = counts.get(name, 0) + 1
            detail = {k: v for k, v in counts.items()}
            details["zero_width"] = detail
            return [f"[CRIT] Zero-width chars: {detail}"]
        return []

    def _check_invisible(self, text: str, details: dict) -> list[str]:
        matches = INVISIBLE_CHARS.findall(text)
        if matches:
            counts: dict[str, int] = {}
            for m in matches:
                name = {0x3164: "HangulFiller", 0x2800: "BrailleBlank"}.get(ord(m), f"TagU+{ord(m):04X}")
                counts[name] = counts.get(name, 0) + 1
            details["invisible"] = counts
            return [f"[CRIT] Invisible chars: {counts}"]
        return []

    def _check_bidi(self, text: str, details: dict) -> list[str]:
        matches = BIDI_OVERRIDES.findall(text)
        if matches:
            names = [{
                "\u202a": "LRE", "\u202b": "RLE", "\u202c": "PDF",
                "\u202d": "LRO", "\u202e": "RLO",
                "\u2066": "LRI", "\u2067": "RLI", "\u2068": "FSI", "\u2069": "PDI",
            }.get(m, f"U+{ord(m):04X}") for m in set(matches)]
            details["bidi"] = names
            return [f"[CRIT] Bidi override chars: {names}"]
        return []

    def _check_variation_selectors(self, text: str, details: dict) -> list[str]:
        matches = VARIATION_SELECTORS.findall(text)
        if matches:
            details["variation_selectors"] = len(matches)
            return [f"[MED] Variation selectors: {len(matches)}"]
        return []

    def _check_zalgo(self, text: str, details: dict) -> list[str]:
        matches = ZALGO.findall(text)
        if matches:
            details["combining_marks"] = len(matches)
            return [f"[MED] Combining marks (zalgo): {len(matches)}"]
        return []

    def _check_confusable_whitespace(self, text: str, details: dict) -> list[str]:
        matches = CONFUSABLE_WHITESPACE.findall(text)
        if matches:
            details["confusable_whitespace"] = len(matches)
            return [f"[MED] Confusable whitespace: {len(matches)}"]
        return []

    def _check_st3gg_markers(self, text: str, details: dict) -> list[str]:
        matches = ST3GG_MARKERS.findall(text)
        if matches:
            details["st3gg_markers"] = matches
            return [f"[CRIT] ST3GG markers: {matches}"]
        return []

    def _check_punycode(self, text: str, details: dict) -> list[str]:
        matches = PUNYCODE.findall(text)
        if matches:
            details["punycode"] = matches
            return [f"[MED] Punycode strings: {matches}"]
        return []

    def _check_math_alphanum(self, text: str, details: dict) -> list[str]:
        matches = MATH_ALPHANUM.findall(text)
        if matches:
            details["math_alphanum"] = len(matches)
            return [f"[MED] Math alphanumeric: {len(matches)}"]
        return []

    def _check_emoji_skin_tones(self, text: str, details: dict) -> list[str]:
        matches = EMOJI_SKIN_TONES.findall(text)
        if matches:
            details["emoji_skin_tones"] = len(matches)
            return [f"[MED] Emoji skin tones (potential encoding): {len(matches)}"]
        return []

    def _check_cyrillic_lookalikes(self, text: str, details: dict) -> list[str]:
        matches = CYRILLIC_PATTERN.findall(text)
        if matches:
            total = len(matches)
            homoglyphs: dict[str, str] = {}
            for m in set(matches):
                homoglyphs[f"U+{ord(m):04X}"] = CYRILLIC_LOOKALIKES.get(m, "?")
            details["homoglyphs"] = homoglyphs
            return [f"[MED] Cyrillic homoglyphs: {total} (masquerading as {set(homoglyphs.values())})"]
        return []

    def _check_base64_in_arg(self, text: str, arguments: dict, details: dict) -> list[str]:
        matches = BASE64_OR_HEX_IN_TEXT.findall(text)
        if matches:
            filtered = [m for m in matches if not self._is_plaintext(m)]
            if filtered:
                details["base64_hex_blobs"] = filtered[:5]
                return [f"[MED] Suspicious base64/hex blobs: {len(filtered)}"]
        return []

    def _check_high_entropy(self, text: str, details: dict) -> list[str]:
        if len(text) < 40:
            return []
        entropy = _shannon_entropy(text)
        if entropy > ENTROPY_THRESHOLD:
            ascii_ratio = sum(1 for c in text if 32 <= ord(c) < 127) / len(text)
            if ascii_ratio < 0.8:
                details["high_entropy"] = round(entropy, 2)
                return [f"[MED] High entropy ({entropy:.2f}): possible encoded payload"]
        return []

    @staticmethod
    def _is_plaintext(s: str) -> bool:
        if len(s) < 20:
            return True
        alpha = sum(1 for c in s if c.isalpha())
        return alpha / len(s) > 0.7 if len(s) > 0 else True

    @staticmethod
    def _extract_text(data: Any, depth: int = 0) -> list[str]:
        if depth > 5:
            return []
        chunks: list[str] = []
        if isinstance(data, str) and len(data) > 5:
            chunks.append(data)
        elif isinstance(data, dict):
            for v in data.values():
                chunks.extend(StegoDetectorPlugin._extract_text(v, depth + 1))
        elif isinstance(data, list):
            for item in data:
                chunks.extend(StegoDetectorPlugin._extract_text(item, depth + 1))
        return chunks


registry.register(StegoDetectorPlugin())
