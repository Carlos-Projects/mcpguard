"""Adapter: MCPGuard -> mcp-taxonomy."""

from mcp_taxonomy import mcpguard_event_to_taxonomy as _normalize


def normalize_event(event) -> dict:
    """Convert a MCPGuard SecurityEvent (dict or object) to a normalized taxonomy dict."""
    tax = _normalize(event)
    return {
        "source": tax.source,
        "attack_category": tax.attack_category.value,
        "severity": tax.severity.value,
        "confidence": tax.confidence.value,
        "detection_method": tax.detection_method.value
        if hasattr(tax.detection_method, "value")
        else str(tax.detection_method),
        "title": tax.title,
        "description": tax.description,
        "target": tax.target,
        "snippet": tax.snippet[:200],
        "blocked": tax.blocked,
        "risk_score": tax.risk_score,
    }
