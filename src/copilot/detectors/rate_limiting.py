"""Rate limiting control detector.

Logic lives in ``rules/rate_limiting.yaml``.
"""

from __future__ import annotations

from .base import Detector, register


@register
class RateLimitingDetector(Detector):
    category = "rate_limiting"

    @property
    def description(self) -> str:
        return "Limiter registration, a global default, and limits on credential endpoints"
