"""Access control configuration detector.

Logic lives in ``rules/access_control.yaml``.
"""

from __future__ import annotations

from .base import Detector, register


@register
class AccessControlDetector(Detector):
    category = "access_control"

    @property
    def description(self) -> str:
        return "CORS policy, debug mode, security headers, admin role checks"
