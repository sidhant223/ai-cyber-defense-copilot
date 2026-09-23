"""Authentication control detector.

All detection logic lives in ``rules/authentication.yaml``. This module only
declares the category, which is the point: a new authentication control is a
YAML edit, not a Python edit.
"""

from __future__ import annotations

from .base import Detector, register


@register
class AuthenticationDetector(Detector):
    category = "authentication"

    @property
    def description(self) -> str:
        return "Route-level auth, session cookie safety, password storage"
