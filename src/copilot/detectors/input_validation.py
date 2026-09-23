"""Input validation control detector.

Logic lives in ``rules/input_validation.yaml``.
"""

from __future__ import annotations

from .base import Detector, register


@register
class InputValidationDetector(Detector):
    category = "input_validation"

    @property
    def description(self) -> str:
        return "Request body schemas, query parameterisation, upload restrictions"
