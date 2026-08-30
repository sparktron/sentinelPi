"""Validation for authenticated sensor-to-collector alert payloads."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any, Dict, Tuple

from .models import Alert, AlertCategory, Severity, alert_from_dict

_STRING_LIMITS = {
    "alert_id": 128,
    "timestamp": 64,
    "affected_host": 255,
    "affected_mac": 32,
    "related_host": 255,
    "title": 512,
    "description": 8192,
    "recommended_action": 4096,
    "confidence_rationale": 2048,
    "dedup_key": 1024,
}
_MAX_SENSOR_ID_LENGTH = 128
_MAX_EXTRA_DEPTH = 6
_MAX_EXTRA_ITEMS = 256
_MAX_EXTRA_KEY_LENGTH = 128
_MAX_EXTRA_STRING_LENGTH = 4096


class PayloadValidationError(ValueError):
    """One client-correctable collector payload error."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field
        self.message = message


def parse_collector_payload(body: Any) -> Tuple[str, Alert]:
    """Validate a collector request body before constructing an ``Alert``."""
    if not isinstance(body, dict):
        raise PayloadValidationError("body", "must be a JSON object")

    sensor_id = body.get("sensor_id", "")
    if not isinstance(sensor_id, str):
        raise PayloadValidationError("sensor_id", "must be a string")
    if len(sensor_id) > _MAX_SENSOR_ID_LENGTH:
        raise PayloadValidationError(
            "sensor_id", f"must be at most {_MAX_SENSOR_ID_LENGTH} characters"
        )

    alert_data = body.get("alert")
    if not isinstance(alert_data, dict):
        raise PayloadValidationError("alert", "must be a JSON object")

    _validate_required_enum(alert_data, "severity", Severity)
    _validate_required_enum(alert_data, "category", AlertCategory)
    for field, limit in _STRING_LIMITS.items():
        value = alert_data.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            raise PayloadValidationError(f"alert.{field}", "must be a string")
        if len(value) > limit:
            raise PayloadValidationError(
                f"alert.{field}", f"must be at most {limit} characters"
            )

    title = alert_data.get("title")
    if not isinstance(title, str) or not title.strip():
        raise PayloadValidationError("alert.title", "must be a non-empty string")

    timestamp = alert_data.get("timestamp")
    if timestamp:
        try:
            datetime.fromisoformat(timestamp)
        except ValueError as exc:
            raise PayloadValidationError(
                "alert.timestamp", "must be a valid ISO-8601 timestamp"
            ) from exc

    confidence = alert_data.get("confidence", 1.0)
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise PayloadValidationError("alert.confidence", "must be a number")
    try:
        confidence_number = float(confidence)
    except OverflowError as exc:
        raise PayloadValidationError("alert.confidence", "must be between 0 and 1") from exc
    if not math.isfinite(confidence_number) or not 0.0 <= confidence_number <= 1.0:
        raise PayloadValidationError("alert.confidence", "must be between 0 and 1")

    extra = alert_data.get("extra", {})
    if not isinstance(extra, dict):
        raise PayloadValidationError("alert.extra", "must be a JSON object")
    item_count = [0]
    _validate_extra(extra, "alert.extra", 0, item_count)

    return sensor_id.strip() or "unknown", alert_from_dict(alert_data)


def _validate_required_enum(data: Dict[str, Any], field: str, enum_cls: Any) -> None:
    value = data.get(field)
    if not isinstance(value, str):
        raise PayloadValidationError(f"alert.{field}", "must be a string")
    try:
        enum_cls(value)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_cls)
        raise PayloadValidationError(
            f"alert.{field}", f"must be one of: {allowed}"
        ) from exc


def _validate_extra(value: Any, field: str, depth: int, item_count: list[int]) -> None:
    if depth > _MAX_EXTRA_DEPTH:
        raise PayloadValidationError(field, f"must be at most {_MAX_EXTRA_DEPTH} levels deep")
    if isinstance(value, dict):
        for key, nested in value.items():
            item_count[0] += 1
            _check_item_count(field, item_count[0])
            if not isinstance(key, str):
                raise PayloadValidationError(field, "keys must be strings")
            if len(key) > _MAX_EXTRA_KEY_LENGTH:
                raise PayloadValidationError(
                    field, f"keys must be at most {_MAX_EXTRA_KEY_LENGTH} characters"
                )
            _validate_extra(nested, f"{field}.{key}", depth + 1, item_count)
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            item_count[0] += 1
            _check_item_count(field, item_count[0])
            _validate_extra(nested, f"{field}[{index}]", depth + 1, item_count)
        return
    if isinstance(value, str):
        if len(value) > _MAX_EXTRA_STRING_LENGTH:
            raise PayloadValidationError(
                field, f"must be at most {_MAX_EXTRA_STRING_LENGTH} characters"
            )
        return
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except OverflowError as exc:
            raise PayloadValidationError(field, "must be a finite number") from exc
        if not math.isfinite(number):
            raise PayloadValidationError(field, "must be a finite number")
        return
    raise PayloadValidationError(field, "must contain only JSON-compatible values")


def _check_item_count(field: str, count: int) -> None:
    if count > _MAX_EXTRA_ITEMS:
        raise PayloadValidationError(
            field, f"must contain at most {_MAX_EXTRA_ITEMS} keys and list items"
        )
