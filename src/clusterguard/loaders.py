from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

Resource = Mapping[str, Any]


def load_resources(path: Path) -> list[Resource]:
    """Load JSON or YAML Kubernetes resources from a file."""
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    if suffix in {".yaml", ".yml"}:
        payloads = [payload for payload in yaml.safe_load_all(text) if payload is not None]
    else:
        payloads = [json.loads(text)]

    resources: list[Resource] = []
    for payload in payloads:
        resources.extend(_normalize_payload(payload))
    return resources


def _normalize_payload(payload: object) -> list[Resource]:
    if isinstance(payload, list):
        return [_as_resource(item) for item in payload]

    if isinstance(payload, Mapping):
        if payload.get("kind") == "List" and isinstance(payload.get("items"), list):
            return [_as_resource(item) for item in payload["items"]]
        return [_as_resource(payload)]

    raise ValueError("Manifest must contain a Kubernetes object, List, or array of objects.")


def _as_resource(payload: object) -> Resource:
    if not isinstance(payload, Mapping):
        raise ValueError("Manifest entries must be Kubernetes object mappings.")
    return payload
