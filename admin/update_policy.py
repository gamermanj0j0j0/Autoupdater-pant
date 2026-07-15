#!/usr/bin/env python3
"""Apply one validated access-policy change and update legacy revoked.txt."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pant_app.device_id import is_anchor_token, is_device_id  # noqa: E402


VALID_ACTIONS = ("revoke", "restore", "deny_all", "allow_all")
VALID_KINDS = ("device", "anchor")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_envelope(path: Path) -> dict[str, Any]:
    try:
        envelope = json.loads(
            path.read_text(encoding="utf-8-sig"), object_pairs_hook=_reject_duplicates
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read policy envelope: {path}") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ValueError("Policy envelope must contain only payload and signature")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Policy payload must be an object")
    expected = {
        "schema",
        "sequence",
        "issued_at",
        "deny_all",
        "min_version",
        "revoked_devices",
        "revoked_anchors",
    }
    if set(payload) != expected:
        raise ValueError("Policy payload fields do not match schema 1")
    if payload.get("schema") != 1 or type(payload.get("sequence")) is not int:
        raise ValueError("Policy schema or sequence is invalid")
    if not 0 <= payload["sequence"] < 9_007_199_254_740_991:
        raise ValueError("Policy sequence cannot be incremented")
    if type(payload.get("deny_all")) is not bool:
        raise ValueError("Policy deny_all must be a boolean")
    if not isinstance(payload.get("min_version"), str):
        raise ValueError("Policy min_version must be a string")
    for field in ("revoked_devices", "revoked_anchors"):
        value = payload.get(field)
        if not isinstance(value, list) or any(
            not isinstance(item, str) for item in value
        ):
            raise ValueError(f"Policy {field} must be a string array")
    return envelope


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}-", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def update_policy(
    envelope: dict[str, Any],
    *,
    action: str,
    kind: str | None,
    identifier: str | None,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    if action not in VALID_ACTIONS:
        raise ValueError(f"Unsupported action: {action}")
    identifier = (identifier or "").strip()

    if action in {"revoke", "restore"}:
        if kind not in VALID_KINDS:
            raise ValueError("revoke/restore requires --kind device or anchor")
        validator = is_device_id if kind == "device" else is_anchor_token
        if not identifier or not validator(identifier):
            raise ValueError(f"Identifier is not a valid {kind} token")
    elif identifier:
        raise ValueError("deny_all/allow_all does not accept an identifier")

    payload = envelope["payload"]
    if action in {"revoke", "restore"}:
        field = "revoked_devices" if kind == "device" else "revoked_anchors"
        entries = set(payload[field])
        if action == "revoke":
            entries.add(identifier)
        else:
            entries.discard(identifier)
        payload[field] = sorted(entries)
    elif action == "deny_all":
        payload["deny_all"] = True
    else:
        payload["deny_all"] = False

    payload["sequence"] += 1
    timestamp = (issued_at or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    payload["issued_at"] = timestamp.isoformat().replace("+00:00", "Z")

    # A stale signature must never look deployable between update and signing.
    existing_signature = envelope.get("signature")
    key_id = "pant-access-v1"
    if isinstance(existing_signature, dict) and isinstance(
        existing_signature.get("key_id"), str
    ):
        key_id = existing_signature["key_id"]
    envelope["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "value": "",
    }
    return envelope


def _legacy_content(payload: dict[str, Any]) -> bytes:
    lines = [
        "# PantKontroll compatibility revocation list.",
        "# Managed by admin/update_policy.py; do not add raw hardware values.",
    ]
    if payload["deny_all"]:
        lines.append("*")
    lines.extend(
        sorted(set(payload["revoked_devices"]) | set(payload["revoked_anchors"]))
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", required=True, choices=VALID_ACTIONS)
    parser.add_argument("--kind", choices=VALID_KINDS)
    parser.add_argument("--identifier", default="")
    parser.add_argument("--policy", type=Path, default=ROOT / "access" / "policy.json")
    parser.add_argument("--legacy", type=Path, default=ROOT / "revoked.txt")
    parser.add_argument(
        "--legacy-mirror",
        type=Path,
        default=ROOT / "access" / "revoked.txt",
        help="Secondary copy retained for packaged/repository compatibility",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        envelope = _read_envelope(arguments.policy)
        update_policy(
            envelope,
            action=arguments.action,
            kind=arguments.kind,
            identifier=arguments.identifier,
        )
        encoded = (
            json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        _atomic_write(arguments.policy, encoded)
        legacy_content = _legacy_content(envelope["payload"])
        _atomic_write(arguments.legacy, legacy_content)
        if arguments.legacy_mirror.resolve() != arguments.legacy.resolve():
            _atomic_write(arguments.legacy_mirror, legacy_content)
    except (OSError, ValueError) as exc:
        print(f"policy update failed: {exc}", file=sys.stderr)
        return 2
    print(
        f"Updated policy to sequence {envelope['payload']['sequence']}; signature is now intentionally empty"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
