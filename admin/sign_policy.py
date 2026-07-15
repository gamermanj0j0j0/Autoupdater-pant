#!/usr/bin/env python3
"""Sign an access policy using an Ed25519 private key kept outside the repo."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]

try:
    from .update_policy import _read_envelope
except ImportError:  # Executed directly as ``python admin/sign_policy.py``.
    from update_policy import _read_envelope


def canonical_policy_bytes(payload: dict[str, Any]) -> bytes:
    """Return the exact canonical byte representation verified by clients."""

    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Policy payload is not canonicalisable") from exc
    return encoded.encode("utf-8")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_private_key(material: bytes) -> Ed25519PrivateKey:
    material = material.strip()
    if not material:
        raise ValueError("Private key material is empty")
    if material.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(material, password=None)
        except (TypeError, ValueError) as exc:
            raise ValueError("Private key PEM is invalid or encrypted") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Private key must use Ed25519")
        return key

    decoded: bytes
    if re.fullmatch(rb"[0-9A-Fa-f]{64}", material):
        decoded = bytes.fromhex(material.decode("ascii"))
    else:
        try:
            decoded = base64.b64decode(material, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Private key must be PEM, hex, or base64") from exc
    if len(decoded) == 32:
        return Ed25519PrivateKey.from_private_bytes(decoded)
    try:
        key = serialization.load_der_private_key(decoded, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("Private key data is not Ed25519") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key must use Ed25519")
    return key


def _atomic_write(path: Path, content: bytes) -> None:
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


def sign_envelope(
    envelope: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
) -> dict[str, Any]:
    if set(envelope) != {"payload", "signature"} or not isinstance(
        envelope.get("payload"), dict
    ):
        raise ValueError("Policy envelope must contain only payload and signature")
    if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", key_id) is None:
        raise ValueError("key_id must contain 1-64 safe characters")
    canonical = canonical_policy_bytes(envelope["payload"])
    signature = private_key.sign(canonical)
    envelope["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "value": base64.b64encode(signature).decode("ascii"),
    }
    try:
        private_key.public_key().verify(signature, canonical)
    except InvalidSignature as exc:  # Defensive check before writing the file.
        raise ValueError("Policy signature verification failed") from exc
    return envelope


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=ROOT / "access" / "policy.json")
    parser.add_argument("--key-env", default="PANT_POLICY_PRIVATE_KEY")
    parser.add_argument("--private-key-file", type=Path)
    parser.add_argument("--key-id", default="pant-access-v1")
    parser.add_argument("--print-public-key", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.private_key_file is not None:
            key_material = arguments.private_key_file.read_bytes()
        else:
            value = os.environ.get(arguments.key_env)
            if value is None:
                raise ValueError(f"Set {arguments.key_env} or use --private-key-file")
            key_material = value.encode("utf-8")
        private_key = _load_private_key(key_material)
        envelope = _read_envelope(arguments.policy)
        sign_envelope(envelope, private_key, key_id=arguments.key_id)
        encoded = (
            json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        _atomic_write(arguments.policy, encoded)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"policy signing failed: {exc}", file=sys.stderr)
        return 2

    print(
        f"Signed policy sequence {envelope['payload']['sequence']} with key id {arguments.key_id}"
    )
    if arguments.print_public_key:
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        print(base64.b64encode(public_bytes).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
