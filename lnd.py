#!/usr/bin/env python3
"""
Minimal, least-privilege LND REST client for BPUB custodial inscription orders.

Only requires an `invoice.macaroon` (never admin/send permissions):
  - POST /v1/invoices          -> create BOLT11 invoice
  - GET  /v1/invoice/{r_hash}  -> check invoice settlement status
"""

import base64
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

import requests

R_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class LndError(RuntimeError):
    """Raised when LND REST returns an error or malformed response."""


class LndClient:
    """HTTP client for LND's REST invoice API."""

    def __init__(
        self,
        rest_url: str,
        macaroon_hex: str,
        tls_verify: Any = True,
        timeout: int = 10,
    ):
        self.rest_url = rest_url.rstrip("/")
        if not self.rest_url:
            raise ValueError("LND rest_url is required")
        mac = (macaroon_hex or "").strip()
        if not mac or not re.fullmatch(r"[0-9a-fA-F]+", mac):
            raise ValueError("LND macaroon_hex must be valid hex")
        self.macaroon_hex = mac
        self.tls_verify = tls_verify
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> Optional["LndClient"]:
        rest_url = os.getenv("LND_REST_URL", "").strip()
        if not rest_url:
            return None

        mac_hex = os.getenv("LND_MACAROON_HEX", "").strip()
        if not mac_hex:
            mac_path = os.getenv("LND_MACAROON_PATH", "").strip()
            if not mac_path:
                raise ValueError(
                    "LND_REST_URL is set, so LND_MACAROON_PATH or LND_MACAROON_HEX is required"
                )
            mac_hex = Path(mac_path).read_bytes().hex()

        tls_cert = os.getenv("LND_TLS_CERT_PATH", "").strip()
        if tls_cert:
            tls_verify: Any = tls_cert
        else:
            tls_verify = os.getenv("LND_TLS_VERIFY", "1").strip() != "0"

        return cls(rest_url=rest_url, macaroon_hex=mac_hex, tls_verify=tls_verify)

    def _headers(self) -> Dict[str, str]:
        return {
            "Grpc-Metadata-macaroon": self.macaroon_hex,
            "Content-Type": "application/json",
        }

    def create_invoice(
        self,
        amount_sats: int,
        memo: str,
        expiry_sec: int = 900,
    ) -> Dict[str, str]:
        if not isinstance(amount_sats, int) or amount_sats <= 0:
            raise ValueError("Invoice amount_sats must be a positive integer")
        payload = {
            "value": str(amount_sats),
            "memo": memo[:200],
            "expiry": str(max(60, int(expiry_sec))),
        }
        try:
            resp = requests.post(
                f"{self.rest_url}/v1/invoices",
                json=payload,
                headers=self._headers(),
                verify=self.tls_verify,
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise LndError(f"Failed connecting to LND: {e}") from e

        if resp.status_code != 200:
            raise LndError(f"LND create_invoice HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            body = resp.json()
            r_hash_b64 = body["r_hash"]
            payreq = body["payment_request"]
            r_hash_hex = base64.b64decode(r_hash_b64).hex()
        except Exception as e:
            raise LndError(f"Malformed LND create_invoice response: {e}") from e

        if not R_HASH_RE.match(r_hash_hex) or not isinstance(payreq, str) or not payreq.lower().startswith("ln"):
            raise LndError("Invalid r_hash or payment_request from LND")

        return {"r_hash": r_hash_hex, "payment_request": payreq}

    def lookup_invoice(self, r_hash_hex: str) -> Dict[str, Any]:
        if not R_HASH_RE.match(r_hash_hex or ""):
            raise ValueError("Invalid r_hash_hex")
        try:
            resp = requests.get(
                f"{self.rest_url}/v1/invoice/{r_hash_hex.lower()}",
                headers=self._headers(),
                verify=self.tls_verify,
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise LndError(f"Failed querying LND invoice: {e}") from e

        if resp.status_code != 200:
            raise LndError(f"LND lookup_invoice HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            body = resp.json()
        except Exception as e:
            raise LndError(f"Malformed LND lookup_invoice response: {e}") from e

        state = str(body.get("state") or ("SETTLED" if body.get("settled") else "OPEN")).upper()
        amt_paid_sat = int(body.get("amt_paid_sat") or 0)
        return {
            "state": state,
            "settled": state == "SETTLED" or bool(body.get("settled")),
            "canceled": state == "CANCELED",
            "amt_paid_sat": amt_paid_sat,
        }
