#!/usr/bin/env python3
"""
BPUB Gallery & Embed Web Server (FastAPI + SQLite).

Serves:
  - Gallery web UI (paginated grid, search, filters, detail view, ownership history)
  - Hardened /media/<stored_filename> endpoint (sandbox CSP, nosniff, allowlisted MIME)
  - BPUB v5 `padv3` embed builder APIs (estimate, fund-psbt, reveal-psbt)
  - Validated transaction broadcaster (defaults to https://mempool.kilombino.com/api/tx)

Security controls:
  - Per-IP tiered sliding-window rate limiting with bounded memory
  - Opt-in proxy header trust (BPUB_TRUST_PROXY=1 only)
  - Strict security headers + script-src 'self' CSP (zero inline scripts)
  - Streaming upload size caps (190 KiB single-tx padv3 cap)
  - Strict input validation on all txids, pubkeys, addresses, filenames, and raw txs
"""

import hashlib
import os
import re
import threading
import time
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional

import requests
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from bitcointx.core import (
    COutPoint,
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    CTransaction,
    CTxOut,
    lx,
)
from bitcointx.core.psbt import PartiallySignedTransaction as PSBT
from bitcointx.core.script import CScript

import bpub
from db import BpubDB
from indexer import SAFE_EXTENSIONS
from lnd import LndClient, LndError
from orders import InsufficientLiquidityError, OrderConfig, OrderService

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

try:
    import segno
except ImportError:
    segno = None


def _make_bolt11_qr_data_uri(payment_request: Optional[str]) -> Optional[str]:
    """
    Generate a self-contained PNG data URI QR code for a BOLT11 invoice.
    Uses uppercase `LIGHTNING:<BOLT11>` so QR encodes in Alphanumeric mode
    (lower density, faster mobile wallet scanning) with zero external requests.
    """
    if segno is None or not payment_request or not isinstance(payment_request, str):
        return None
    clean = payment_request.strip()
    if not clean:
        return None
    qr = segno.make(f"LIGHTNING:{clean.upper()}", error="m")
    return qr.png_data_uri(scale=5, border=4)


# ---------------------------------------------------------------------------
# Configuration & Validation Constants
# ---------------------------------------------------------------------------

TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ORDER_ID_RE = re.compile(r"^[0-9a-f]{32}$")
PUBKEY_RE = re.compile(r"^(02|03)[0-9a-fA-F]{64}$")
STORED_FILENAME_RE = re.compile(r"^[0-9a-fA-F]{1,64}_[A-Za-z0-9._-]+$")
UTXO_RE = re.compile(r"^([0-9a-fA-F]{64}):(\d+)$")
BPUB_UTXO_RE = re.compile(r"^([0-9a-fA-F]{64}):(\d+):(\d+)$")

# Single-tx padv3 standardness cap (~630 inputs * 310 bytes ≈ 195 KB stream)
MAX_UPLOAD_BYTES = int(os.getenv("BPUB_MAX_UPLOAD_BYTES", str(190 * 1024)))
# Instant Inscribe supports automatic BPUB v1 multipart splitting up to this limit (default 1 MiB)
MAX_ORDER_UPLOAD_BYTES = max(
    MAX_UPLOAD_BYTES,
    int(os.getenv("BPUB_MAX_ORDER_UPLOAD_BYTES", str(1024 * 1024))),
)
MAX_JSON_BODY_BYTES = 512 * 1024
MAX_MULTIPART_BODY_BYTES = MAX_UPLOAD_BYTES + 64 * 1024
MAX_ORDER_MULTIPART_BODY_BYTES = MAX_ORDER_UPLOAD_BYTES + 64 * 1024
MAX_UPSTREAM_EXPLORER_BYTES = 2 * 1024 * 1024
MAX_RAW_TX_HEX_LEN = 400_000  # 200 KB raw tx (~800k WU upper sanity bound)
MAX_FEERATE = 10_000
MIN_OWNER_VALUE = 330
MAX_OWNER_VALUE = 100_000_000

SAFE_MEDIA_MIMES: Dict[str, str] = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".txt": "text/plain; charset=utf-8",
    ".bin": "application/octet-stream",
}
INLINE_MEDIA_EXTS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".mp4",
    ".webm",
    ".mp3",
    ".wav",
    ".ogg",
}


# ---------------------------------------------------------------------------
# Bounded Per-IP Sliding-Window Rate Limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """In-memory per-IP sliding-window limiter with bounded cardinality."""

    def __init__(self, max_tracked_ips: int = 50_000):
        self.max_tracked_ips = max_tracked_ips
        self._lock = threading.Lock()
        self._buckets: Dict[str, deque] = {}

    def check(self, key: str, limit: int, window_sec: int) -> Optional[int]:
        """
        Record a hit for `key`. Returns None if allowed, or retry_after seconds
        if the rate limit has been exceeded.
        """
        now = time.monotonic()
        cutoff = now - window_sec
        with self._lock:
            dq = self._buckets.get(key)
            if dq is None:
                if len(self._buckets) >= self.max_tracked_ips:
                    self._evict_oldest(now, window_sec)
                dq = deque()
                self._buckets[key] = dq

            while dq and dq[0] <= cutoff:
                dq.popleft()

            if len(dq) >= limit:
                retry_after = max(1, int(dq[0] + window_sec - now) + 1)
                return retry_after

            dq.append(now)
            return None

    def _evict_oldest(self, now: float, window_sec: int) -> None:
        cutoff = now - window_sec
        stale = [k for k, v in self._buckets.items() if not v or v[-1] <= cutoff]
        for k in stale[: max(1, len(stale))]:
            self._buckets.pop(k, None)
        if len(self._buckets) >= self.max_tracked_ips:
            # Drop oldest 10% to guarantee bounded memory under IP-flood DoS.
            drop_n = max(1, self.max_tracked_ips // 10)
            for k in list(self._buckets.keys())[:drop_n]:
                self._buckets.pop(k, None)


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class BroadcastRequest(BaseModel):
    raw_hex: str = Field(..., min_length=20, max_length=MAX_RAW_TX_HEX_LEN)


class EstimateRequest(BaseModel):
    size_bytes: int = Field(..., ge=1, le=MAX_UPLOAD_BYTES)
    feerate: int = Field(1, ge=1, le=MAX_FEERATE)
    reveal_feerate: Optional[int] = Field(None, ge=1, le=MAX_FEERATE)
    owner_value: int = Field(10_000, ge=MIN_OWNER_VALUE, le=MAX_OWNER_VALUE)
    filename: str = Field("", max_length=120)
    mime: str = Field("application/octet-stream", max_length=100)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client_ip(request: Request, trust_proxy: bool) -> str:
    if trust_proxy:
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip and cf_ip.strip():
            return cf_ip.strip()
        xff = request.headers.get("x-forwarded-for")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
        xri = request.headers.get("x-real-ip")
        if xri and xri.strip():
            return xri.strip()
    return request.client.host if request.client else "unknown"


async def _read_upload_bounded(upload: UploadFile, max_bytes: int) -> bytes:
    """Stream an uploaded file in chunks and abort immediately if > max_bytes."""
    chunks: List[bytes] = []
    total = 0
    while True:
        chunk = await upload.read(32 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds maximum upload size ({max_bytes} bytes)",
            )
        chunks.append(chunk)
    data = b"".join(chunks)
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    return data


def _validate_txid(txid: str, label: str = "txid") -> str:
    if not TXID_RE.match(txid or ""):
        raise HTTPException(status_code=400, detail=f"Invalid {label} (expected 64 hex chars)")
    return txid.lower()


def _validate_pubkey(pubkey_hex: str) -> bytes:
    if not PUBKEY_RE.match(pubkey_hex or ""):
        raise HTTPException(
            status_code=400,
            detail="Invalid control_pubkey (expected 33-byte compressed pubkey hex)",
        )
    return bytes.fromhex(pubkey_hex)


def _validate_feerate(val: int, label: str = "feerate") -> int:
    if not isinstance(val, int) or val < 1 or val > MAX_FEERATE:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {label} (must be between 1 and {MAX_FEERATE} sat/vB)",
        )
    return val


def _build_padv3_funding_psbt(
    data: bytes,
    filename: str,
    mime: str,
    compress: bool,
    control_pubkey: bytes,
    owner_address: str,
    utxo_str: str,
    utxo_value: int,
    prev_address: str,
    change_address: str,
    feerate: int,
    reveal_feerate: Optional[int] = None,
    owner_value: int = 10_000,
) -> Dict:
    m = UTXO_RE.match((utxo_str or "").strip())
    if not m:
        raise HTTPException(status_code=400, detail="Invalid utxo (expected TXID:VOUT)")
    txid_str, vout_num = m.group(1).lower(), int(m.group(2))
    if utxo_value <= bpub.BPUB_DUST or utxo_value > 21_000_000 * 100_000_000:
        raise HTTPException(status_code=400, detail="Invalid UTXO value in sats")
    if not isinstance(owner_value, int) or owner_value < MIN_OWNER_VALUE or owner_value > MAX_OWNER_VALUE:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid owner_value (must be between {MIN_OWNER_VALUE} and {MAX_OWNER_VALUE} sats)",
        )

    stream = bpub.build_stream_v5(data, mime[:100], filename[:120], compress=compress)
    bpub_id = bpub.compute_bpub_v5_id(data)
    data_pubkeys = bpub.encode_stream_to_pubkeys(stream)
    chunks = list(bpub.chunk_data_pubkeys(data_pubkeys, max_pubkeys=bpub.MAX_PUBKEYS_PER_SCRIPT))
    if len(chunks) > 630:
        raise HTTPException(
            status_code=413,
            detail=f"Encoded stream needs {len(chunks)} padv3 outputs (max 630 for single standard reveal tx)",
        )

    redeem_scripts = [
        bpub.build_multisig_script(c, control_pubkey, pad_suffix=True) for c in chunks
    ]
    bpub_spks = [bpub.p2wsh_scriptpubkey(rs) for rs in redeem_scripts]

    try:
        owner_h160 = bpub.owner_h160_from_address(owner_address.strip())
        prev_spk = bpub.bech32_to_scriptpubkey(prev_address.strip())
        change_spk = bpub.bech32_to_scriptpubkey(change_address.strip())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    owner_redeem = bpub.build_owner_redeem_script(bpub_id, owner_h160)
    owner_spk = bpub.p2wsh_scriptpubkey(owner_redeem)

    n_out_p2wsh = len(bpub_spks) + 1
    fee = bpub.estimate_fee_funding(
        n_in_p2wpkh=1, n_out_p2wsh=n_out_p2wsh, n_out_p2wpkh=1, feerate=feerate
    )
    eff_reveal_feerate = reveal_feerate if reveal_feerate is not None else feerate
    values = bpub.bpub_output_values(len(bpub_spks), eff_reveal_feerate, pad_suffix=True)
    bpub_total = sum(values)
    change_value = utxo_value - fee - bpub_total - owner_value
    if change_value < bpub.BPUB_DUST:
        needed = fee + bpub_total + owner_value + bpub.BPUB_DUST
        raise HTTPException(
            status_code=400,
            detail=f"Funding UTXO too small ({utxo_value} sats); need at least {needed} sats",
        )

    txin = CMutableTxIn(COutPoint(lx(txid_str), vout_num))
    txouts = [CMutableTxOut(v, CScript(spk)) for v, spk in zip(values, bpub_spks)]
    txouts.append(CMutableTxOut(owner_value, CScript(owner_spk)))
    txouts.append(CMutableTxOut(change_value, CScript(change_spk)))

    tx = CMutableTransaction([txin], txouts)
    psbt = PSBT(unsigned_tx=tx)
    psbt.set_utxo(CTxOut(utxo_value, prev_spk), 0, force_witness_utxo=True)

    funding_txid = tx.GetTxid()[::-1].hex()
    return {
        "funding_psbt": psbt.to_base64(),
        "funding_txid": funding_txid,
        "bpub_id": bpub_id.hex(),
        "pad_version": "padv3",
        "data_outputs_count": len(values),
        "per_output_sats": values[0],
        "bpub_utxos": [f"{funding_txid}:{i}:{v}" for i, v in enumerate(values)],
        "owner_vout": len(values),
        "owner_value_sats": owner_value,
        "change_value_sats": change_value,
        "funding_fee_sats": fee,
        "assumed_reveal_feerate": eff_reveal_feerate,
    }


def _build_padv3_reveal_psbt(
    data: bytes,
    filename: str,
    mime: str,
    compress: bool,
    control_pubkey: bytes,
    bpub_utxo_list: List[str],
    change_address: str,
    feerate: int,
) -> Dict:
    stream = bpub.build_stream_v5(data, mime[:100], filename[:120], compress=compress)
    data_pubkeys = bpub.encode_stream_to_pubkeys(stream)
    chunks = list(bpub.chunk_data_pubkeys(data_pubkeys, max_pubkeys=bpub.MAX_PUBKEYS_PER_SCRIPT))

    if len(bpub_utxo_list) != len(chunks):
        raise HTTPException(
            status_code=400,
            detail=f"Expected exactly {len(chunks)} bpub_utxos for this file, got {len(bpub_utxo_list)}",
        )

    parsed_utxos = []
    for item in bpub_utxo_list:
        m = BPUB_UTXO_RE.match(item.strip())
        if not m:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid bpub_utxo format: {item!r} (need TXID:VOUT:VALUE)",
            )
        parsed_utxos.append((m.group(1).lower(), int(m.group(2)), int(m.group(3))))

    total_in = sum(v for _, _, v in parsed_utxos)
    fee = bpub.estimate_fee_reveal(
        n_inputs=len(parsed_utxos), n_outputs=1, feerate=feerate, pad_suffix=True
    )
    change_value = total_in - fee
    if change_value < bpub.BPUB_DUST:
        raise HTTPException(
            status_code=400,
            detail=f"Reveal change ({change_value} sats) would be dust; lower feerate or increase funded UTXOs",
        )

    try:
        change_spk = bpub.bech32_to_scriptpubkey(change_address.strip())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    redeem_scripts = [
        bpub.build_multisig_script(c, control_pubkey, pad_suffix=True) for c in chunks
    ]
    txins = [CMutableTxIn(COutPoint(lx(txid), vout)) for txid, vout, _ in parsed_utxos]
    tx = CMutableTransaction(txins, [CMutableTxOut(change_value, CScript(change_spk))])
    psbt = PSBT(unsigned_tx=tx)

    for idx, ((_, _, val), rs) in enumerate(zip(parsed_utxos, redeem_scripts)):
        spk = bpub.p2wsh_scriptpubkey(rs)
        psbt.set_utxo(CTxOut(val, CScript(spk)), idx, force_witness_utxo=True)
        psbt.inputs[idx].witness_script = rs

    reserved, ceiling = bpub.reveal_feerate_budget(
        [v for _, _, v in parsed_utxos], pad_suffix=True
    )
    return {
        "reveal_psbt": psbt.to_base64(),
        "inputs": len(parsed_utxos),
        "fee_sats": fee,
        "change_value_sats": change_value,
        "reserved_feerate": reserved,
        "dust_ceiling_feerate": ceiling,
        "pad_version": "padv3",
    }


# ---------------------------------------------------------------------------
# FastAPI App Factory
# ---------------------------------------------------------------------------


def create_app(
    gallery_dir: Optional[Path] = None,
    broadcast_url: Optional[str] = None,
    explorer_base_url: Optional[str] = None,
    trust_proxy: Optional[bool] = None,
    rate_limits: Optional[Dict[str, tuple]] = None,
    order_service: Optional[OrderService] = None,
) -> FastAPI:
    gdir = Path(gallery_dir or os.getenv("GALLERY_DIR", "gallery"))
    gdir.mkdir(parents=True, exist_ok=True)
    media_dir = gdir / "media"
    media_dir.mkdir(parents=True, exist_ok=True)
    static_dir = Path(__file__).resolve().parent / "gallery"

    db_path = Path(os.getenv("BPUB_DB_PATH", str(gdir / "bpub.db")))
    db = BpubDB(db_path)
    db.migrate_legacy_json(gdir)

    if order_service is None:
        try:
            lnd_client = LndClient.from_env()
        except Exception:
            lnd_client = None
        if lnd_client is not None:
            payload_dir = Path(os.getenv("ORDER_PAYLOAD_DIR", str(gdir / "order_payloads")))
            order_service = OrderService(
                db=db,
                payload_dir=payload_dir,
                lnd=lnd_client,
                wallet_backend=None,  # Web tier only creates/checks invoices; order_worker spends
                cfg=OrderConfig.from_env(),
            )

    bcast_url = (
        broadcast_url
        if broadcast_url is not None
        else os.getenv("BROADCAST_URL", "https://mempool.kilombino.com/api/tx")
    ).strip()
    explorer_url = (
        explorer_base_url
        if explorer_base_url is not None
        else os.getenv("EXPLORER_BASE_URL", "https://mempool.kilombino.com")
    ).rstrip("/")
    esplora_pool_raw = (
        explorer_base_url
        if explorer_base_url is not None
        else os.getenv(
            "ESPLORA_URLS",
            f"{explorer_url},https://mempool.guide" if explorer_url else "",
        )
    )
    esplora_urls = []
    for u in (esplora_pool_raw or "").split(","):
        u = u.strip().rstrip("/")
        if u and u not in esplora_urls:
            esplora_urls.append(u)
    if explorer_url and explorer_url not in esplora_urls:
        esplora_urls.insert(0, explorer_url)

    bcast_urls = []
    if broadcast_url is not None:
        if bcast_url:
            bcast_urls.append(bcast_url)
    else:
        if bcast_url:
            bcast_urls.append(bcast_url)
        for u in esplora_urls:
            tx_ep = f"{u}/api/tx"
            if tx_ep not in bcast_urls:
                bcast_urls.append(tx_ep)
    rr_state = {"idx": 0}
    use_proxy = (
        trust_proxy
        if trust_proxy is not None
        else os.getenv("BPUB_TRUST_PROXY", "0") == "1"
    )

    limits = {
        "read": (int(os.getenv("BPUB_RL_READ", "120")), 60),
        "embed": (int(os.getenv("BPUB_RL_EMBED", "15")), 60),
        "order": (int(os.getenv("BPUB_RL_ORDER", "5")), 60),
        "broadcast": (int(os.getenv("BPUB_RL_BROADCAST", "10")), 60),
        "media": (int(os.getenv("BPUB_RL_MEDIA", "300")), 60),
    }
    if rate_limits:
        limits.update(rate_limits)
    limiter = RateLimiter()

    app = FastAPI(title="BPUB On-Chain Gallery", docs_url=None, redoc_url=None)
    app.state.db = db
    app.state.media_dir = media_dir
    app.state.limiter = limiter
    app.state.order_service = order_service

    cors_raw = os.getenv("BPUB_CORS_ORIGINS", "").strip()
    if cors_raw:
        origins = [o.strip() for o in cors_raw.split(",") if o.strip()]
        if origins:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=origins,
                allow_methods=["GET", "POST"],
                allow_headers=["Content-Type"],
            )

    @app.middleware("http")
    async def security_and_rate_limit_middleware(request: Request, call_next):
        path = request.url.path
        ip = _client_ip(request, use_proxy)

        # Pre-buffering Content-Length cap to prevent memory exhaustion on large POSTs.
        cl_header = request.headers.get("content-length")
        if cl_header is not None:
            try:
                cl = int(cl_header)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
            ctype = (request.headers.get("content-type") or "").lower()
            if "multipart/form-data" in ctype:
                max_body = (
                    MAX_ORDER_MULTIPART_BODY_BYTES
                    if path.startswith("/api/orders")
                    else MAX_MULTIPART_BODY_BYTES
                )
            else:
                max_body = MAX_JSON_BODY_BYTES
            if cl > max_body:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body exceeds limit ({max_body} bytes)"},
                )

        if path.startswith("/api/tx/broadcast"):
            bucket, (lim, win) = "broadcast", limits["broadcast"]
        elif path == "/api/orders" and request.method == "POST":
            bucket, (lim, win) = "order", limits["order"]
        elif path.startswith("/api/embed/") or path.startswith("/api/orders/quote"):
            bucket, (lim, win) = "embed", limits["embed"]
        elif path.startswith("/media/"):
            bucket, (lim, win) = "media", limits["media"]
        elif path.startswith("/api/"):
            bucket, (lim, win) = "read", limits["read"]
        else:
            bucket, (lim, win) = None, (0, 0)

        if bucket is not None:
            retry_after = limiter.check(f"{bucket}:{ip}", lim, win)
            if retry_after is not None:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Please try again shortly."},
                    headers={"Retry-After": str(retry_after)},
                )

        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )

        if path.startswith("/media/"):
            response.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        else:
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data: blob:; "
                "style-src 'self'; script-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            )
        return response

    # ------------------------------------------------------------------
    # Frontend & Safe Media Serving
    # ------------------------------------------------------------------

    @app.get("/")
    def serve_index():
        idx = static_dir / "index.html"
        if not idx.is_file():
            raise HTTPException(status_code=404, detail="Frontend not found")
        return FileResponse(idx, media_type="text/html; charset=utf-8")

    @app.get("/static/{asset}")
    def serve_static(asset: str):
        if asset not in ("app.js", "styles.css"):
            raise HTTPException(status_code=404, detail="Not found")
        p = static_dir / asset
        if not p.is_file():
            raise HTTPException(status_code=404, detail="Not found")
        mt = "application/javascript; charset=utf-8" if asset.endswith(".js") else "text/css; charset=utf-8"
        return FileResponse(p, media_type=mt)

    @app.get("/media/{stored_filename}")
    def serve_media(stored_filename: str):
        if not STORED_FILENAME_RE.match(stored_filename) or ".." in stored_filename:
            raise HTTPException(status_code=400, detail="Invalid media filename")

        ext = Path(stored_filename).suffix.lower()
        if ext not in SAFE_EXTENSIONS or ext not in SAFE_MEDIA_MIMES:
            raise HTTPException(status_code=403, detail="File extension not allowed")

        resolved_media = media_dir.resolve()
        target = (media_dir / stored_filename).resolve()
        if target.parent != resolved_media or not target.is_file():
            raise HTTPException(status_code=404, detail="Media file not found")

        headers = {"Cache-Control": "public, max-age=31536000, immutable"}
        if ext not in INLINE_MEDIA_EXTS:
            headers["Content-Disposition"] = f'attachment; filename="{stored_filename}"'
        return FileResponse(target, media_type=SAFE_MEDIA_MIMES[ext], headers=headers)

    # ------------------------------------------------------------------
    # Gallery Read APIs
    # ------------------------------------------------------------------

    @app.api_route("/api/health", methods=["GET", "HEAD"])
    def api_health():
        st = db.get_stats()
        return {
            "status": "ok",
            "indexed_height": st["indexed_height"],
            "total_items": st["total_items"],
        }

    @app.get("/api/stats")
    def api_stats():
        st = db.get_stats()
        return {
            **st,
            "explorer_base_url": explorer_url,
            "broadcast_enabled": bool(bcast_url),
            "orders_enabled": order_service is not None,
            "max_upload_bytes": MAX_UPLOAD_BYTES,
            "max_order_upload_bytes": MAX_ORDER_UPLOAD_BYTES,
            "pad_version": "padv3",
        }

    @app.get("/api/items")
    def api_list_items(
        limit: int = Query(24, ge=1, le=100),
        offset: int = Query(0, ge=0, le=100_000),
        q: Optional[str] = Query(None, max_length=128),
        mime: Optional[str] = Query(None, pattern="^(image|text|other)$"),
        version: Optional[str] = Query(None, pattern="^(1|4|5)$"),
    ):
        items, total = db.list_items(
            limit=limit, offset=offset, q=q, mime_group=mime, version=version
        )
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/items/{txid}")
    def api_get_item(txid: str):
        txid_clean = _validate_txid(txid, "txid")
        item = db.get_item_by_txid(txid_clean)
        if item is None:
            raise HTTPException(status_code=404, detail="Item not found")
        return item

    @app.get("/api/id/{bpub_id}")
    def api_get_by_bpub_id(bpub_id: str):
        bpub_id_clean = _validate_txid(bpub_id, "bpub_id")
        item = db.get_item_by_bpub_id(bpub_id_clean)
        if item is None:
            raise HTTPException(status_code=404, detail="BPUB ID not found")
        return item

    @app.get("/api/utxo/{txid}/{vout}")
    def api_lookup_utxo(txid: str, vout: int):
        txid_clean = _validate_txid(txid, "txid")
        if vout < 0 or vout > 10_000:
            raise HTTPException(status_code=400, detail="Invalid vout")
        if not esplora_urls:
            raise HTTPException(status_code=503, detail="Explorer lookup disabled")
        n = len(esplora_urls)
        start = rr_state["idx"] % n
        rr_state["idx"] = (rr_state["idx"] + 1) % n
        ordered = [esplora_urls[(start + i) % n] for i in range(n)]

        tx_json = None
        saw_404 = False
        import json as _json

        for base in ordered:
            try:
                with requests.get(
                    f"{base}/api/tx/{txid_clean}",
                    headers={"User-Agent": "bpub-server/1.0"},
                    timeout=10,
                    stream=True,
                ) as resp:
                    if resp.status_code == 404:
                        saw_404 = True
                        continue
                    if resp.status_code != 200:
                        continue
                    chunks: List[bytes] = []
                    total = 0
                    for chunk in resp.iter_content(chunk_size=32 * 1024):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > MAX_UPSTREAM_EXPLORER_BYTES:
                            raise HTTPException(
                                status_code=502, detail="Explorer response too large"
                            )
                        chunks.append(chunk)
                    tx_json = _json.loads(b"".join(chunks))
                    break
            except HTTPException:
                raise
            except Exception:
                continue

        if tx_json is None:
            if saw_404:
                raise HTTPException(status_code=404, detail="Transaction not found on explorer")
            raise HTTPException(status_code=502, detail="Explorer lookup failed")
        try:
            vouts = tx_json.get("vout", [])
            out = vouts[vout]
        except Exception:
            raise HTTPException(status_code=404, detail="Output index not found")
        return {
            "txid": txid_clean,
            "vout": vout,
            "value": out.get("value"),
            "address": out.get("scriptpubkey_address"),
            "scriptpubkey_type": out.get("scriptpubkey_type"),
        }

    # ------------------------------------------------------------------
    # Custodial Lightning (LND) `padv3` Inscription Orders
    # ------------------------------------------------------------------

    @app.post("/api/orders/quote")
    async def api_order_quote(
        file: UploadFile = File(...),
        filename: str = Form(""),
        mime: str = Form("application/octet-stream"),
        compress: bool = Form(True),
    ):
        if order_service is None:
            raise HTTPException(
                status_code=503, detail="Lightning inscription service is not enabled"
            )
        data = await _read_upload_bounded(file, MAX_ORDER_UPLOAD_BYTES)
        fname = (filename or file.filename or "file.bin").strip()[:120]
        try:
            return order_service.quote(
                data=data,
                filename=fname,
                mime=(mime or "application/octet-stream").strip()[:100],
                compress=compress,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/orders")
    async def api_create_order(
        request: Request,
        file: UploadFile = File(...),
        filename: str = Form(""),
        mime: str = Form("application/octet-stream"),
        compress: bool = Form(True),
    ):
        if order_service is None:
            raise HTTPException(
                status_code=503, detail="Lightning inscription service is not enabled"
            )
        data = await _read_upload_bounded(file, MAX_ORDER_UPLOAD_BYTES)
        fname = (filename or file.filename or "file.bin").strip()[:120]
        ip = _client_ip(request, use_proxy)
        try:
            order = order_service.create_order(
                data=data,
                filename=fname,
                mime=(mime or "application/octet-stream").strip()[:100],
                compress=compress,
                client_ip=ip,
            )
        except InsufficientLiquidityError as e:
            raise HTTPException(status_code=503, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except LndError as e:
            raise HTTPException(status_code=502, detail=f"Lightning node error: {e}")
        order["payment_request_qr"] = (
            _make_bolt11_qr_data_uri(order.get("payment_request"))
            if order.get("status") == "awaiting_payment"
            else None
        )
        return order

    @app.get("/api/orders/{order_id}")
    def api_get_order(order_id: str):
        if not ORDER_ID_RE.match(order_id or ""):
            raise HTTPException(status_code=400, detail="Invalid order_id")
        if order_service is not None:
            order = order_service.process_order(order_id)
        else:
            order = db.get_order_public(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="Order not found")
        order["payment_request_qr"] = (
            _make_bolt11_qr_data_uri(order.get("payment_request"))
            if order.get("status") == "awaiting_payment"
            else None
        )
        if explorer_url:
            order["funding_explorer_url"] = (
                f"{explorer_url}/tx/{order['funding_txid']}"
                if order.get("funding_txid")
                else None
            )
            order["reveal_explorer_url"] = (
                f"{explorer_url}/tx/{order['reveal_txid']}"
                if order.get("reveal_txid")
                else None
            )
            order["part_explorer_urls"] = [
                f"{explorer_url}/tx/{ptx}" for ptx in (order.get("part_txids") or [])
            ]
        return order

    # ------------------------------------------------------------------
    # BPUB v5 `padv3` Embed Builder APIs
    # ------------------------------------------------------------------

    @app.post("/api/embed/estimate")
    def api_embed_estimate(req: EstimateRequest):
        eff_rev = req.reveal_feerate if req.reveal_feerate is not None else req.feerate
        # Conservative stream size estimate (48B header + ~120B compressed meta + content)
        est_stream = req.size_bytes + 48 + 120
        n_pubkeys = (est_stream + 30) // 31
        n_outputs = max(1, (n_pubkeys + 9) // 10)
        values = bpub.bpub_output_values(n_outputs, eff_rev, pad_suffix=True)
        fund_fee = bpub.estimate_fee_funding(
            n_in_p2wpkh=1, n_out_p2wsh=n_outputs + 1, n_out_p2wpkh=1, feerate=req.feerate
        )
        reveal_fee = bpub.estimate_fee_reveal(
            n_inputs=n_outputs, n_outputs=1, feerate=eff_rev, pad_suffix=True
        )
        owner_sats = req.owner_value
        min_funding_utxo = fund_fee + sum(values) + owner_sats + bpub.BPUB_DUST
        return {
            "pad_version": "padv3",
            "data_outputs": n_outputs,
            "per_output_sats": values[0],
            "bpub_outputs_total_sats": sum(values),
            "owner_output_sats": owner_sats,
            "funding_fee_sats": fund_fee,
            "reveal_fee_sats": reveal_fee,
            "min_funding_utxo_sats": min_funding_utxo,
            "fits_single_tx": n_outputs <= 630,
        }

    @app.post("/api/embed/fund-psbt")
    async def api_embed_fund_psbt(
        file: UploadFile = File(...),
        filename: str = Form(""),
        mime: str = Form("application/octet-stream"),
        compress: bool = Form(True),
        control_pubkey: str = Form(...),
        owner_address: str = Form(...),
        owner_value: int = Form(10_000),
        utxo: str = Form(...),
        value: int = Form(...),
        prev_address: str = Form(...),
        change: str = Form(...),
        feerate: int = Form(1),
        reveal_feerate: Optional[int] = Form(None),
    ):
        data = await _read_upload_bounded(file, MAX_UPLOAD_BYTES)
        ctrl_pk = _validate_pubkey(control_pubkey.strip())
        _validate_feerate(feerate, "feerate")
        if reveal_feerate is not None:
            _validate_feerate(reveal_feerate, "reveal_feerate")
        fname = (filename or file.filename or "file.bin").strip()[:120]
        return _build_padv3_funding_psbt(
            data=data,
            filename=fname,
            mime=(mime or "application/octet-stream").strip()[:100],
            compress=compress,
            control_pubkey=ctrl_pk,
            owner_address=owner_address,
            owner_value=owner_value,
            utxo_str=utxo,
            utxo_value=value,
            prev_address=prev_address,
            change_address=change,
            feerate=feerate,
            reveal_feerate=reveal_feerate,
        )

    @app.post("/api/embed/reveal-psbt")
    async def api_embed_reveal_psbt(
        file: UploadFile = File(...),
        filename: str = Form(""),
        mime: str = Form("application/octet-stream"),
        compress: bool = Form(True),
        control_pubkey: str = Form(...),
        bpub_utxos: str = Form(...),  # newline- or comma-separated TXID:VOUT:VALUE
        change: str = Form(...),
        feerate: int = Form(1),
    ):
        data = await _read_upload_bounded(file, MAX_UPLOAD_BYTES)
        ctrl_pk = _validate_pubkey(control_pubkey.strip())
        _validate_feerate(feerate, "feerate")
        utxo_list = [
            tok.strip()
            for tok in re.split(r"[\s,]+", bpub_utxos.strip())
            if tok.strip()
        ]
        if not utxo_list or len(utxo_list) > 630:
            raise HTTPException(status_code=400, detail="Invalid bpub_utxos list")
        fname = (filename or file.filename or "file.bin").strip()[:120]
        return _build_padv3_reveal_psbt(
            data=data,
            filename=fname,
            mime=(mime or "application/octet-stream").strip()[:100],
            compress=compress,
            control_pubkey=ctrl_pk,
            bpub_utxo_list=utxo_list,
            change_address=change,
            feerate=feerate,
        )

    # ------------------------------------------------------------------
    # Validated Transaction Broadcaster (mempool.kilombino.com)
    # ------------------------------------------------------------------

    @app.post("/api/tx/broadcast")
    def api_broadcast_tx(req: BroadcastRequest):
        if not bcast_urls:
            raise HTTPException(status_code=503, detail="Broadcasting is disabled")

        raw_hex = req.raw_hex.strip()
        if len(raw_hex) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", raw_hex):
            raise HTTPException(status_code=400, detail="Invalid transaction hex")

        try:
            raw_bytes = bytes.fromhex(raw_hex)
            tx = CTransaction.deserialize(raw_bytes)
        except Exception:
            raise HTTPException(status_code=400, detail="Malformed Bitcoin transaction")

        if not tx.vin or not tx.vout:
            raise HTTPException(status_code=400, detail="Transaction must have inputs and outputs")

        expected_txid = tx.GetTxid()[::-1].hex()
        last_reject = None
        for ep in bcast_urls:
            try:
                resp = requests.post(
                    ep,
                    data=raw_hex,
                    headers={
                        "Content-Type": "text/plain",
                        "User-Agent": "bpub-server/1.0",
                    },
                    timeout=15,
                )
            except requests.RequestException:
                continue

            if resp.status_code == 200:
                returned_txid = resp.text.strip()
                txid_out = returned_txid if TXID_RE.match(returned_txid) else expected_txid
                return {
                    "txid": txid_out,
                    "explorer_url": f"{explorer_url}/tx/{txid_out}" if explorer_url else None,
                }
            if resp.status_code in (403, 429) or resp.status_code >= 500:
                continue
            last_reject = (resp.text or "Broadcast rejected").strip()[:300]
            break

        if last_reject is not None:
            raise HTTPException(status_code=400, detail=f"Broadcast rejected: {last_reject}")
        raise HTTPException(status_code=502, detail="Upstream broadcast endpoints unreachable")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("BPUB_HOST", "0.0.0.0")
    port = int(os.getenv("BPUB_PORT", "8888"))
    uvicorn.run("server:app", host=host, port=port)
