#!/usr/bin/env python3
"""
BPUB indexer: scan the Bitcoin blockchain for BPUB reveal transactions
(v3.5 legacy, v4 stealth, and v5 stealth with ownership) and build a simple
on-disk "gallery":

    GALLERY_DIR/
      manifest.json
      media/
        <txid>_<safe_filename>

- Connects to bitcoind via RPC.
- Starts from a configured height (and optional hash sanity-check).
- Runs forever, polling for new blocks.
- Auto-detects BPUB-style 1-of-N multisig P2WSH spends (legacy suffix-free,
  padv1, padv2, padv3, and unknown trailing suffixes) via
  bpub.parse_bpub_multisig() and reconstructs the embedded BPUB stream via
  bpub.decode_*().

This works with:

- BPUB v3.5 streams (with "BPUB" magic + TLV header).
- BPUB v4/v5 stealth streams (headerless, raw DEFLATE + XOR).
"""

import os
import sys
import time
import json
import re
import io
import struct
import hashlib
from pathlib import Path
from typing import Optional, Tuple, List

import requests

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

try:
    from bitcoinrpc.authproxy import AuthServiceProxy
except ImportError:
    AuthServiceProxy = None

from bitcointx.core import CTransaction
from bitcointx.core.script import CScript
from bitcointx.wallet import P2WPKHBitcoinAddress, P2WSHBitcoinAddress

from bpub import (
    assemble_multipart,
    decode_pubkeys_to_stream,
    decode_stream,
    decode_owner_redeem_script,
    encode_manifest,
    is_manifest_meta,
    is_part_meta,
    manifest_file_meta,
    parse_bpub_multisig,
    parse_manifest,
)
from db import BpubDB


def load_config():
    """Load config from .env and environment variables."""
    if load_dotenv is not None:
        load_dotenv()

    rpc_user = os.getenv("BITCOIN_RPC_USER", "").strip()
    rpc_pass = os.getenv("BITCOIN_RPC_PASSWORD", "").strip()
    rpc_host = os.getenv("BITCOIN_RPC_HOST", "127.0.0.1").strip()
    rpc_port = os.getenv("BITCOIN_RPC_PORT", "8332").strip()

    explorer_url = os.getenv("EXPLORER_BASE_URL", "https://mempool.kilombino.com").strip().rstrip("/")
    esplora_urls_raw = os.getenv(
        "ESPLORA_URLS",
        "https://mempool.kilombino.com,https://mempool.guide",
    ).strip()
    esplora_urls = [u.strip().rstrip("/") for u in esplora_urls_raw.split(",") if u.strip()]
    if not esplora_urls and explorer_url:
        esplora_urls = [explorer_url]

    source = os.getenv("INDEXER_SOURCE", "").strip().lower()
    if not source:
        source = "rpc" if (rpc_user and rpc_pass) else "esplora"
    if source not in ("rpc", "esplora"):
        sys.exit("INDEXER_SOURCE must be 'rpc' or 'esplora'")
    if source == "rpc" and (not rpc_user or not rpc_pass):
        sys.exit("BITCOIN_RPC_USER and BITCOIN_RPC_PASSWORD must be set when INDEXER_SOURCE=rpc")
    if source == "esplora" and not esplora_urls:
        sys.exit("ESPLORA_URLS or EXPLORER_BASE_URL must be set when INDEXER_SOURCE=esplora")

    gallery_dir = os.getenv("GALLERY_DIR", "gallery").strip() or "gallery"

    start_height_str = os.getenv("START_HEIGHT", "961640")
    try:
        start_height = int(start_height_str)
    except ValueError:
        sys.exit("START_HEIGHT must be an integer")

    poll_interval = int(os.getenv("POLL_INTERVAL", "30"))
    esplora_delay = max(0.0, float(os.getenv("ESPLORA_REQUEST_DELAY", "0.25")))

    return {
        "source": source,
        "rpc_user": rpc_user,
        "rpc_pass": rpc_pass,
        "rpc_host": rpc_host,
        "rpc_port": rpc_port,
        "explorer_url": explorer_url,
        "esplora_urls": esplora_urls,
        "esplora_delay": esplora_delay,
        "gallery_dir": Path(gallery_dir),
        "start_height": start_height,
        "poll_interval": poll_interval,
    }


def _read_compact_size(stream: io.BytesIO) -> int:
    b = stream.read(1)
    if not b:
        raise ValueError("Unexpected EOF reading compactSize")
    n = b[0]
    if n < 0xFD:
        return n
    if n == 0xFD:
        return struct.unpack("<H", stream.read(2))[0]
    if n == 0xFE:
        return struct.unpack("<I", stream.read(4))[0]
    return struct.unpack("<Q", stream.read(8))[0]


def parse_raw_block(raw_bytes: bytes, blockhash: str = "") -> dict:
    """
    Deserialize a raw Bitcoin (80-byte header) or BLAKE2b (164-byte header,
    version bit 0x80000000 set) block into the verbosity-2 block dict shape
    expected by `index_block()`.
    """
    if len(raw_bytes) < 81:
        raise ValueError("Raw block too short")
    version = struct.unpack_from("<I", raw_bytes, 0)[0]
    header_len = 164 if (version & 0x80000000) else 80
    if len(raw_bytes) < header_len + 1:
        raise ValueError("Raw block shorter than header")

    block_time = struct.unpack_from("<I", raw_bytes, 68)[0]
    stream = io.BytesIO(raw_bytes[header_len:])
    tx_count = _read_compact_size(stream)
    txs = []
    for _ in range(tx_count):
        tx = CTransaction.stream_deserialize(stream)
        txid = tx.GetTxid()[::-1].hex()
        tx_hex = tx.serialize(include_witness=True).hex()
        vins = []
        wit = getattr(tx, "wit", None)
        for idx, vin in enumerate(tx.vin):
            if vin.prevout.is_null():
                vins.append({"coinbase": bytes(vin.scriptSig).hex()})
                continue
            vin_d = {}
            if wit is not None and idx < len(wit.vtxinwit):
                stack = list(wit.vtxinwit[idx].scriptWitness.stack)
                if stack:
                    vin_d["txinwitness"] = [bytes(item).hex() for item in stack]
            vins.append(vin_d)
        txs.append({"txid": txid, "hex": tx_hex, "vin": vins})
    return {"hash": blockhash, "time": block_time, "tx": txs}


class EsploraBlockClient:
    """
    Drop-in RPC-compatible block reader backed by one or more Esplora / mempool
    APIs (e.g. mempool.kilombino.com + mempool.guide). Round-robins requests
    with per-host pacing and automatic failover + cooldown on 429/5xx/errors.
    """

    def __init__(self, base_urls, request_delay: float = 0.25, timeout: int = 30):
        if isinstance(base_urls, str):
            urls = [u.strip().rstrip("/") for u in base_urls.split(",") if u.strip()]
        else:
            urls = [str(u).strip().rstrip("/") for u in base_urls if str(u).strip()]
        if not urls:
            raise ValueError("At least one Esplora URL is required")
        self.apis = [f"{u}/api" for u in urls]
        self.request_delay = max(0.0, float(request_delay))
        self.timeout = timeout
        self._rr = 0
        self._last_req = {api: 0.0 for api in self.apis}
        self._cooldown_until = {api: 0.0 for api in self.apis}
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "bpub-indexer/1.0"

    def _ordered_apis(self) -> List[str]:
        n = len(self.apis)
        start = self._rr % n
        self._rr = (self._rr + 1) % n
        rotated = [self.apis[(start + i) % n] for i in range(n)]
        now = time.monotonic()
        healthy = [a for a in rotated if self._cooldown_until[a] <= now]
        cooling = [a for a in rotated if self._cooldown_until[a] > now]
        cooling.sort(key=lambda a: self._cooldown_until[a])
        return healthy + cooling

    def _get(self, path: str, expect_bytes: bool = False):
        last_err = None
        for round_idx in range(3):
            for api in self._ordered_apis():
                now = time.monotonic()
                cd_wait = self._cooldown_until[api] - now
                if cd_wait > 0 and round_idx > 0:
                    time.sleep(min(30.0, cd_wait))
                wait = self.request_delay - (time.monotonic() - self._last_req[api])
                if wait > 0:
                    time.sleep(wait)
                self._last_req[api] = time.monotonic()
                try:
                    resp = self._session.get(f"{api}{path}", timeout=self.timeout)
                except requests.RequestException as e:
                    self._cooldown_until[api] = time.monotonic() + 10.0
                    last_err = e
                    continue
                if resp.status_code in (403, 429):
                    retry_after = int(resp.headers.get("Retry-After") or (2 ** (round_idx + 1)))
                    self._cooldown_until[api] = time.monotonic() + min(60, max(2, retry_after))
                    last_err = RuntimeError(f"HTTP {resp.status_code} from {api}{path}")
                    continue
                if resp.status_code >= 500:
                    self._cooldown_until[api] = time.monotonic() + 10.0
                    last_err = RuntimeError(f"HTTP {resp.status_code} from {api}{path}")
                    continue
                if resp.status_code != 200:
                    raise RuntimeError(
                        f"Esplora GET {api}{path} HTTP {resp.status_code}: {resp.text[:200]}"
                    )
                return resp.content if expect_bytes else resp.text.strip()
        raise RuntimeError(f"All Esplora backends failed for {path}: {last_err}")

    def getblockcount(self) -> int:
        return int(self._get("/blocks/tip/height"))

    def getblockhash(self, height: int) -> str:
        return str(self._get(f"/block-height/{int(height)}"))

    def getblock(self, blockhash: str, verbosity: int = 2) -> dict:
        raw = self._get(f"/block/{blockhash}/raw", expect_bytes=True)
        return parse_raw_block(raw, blockhash=blockhash)


def make_rpc(config):
    if config.get("source") == "esplora":
        return EsploraBlockClient(
            config.get("esplora_urls") or config["explorer_url"],
            request_delay=config.get("esplora_delay", 0.25),
        )
    if AuthServiceProxy is None:
        sys.exit("python-bitcoinrpc is required when INDEXER_SOURCE=rpc")
    uri = (
        f"http://{config['rpc_user']}:{config['rpc_pass']}@"
        f"{config['rpc_host']}:{config['rpc_port']}"
    )
    return AuthServiceProxy(uri)


def load_manifest(gallery_dir: Path):
    """Load (or initialize) manifest.json and known txid set."""
    manifest_path = gallery_dir / "manifest.json"
    media_dir = gallery_dir / "media"
    media_dir.mkdir(parents=True, exist_ok=True)

    if manifest_path.exists():
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        if not isinstance(manifest, list):
            manifest = []
    else:
        manifest = []

    known_txids = {entry.get("txid") for entry in manifest if "txid" in entry}
    return manifest, known_txids, manifest_path, media_dir


def save_manifest(manifest, manifest_path: Path):
    manifest_sorted = sorted(
        manifest,
        key=lambda e: (e.get("block_height", 0), e.get("txid", "")),
    )
    tmp = manifest_path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(manifest_sorted, f, indent=2)
    tmp.replace(manifest_path)


def load_ownership(gallery_dir: Path):
    """Load (or initialize) ownership.json mapping BPUB v5 IDs to current owner info."""
    ownership_path = gallery_dir / "ownership.json"
    if ownership_path.exists():
        try:
            with open(ownership_path, "r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                data = {}
        except Exception:
            data = {}
    else:
        data = {}
    return data, ownership_path


def save_ownership(ownership, ownership_path: Path):
    tmp = ownership_path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(ownership, f, indent=2, sort_keys=True)
    tmp.replace(ownership_path)


SAFE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".txt", ".bin"}
MAX_BASENAME_LEN = 120


def safe_filename(name) -> str:
    """Sanitize filename for filesystem (bounded length, no leading dots)."""
    if not isinstance(name, str):
        return "file"
    name = name.strip()
    if not name:
        return "file"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")
    if not name:
        return "file"
    return name[:MAX_BASENAME_LEN]


def guess_extension(mime: Optional[str], existing_name: str) -> str:
    """
    Enforce an allowlist of safe non-active extensions so untrusted on-chain
    files (e.g. .html, .svg, .js) are never served inline as active content.
    """
    p = Path(existing_name)
    suffix = p.suffix.lower()
    if suffix in SAFE_EXTENSIONS:
        stem = p.stem[: MAX_BASENAME_LEN - len(suffix)] or "file"
        return f"{stem}{suffix}"

    ext = ""
    if isinstance(mime, str):
        m = mime.lower()
        if "jpeg" in m or m == "image/jpg":
            ext = ".jpg"
        elif "png" in m:
            ext = ".png"
        elif "gif" in m:
            ext = ".gif"
        elif "webp" in m:
            ext = ".webp"
        elif m == "text/plain" or m.startswith("text/plain;"):
            ext = ".txt"
    if not ext:
        ext = ".bin"

    # Flatten any unsafe dots/extensions in the stem to avoid double-extension
    # ambiguity on static file servers.
    stem = existing_name.replace(".", "_")[: MAX_BASENAME_LEN - len(ext)] or "file"
    return f"{stem}{ext}"


def make_stored_filename(txid: str, filename_meta, mime) -> str:
    """Build a bounded, safe on-disk filename '<txid>_<safe_name><safe_ext>'."""
    safe_txid = re.sub(r"[^0-9a-fA-F]", "", txid or "")[:64] or "tx"
    base_name = safe_filename(filename_meta if isinstance(filename_meta, str) and filename_meta.strip() else "file")
    name_with_ext = guess_extension(mime, base_name)
    return f"{safe_txid}_{name_with_ext}"


def _tx_maybe_bpub_reveal(tx_dict: dict) -> bool:
    """
    Fast pre-filter on getblock(..., 2) transaction JSON before deserializing.
    A BPUB 1-of-N multisig P2WSH witness script is >= 70 bytes (>= 140 hex chars)
    and begins with 0x51 0x21 (OP_1 PUSH33).
    """
    vins = tx_dict.get("vin")
    if not isinstance(vins, list):
        return True
    saw_witness_field = False
    for vin in vins:
        wit = vin.get("txinwitness")
        if not isinstance(wit, list):
            continue
        saw_witness_field = True
        if len(wit) >= 2:
            last = wit[-1]
            if isinstance(last, str) and len(last) >= 140 and last[:4].lower() == "5121":
                return True
    # If RPC returned decoded vins (standard verbosity=2) and none matched, skip.
    return not saw_witness_field and not any("coinbase" in v for v in vins if isinstance(v, dict))


def _tx_maybe_bpub_owner(tx_dict: dict) -> bool:
    """
    Fast pre-filter on getblock(..., 2) transaction JSON for v5 ownership spends.
    An owner P2WSH redeemScript is always exactly 59 bytes (118 hex chars):
      20 <32B bpub_id> 75 76 a9 14 <20B h160> 88 ac
    """
    vins = tx_dict.get("vin")
    if not isinstance(vins, list):
        return True
    for vin in vins:
        wit = vin.get("txinwitness")
        if not isinstance(wit, list) or len(wit) < 2:
            continue
        last = wit[-1]
        if (
            isinstance(last, str)
            and len(last) == 118
            and last[:2].lower() == "20"
            and last[66:74].lower() == "7576a914"
        ):
            return True
    return False


def try_extract_bpub_from_tx(rawtx_hex: str):
    """
    Try to detect and extract a BPUB stream (v3.5 or v4/v5) from a transaction.

    Returns:
      (meta, content) on success, or None if no BPUB-like multisig is found
      or decoding fails.
    """
    try:
        tx = CTransaction.deserialize(bytes.fromhex(rawtx_hex))
    except Exception:
        return None

    wit = getattr(tx, "wit", None)
    if wit is None or len(wit.vtxinwit) == 0:
        return None

    all_data_pubkeys: List[bytes] = []
    detected_controls: List[bytes] = []
    funding_txids = set()
    suffix_kinds = set()

    for idx, vin in enumerate(tx.vin):
        if idx >= len(tx.wit.vtxinwit):
            continue

        inwit = tx.wit.vtxinwit[idx]
        wstack = list(inwit.scriptWitness.stack)
        if len(wstack) < 2:
            continue

        redeem_script = bytes(wstack[-1])
        # Fast byte check: OP_1 (0x51) + PUSH33 (0x21) and >= 70 bytes.
        if len(redeem_script) < 70 or redeem_script[0] != 0x51 or redeem_script[1] != 0x21:
            continue
        parsed = parse_bpub_multisig(redeem_script)
        if parsed is None:
            continue

        data_pks, control_pk_here, suffix_kind = parsed
        detected_controls.append(control_pk_here)
        funding_txids.add(vin.prevout.hash[::-1].hex())
        suffix_kinds.add(suffix_kind)
        all_data_pubkeys.extend(data_pks)

    if not all_data_pubkeys:
        return None

    unique_controls = {pk for pk in detected_controls}
    if len(unique_controls) > 1:
        return None

    try:
        raw_stream = decode_pubkeys_to_stream(all_data_pubkeys)
        meta, content = decode_stream(raw_stream)
    except Exception:
        return None

    if "bpub_version" not in meta:
        meta["bpub_version"] = "unknown"

    if len(suffix_kinds) == 1:
        meta["script_suffix"] = next(iter(suffix_kinds))
    else:
        meta["script_suffix"] = "mixed"

    meta["funding_txids"] = sorted(funding_txids)

    return meta, content


def try_extract_owner_from_tx(rawtx_hex: str):
    """
    Try to detect a BPUB v5 ownership spend in a transaction and extract
    chain-of-custody info (spent outpoint, signer owner, and destination
    P2WSH owner output).

    Returns a dict or None if no owner spend is found.
    """
    try:
        tx = CTransaction.deserialize(bytes.fromhex(rawtx_hex))
    except Exception:
        return None

    wit = getattr(tx, "wit", None)
    if wit is None or len(wit.vtxinwit) == 0:
        return None

    for idx, vin in enumerate(tx.vin):
        if idx >= len(tx.wit.vtxinwit):
            continue

        inwit = tx.wit.vtxinwit[idx]
        wstack = list(inwit.scriptWitness.stack)
        if len(wstack) < 2:
            continue

        redeem_script = bytes(wstack[-1])
        # Fast byte check: 59-byte v5 owner redeemScript.
        if (
            len(redeem_script) != 59
            or redeem_script[0] != 0x20
            or redeem_script[33:37] != b"\x75\x76\xa9\x14"
        ):
            continue
        try:
            bpub_id_bytes, owner_h160 = decode_owner_redeem_script(redeem_script)
        except Exception:
            continue

        bpub_id_hex = bpub_id_bytes.hex()
        owner_h160_hex = owner_h160.hex()
        spent_txid = vin.prevout.hash[::-1].hex()
        spent_vout = int(vin.prevout.n)
        spent_outpoint = f"{spent_txid}:{spent_vout}"

        # Signer's (input) P2WSH and canonical P2WPKH addresses
        signer_spk_p2wsh = b"\x00\x20" + hashlib.sha256(redeem_script).digest()
        signer_p2wsh_addr = str(
            P2WSHBitcoinAddress.from_scriptPubKey(CScript(signer_spk_p2wsh))
        )
        signer_spk_p2wpkh = b"\x00\x14" + owner_h160
        signer_p2wpkh_addr = str(
            P2WPKHBitcoinAddress.from_scriptPubKey(CScript(signer_spk_p2wpkh))
        )

        # Inspect outputs: a self-transfer pays back to signer_spk_p2wsh (keeping
        # P2WPKH known); a transfer to a new owner pays to a different P2WSH
        # output (new owner's P2WPKH remains hashed until they spend it).
        self_outputs = []
        p2wsh_outputs = []
        for vout_index, out in enumerate(tx.vout):
            spk = bytes(out.scriptPubKey)
            if spk == signer_spk_p2wsh:
                self_outputs.append(
                    {
                        "vout": vout_index,
                        "value_sats": int(out.nValue),
                        "p2wsh": signer_p2wsh_addr,
                    }
                )
            if len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
                p2wsh_outputs.append(
                    {
                        "vout": vout_index,
                        "value_sats": int(out.nValue),
                        "p2wsh": str(
                            P2WSHBitcoinAddress.from_scriptPubKey(CScript(spk))
                        ),
                    }
                )

        if self_outputs:
            dest = self_outputs[0]
            new_owner_p2wpkh = signer_p2wpkh_addr
            new_owner_p2wsh = dest["p2wsh"]
            dest_vout = dest["vout"]
            owner_outputs = [
                {"vout": o["vout"], "value_sats": o["value_sats"]}
                for o in self_outputs
            ]
        elif p2wsh_outputs:
            dest = p2wsh_outputs[0]
            new_owner_p2wpkh = None
            new_owner_p2wsh = dest["p2wsh"]
            dest_vout = dest["vout"]
            owner_outputs = [
                {"vout": dest["vout"], "value_sats": dest["value_sats"]}
            ]
        else:
            new_owner_p2wpkh = None
            new_owner_p2wsh = None
            dest_vout = None
            owner_outputs = []

        return {
            "bpub_id": bpub_id_hex,
            "spent_txid": spent_txid,
            "spent_vout": spent_vout,
            "spent_outpoint": spent_outpoint,
            "signer_h160": owner_h160_hex,
            "signer_p2wpkh": signer_p2wpkh_addr,
            "signer_p2wsh": signer_p2wsh_addr,
            "owner_h160": owner_h160_hex if new_owner_p2wpkh else None,
            "owner_p2wpkh": new_owner_p2wpkh,
            "owner_p2wsh": new_owner_p2wsh,
            "dest_vout": dest_vout,
            "owner_outputs": owner_outputs,
        }

    return None


def register_bpub_genesis(
    ownership: dict, bpub_id_hex: str, funding_txids: List[str]
) -> bool:
    """Anchor genesis ownership tracking for a newly revealed v5 BPUB."""
    if not bpub_id_hex or bpub_id_hex in ownership:
        return False
    ownership[bpub_id_hex] = {
        "bpub_id": bpub_id_hex,
        "funding_txids": sorted(set(funding_txids or [])),
        "current_outpoint": None,
        "current_owner_p2wpkh": None,
        "current_owner_p2wsh": None,
        "outputs": [],
    }
    return True


def apply_owner_update(
    ownership: dict,
    owner_info: dict,
    txid: str,
    block_height: int,
    block_hash: str,
    block_time,
) -> bool:
    """
    Apply a verified ownership transition to `ownership` only if the spent
    outpoint chains cleanly from either:
      - the BPUB's original funding transaction (genesis spend), or
      - the currently tracked owner outpoint (subsequent transfer).

    Returns True if ownership state was updated, False if ignored.
    """
    bpub_id_hex = owner_info.get("bpub_id")
    if not bpub_id_hex or bpub_id_hex not in ownership:
        return False

    cur = ownership[bpub_id_hex]
    tracked_outpoint = cur.get("current_outpoint")
    funding_txids = cur.get("funding_txids") or []

    if tracked_outpoint is None:
        # Genesis ownership spend must consume an output from the BPUB's
        # funding transaction.
        if owner_info.get("spent_txid") not in funding_txids:
            return False
    else:
        if owner_info.get("spent_outpoint") != tracked_outpoint:
            return False

    dest_vout = owner_info.get("dest_vout")
    next_outpoint = f"{txid}:{dest_vout}" if dest_vout is not None else None
    ownership[bpub_id_hex] = {
        "bpub_id": bpub_id_hex,
        "funding_txids": funding_txids,
        "current_outpoint": next_outpoint,
        "current_owner_p2wpkh": owner_info.get("owner_p2wpkh"),
        "current_owner_p2wsh": owner_info.get("owner_p2wsh"),
        "last_signer_p2wpkh": owner_info.get("signer_p2wpkh"),
        "txid": txid,
        "block_height": block_height,
        "block_hash": block_hash,
        "time": block_time,
        "outputs": owner_info.get("owner_outputs", []),
    }
    return True


def load_state(gallery_dir: Path, default_height: int):
    state_path = gallery_dir / "indexer_state.json"
    if state_path.exists():
        try:
            with open(state_path, "r") as f:
                st = json.load(f)
            return st.get("next_height", default_height), state_path
        except Exception:
            return default_height, state_path
    else:
        return default_height, state_path


def save_state(state_path: Path, next_height: int):
    tmp = state_path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump({"next_height": next_height}, f)
    tmp.replace(state_path)


def _try_assemble_manifest_tx(
    conn,
    db: BpubDB,
    media_dir: Path,
    media_dir_resolved: Path,
    parts_dir: Path,
    parts_dir_resolved: Path,
    mrow: dict,
) -> bool:
    """
    Attempt to assemble a stored multipart manifest if all its referenced part
    inscriptions are present in `multipart_parts`. Returns True if newly
    assembled and inserted into `items`.
    """
    manifest_txid = mrow["txid"]
    if db.has_item_tx(conn, manifest_txid):
        db.mark_multipart_manifest_assembled_tx(conn, manifest_txid)
        return False

    try:
        manifest = parse_manifest(mrow["manifest_json"].encode("utf-8"))
    except Exception as e:
        sys.stderr.write(f"[WARN] Corrupt stored manifest {manifest_txid}: {e}\n")
        return False

    part_txids = manifest["parts"]
    found_parts = db.get_multipart_parts_tx(conn, part_txids)
    if len(found_parts) < len(set(part_txids)):
        return False

    part_contents: List[bytes] = []
    for ptxid in part_txids:
        prec = found_parts.get(ptxid)
        if prec is None:
            return False
        ppath = (parts_dir / prec["stored_path"]).resolve()
        if ppath.parent != parts_dir_resolved or not ppath.is_file():
            return False
        part_contents.append(ppath.read_bytes())

    try:
        content = assemble_multipart(manifest, part_contents)
    except Exception as e:
        sys.stderr.write(
            f"[WARN] Failed assembling multipart manifest {manifest_txid}: {e}\n"
        )
        return False

    file_meta = manifest_file_meta(manifest)
    filename_meta = file_meta.get("filename")
    mime = file_meta.get("mime")
    size = file_meta["size"]
    bpub_id_hex = file_meta["bpub_id"].hex()

    stored_name = make_stored_filename(manifest_txid, filename_meta, mime)
    out_path = (media_dir / stored_name).resolve()
    if out_path.parent != media_dir_resolved:
        sys.stderr.write(
            f"[WARN] Refusing unsafe output path for multipart manifest {manifest_txid}\n"
        )
        return False

    if not out_path.exists():
        with open(out_path, "wb") as f:
            f.write(content)

    try:
        funding_txids = json.loads(mrow.get("funding_txids_json") or "[]")
    except Exception:
        funding_txids = []

    entry = {
        "txid": manifest_txid,
        "block_height": int(mrow["block_height"]),
        "block_hash": str(mrow.get("block_hash") or ""),
        "time": mrow.get("block_time"),
        "filename": filename_meta if isinstance(filename_meta, str) else None,
        "stored_filename": stored_name,
        "mime": mime,
        "size": size,
        "bpub_version": 5,
        "script_suffix": mrow.get("script_suffix"),
        "bpub_id": bpub_id_hex,
        "funding_txids": funding_txids,
        "parts_count": len(part_txids),
    }

    inserted = db.insert_item_tx(conn, entry)
    db.register_genesis_tx(conn, bpub_id_hex, funding_txids)
    db.mark_multipart_manifest_assembled_tx(conn, manifest_txid)
    sys.stderr.write(
        f"[FOUND] BPUB v5 multipart file in tx {manifest_txid}: "
        f"{stored_name} ({size} bytes, {len(part_txids)} parts, mime={mime})\n"
    )
    return inserted


def index_block(db: BpubDB, media_dir: Path, block: dict, height: int) -> Tuple[int, int]:
    """
    Scan a single verbosity-2 block dict and persist all BPUB reveals
    (including multipart v1 parts & manifests), verified v5 ownership updates,
    and the updated next_height atomically in SQLite. Returns
    (reveals_indexed, owner_updates_applied).
    """
    blockhash = str(block.get("hash") or "")
    block_time = block.get("time", None)
    txs = block.get("tx", [])
    media_dir.mkdir(parents=True, exist_ok=True)
    media_dir_resolved = media_dir.resolve()
    parts_dir = media_dir.parent / "parts"
    parts_dir.mkdir(parents=True, exist_ok=True)
    parts_dir_resolved = parts_dir.resolve()

    reveals_count = 0
    owners_count = 0

    with db.transaction() as conn:
        # Pass 1: extract BPUB reveals (single, multipart parts, multipart manifests)
        # and anchor v5 genesis ownership.
        for tx in txs:
            txid = tx.get("txid")
            raw_hex = tx.get("hex")
            if not txid or not raw_hex:
                continue
            if not _tx_maybe_bpub_reveal(tx):
                continue
            if (
                db.has_item_tx(conn, txid)
                or db.has_multipart_part_tx(conn, txid)
                or db.has_multipart_manifest_tx(conn, txid)
            ):
                continue

            try:
                res = try_extract_bpub_from_tx(raw_hex)
                if not res:
                    continue

                meta, content = res

                # Multipart part inscription: store privately outside media/ so
                # raw parts never appear as gallery items, then try assembling
                # any waiting manifests that reference this part.
                if is_part_meta(meta):
                    safe_txid = re.sub(r"[^0-9a-fA-F]", "", txid)[:64].lower()
                    part_fname = f"{safe_txid}.part"
                    part_path = (parts_dir / part_fname).resolve()
                    if part_path.parent != parts_dir_resolved:
                        sys.stderr.write(
                            f"[WARN] Refusing unsafe part path for tx {txid}\n"
                        )
                        continue
                    if not part_path.exists():
                        with open(part_path, "wb") as f:
                            f.write(content)
                    db.insert_multipart_part_tx(
                        conn, txid, height, blockhash, part_fname, len(content)
                    )
                    for pending_m in db.list_pending_multipart_manifests_tx(conn):
                        if _try_assemble_manifest_tx(
                            conn,
                            db,
                            media_dir,
                            media_dir_resolved,
                            parts_dir,
                            parts_dir_resolved,
                            pending_m,
                        ):
                            reveals_count += 1
                    continue

                # Multipart manifest inscription: validate schema, persist, and
                # assemble immediately if all parts are already indexed.
                if is_manifest_meta(meta):
                    try:
                        manifest = parse_manifest(content)
                    except ValueError as e:
                        sys.stderr.write(
                            f"[WARN] Ignoring invalid multipart manifest in tx {txid}: {e}\n"
                        )
                        continue
                    canonical_json = encode_manifest(manifest).decode("utf-8")
                    funding_txids = meta.get("funding_txids", [])
                    db.insert_multipart_manifest_tx(
                        conn,
                        txid=txid,
                        block_height=height,
                        block_hash=blockhash,
                        block_time=block_time,
                        script_suffix=meta.get("script_suffix"),
                        funding_txids=funding_txids,
                        manifest_json=canonical_json,
                    )
                    mrow = {
                        "txid": txid,
                        "block_height": height,
                        "block_hash": blockhash,
                        "block_time": block_time,
                        "script_suffix": meta.get("script_suffix"),
                        "funding_txids_json": json.dumps(funding_txids),
                        "manifest_json": canonical_json,
                    }
                    if _try_assemble_manifest_tx(
                        conn,
                        db,
                        media_dir,
                        media_dir_resolved,
                        parts_dir,
                        parts_dir_resolved,
                        mrow,
                    ):
                        reveals_count += 1
                    continue

                filename_meta = meta.get("filename")
                mime = meta.get("mime") if isinstance(meta.get("mime"), str) else None
                size = meta.get("size")
                bpub_version = meta.get("bpub_version")

                stored_name = make_stored_filename(txid, filename_meta, mime)
                out_path = (media_dir / stored_name).resolve()
                if out_path.parent != media_dir_resolved:
                    sys.stderr.write(
                        f"[WARN] Refusing unsafe output path for tx {txid}\n"
                    )
                    continue

                if not out_path.exists():
                    with open(out_path, "wb") as f:
                        f.write(content)

                bpub_id_val = meta.get("bpub_id")
                bpub_id_hex = None
                if bpub_id_val is not None:
                    bpub_id_hex = (
                        bpub_id_val.hex()
                        if isinstance(bpub_id_val, (bytes, bytearray))
                        else str(bpub_id_val)
                    )

                entry = {
                    "txid": txid,
                    "block_height": height,
                    "block_hash": blockhash,
                    "time": block_time,
                    "filename": filename_meta if isinstance(filename_meta, str) else None,
                    "stored_filename": stored_name,
                    "mime": mime,
                    "size": size,
                    "bpub_version": bpub_version,
                    "script_suffix": meta.get("script_suffix"),
                    "bpub_id": bpub_id_hex,
                    "funding_txids": meta.get("funding_txids", []),
                }

                if db.insert_item_tx(conn, entry):
                    reveals_count += 1
                if bpub_id_hex:
                    db.register_genesis_tx(
                        conn, bpub_id_hex, meta.get("funding_txids", [])
                    )

                sys.stderr.write(
                    f"[FOUND] BPUB v{bpub_version} file in tx {txid}: "
                    f"{stored_name} ({size} bytes, mime={mime})\n"
                )
            except Exception as e:
                sys.stderr.write(
                    f"[ERROR] Failed processing reveal tx {txid}: {e}\n"
                )

        # Pass 2: process verified v5 ownership transitions (runs after pass 1
        # so same-block reveal + owner-reveal link cleanly).
        for tx in txs:
            txid = tx.get("txid")
            raw_hex = tx.get("hex")
            if not txid or not raw_hex:
                continue
            if not _tx_maybe_bpub_owner(tx):
                continue
            try:
                owner_info = try_extract_owner_from_tx(raw_hex)
                if owner_info and db.apply_owner_update_tx(
                    conn, owner_info, txid, height, blockhash, block_time
                ):
                    owners_count += 1
                    sys.stderr.write(
                        f"[FOUND] BPUB v5 ownership update for "
                        f"{owner_info['bpub_id']} in tx {txid}\n"
                    )
            except Exception as e:
                sys.stderr.write(
                    f"[ERROR] Failed processing owner tx {txid}: {e}\n"
                )

        db.record_block_tx(conn, height, blockhash)
        db.set_state_tx(conn, "next_height", str(height + 1))
        if blockhash:
            db.set_state_tx(conn, "last_block_hash", blockhash)

    return reveals_count, owners_count


def reconcile_reorg(
    rpc,
    db: BpubDB,
    media_dir: Path,
    current_height: int,
    min_height: int,
) -> int:
    """
    Detect chain reorganizations by checking stored block hashes in
    `indexed_blocks` against `rpc.getblockhash(h)`. Walks back to the common
    ancestor, atomically rolls back orphaned items/ownership/blocks, and
    returns the height to resume scanning from.
    """
    check_h = current_height - 1
    if check_h < min_height:
        return current_height

    stored_hash = db.get_block_hash(check_h)
    if not stored_hash:
        return current_height

    try:
        chain_hash = rpc.getblockhash(check_h)
    except Exception:
        return current_height

    if chain_hash == stored_hash:
        return current_height

    sys.stderr.write(
        f"[WARN] Reorg detected at height {check_h}: "
        f"indexed={stored_hash} chain={chain_hash}. Walking back...\n"
    )
    fork_h = check_h - 1
    while fork_h >= min_height:
        s_hash = db.get_block_hash(fork_h)
        if not s_hash:
            break
        if rpc.getblockhash(fork_h) == s_hash:
            break
        fork_h -= 1

    res = db.rollback_above(fork_h, media_dir=media_dir)
    sys.stderr.write(
        f"[WARN] Rolled back blocks above height {fork_h}: {res}. "
        f"Resuming at height {fork_h + 1}.\n"
    )
    return fork_h + 1


def main():
    config = load_config()
    rpc = make_rpc(config)

    gallery_dir: Path = config["gallery_dir"]
    gallery_dir.mkdir(parents=True, exist_ok=True)
    media_dir = gallery_dir / "media"
    media_dir.mkdir(parents=True, exist_ok=True)

    db_path = Path(os.getenv("BPUB_DB_PATH", str(gallery_dir / "bpub.db")))
    db = BpubDB(db_path)
    migrated = db.migrate_legacy_json(gallery_dir)
    if any(migrated.values()):
        sys.stderr.write(
            f"[INFO] Migrated legacy JSON files into {db_path}: {migrated}\n"
        )

    current_height = db.get_next_height(config["start_height"])
    sys.stderr.write(
        f"[INFO] Starting BPUB indexer at height {current_height}, "
        f"db={db_path}, media={media_dir}\n"
    )

    poll_interval = config["poll_interval"]

    while True:
        try:
            best_height = rpc.getblockcount()
        except Exception as e:
            sys.stderr.write(f"[ERROR] RPC getblockcount failed: {e}\n")
            time.sleep(poll_interval)
            continue

        try:
            current_height = reconcile_reorg(
                rpc, db, media_dir, current_height, config["start_height"]
            )
        except Exception as e:
            sys.stderr.write(f"[ERROR] Reorg check failed: {e}\n")
            time.sleep(5)
            continue

        while current_height <= best_height:
            try:
                blockhash = rpc.getblockhash(current_height)
                block = rpc.getblock(blockhash, 2)
            except Exception as e:
                sys.stderr.write(
                    f"[ERROR] Failed to fetch block {current_height}: {e}\n"
                )
                time.sleep(5)
                break

            sys.stderr.write(
                f"[INFO] Scanning block {current_height} ({blockhash}), "
                f"{len(block.get('tx', []))} txs\n"
            )
            block.setdefault("hash", blockhash)
            index_block(db, media_dir, block, current_height)
            current_height += 1

        time.sleep(poll_interval)


if __name__ == "__main__":
    main()
