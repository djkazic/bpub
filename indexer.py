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
import hashlib
from pathlib import Path
from typing import Optional, Tuple, List

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
    decode_pubkeys_to_stream,
    decode_stream,
    decode_owner_redeem_script,
    parse_bpub_multisig,
)


def load_config():
    """Load config from .env and environment variables."""
    if load_dotenv is None:
        sys.exit("python-dotenv is required to run indexer.py")
    load_dotenv()

    rpc_user = os.getenv("BITCOIN_RPC_USER")
    rpc_pass = os.getenv("BITCOIN_RPC_PASSWORD")
    rpc_host = os.getenv("BITCOIN_RPC_HOST", "127.0.0.1")
    rpc_port = os.getenv("BITCOIN_RPC_PORT", "8332")

    if not rpc_user or not rpc_pass:
        sys.exit("BITCOIN_RPC_USER and BITCOIN_RPC_PASSWORD must be set in .env")

    gallery_dir = os.getenv("GALLERY_DIR")
    if not gallery_dir:
        sys.exit("GALLERY_DIR must be set in .env")

    start_height_str = os.getenv("START_HEIGHT", "924329")
    try:
        start_height = int(start_height_str)
    except ValueError:
        sys.exit("START_HEIGHT must be an integer")

    poll_interval = int(os.getenv("POLL_INTERVAL", "30"))

    return {
        "rpc_user": rpc_user,
        "rpc_pass": rpc_pass,
        "rpc_host": rpc_host,
        "rpc_port": rpc_port,
        "gallery_dir": Path(gallery_dir),
        "start_height": start_height,
        "poll_interval": poll_interval,
    }


def make_rpc(config):
    if AuthServiceProxy is None:
        sys.exit("python-bitcoinrpc is required to run indexer.py")
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


def main():
    config = load_config()
    rpc = make_rpc(config)

    gallery_dir: Path = config["gallery_dir"]
    gallery_dir.mkdir(parents=True, exist_ok=True)

    manifest, known_txids, manifest_path, media_dir = load_manifest(gallery_dir)
    ownership, ownership_path = load_ownership(gallery_dir)
    current_height, state_path = load_state(gallery_dir, config["start_height"])

    sys.stderr.write(
        f"[INFO] Starting BPUB indexer at height {current_height}, "
        f"gallery={gallery_dir}\n"
    )

    poll_interval = config["poll_interval"]

    while True:
        try:
            best_height = rpc.getblockcount()
        except Exception as e:
            sys.stderr.write(f"[ERROR] RPC getblockcount failed: {e}\n")
            time.sleep(poll_interval)
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

            block_time = block.get("time", None)
            txs = block.get("tx", [])
            manifest_dirty = False
            ownership_dirty = False
            media_dir_resolved = media_dir.resolve()

            # Pass 1: extract BPUB reveals and anchor v5 genesis ownership.
            for tx in txs:
                txid = tx.get("txid")
                raw_hex = tx.get("hex")
                if not txid or not raw_hex or txid in known_txids:
                    continue

                try:
                    res = try_extract_bpub_from_tx(raw_hex)
                    if not res:
                        continue

                    meta, content = res
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

                    entry = {
                        "txid": txid,
                        "block_height": current_height,
                        "block_hash": blockhash,
                        "time": block_time,
                        "filename": filename_meta if isinstance(filename_meta, str) else None,
                        "stored_filename": stored_name,
                        "mime": mime,
                        "size": size,
                        "bpub_version": bpub_version,
                    }

                    bpub_id_val = meta.get("bpub_id")
                    bpub_id_hex = None
                    if bpub_id_val is not None:
                        bpub_id_hex = (
                            bpub_id_val.hex()
                            if isinstance(bpub_id_val, (bytes, bytearray))
                            else str(bpub_id_val)
                        )
                        entry["bpub_id"] = bpub_id_hex
                        if register_bpub_genesis(
                            ownership, bpub_id_hex, meta.get("funding_txids", [])
                        ):
                            ownership_dirty = True

                    manifest.append(entry)
                    known_txids.add(txid)
                    manifest_dirty = True
                    sys.stderr.write(
                        f"[FOUND] BPUB v{bpub_version} file in tx {txid}: "
                        f"{stored_name} ({size} bytes, mime={mime})\n"
                    )
                except Exception as e:
                    sys.stderr.write(
                        f"[ERROR] Failed processing reveal tx {txid}: {e}\n"
                    )

            # Pass 2: process verified v5 ownership transitions (runs after
            # pass 1 so same-block reveal + owner-reveal link properly).
            for tx in txs:
                txid = tx.get("txid")
                raw_hex = tx.get("hex")
                if not txid or not raw_hex:
                    continue
                try:
                    owner_info = try_extract_owner_from_tx(raw_hex)
                    if owner_info and apply_owner_update(
                        ownership,
                        owner_info,
                        txid,
                        current_height,
                        blockhash,
                        block_time,
                    ):
                        ownership_dirty = True
                        sys.stderr.write(
                            f"[FOUND] BPUB v5 ownership update for "
                            f"{owner_info['bpub_id']} in tx {txid}\n"
                        )
                except Exception as e:
                    sys.stderr.write(
                        f"[ERROR] Failed processing owner tx {txid}: {e}\n"
                    )

            if manifest_dirty:
                try:
                    save_manifest(manifest, manifest_path)
                except Exception as e:
                    sys.stderr.write(f"[ERROR] Failed to save manifest.json: {e}\n")
            if ownership_dirty:
                try:
                    save_ownership(ownership, ownership_path)
                except Exception as e:
                    sys.stderr.write(
                        f"[ERROR] Failed to save ownership.json: {e}\n"
                    )

            current_height += 1
            save_state(state_path, current_height)

        time.sleep(poll_interval)


if __name__ == "__main__":
    main()
