#!/usr/bin/env python3
"""
BPUB indexer: scan the Bitcoin blockchain for BPUB reveal transactions
(v3.5 legacy and v4 stealth) and build a simple on-disk "gallery":

    GALLERY_DIR/
      manifest.json
      media/
        <txid>_<safe_filename>

- Connects to bitcoind via RPC.
- Starts from a configured height (and optional hash sanity-check).
- Runs forever, polling for new blocks.
- Auto-detects BPUB-style 1-of-N multisig P2WSH spends and reconstructs
  the embedded BPUB stream via bpub.decode_*().

This works with:

- BPUB v3.5 streams (with "BPUB" magic + TLV header).
- BPUB v4 stealth streams (headerless, raw DEFLATE + XOR).
"""

import os
import sys
import time
import json
import re
import hashlib
from pathlib import Path
from typing import Optional, Tuple, List

from dotenv import load_dotenv
from bitcoinrpc.authproxy import AuthServiceProxy

from bitcointx.core import CTransaction
from bitcointx.core.script import CScript
from bitcointx.wallet import P2WPKHBitcoinAddress, P2WSHBitcoinAddress

from bpub import decode_pubkeys_to_stream, decode_stream, decode_owner_redeem_script


def load_config():
    """Load config from .env and environment variables."""
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


def safe_filename(name: str) -> str:
    """Sanitize filename for filesystem."""
    name = name.strip()
    if not name:
        return "file"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:255]


def guess_extension(mime: Optional[str], existing_name: str) -> str:
    """If existing_name has an extension, keep it; otherwise guess from mime."""
    if "." in existing_name:
        return existing_name

    ext = ""
    if mime:
        m = mime.lower()
        if "jpeg" in m or m == "image/jpg":
            ext = ".jpg"
        elif "png" in m:
            ext = ".png"
        elif "gif" in m:
            ext = ".gif"
        elif "webp" in m:
            ext = ".webp"
        elif "json" in m:
            ext = ".json"
        elif "text" in m:
            ext = ".txt"
        elif "pdf" in m:
            ext = ".pdf"
        elif "svg" in m:
            ext = ".svg"
    if not ext:
        ext = ".bin"
    return existing_name + ext


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

    for idx, vin in enumerate(tx.vin):
        if idx >= len(tx.wit.vtxinwit):
            continue

        inwit = tx.wit.vtxinwit[idx]
        wstack = list(inwit.scriptWitness.stack)
        if len(wstack) < 2:
            continue

        redeem_script = bytes(wstack[-1])
        try:
            elems = list(CScript(redeem_script))
        except Exception:
            continue

        if len(elems) < 4:
            continue

        op_1 = elems[0]
        op_n = elems[-2]
        op_checkmultisig = elems[-1]

        is_op_1 = isinstance(op_1, int) and (op_1 == 1 or op_1 == 0x51)
        if not is_op_1:
            continue

        is_op_checkmultisig = isinstance(op_checkmultisig, int) and (
            op_checkmultisig == 174 or op_checkmultisig == 0xAE
        )
        if not is_op_checkmultisig:
            continue

        if not isinstance(op_n, int):
            continue

        middle = elems[1:-2]
        pubkeys = [e for e in middle if isinstance(e, (bytes, bytearray))]
        if len(pubkeys) != len(middle):
            continue

        total_keys = len(pubkeys)
        if total_keys < 2:
            continue

        if op_n != 0x50 + total_keys and op_n != total_keys:
            continue

        control_pk_here = pubkeys[-1]
        detected_controls.append(control_pk_here)

        data_pks = pubkeys[:-1]
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

    return meta, content


def try_extract_owner_from_tx(rawtx_hex: str):
    """
    Try to detect a BPUB v5 ownership script in a transaction and extract
    ownership info (bpub_id + owner address + owner UTXOs in that tx).

    Returns:
      dict with keys:
        - bpub_id (hex)
        - owner_h160 (hex)
        - owner_p2wpkh (address string)
        - owner_p2wsh (address string)
        - owner_outputs: list of {vout, value_sats}
      or None if no owner script is found.
    """
    try:
        tx = CTransaction.deserialize(bytes.fromhex(rawtx_hex))
    except Exception:
        return None

    wit = getattr(tx, "wit", None)
    if wit is None or len(wit.vtxinwit) == 0:
        return None

    owner_info = None

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

        # We found an owner script; derive addresses and outputs.
        bpub_id_hex = bpub_id_bytes.hex()
        owner_h160_hex = owner_h160.hex()

        # Outer owner P2WSH scriptPubKey for this redeem_script
        spk_p2wsh = b"\x00\x20" + hashlib.sha256(redeem_script).digest()
        owner_p2wsh_addr = str(
            P2WSHBitcoinAddress.from_scriptPubKey(CScript(spk_p2wsh))
        )

        # Canonical P2WPKH for the owner hash160 (for human-friendly "owner" display)
        spk_p2wpkh = b"\x00\x14" + owner_h160
        owner_p2wpkh_addr = str(
            P2WPKHBitcoinAddress.from_scriptPubKey(CScript(spk_p2wpkh))
        )

        # Find owner UTXOs in *this* tx (outputs paying to that P2WSH)
        owner_outputs = []
        for vout_index, out in enumerate(tx.vout):
            if bytes(out.scriptPubKey) == spk_p2wsh:
                owner_outputs.append(
                    {
                        "vout": vout_index,
                        "value_sats": int(out.nValue),
                    }
                )

        owner_info = {
            "bpub_id": bpub_id_hex,
            "owner_h160": owner_h160_hex,
            "owner_p2wpkh": owner_p2wpkh_addr,
            "owner_p2wsh": owner_p2wsh_addr,
            "owner_outputs": owner_outputs,
        }
        break

    return owner_info


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

            for tx in block.get("tx", []):
                txid = tx.get("txid")
                if not txid:
                    continue

                if txid in known_txids:
                    continue

                raw_hex = tx.get("hex")
                if not raw_hex:
                    continue

                # 1) Try to extract BPUB content (v3.5/v4/v5) as before.
                res = try_extract_bpub_from_tx(raw_hex)
                if res:
                    meta, content = res
                    filename_meta = meta.get("filename") or txid
                    mime = meta.get("mime")
                    size = meta.get("size")
                    bpub_version = meta.get("bpub_version")

                    base_name = safe_filename(filename_meta)
                    stored_name = guess_extension(mime, base_name)
                    stored_name = f"{txid}_{stored_name}"
                    out_path = media_dir / stored_name

                    if not out_path.exists():
                        try:
                            with open(out_path, "wb") as f:
                                f.write(content)
                        except Exception as e:
                            sys.stderr.write(
                                f"[ERROR] Failed to write file for tx {txid}: {e}\n"
                            )
                            # even if file write fails, we can still attempt ownership below
                            # so do NOT 'continue' here
                    entry = {
                        "txid": txid,
                        "block_height": current_height,
                        "block_hash": blockhash,
                        "time": block_time,
                        "filename": meta.get("filename"),
                        "stored_filename": stored_name,
                        "mime": mime,
                        "size": size,
                        "bpub_version": bpub_version,
                    }

                    # If this is BPUB v5 and we have a bpub_id, persist it on the manifest entry.
                    bpub_id_val = meta.get("bpub_id")
                    if bpub_id_val is not None:
                        if isinstance(bpub_id_val, (bytes, bytearray)):
                            entry["bpub_id"] = bpub_id_val.hex()
                        else:
                            entry["bpub_id"] = str(bpub_id_val)

                    manifest.append(entry)
                    known_txids.add(txid)
                    sys.stderr.write(
                        f"[FOUND] BPUB v{bpub_version} file in tx {txid}: "
                        f"{stored_name} ({size} bytes, mime={mime})\n"
                    )

                    try:
                        save_manifest(manifest, manifest_path)
                    except Exception as e:
                        sys.stderr.write(f"[ERROR] Failed to save manifest.json: {e}\n")

                # 2) Independently, try to detect BPUB v5 ownership updates in this tx.
                owner_info = try_extract_owner_from_tx(raw_hex)
                if owner_info:
                    bpub_id_hex = owner_info["bpub_id"]
                    record = {
                        "bpub_id": bpub_id_hex,
                        "current_owner_p2wpkh": owner_info["owner_p2wpkh"],
                        "txid": txid,
                        "block_height": current_height,
                        "block_hash": blockhash,
                        "time": block_time,
                        "outputs": owner_info["owner_outputs"],
                    }
                    ownership[bpub_id_hex] = record
                    sys.stderr.write(
                        f"[FOUND] BPUB v5 ownership update for {bpub_id_hex} in tx {txid}\n"
                    )
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
