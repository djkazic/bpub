#!/usr/bin/env python3
import os
import sys
import json
import time
import hashlib

from bitcoinrpc.authproxy import AuthServiceProxy
from bitcointx import select_chain_params, BitcoinMainnetParams
from bitcointx.core import CTransaction
from bitcointx.core.script import CScript


def decode_pubkeys_to_stream(pubkeys):
    return b"".join(pk[1:-1] for pk in pubkeys)


def decode_stream(payload: bytes):
    if payload[:4] != b"BPUB":
        raise ValueError("Bad magic, not a BPUB stream")

    version = payload[4]
    if version != 1:
        raise ValueError(f"Unsupported BPUB version: {version}")

    header_len = int.from_bytes(payload[5:8], "big")
    header = payload[8 : 8 + header_len]

    meta = {}
    i = 0
    import hashlib

    while i < len(header):
        t, l = header[i], header[i + 1]
        val = header[i + 2 : i + 2 + l]
        if t == 0xFF:
            break
        if t == 0x01:
            meta["size"] = int.from_bytes(val, "big")
        elif t == 0x02:
            meta["sha"] = val
        elif t == 0x03:
            meta["mime"] = val.decode()
        elif t == 0x05:
            meta["filename"] = val.decode()
        i += 2 + l

    if "size" not in meta or "sha" not in meta:
        raise ValueError("Missing mandatory metadata (size/sha) in BPUB header")

    start = 8 + header_len
    content = payload[start : start + meta["size"]]

    if hashlib.sha256(content).digest() != meta["sha"]:
        raise ValueError("SHA-256 mismatch in content")

    return meta, content


select_chain_params(BitcoinMainnetParams)


def load_dotenv(path: str = ".env"):
    """Very small .env parser, avoids extra deps."""
    if not os.path.isfile(path):
        return
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k and k not in os.environ:
                os.environ[k] = v


STATE_FILE = "bpub_indexer_state.json"
FIRST_BPUB_HEIGHT = 924329


def load_state():
    if not os.path.isfile(STATE_FILE):
        return None
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        return data.get("last_height")
    except Exception:
        return None


def save_state(height: int):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"last_height": height}, f)
    os.replace(tmp, STATE_FILE)


def make_rpc():
    load_dotenv()

    user = os.environ.get("BITCOIN_RPC_USER", "user")
    pwd = os.environ.get("BITCOIN_RPC_PASSWORD", "pass")
    host = os.environ.get("BITCOIN_RPC_HOST", "127.0.0.1")
    port = os.environ.get("BITCOIN_RPC_PORT", "8332")

    url = f"http://{user}:{pwd}@{host}:{port}"
    return AuthServiceProxy(url)


def scan_tx_for_bpub(tx_hex: str):
    """
    Return (control_pubkey_hex, meta) if this tx looks like a BPUB reveal,
    otherwise None.

    This is essentially txrecover in 'auto' mode but without writing the file;
    it just checks for a valid BPUB header.
    """
    tx = CTransaction.deserialize(bytes.fromhex(tx_hex))

    wit = getattr(tx, "wit", None)
    if wit is None or len(wit.vtxinwit) == 0:
        return None

    all_data_pubkeys = []
    detected_controls = []

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

        is_op_1 = isinstance(op_1, int) and (op_1 == 0x51 or op_1 == 1)
        if not is_op_1:
            continue

        is_op_checkmultisig = isinstance(op_checkmultisig, int) and (
            op_checkmultisig == 0xAE or op_checkmultisig == 174
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
        if op_n != 0x50 + total_keys and op_n != total_keys:
            continue

        control_pk_here = pubkeys[-1]
        detected_controls.append(control_pk_here)

        data_pks = pubkeys[:-1]
        all_data_pubkeys.extend(data_pks)

    if not all_data_pubkeys:
        return None

    uniq_controls = {pk for pk in detected_controls}
    if not uniq_controls or len(uniq_controls) > 1:
        return None

    control_pk = next(iter(uniq_controls))

    try:
        raw_stream = decode_pubkeys_to_stream(all_data_pubkeys)
        meta, _content = decode_stream(raw_stream)
    except Exception:
        return None

    return control_pk.hex(), meta


def main():
    rpc = make_rpc()

    tip = rpc.getblockcount()
    last = load_state()
    if last is None:
        current = FIRST_BPUB_HEIGHT
    else:
        current = max(last + 1, FIRST_BPUB_HEIGHT)

    print(
        f"[bpub-indexer] Starting at height {current}, current tip {tip}",
        file=sys.stderr,
    )

    POLL_SECONDS = 15

    while True:
        try:
            tip = rpc.getblockcount()
        except Exception as e:
            print(f"[bpub-indexer] RPC error: {e}", file=sys.stderr)
            time.sleep(POLL_SECONDS)
            continue

        if current > tip:
            time.sleep(POLL_SECONDS)
            continue

        while current <= tip:
            try:
                bhash = rpc.getblockhash(current)
                block = rpc.getblock(bhash, 2)
            except Exception as e:
                print(
                    f"[bpub-indexer] Error fetching block {current}: {e}",
                    file=sys.stderr,
                )
                break

            for tx in block.get("tx", []):
                txid = tx["txid"]
                tx_hex = tx.get("hex")
                if not tx_hex:
                    try:
                        tx_hex = rpc.getrawtransaction(txid)
                    except Exception:
                        continue

                result = scan_tx_for_bpub(tx_hex)
                if result is None:
                    continue

                control_pk_hex, meta = result
                print(
                    json.dumps(
                        {
                            "height": current,
                            "blockhash": bhash,
                            "txid": txid,
                            "control_pubkey": control_pk_hex,
                            "filename": meta.get("filename"),
                            "size": meta.get("size"),
                            "mime": meta.get("mime"),
                        }
                    ),
                    flush=True,
                )

            save_state(current)
            current += 1


if __name__ == "__main__":
    main()
