#!/usr/bin/env python3
"""
BPUB v1 — Embed data as valid compressed secp256k1 pubkeys + P2WSH storage TX.
"""

import os
import sys, json, zlib, hashlib, argparse
from dataclasses import dataclass


from bitcointx.core import (
    x,
    lx,
    COutPoint,
    CMutableTxIn,
    CMutableTxOut,
    CMutableTransaction,
    CTransaction,
    CTxOut,
)
from bitcointx.core.script import CScript
from bitcointx.wallet import P2WPKHBitcoinAddress, P2WSHBitcoinAddress
from bitcointx.wallet import P2TRBitcoinAddress
from bitcointx import select_chain_params
from bitcointx import select_chain_params, BitcoinMainnetParams
from bitcointx.core.psbt import PartiallySignedTransaction as PSBT

select_chain_params(BitcoinMainnetParams)

# -------------------------
# SEC256K1 MATH / ENCODING
# -------------------------
p = 2**256 - 2**32 - 977
b = 7
MAX_PUBKEYS_PER_OUTPUT = 16


def is_quadratic_residue(n):
    return pow(n % p, (p - 1) // 2, p) == 1


def sqrt_mod_p(n):
    return pow(n % p, (p + 1) // 4, p)


def chunk_pubkeys(pubkeys):
    for i in range(0, len(pubkeys), MAX_PUBKEYS_PER_OUTPUT):
        yield pubkeys[i : i + MAX_PUBKEYS_PER_OUTPUT]


def build_stream(data, mime, filename, compress=False):
    content = zlib.compress(data) if compress else data

    header = b"".join(
        [
            bytes([0x01, 8]) + len(content).to_bytes(8, "big"),
            bytes([0x02, 32]) + hashlib.sha256(content).digest(),
            bytes([0x03, len(mime)]) + mime.encode(),
            bytes([0x05, len(filename)]) + filename.encode() if filename else b"",
            bytes([0xFF, 0]),
        ]
    )

    prefix = b"BPUB" + bytes([1]) + len(header).to_bytes(3, "big")
    stream = prefix + header + content
    pad = (-len(stream)) % 31
    return stream + (b"\x00" * pad if pad else b"")


def encode_to_pubkeys(stream):
    out = []
    for i in range(0, len(stream), 31):
        chunk = stream[i : i + 31]
        for nonce in range(256):
            x_bytes = chunk + bytes([nonce])
            x = int.from_bytes(x_bytes, "big")
            if x >= p:
                continue
            rhs = (pow(x, 3, p) + b) % p
            if is_quadratic_residue(rhs):
                y = sqrt_mod_p(rhs)
                out.append(bytes([0x02 | (y & 1)]) + x_bytes)
                break
        else:
            raise RuntimeError("No valid nonce")
    return out


def decode_pubkeys(pubkeys):
    payload = b"".join(pk[1:-1] for pk in pubkeys)
    if payload[:4] != b"BPUB":
        raise ValueError("Bad magic")

    header_len = int.from_bytes(payload[5:8], "big")
    header = payload[8 : 8 + header_len]

    meta = {}
    i = 0
    while i < len(header):
        t, l = header[i], header[i + 1]
        val = header[i + 2 : i + 2 + l]
        if t == 0xFF:
            break
        if t == 0x01:
            meta["size"] = int.from_bytes(val, "big")
        if t == 0x02:
            meta["sha"] = val
        if t == 0x03:
            meta["mime"] = val.decode()
        if t == 0x05:
            meta["filename"] = val.decode()
        i += 2 + l

    start = 8 + header_len
    content = payload[start : start + meta["size"]]
    if hashlib.sha256(content).digest() != meta["sha"]:
        raise ValueError("SHA-256 mismatch")
    return meta, content


def build_multisig_script(pubkeys):
    if len(pubkeys) > 16:
        raise ValueError("Too many pubkeys")
    scr = bytearray([0x51])  # OP_1
    for pk in pubkeys:
        scr.append(0x21)
        scr.extend(pk)
    scr.append(0x50 + len(pubkeys))
    scr.append(0xAE)
    return bytes(scr)


def p2wsh_scriptpubkey(redeem_script):
    return b"\x00\x20" + hashlib.sha256(redeem_script).digest()


def bech32_to_scriptpubkey(addr):
    """
    Convert a Bech32 SegWit or Taproot address into raw scriptPubKey
    Works for P2WPKH, P2WSH, and P2TR.
    """
    if addr.startswith("bc1p"):  # Taproot (Bech32m)
        a = P2TRBitcoinAddress(addr)
    elif addr.startswith("bc1q"):  # P2WPKH / P2WSH
        try:
            a = P2WPKHBitcoinAddress(addr)
        except Exception:
            a = P2WSHBitcoinAddress(addr)
    else:
        raise ValueError(f"Unsupported address format: {addr}")

    return a.to_scriptPubKey()


@dataclass
class UTXO:
    txid: str
    vout: int
    value_sats: int


def estimate_fee(for_outputs, feerate):
    return (68 + (for_outputs * 34) + 10) * feerate


def main():
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(dest="cmd", required=True)

    e = sp.add_parser("encode")
    e.add_argument("file")
    e.add_argument("--mime", default="application/octet-stream")
    e.add_argument("--filename", default="")
    e.add_argument("--compress", action="store_true")

    d = sp.add_parser("decode")
    d.add_argument("pubkeys_json")

    tb = sp.add_parser("txbuild")
    tb.add_argument("pubkeys_json")
    tb.add_argument("--utxo", required=True)
    tb.add_argument("--value", required=True, type=int)
    tb.add_argument("--feerate", type=int, default=1)
    tb.add_argument("--change")

    tp = sp.add_parser("txpsbt")
    tp.add_argument("pubkeys_json")
    tp.add_argument("--utxo", required=True)
    tp.add_argument("--value", required=True, type=int)
    tp.add_argument("--feerate", type=int, default=1)
    tp.add_argument("--change")
    tp.add_argument(
        "--prev-address", help="Bech32 address that the funding UTXO pays to"
    )
    tp.add_argument("--prev-spk", help="Hex scriptPubKey that the funding UTXO pays to")

    tr = sp.add_parser("txrecover")
    tr.add_argument("rawtx", help="Final raw signed transaction hex OR filename")

    args = p.parse_args()

    # ---------- encode ----------
    if args.cmd == "encode":
        data = open(args.file, "rb").read()
        stream = build_stream(data, args.mime, args.filename, args.compress)
        json.dump([pk.hex() for pk in encode_to_pubkeys(stream)], sys.stdout, indent=2)
        print()
        return

    # ---------- decode ----------
    if args.cmd == "decode":
        pubs = [bytes.fromhex(h) for h in json.load(open(args.pubkeys_json))]
        _, c = decode_pubkeys(pubs)
        sys.stdout.buffer.write(c)
        return

    # ---------- txrecover ----------
    if args.cmd == "txrecover":
        # Accept filename or raw hex
        if os.path.isfile(args.rawtx):
            rawtx = open(args.rawtx, "r").read().strip()
        else:
            rawtx = args.rawtx

        tx = CTransaction.deserialize(bytes.fromhex(rawtx))
        print(f"# Loaded TX with {len(tx.vout)} outputs", file=sys.stderr)

        # Load redeem scripts (created during txbuild/txpsbt)
        if not os.path.exists("redeem_scripts.json"):
            sys.exit("ERROR: redeem_scripts.json not found. Needed for recovery!")

        redeem_scripts = [
            bytes.fromhex(x) for x in json.load(open("redeem_scripts.json"))
        ]
        print(f"# Loaded {len(redeem_scripts)} redeem scripts", file=sys.stderr)

        # Extract all 33-byte pubkeys from each multisig redeem script
        recovered_pks = []
        for rs in redeem_scripts:
            i = 0
            while i < len(rs):
                if rs[i] == 0x21 and i + 33 <= len(rs):  # PUSH 33
                    recovered_pks.append(rs[i + 1 : i + 34])
                    i += 34
                else:
                    i += 1

        print(f"# Recovered {len(recovered_pks)} pubkeys", file=sys.stderr)

        meta, content = decode_pubkeys(recovered_pks)
        sys.stderr.write(
            f"# Recovered file: {meta.get('filename')} ({meta.get('size')} bytes)\n"
        )
        sys.stdout.buffer.write(content)
        return

    # ---- shared UTXO parsing ----
    # Only for txbuild / txpsbt
    if args.cmd in ("txbuild", "txpsbt"):
        txid, vout = args.utxo.split(":")
        utxo = UTXO(txid, int(vout), int(args.value))
    else:
        raise SystemExit(f"Unexpected cmd needing UTXO parsing: {args.cmd}")

    # ---------- txbuild ----------
    if args.cmd == "txbuild":
        pubs = [bytes.fromhex(h) for h in json.load(open(args.pubkeys_json))]
        chunks = list(chunk_pubkeys(pubs))

        redeem_scripts = []
        spks = []
        for ch in chunks:
            rs = build_multisig_script(ch)
            redeem_scripts.append(rs)
            spks.append(p2wsh_scriptpubkey(rs))

        fee = estimate_fee(len(spks) + (1 if args.change else 0), args.feerate)
        DUST = 546
        need = len(spks) * DUST + fee
        if utxo.value_sats < need:
            sys.exit(f"UTXO too small, need {need}")
        change = utxo.value_sats - need

        txouts = [CMutableTxOut(DUST, CScript(spk)) for spk in spks]
        if args.change and change > DUST:
            txouts.append(CMutableTxOut(change, bech32_to_scriptpubkey(args.change)))

        tx = CMutableTransaction(
            [CMutableTxIn(COutPoint(lx(utxo.txid), utxo.vout))], txouts
        )
        json.dump(
            [rs.hex() for rs in redeem_scripts],
            open("redeem_scripts.json", "w"),
            indent=2,
        )
        print(tx.serialize().hex())
        print(f"# Fee {fee}  Change {change}")
        return

    # ---------- txpsbt ----------
    if args.cmd == "txpsbt":
        # Load pubkeys and chunk them
        pubs = [bytes.fromhex(h) for h in json.load(open(args.pubkeys_json))]
        chunks = list(chunk_pubkeys(pubs))

        # Build BPUB P2WSH outputs (same as txbuild)
        spks = []
        redeem_scripts = []
        for ch in chunks:
            rs = build_multisig_script(ch)
            redeem_scripts.append(rs)
            spks.append(p2wsh_scriptpubkey(rs))

        fee = estimate_fee(len(spks) + (1 if args.change else 0), args.feerate)
        DUST = 546
        need = len(spks) * DUST + fee
        if utxo.value_sats < need:
            sys.exit(f"UTXO too small for PSBT, need {need}")
        change = utxo.value_sats - need

        txouts = [CMutableTxOut(DUST, CScript(spk)) for spk in spks]
        if args.change and change > DUST:
            txouts.append(CMutableTxOut(change, bech32_to_scriptpubkey(args.change)))

        # Unsigned transaction
        txin = CMutableTxIn(COutPoint(lx(utxo.txid), utxo.vout))
        tx = CMutableTransaction([txin], txouts)

        json.dump(
            [rs.hex() for rs in redeem_scripts],
            open("redeem_scripts.json", "w"),
            indent=2,
        )

        psbt = PSBT(unsigned_tx=tx)

        # Prevout scriptPubKey for the funding UTXO
        if args.prev_spk:
            prev_spk = CScript(bytes.fromhex(args.prev_spk))
        elif args.prev_address:
            prev_spk = bech32_to_scriptpubkey(args.prev_address)
        else:
            raise SystemExit(
                "\n[!] Need to know what the funding UTXO pays to.\n"
                "    Please re-run with ONE of:\n"
                "      --prev-address bc1q...   (Bech32 segwit/taproot address)\n"
                "      --prev-spk <scriptPubKey-hex>\n"
            )

        psbt.set_utxo(
            CTxOut(utxo.value_sats, prev_spk),
            0,
            force_witness_utxo=True,
        )

        with open("bpub.psbt", "w") as f:
            f.write(psbt.to_base64())

        print("\nPSBT written to bpub.psbt")
        print('# bitcoin-cli decodepsbt "$(cat bpub.psbt)"')
        print('# bitcoin-cli walletprocesspsbt "$(cat bpub.psbt)" sign=1 finalize=1')
        return


if __name__ == "__main__":
    main()
