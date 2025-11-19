#!/usr/bin/env python3
"""
BPUB v3.5 — 1-of-N multisig P2WSH with data embedded in redeemScript.

Design:

- For each file, we build a BPUB stream:
    [ "BPUB" ][version=1][header_len(3)][header][content]

- We then encode the stream into a sequence of fake compressed secp256k1 pubkeys:
    - Each pubkey encodes 31 bytes of payload + 1 byte nonce in its x-coordinate.
    - We "grind" over nonces until x is on the secp256k1 curve.

- We group the data pubkeys into chunks, and for each chunk build a 1-of-N multisig
  witness script:

      OP_1 <data_pk_0> ... <data_pk_M> <control_pubkey> OP_(M+1) OP_CHECKMULTISIG

  where:
    - M+1 <= MAX_PUBKEYS_PER_SCRIPT (standardness-friendly).
    - `control_pubkey` is the only key that has a real private key.

- For each such script, we create a P2WSH output:

      scriptPubKey = 0 <sha256(redeemScript)>

  The funding transaction (built by `txbuild` / `fundpsbt`) pays to these P2WSH outputs
  (plus an optional change output back to your wallet).

- Reveal:

  To "reveal" the data, you spend these P2WSH outputs in a normal P2WSH 1-of-N
  CHECKMULTISIG spend, using the private key corresponding to `control_pubkey`.

  The redeemScript(s) become visible in the spending transaction; they contain all
  the data pubkeys and the control pubkey. No witness preimage tricks; this is
  standard multisig.

- Recovery:

  Given a reveal transaction:
    - For each input, if the witness script is a 1-of-N multisig whose *last*
      pubkey matches `control_pubkey`, we:
        - collect all preceding pubkeys as data pubkeys,
        - concatenate them in input order,
        - decode the resulting pubkey sequence as a BPUB stream,
        - verify header + SHA-256,
        - output the recovered content.

CLI overview:

  encode        file -> BPUB stream hex
  decode        BPUB stream hex -> file
  txbuild       raw unsigned funding tx (you sign it yourself)
  fundpsbt      funding PSBT (easy to sign in Sparrow)
  revealpsbt    reveal PSBT (spend BPUB outputs to your address)
  txrecover     recover file from reveal tx (raw hex or file)
"""

import os
import sys
import json
import zlib
import hashlib
import argparse
from dataclasses import dataclass

from bitcointx import select_chain_params, BitcoinMainnetParams
from bitcointx.core import (
    lx,
    COutPoint,
    CMutableTxIn,
    CMutableTxOut,
    CMutableTransaction,
    CTransaction,
    CTxOut,
)
from bitcointx.core.key import CKey, CPubKey
from bitcointx.core.script import CScript
from bitcointx.core.psbt import PartiallySignedTransaction as PSBT, KeyStore
from bitcointx.wallet import (
    P2WPKHBitcoinAddress,
    P2WSHBitcoinAddress,
    P2TRBitcoinAddress,
    CBitcoinSecret,
)

select_chain_params(BitcoinMainnetParams)


# ---------------------------------------------------------------------------
# SEC256K1 MATH / ENCODING (grinding scheme)
# ---------------------------------------------------------------------------

# Curve: y^2 = x^3 + 7 over F_p
p = 2**256 - 2**32 - 977
b = 7

# Standard multisig standardness historically limits pubkeys per script; keep <= 15 total.
MAX_PUBKEYS_PER_SCRIPT = 15  # 1-of-15 multisig -> 14 data pubkeys + 1 control pubkey


def is_quadratic_residue(n: int) -> bool:
    return pow(n % p, (p - 1) // 2, p) == 1


def sqrt_mod_p(n: int) -> int:
    # Since p % 4 == 3 for secp256k1, sqrt(n) = n^((p+1)/4) mod p
    return pow(n % p, (p + 1) // 4, p)


def encode_stream_to_pubkeys(stream: bytes):
    """
    Encode arbitrary bytes into a list of valid compressed secp256k1 pubkeys.

    We take 31-byte chunks of the stream, append a 1-byte nonce,
    interpret as 32-byte x-coordinate, and grind nonce until x lies on the curve.
    """
    out = []
    for i in range(0, len(stream), 31):
        chunk = stream[i : i + 31]
        if len(chunk) < 31:
            chunk = chunk + b"\x00" * (31 - len(chunk))

        for nonce in range(256):
            x_bytes = chunk + bytes([nonce])
            x_int = int.from_bytes(x_bytes, "big")
            if x_int >= p:
                continue

            rhs = (pow(x_int, 3, p) + b) % p
            if not is_quadratic_residue(rhs):
                continue

            y = sqrt_mod_p(rhs)
            # Compressed SEC format: 0x02 | (y & 1)
            prefix = 0x02 | (y & 1)
            out.append(bytes([prefix]) + x_bytes)
            break
        else:
            raise RuntimeError("No valid nonce found for a chunk (unexpected)")

    return out


def decode_pubkeys_to_stream(pubkeys):
    """
    Reverse of encode_stream_to_pubkeys (ignoring y / prefix),
    assuming all pubkeys were generated via that grinding method.

    Each pubkey: [0x02 or 0x03][31-byte chunk][1-byte nonce]
    We discard the last byte (nonce) and concatenate the 31-byte chunks.
    Caller is responsible for trimming any padding and interpreting BPUB header.
    """
    payload = b"".join(pk[1:-1] for pk in pubkeys)
    return payload


# ---------------------------------------------------------------------------
# BPUB HEADER / STREAM
# ---------------------------------------------------------------------------


def build_stream(
    data: bytes, mime: str, filename: str, compress: bool = False
) -> bytes:
    """
    Build a BPUB v1/v2/v3-compatible stream:
    [ "BPUB" ][version=1][header_len(3)][header][content]

    Header TLVs:
      0x01: size (8 bytes)
      0x02: sha256(content) (32 bytes)
      0x03: mime (len-prefixed)
      0x05: filename (len-prefixed)
      0xFF: terminator (len=0)
    """
    content = zlib.compress(data) if compress else data

    header_parts = [
        bytes([0x01, 8]) + len(content).to_bytes(8, "big"),
        bytes([0x02, 32]) + hashlib.sha256(content).digest(),
        bytes([0x03, len(mime)]) + mime.encode(),
    ]
    if filename:
        header_parts.append(bytes([0x05, len(filename)]) + filename.encode())

    header_parts.append(bytes([0xFF, 0]))
    header = b"".join(header_parts)

    prefix = b"BPUB" + bytes([1]) + len(header).to_bytes(3, "big")
    return prefix + header + content


def decode_stream(payload: bytes):
    """
    Inverse of build_stream: given a raw BPUB stream, return (meta, content).
    """
    if payload[:4] != b"BPUB":
        raise ValueError("Bad magic, not a BPUB stream")

    version = payload[4]
    if version != 1:
        raise ValueError(f"Unsupported BPUB version: {version}")

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


# ---------------------------------------------------------------------------
# MULTISIG SCRIPT CONSTRUCTION
# ---------------------------------------------------------------------------


def build_multisig_script(data_pubkeys, control_pubkey: bytes) -> CScript:
    """
    Build a 1-of-N multisig script:

        OP_1 <data_pk_0> ... <data_pk_M> <control_pubkey> OP_(M+1) OP_CHECKMULTISIG

    where:
      - len(data_pubkeys) + 1 <= MAX_PUBKEYS_PER_SCRIPT
      - `control_pubkey` is a 33-byte compressed SEC pubkey with a real private key.
    """
    if len(control_pubkey) != 33:
        raise ValueError("control_pubkey must be 33-byte compressed SEC pubkey")

    total_keys = len(data_pubkeys) + 1
    if total_keys > MAX_PUBKEYS_PER_SCRIPT:
        raise ValueError(
            f"Too many pubkeys in one script (max {MAX_PUBKEYS_PER_SCRIPT})"
        )

    OP_1 = 0x51
    OP_CHECKMULTISIG = 0xAE

    scr = bytearray()
    scr.append(OP_1)

    for pk in data_pubkeys:
        scr.append(0x21)  # PUSH 33
        scr.extend(pk)

    scr.append(0x21)  # PUSH 33 for control_pubkey
    scr.extend(control_pubkey)

    scr.append(0x50 + total_keys)  # OP_(M+1), e.g. OP_15 etc.
    scr.append(OP_CHECKMULTISIG)

    return CScript(scr)


def p2wsh_scriptpubkey(redeem_script: CScript) -> bytes:
    # 0 <32-byte sha256(redeem_script)>
    return b"\x00\x20" + hashlib.sha256(bytes(redeem_script)).digest()


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------


@dataclass
class UTXO:
    txid: str
    vout: int
    value_sats: int


def bech32_to_scriptpubkey(addr: str) -> bytes:
    """
    Convert a Bech32 SegWit or Taproot address into raw scriptPubKey bytes.
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


def estimate_fee(n_inputs: int, n_outputs: int, feerate: int) -> int:
    """
    Very rough fee estimator (in sats) for segwit txs.

    - Base tx: ~10 bytes version+locktime, ~41 bytes overhead
    - Input: P2WPKH ~68 vbytes, P2WSH multisig ~ ~100+ vbytes
      We'll just approximate with 100 vbytes per input.
    - Output: 34 vbytes

    This is deliberately conservative; use `testmempoolaccept` for exact numbers.
    """
    base_vbytes = 100
    in_vbytes = n_inputs * 100
    out_vbytes = n_outputs * 34
    vbytes = base_vbytes + in_vbytes + out_vbytes
    return vbytes * feerate


def estimate_fee_reveal(n_inputs: int, n_outputs: int, feerate: int) -> int:
    base_vbytes = 100
    in_vbytes = n_inputs * 188
    out_vbytes = n_outputs * 34
    vbytes = base_vbytes + in_vbytes + out_vbytes
    return vbytes * feerate


def estimate_fee_funding(
    n_in_p2wpkh: int, n_out_p2wsh: int, n_out_p2wpkh: int, feerate: int
) -> int:
    """
    Fee estimator for a BPUB funding tx.

    Constants (vbytes):
      - base overhead ~ 12 vbytes
      - P2WPKH input: 68 vbytes
      - P2WSH output: 43 vbytes
      - P2WPKH output (change): 31 vbytes
    """
    base = 12
    in_vbytes = 68 * n_in_p2wpkh
    out_vbytes = 43 * n_out_p2wsh + 31 * n_out_p2wpkh
    vbytes = base + in_vbytes + out_vbytes
    return vbytes * feerate


def chunk_data_pubkeys(pubkeys):
    max_data = MAX_PUBKEYS_PER_SCRIPT - 1
    chunk = []
    for pk in pubkeys:
        chunk.append(pk)
        if len(chunk) == max_data:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def load_psbt_from_arg(psbt_arg: str) -> PSBT:
    """
    Helper: load a PSBT either from a file path or from a base64 string.
    """
    # If it's a file on disk, read its contents
    if os.path.isfile(psbt_arg):
        b64 = open(psbt_arg, "r").read().strip()
    else:
        b64 = psbt_arg.strip()

    return PSBT.from_base64(b64)


# ---------------------------------------------------------------------------
# CLI SUBCOMMANDS
# ---------------------------------------------------------------------------


def cmd_encode(args):
    """
    encode: file -> BPUB stream hex (just a helper)
    """
    data = open(args.file, "rb").read()
    stream = build_stream(data, args.mime, args.filename, args.compress)
    sys.stdout.write(stream.hex() + "\n")


def cmd_decode(args):
    """
    decode: BPUB stream hex -> raw file bytes
    """
    if os.path.isfile(args.stream_hex):
        hexdata = open(args.stream_hex, "r").read().strip()
    else:
        hexdata = args.stream_hex.strip()

    payload = bytes.fromhex(hexdata)
    meta, content = decode_stream(payload)
    sys.stderr.write(
        f"# Decoded BPUB stream: filename={meta.get('filename')}, "
        f"size={meta.get('size')} bytes, mime={meta.get('mime')}\n"
    )
    sys.stdout.buffer.write(content)


def cmd_txbuild(args):
    """
    txbuild: build a funding transaction that commits to the file
    via P2WSH 1-of-N multisig scripts with data-embedded fake pubkeys.

    This produces a raw unsigned transaction (not a PSBT). You can use it
    if you prefer to handle signing yourself via bitcoin-cli, etc.

    Inputs:
      --file, --mime, --filename, --compress
      --control-pubkey: hex compressed SEC pubkey (33 bytes) with a real privkey
      --utxo: TXID:VOUT funding UTXO (P2WPKH/P2WSH/P2TR, etc.)
      --value: value of that UTXO in sats
      --feerate: sats/vbyte
      --change: bech32 change address (optional; if omitted we pay all to BPUB outputs)

    Output:
      - raw hex tx on stdout
    """
    txid_str, vout_str = args.utxo.split(":")
    utxo = UTXO(txid_str, int(vout_str), int(args.value))

    control_pubkey = bytes.fromhex(args.control_pubkey)
    if len(control_pubkey) != 33:
        sys.exit("control-pubkey must be 33-byte compressed pubkey hex")

    data = open(args.file, "rb").read()
    stream = build_stream(data, args.mime, args.filename, args.compress)
    data_pubkeys = encode_stream_to_pubkeys(stream)

    redeem_scripts = []
    spks = []
    n_outputs = 0
    for chunk in chunk_data_pubkeys(data_pubkeys):
        rs = build_multisig_script(chunk, control_pubkey)
        redeem_scripts.append(rs)
        spks.append(p2wsh_scriptpubkey(rs))
        n_outputs += 1

    include_change = bool(args.change)
    if include_change:
        n_outputs += 1

    fee = estimate_fee(n_inputs=1, n_outputs=n_outputs, feerate=args.feerate)
    if utxo.value_sats <= fee:
        sys.exit(f"UTXO too small for fee: need > {fee} sats")

    change_value = utxo.value_sats - fee

    if not include_change:
        per_out = utxo.value_sats // len(spks)
        if per_out <= 546:
            sys.exit(
                "Per-output value would be dust without change; please use --change"
            )
        values = [per_out] * len(spks)
    else:
        DUST = 546
        bpub_total = len(spks) * DUST
        if change_value <= bpub_total:
            sys.exit(f"Not enough for bpub outputs + change, need > {bpub_total} sats")
        values = [DUST] * len(spks)
        change_value = utxo.value_sats - fee - bpub_total
        if change_value < DUST:
            sys.exit(
                f"Change ({change_value} sats) would be dust; increase UTXO or lower fee"
            )

    txin = CMutableTxIn(COutPoint(lx(utxo.txid), utxo.vout))
    txouts = [CMutableTxOut(val, CScript(spk)) for val, spk in zip(values, spks)]

    if include_change:
        change_spk_bytes = bech32_to_scriptpubkey(args.change)
        txouts.append(CMutableTxOut(change_value, CScript(change_spk_bytes)))

    tx = CMutableTransaction([txin], txouts)

    raw = tx.serialize().hex()
    sys.stderr.write(
        f"# Built BPUB v3.5 funding tx with 1 input, {len(txouts)} outputs, "
        f"{len(redeem_scripts)} BPUB outputs, fee≈{fee} sats\n"
    )
    sys.stdout.write(raw + "\n")


def cmd_fundpsbt(args):
    """
    fundpsbt: build a PSBT that funds BPUB v3.5 P2WSH multisig outputs.

    This is like txbuild, but instead of outputting a raw unsigned tx,
    it creates a PSBT that Sparrow (or any wallet) can sign and broadcast.

    Inputs:
      --file, --mime, --filename, --compress
      --control-pubkey: 33-byte compressed pubkey hex
      --utxo: TXID:VOUT funding UTXO
      --value: value of that UTXO in sats
      --feerate: sats/vbyte
      --change: bech32 change address (recommended)

    Output:
      - PSBT (base64) on stdout
    """
    txid_str, vout_str = args.utxo.split(":")
    utxo = UTXO(txid_str, int(vout_str), int(args.value))

    control_pubkey = bytes.fromhex(args.control_pubkey)
    if len(control_pubkey) != 33:
        sys.exit("control-pubkey must be 33-byte compressed pubkey hex")

    data = open(args.file, "rb").read()
    stream = build_stream(data, args.mime, args.filename, args.compress)
    data_pubkeys = encode_stream_to_pubkeys(stream)

    redeem_scripts = []
    spks = []
    n_outputs = 0
    for chunk in chunk_data_pubkeys(data_pubkeys):
        rs = build_multisig_script(chunk, control_pubkey)
        redeem_scripts.append(rs)
        spks.append(p2wsh_scriptpubkey(rs))
        n_outputs += 1

    include_change = bool(args.change)
    if include_change:
        n_outputs += 1

    n_out_p2wsh = n_outputs - 1
    n_out_p2wpkh = 1
    fee = estimate_fee_funding(
        n_in_p2wpkh=1,
        n_out_p2wsh=n_out_p2wsh,
        n_out_p2wpkh=n_out_p2wpkh,
        feerate=args.feerate,
    )
    if utxo.value_sats <= fee:
        sys.exit(f"UTXO too small for fee: need > {fee} sats")

    DUST = 546
    if not include_change:
        per_out = utxo.value_sats // len(spks)
        if per_out <= DUST:
            sys.exit(
                "Per-output value would be dust; please use --change or bigger UTXO"
            )
        values = [per_out] * len(spks)
        change_value = 0
    else:
        bpub_total = len(spks) * DUST
        if utxo.value_sats - fee <= bpub_total:
            sys.exit(
                f"Not enough for BPUB outputs + fee, need > {bpub_total + fee} sats"
            )
        values = [DUST] * len(spks)
        change_value = utxo.value_sats - fee - bpub_total
        if change_value < DUST:
            sys.exit(
                f"Change ({change_value} sats) would be dust; increase UTXO or lower fee"
            )

    txin = CMutableTxIn(COutPoint(lx(utxo.txid), utxo.vout))
    txouts = [CMutableTxOut(val, CScript(spk)) for val, spk in zip(values, spks)]

    if include_change and change_value > 0:
        change_spk_bytes = bech32_to_scriptpubkey(args.change)
        txouts.append(CMutableTxOut(change_value, CScript(change_spk_bytes)))

    tx = CMutableTransaction([txin], txouts)

    psbt = PSBT(unsigned_tx=tx)
    if args.prev_spk:
        prev_spk = CScript(bytes.fromhex(args.prev_spk))
    elif args.prev_address:
        prev_spk = bech32_to_scriptpubkey(args.prev_address)
    else:
        sys.exit(
            "\n[!] Need to know what the funding UTXO pays to for fundpsbt.\n"
            "    Please re-run with ONE of:\n"
            "      --prev-address bc1q...   (Bech32 segwit/taproot address)\n"
            "      --prev-spk <scriptPubKey-hex>\n"
        )

    psbt.set_utxo(
        CTxOut(utxo.value_sats, prev_spk),
        0,
        force_witness_utxo=True,
    )

    sys.stderr.write(
        f"# Built BPUB v3.5 funding PSBT with 1 input, {len(txouts)} outputs, "
        f"{len(redeem_scripts)} BPUB outputs, fee≈{fee} sats\n"
    )
    sys.stdout.write(psbt.to_base64() + "\n")


def cmd_revealpsbt(args):
    """
    revealpsbt: build a PSBT that spends BPUB v3.5 P2WSH multisig outputs
    to your change address.

    Inputs:
      --file, --mime, --filename, --compress
      --control-pubkey: 33-byte compressed pubkey hex
      --bpub-utxo: repeated, format TXID:VOUT:VALUE (one per BPUB output)
      --change: bech32 address to receive all funds
      --feerate: sats/vbyte (default 1)

    Output:
      - PSBT (base64) on stdout
    """
    control_pubkey = bytes.fromhex(args.control_pubkey)
    if len(control_pubkey) != 33:
        sys.exit("control-pubkey must be 33-byte compressed pubkey hex")

    if not args.bpub_utxo:
        sys.exit("Need at least one --bpub-utxo TXID:VOUT:VALUE")

    data = open(args.file, "rb").read()
    stream = build_stream(data, args.mime, args.filename, args.compress)
    data_pubkeys = encode_stream_to_pubkeys(stream)

    script_chunks = list(chunk_data_pubkeys(data_pubkeys))
    expected_scripts = len(script_chunks)

    utxos = []
    for u in args.bpub_utxo:
        try:
            txid_str, vout_str, val_str = u.split(":")
            utxos.append(UTXO(txid_str, int(vout_str), int(val_str)))
        except ValueError:
            sys.exit(f"Bad --bpub-utxo format: {u} (need TXID:VOUT:VALUE)")

    if len(utxos) != expected_scripts:
        sys.stderr.write(
            f"# WARNING: number of BPUB UTXOs ({len(utxos)}) does not match "
            f"number of scripts needed ({expected_scripts}). Proceeding anyway.\n"
        )

    total_in = sum(u.value_sats for u in utxos)

    redeem_scripts = [
        build_multisig_script(chunk, control_pubkey) for chunk in script_chunks
    ]

    if len(redeem_scripts) > len(utxos):
        sys.exit("Not enough BPUB UTXOs provided for all data chunks")

    # Estimate fee: n_inputs = len(utxos), n_outputs = 1
    fee = estimate_fee_reveal(n_inputs=len(utxos), n_outputs=1, feerate=args.feerate)
    if total_in <= fee:
        sys.exit(f"Total BPUB UTXO value ({total_in}) <= fee ({fee})")

    change_value = total_in - fee
    DUST = 546
    if change_value < DUST:
        sys.exit(
            f"Change ({change_value} sats) would be dust; increase total BPUB value or lower feerate"
        )

    change_spk_bytes = bech32_to_scriptpubkey(args.change)
    change_spk = CScript(change_spk_bytes)

    txins = [CMutableTxIn(COutPoint(lx(u.txid), u.vout)) for u in utxos]
    txout = CMutableTxOut(change_value, change_spk)
    tx = CMutableTransaction(txins, [txout])

    psbt = PSBT(unsigned_tx=tx)

    # For each input, attach the witness_utxo and witness_script.
    for idx, (u, rs) in enumerate(zip(utxos, redeem_scripts)):
        spk = p2wsh_scriptpubkey(rs)
        prevout = CTxOut(u.value_sats, CScript(spk))
        psbt.set_utxo(prevout, idx, force_witness_utxo=True)
        psbt.inputs[idx].witness_script = rs

    sys.stderr.write(
        f"# Built BPUB v3.5 reveal PSBT with {len(utxos)} inputs, 1 output, "
        f"fee≈{fee} sats\n"
    )
    sys.stdout.write(psbt.to_base64() + "\n")


def cmd_signreveal(args):
    """
    signreveal: sign a BPUB v3.5 reveal PSBT with a single WIF control key and
    output the final raw transaction hex.

    Usage:
        python3 bpub.py signreveal reveal.psbt \
          --wif <WIF> \
          --control-pubkey <optional sanity-check>
    """
    psbt = load_psbt_from_arg(args.psbt)

    try:
        priv = CBitcoinSecret(args.wif)
    except Exception as e:
        sys.exit(f"Failed to parse WIF: {e}")

    pub = priv.pub
    pub_hex = pub.hex()

    if args.control_pubkey:
        control_hex = args.control_pubkey.lower()
        if control_hex != pub_hex.lower():
            sys.exit(
                f"[!] WIF/pubkey mismatch:\n"
                f"    WIF pubkey:      {pub_hex}\n"
                f"    control-pubkey:  {control_hex}"
            )

    ks = KeyStore()
    ks.add_key(priv)

    unsigned_tx = psbt.unsigned_tx
    for idx, inp in enumerate(psbt.inputs):
        inp.sign(unsigned_tx, ks, finalize=False)

    try:
        psbt.finalize_all()
    except Exception:
        # print("[!] finalize_all() failed or unavailable, trying per-input finalize")
        for inp in psbt.inputs:
            try:
                inp.finalize(unsigned_tx)
            except Exception:
                pass

    try:
        final_tx = psbt.extract_transaction()
    except Exception as e:
        sys.exit(f"Failed to extract transaction: {e}")

    raw_hex = final_tx.serialize().hex()
    sys.stdout.write(raw_hex + "\n")


def cmd_txrecover(args):
    """
    txrecover: recover BPUB v3.5 data from a *reveal* transaction (hex or filename).

    - We assume:
        - The reveal transaction spends 1-of-N multisig P2WSH outputs created earlier.
        - The multisig script looks like:
              OP_1 <data_pk_0> ... <data_pk_M> <control_pubkey> OP_(M+1) OP_CHECKMULTISIG
        - control_pubkey is supplied via --control-pubkey, or the special value
          'auto' can be used to auto-detect it from the scripts.

    - For each input:
        - If witness' last stack item is such a multisig script, and (if provided)
          last pubkey == control_pubkey:
            - We take all prior pubkeys in that script as data pubkeys.
            - We concatenate them across all inputs in order.
        - We ignore the actual signature in the witness (wallet-specific).

    - After collecting all data pubkeys, we decode them back into a BPUB stream and
      then into the original file.
    """

    if os.path.isfile(args.rawtx):
        rawtx_hex = open(args.rawtx, "r").read().strip()
    else:
        rawtx_hex = args.rawtx.strip()

    tx = CTransaction.deserialize(bytes.fromhex(rawtx_hex))
    sys.stderr.write(
        f"# Loaded TX with {len(tx.vin)} inputs and {len(tx.vout)} outputs\n"
    )

    # Auto-detect mode if user passed the sentinel "auto"
    auto_detect = args.control_pubkey.lower() == "auto"

    expected_control = None
    if not auto_detect:
        try:
            expected_control = bytes.fromhex(args.control_pubkey)
        except ValueError:
            sys.exit("control-pubkey must be hex, or the string 'auto'")
        if len(expected_control) != 33:
            sys.exit("control-pubkey must be 33-byte compressed pubkey hex")

    all_data_pubkeys = []
    detected_controls = []  # collect candidate control pubkeys in auto mode

    wit = getattr(tx, "wit", None)
    if wit is None or len(wit.vtxinwit) == 0:
        sys.exit("ERROR: transaction has no witness data")

    for idx, vin in enumerate(tx.vin):
        if idx >= len(tx.wit.vtxinwit):
            continue

        inwit = tx.wit.vtxinwit[idx]
        wstack = list(inwit.scriptWitness.stack)

        if len(wstack) < 2:
            continue

        # Multisig P2WSH spends usually have witness:
        #   <dummy or sigs...> <redeemScript>
        redeem_script = bytes(wstack[-1])
        try:
            elems = list(CScript(redeem_script))
        except Exception:
            continue

        # Expect pattern: OP_1, <33B>*..., OP_(M+1), OP_CHECKMULTISIG
        if len(elems) < 4:
            continue

        op_1 = elems[0]
        op_n = elems[-2]
        op_checkmultisig = elems[-1]

        # bitcointx often parses small integer opcodes as Python ints 1..16
        # rather than raw opcode bytes, so accept both representations.
        is_op_1 = isinstance(op_1, int) and (op_1 == 0x51 or op_1 == 1)
        if not is_op_1:
            continue

        # OP_CHECKMULTISIG should be 0xAE or int 174
        is_op_checkmultisig = isinstance(op_checkmultisig, int) and (
            op_checkmultisig == 0xAE or op_checkmultisig == 174
        )
        if not is_op_checkmultisig:
            continue

        if not isinstance(op_n, int):
            continue

        # All middle elements should be 33-byte pubkeys
        middle = elems[1:-2]
        pubkeys = [e for e in middle if isinstance(e, (bytes, bytearray))]
        if len(pubkeys) != len(middle):
            # Something else (like OP codes) in the middle; skip
            continue

        # Check that op_n matches count of pubkeys (1-of-N => N pubkeys)
        total_keys = len(pubkeys)
        if op_n != 0x50 + total_keys and op_n != total_keys:
            # Accept either OP_(N) form (0x50+N) or raw smallint N
            continue

        # Last pubkey in script is the control key for this script
        control_pk_here = pubkeys[-1]

        if not auto_detect:
            # Explicit mode: must match supplied control key
            if control_pk_here != expected_control:
                continue
        else:
            # Auto-detect mode: keep track of all candidate control keys
            detected_controls.append(control_pk_here)

        data_pks = pubkeys[:-1]
        sys.stderr.write(
            f"# Input {idx}: found BPUB v3.5 script with {len(data_pks)} data pubkeys\n"
        )
        all_data_pubkeys.extend(data_pks)

    # If auto-detect, resolve the control pubkey now and sanity-check uniqueness
    if auto_detect:
        if not detected_controls:
            sys.exit("ERROR: no BPUB-like multisig scripts found (auto-detect failed)")

        unique_controls = {pk for pk in detected_controls}
        if len(unique_controls) > 1:
            sys.stderr.write(
                "# ERROR: auto-detect found multiple distinct control pubkeys:\n"
            )
            for pk in unique_controls:
                sys.stderr.write(f"  - {pk.hex()}\n")
            sys.stderr.write("# Please rerun with an explicit --control-pubkey=<hex>\n")
            sys.exit(1)

        detected = next(iter(unique_controls))
        sys.stderr.write(f"# Auto-detected control pubkey: {detected.hex()}\n")

    if not all_data_pubkeys:
        sys.exit("ERROR: no BPUB v3.5 multisig scripts found in this transaction")

    # Decode data pubkeys back into BPUB stream and content
    raw_stream = decode_pubkeys_to_stream(all_data_pubkeys)
    meta, content = decode_stream(raw_stream)
    sys.stderr.write(
        f"# Recovered BPUB v3.5 file: {meta.get('filename')} "
        f"({meta.get('size')} bytes, mime={meta.get('mime')})\n"
    )
    sys.stdout.buffer.write(content)


# ---------------------------------------------------------------------------
# MAIN / ARGPARSE
# ---------------------------------------------------------------------------


def main():
    p = argparse.ArgumentParser(
        description="BPUB v3.5 — 1-of-N multisig P2WSH with data embedded in redeemScript"
    )
    sp = p.add_subparsers(dest="cmd", required=True)

    # encode: file -> BPUB stream hex
    e = sp.add_parser("encode", help="encode a file into a BPUB stream (hex)")
    e.add_argument("file")
    e.add_argument("--mime", default="application/octet-stream")
    e.add_argument("--filename", default="")
    e.add_argument("--compress", action="store_true")
    e.set_defaults(func=cmd_encode)

    # decode: BPUB stream hex -> raw file bytes
    d = sp.add_parser("decode", help="decode a BPUB stream (hex) back to raw content")
    d.add_argument(
        "stream_hex", help="hex string or filename containing BPUB stream hex"
    )
    d.set_defaults(func=cmd_decode)

    # txbuild: build funding tx with data-embedded P2WSH multisig outputs (raw unsigned)
    tb = sp.add_parser(
        "txbuild", help="build a BPUB v3.5 funding transaction (raw unsigned)"
    )
    tb.add_argument("file", help="file to commit via data-embedded multisig")
    tb.add_argument("--mime", default="application/octet-stream")
    tb.add_argument("--filename", default="")
    tb.add_argument("--compress", action="store_true")
    tb.add_argument(
        "--control-pubkey",
        required=True,
        help="33-byte compressed pubkey hex that will control the funds",
    )
    tb.add_argument("--utxo", required=True, help="funding UTXO as TXID:VOUT")
    tb.add_argument(
        "--value", required=True, type=int, help="value of funding UTXO in sats"
    )
    tb.add_argument(
        "--feerate", required=True, type=int, help="target feerate in sats/vbyte"
    )
    tb.add_argument("--change", help="bech32 change address (optional)")
    tb.set_defaults(func=cmd_txbuild)

    # fundpsbt: build PSBT to fund BPUB multisig outputs (Sparrow-friendly)
    fp = sp.add_parser("fundpsbt", help="build a PSBT to fund BPUB v3.5 P2WSH outputs")
    fp.add_argument("file")
    fp.add_argument("--mime", default="application/octet-stream")
    fp.add_argument("--filename", default="")
    fp.add_argument("--compress", action="store_true")
    fp.add_argument(
        "--control-pubkey",
        required=True,
        help="33-byte compressed pubkey hex that will control the funds",
    )
    fp.add_argument("--utxo", required=True, help="funding UTXO as TXID:VOUT")
    fp.add_argument(
        "--value", required=True, type=int, help="value of funding UTXO in sats"
    )
    fp.add_argument(
        "--feerate", required=True, type=int, help="target feerate in sats/vbyte"
    )
    fp.add_argument("--change", help="bech32 change address (recommended)")
    fp.add_argument(
        "--prev-address",
        help="Bech32 address that the funding UTXO pays to (P2WPKH/P2WSH/P2TR)",
    )
    fp.add_argument(
        "--prev-spk",
        help="Hex scriptPubKey that the funding UTXO pays to",
    )
    fp.set_defaults(func=cmd_fundpsbt)

    # revealpsbt: build PSBT to spend BPUB P2WSH outputs (reveal)
    rp = sp.add_parser(
        "revealpsbt",
        help="build a PSBT to reveal BPUB v3.5 data by spending its P2WSH outputs",
    )
    rp.add_argument("file")
    rp.add_argument("--mime", default="application/octet-stream")
    rp.add_argument("--filename", default="")
    rp.add_argument("--compress", action="store_true")
    rp.add_argument(
        "--control-pubkey",
        required=True,
        help="33-byte compressed pubkey hex used as the control key in multisig scripts",
    )
    rp.add_argument(
        "--bpub-utxo",
        action="append",
        required=True,
        help="BPUB UTXO as TXID:VOUT:VALUE (can be given multiple times)",
    )
    rp.add_argument(
        "--change", required=True, help="bech32 address to receive swept funds"
    )
    rp.add_argument(
        "--feerate", type=int, default=1, help="target feerate in sats/vbyte"
    )
    rp.set_defaults(func=cmd_revealpsbt)

    # signreveal: sign a reveal PSBT with a single WIF key
    sr = sp.add_parser(
        "signreveal", help="sign a BPUB v3.5 reveal PSBT with a WIF control key"
    )
    sr.add_argument(
        "psbt", help="PSBT base64 string or filename containing PSBT base64"
    )
    sr.add_argument(
        "--wif",
        required=True,
        help="WIF private key corresponding to the control pubkey",
    )
    sr.add_argument(
        "--control-pubkey",
        help="(optional) 33-byte compressed pubkey hex for sanity-checking against the WIF",
    )
    sr.set_defaults(func=cmd_signreveal)

    # txrecover: decode from a reveal transaction
    rr = sp.add_parser(
        "txrecover", help="recover file from BPUB v3.5 reveal transaction"
    )
    rr.add_argument("rawtx", help="raw tx hex OR filename containing raw tx hex")
    rr.add_argument(
        "--control-pubkey",
        required=True,
        help="33-byte compressed pubkey hex used as the control key in multisig scripts",
    )
    rr.set_defaults(func=cmd_txrecover)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
