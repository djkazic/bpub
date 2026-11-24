#!/usr/bin/env python3
"""
Custodial BPUB v5 `padv3` Inscription Service (Lightning LND -> BLAKE2b / BTC).

Security properties:
  - Uses LND invoice-only macaroon (LndClient) to generate & verify BOLT11 invoices.
  - Supports BLAKE2b `SIGHASH_ALL | SIGHASH_UNIFIED` (0x21) (pinned to
    privkeyio/bitcoin@54d757f) as well as standard Bitcoin BIP143 SIGHASH_ALL (0x01).
  - Funding transactions are funded & signed via the node's own RPC wallet
    (`fundrawtransaction` + `signrawtransactionwithwallet`), so no hot-wallet
    private keys live in Python env or SQLite.
  - Reveal transactions are signed with a per-order ephemeral control key, verified
    locally before broadcast, persisted durably before funding broadcast, and the
    ephemeral key + private payload file are wiped immediately on completion/expiry.
  - Large funding+reveal pairs (>101,000 vB ancestor limit) automatically wait for
    1 funding confirmation before broadcasting the saved reveal.
  - Ownership is out of scope for this first pass: a minimal 330-sat v5 owner output
    is locked to an ephemeral/service key so the reveal is valid BPUB v5 `padv3`.
"""

import hashlib
import math
import os
import secrets
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from bitcointx.core import (
    COutPoint,
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    CTransaction,
    lx,
)
from bitcointx.core.key import CKey
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUALVERIFY,
    OP_HASH160,
    SIGHASH_ALL,
    SIGVERSION_WITNESS_V0,
    SignatureHash,
)
from bitcointx.wallet import CBitcoinSecret, P2WPKHBitcoinAddress

import bpub
from db import BpubDB
from lnd import LndClient, LndError

# ---------------------------------------------------------------------------
# BLAKE2b Unified Sighash (privkeyio/bitcoin@54d757f269d21e784c771497e0a26b35ab7d0c5a)
# ---------------------------------------------------------------------------

SIGHASH_ALL_INT = 0x01
SIGHASH_UNIFIED = 0x20
SIGHASH_ALL_UNIFIED = SIGHASH_ALL_INT | SIGHASH_UNIFIED  # 0x21
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

UNIFIED_SCRIPT_TYPE_BASE = 0
UNIFIED_SCRIPT_TYPE_WITNESS_V0 = 1
UNIFIED_SCRIPT_TYPE_TAPROOT = 2
UNIFIED_SCRIPT_TYPE_TAPSCRIPT = 3

BPUB_ANCESTOR_VSIZE_LIMIT = 101_000
BPUB_MAX_STANDARD_WEIGHT = 400_000
BPUB_MIN_OWNER_SATS = 330
BPUB_RETURN_DUST_SATS = 330
HOT_WALLET_STALE_SEC = 120


class InsufficientLiquidityError(RuntimeError):
    """Raised when confirmed hot-wallet BTCB2 liquidity cannot cover upfront funding."""


def _compact_size(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack("<B", n)
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def _var_bytes(data: bytes) -> bytes:
    return _compact_size(len(data)) + data


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _serialize_outpoint(txin) -> bytes:
    # bitcointx COutPoint.hash is already in internal little-endian byte order.
    return bytes(txin.prevout.hash) + struct.pack("<I", int(txin.prevout.n))


def _serialize_output(amount: int, script_pubkey: bytes) -> bytes:
    return struct.pack("<q", int(amount)) + _var_bytes(bytes(script_pubkey))


def unified_signature_hash(
    tx: CTransaction,
    input_index: int,
    hash_type: int,
    spent_outputs: List[Tuple[int, bytes]],
    script_type: int = UNIFIED_SCRIPT_TYPE_WITNESS_V0,
    script_code: bytes = b"",
    annex: Optional[bytes] = None,
    leaf_script: Optional[bytes] = None,
    leaf_version: int = 0xC0,
    code_separator_position: int = 0xFFFFFFFF,
) -> Optional[bytes]:
    """
    Compute the BLAKE2b UnifiedSighash digest (returns None for invalid combinations).
    """
    if input_index < 0 or input_index >= len(tx.vin):
        return None
    if len(spent_outputs) != len(tx.vin):
        return None
    if hash_type < 0 or hash_type > 0xFF or (hash_type & SIGHASH_UNIFIED) == 0:
        return None

    output_type = hash_type & 0x1F
    anyone_can_pay = (hash_type & SIGHASH_ANYONECANPAY) != 0
    is_taproot = script_type in (UNIFIED_SCRIPT_TYPE_TAPROOT, UNIFIED_SCRIPT_TYPE_TAPSCRIPT)

    if is_taproot:
        allowed_mask = 0x1F | SIGHASH_ANYONECANPAY | SIGHASH_UNIFIED
        if (hash_type & ~allowed_mask) != 0:
            return None
        if output_type not in (SIGHASH_ALL_INT, SIGHASH_NONE, SIGHASH_SINGLE):
            return None

    parts: List[bytes] = [
        bytes([0, hash_type]),
        struct.pack("<I", int(tx.nVersion) & 0xFFFFFFFF),
        struct.pack("<I", int(tx.nLockTime) & 0xFFFFFFFF),
        b"\x00",  # Reserved high byte of 5-byte locktime
    ]

    if not anyone_can_pay:
        parts.append(hashlib.sha256(b"".join(_serialize_outpoint(i) for i in tx.vin)).digest())
        parts.append(
            hashlib.sha256(b"".join(struct.pack("<q", int(a)) for a, _ in spent_outputs)).digest()
        )
        parts.append(
            hashlib.sha256(b"".join(_var_bytes(bytes(s)) for _, s in spent_outputs)).digest()
        )
        parts.append(
            hashlib.sha256(
                b"".join(struct.pack("<I", int(i.nSequence) & 0xFFFFFFFF) for i in tx.vin)
            ).digest()
        )

    if output_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        parts.append(
            hashlib.sha256(
                b"".join(_serialize_output(o.nValue, bytes(o.scriptPubKey)) for o in tx.vout)
            ).digest()
        )

    parts.append(bytes([script_type]))

    if anyone_can_pay:
        parts.append(_serialize_outpoint(tx.vin[input_index]))
        amt, spk = spent_outputs[input_index]
        parts.append(_serialize_output(amt, spk))
        parts.append(struct.pack("<I", int(tx.vin[input_index].nSequence) & 0xFFFFFFFF))
    else:
        parts.append(struct.pack("<I", input_index))

    if not is_taproot:
        parts.append(_var_bytes(bytes(script_code)))
    else:
        parts.append(b"\x01" if annex is not None else b"\x00")
        if annex is not None:
            parts.append(hashlib.sha256(_var_bytes(bytes(annex))).digest())

    if output_type == SIGHASH_SINGLE:
        if input_index >= len(tx.vout):
            return None
        out = tx.vout[input_index]
        parts.append(hashlib.sha256(_serialize_output(out.nValue, bytes(out.scriptPubKey))).digest())

    if script_type == UNIFIED_SCRIPT_TYPE_TAPSCRIPT:
        ls = leaf_script if leaf_script is not None else script_code
        if not ls or leaf_version < 0 or leaf_version > 0xFF:
            return None
        parts.append(_tagged_hash("TapLeaf", bytes([leaf_version]) + _var_bytes(bytes(ls))))
        parts.append(b"\x00")
        parts.append(struct.pack("<I", int(code_separator_position) & 0xFFFFFFFF))

    return _tagged_hash("UnifiedSighash", b"".join(parts))


# ---------------------------------------------------------------------------
# Order Configuration & Quoting
# ---------------------------------------------------------------------------


@dataclass
class OrderConfig:
    feerate_sat_vb: int = 2
    price_base_sats: int = 500
    price_per_kb_sats: int = 100
    onchain_to_ln_ratio: float = 0.0  # optional multiplier for on-chain sats -> LN sats
    min_ln_sats: int = 500
    max_ln_sats: int = 500_000
    invoice_expiry_sec: int = 900
    max_pending_per_ip: int = 3
    max_total_pending: int = 50
    daily_onchain_budget_sats: int = 5_000_000
    sign_mode: str = "unified"  # "unified" (BLAKE2b 0x21) or "btc" (BIP143 0x01)
    owner_value_sats: int = BPUB_MIN_OWNER_SATS
    rpc_wallet: str = ""
    broadcast_url: str = "https://mempool.kilombino.com/api/tx"

    @classmethod
    def from_env(cls) -> "OrderConfig":
        sign_mode = os.getenv("ORDER_SIGN_MODE", "unified").strip().lower()
        if sign_mode not in ("unified", "btc"):
            sign_mode = "unified"
        return cls(
            feerate_sat_vb=max(1, int(os.getenv("ORDER_FEERATE_SAT_VB", "2"))),
            price_base_sats=max(0, int(os.getenv("ORDER_PRICE_BASE_SATS", "500"))),
            price_per_kb_sats=max(0, int(os.getenv("ORDER_PRICE_PER_KB_SATS", "100"))),
            onchain_to_ln_ratio=max(0.0, float(os.getenv("ORDER_ONCHAIN_TO_LN_RATIO", "0.0"))),
            min_ln_sats=max(1, int(os.getenv("ORDER_MIN_LN_SATS", "500"))),
            max_ln_sats=max(1000, int(os.getenv("ORDER_MAX_LN_SATS", "500000"))),
            invoice_expiry_sec=max(120, int(os.getenv("ORDER_INVOICE_EXPIRY_SEC", "900"))),
            max_pending_per_ip=max(1, int(os.getenv("ORDER_MAX_PENDING_PER_IP", "3"))),
            max_total_pending=max(1, int(os.getenv("ORDER_MAX_TOTAL_PENDING", "50"))),
            daily_onchain_budget_sats=max(
                10_000, int(os.getenv("ORDER_DAILY_BUDGET_SATS", "5000000"))
            ),
            sign_mode=sign_mode,
            owner_value_sats=max(
                BPUB_MIN_OWNER_SATS, int(os.getenv("ORDER_OWNER_VALUE_SATS", "330"))
            ),
            rpc_wallet=os.getenv("ORDER_RPC_WALLET", "").strip(),
            broadcast_url=os.getenv(
                "BROADCAST_URL", "https://mempool.kilombino.com/api/tx"
            ).strip(),
        )


def _tx_weight(tx: CTransaction) -> int:
    stripped = len(tx.serialize(include_witness=False))
    full = len(tx.serialize(include_witness=True))
    return stripped * 3 + full


def quote_padv3_inscription(
    data: bytes,
    filename: str,
    mime: str,
    compress: bool,
    cfg: OrderConfig,
) -> Dict[str, Any]:
    """
    Compute exact `padv3` stream/script counts, exact worst-case reveal weight,
    estimated on-chain cost, and Lightning invoice price in sats.
    """
    if not data:
        raise ValueError("Payload is empty")

    # Use compression only if requested AND it actually reduces payload size.
    use_compress = bool(compress and len(bpub._raw_deflate(data)) < len(data))
    stream = bpub.build_stream_v5(data, mime[:100], filename[:120], compress=use_compress)
    bpub_id = bpub.compute_bpub_v5_id(data)
    data_pubkeys = bpub.encode_stream_to_pubkeys(stream)
    chunks = list(bpub.chunk_data_pubkeys(data_pubkeys, max_pubkeys=bpub.MAX_PUBKEYS_PER_SCRIPT))
    n_outputs = len(chunks)
    if n_outputs < 1 or n_outputs > 643:
        raise ValueError("Payload exceeds single-transaction padv3 capacity (~195 KiB)")

    # Build dummy padv3 scripts to compute exact worst-case reveal weight.
    dummy_ctrl = b"\x02" + b"\x11" * 32
    scripts = [bpub.build_multisig_script(c, dummy_ctrl, pad_suffix=True) for c in chunks]
    dummy_reveal = CMutableTransaction(
        [CMutableTxIn(COutPoint(b"\x00" * 32, i)) for i in range(n_outputs)],
        [CMutableTxOut(BPUB_RETURN_DUST_SATS, CScript(b"\x00\x14" + b"\x00" * 20))],
    )
    for i, rs in enumerate(scripts):
        dummy_reveal.wit.vtxinwit[i].scriptWitness = CScriptWitness([b"", b"\x00" * 73, bytes(rs)])

    reveal_weight = _tx_weight(dummy_reveal)
    if reveal_weight > BPUB_MAX_STANDARD_WEIGHT:
        raise ValueError(
            f"Encoded padv3 reveal ({reveal_weight} WU) exceeds 400,000 WU standard limit"
        )

    reveal_vsize = math.ceil(reveal_weight / 4)
    reveal_fee = math.ceil(reveal_vsize * cfg.feerate_sat_vb)
    per_output_sats = max(547, math.ceil((reveal_fee + BPUB_RETURN_DUST_SATS) / n_outputs))
    data_outputs_total = per_output_sats * n_outputs

    # Conservative funding vsize: 2 inputs + (n_outputs + 1 owner) P2WSH + 1 change output
    funding_vsize = 11 + 2 * 68 + (n_outputs + 1) * 43 + 43
    funding_fee = math.ceil(funding_vsize * cfg.feerate_sat_vb)
    est_onchain_sats = funding_fee + reveal_fee + cfg.owner_value_sats
    upfront_funding_sats = (
        data_outputs_total + funding_fee + cfg.owner_value_sats + BPUB_RETURN_DUST_SATS
    )
    needs_funding_conf = (funding_vsize + reveal_vsize) > BPUB_ANCESTOR_VSIZE_LIMIT

    kb = math.ceil(len(stream) / 1024)
    raw_ln = (
        cfg.price_base_sats
        + kb * cfg.price_per_kb_sats
        + math.ceil(est_onchain_sats * cfg.onchain_to_ln_ratio)
    )
    ln_amount_sats = max(cfg.min_ln_sats, raw_ln)
    if ln_amount_sats > cfg.max_ln_sats:
        raise ValueError(
            f"Computed Lightning price ({ln_amount_sats} sats) exceeds configured cap ({cfg.max_ln_sats} sats)"
        )

    return {
        "bpub_id": bpub_id.hex(),
        "compress": use_compress,
        "stream_bytes": len(stream),
        "data_outputs_count": n_outputs,
        "per_output_sats": per_output_sats,
        "data_outputs_total_sats": data_outputs_total,
        "funding_vsize": funding_vsize,
        "reveal_vsize": reveal_vsize,
        "funding_fee_sats": funding_fee,
        "reveal_fee_sats": reveal_fee,
        "owner_value_sats": cfg.owner_value_sats,
        "est_onchain_sats": est_onchain_sats,
        "upfront_funding_sats": upfront_funding_sats,
        "feerate_sat_vb": cfg.feerate_sat_vb,
        "ln_amount_sats": ln_amount_sats,
        "needs_funding_conf": needs_funding_conf,
        "pad_version": "padv3",
    }


# ---------------------------------------------------------------------------
# Reveal Transaction Builder & Signer (padv3, unified 0x21 or btc 0x01)
# ---------------------------------------------------------------------------


def build_and_sign_padv3_reveal(
    funding_tx: CTransaction,
    redeem_scripts: List[CScript],
    control_key: CKey,
    return_spk: bytes,
    feerate_sat_vb: int,
    sign_mode: str = "unified",
) -> Tuple[str, str, int]:
    """
    Build, sign, and locally verify a `padv3` reveal transaction spending
    outputs `0..len(redeem_scripts)-1` of `funding_tx`.

    Returns `(reveal_txid, reveal_raw_hex, reveal_vsize)`.
    """
    funding_txid_le = funding_tx.GetTxid()
    n = len(redeem_scripts)
    if len(funding_tx.vout) < n:
        raise ValueError("Funding transaction has fewer outputs than redeem scripts")

    spent_outputs: List[Tuple[int, bytes]] = []
    for i, rs in enumerate(redeem_scripts):
        expected_spk = bpub.p2wsh_scriptpubkey(rs)
        out = funding_tx.vout[i]
        if bytes(out.scriptPubKey) != expected_spk:
            raise ValueError(f"Funding output {i} scriptPubKey mismatch for padv3 script")
        spent_outputs.append((int(out.nValue), bytes(out.scriptPubKey)))

    total_in = sum(a for a, _ in spent_outputs)
    txins = [CMutableTxIn(COutPoint(funding_txid_le, i), nSequence=0xFFFFFFFD) for i in range(n)]
    tx = CMutableTransaction(txins, [CMutableTxOut(BPUB_RETURN_DUST_SATS, CScript(return_spk))])

    # Size with worst-case 73-byte DER+sighash signatures.
    for i, rs in enumerate(redeem_scripts):
        tx.wit.vtxinwit[i].scriptWitness = CScriptWitness([b"", b"\x00" * 73, bytes(rs)])
    weight = _tx_weight(tx)
    if weight > BPUB_MAX_STANDARD_WEIGHT:
        raise ValueError(f"Reveal transaction weight {weight} exceeds 400,000 WU")
    vsize = math.ceil(weight / 4)
    fee = math.ceil(vsize * feerate_sat_vb)
    return_value = total_in - fee
    if return_value < BPUB_RETURN_DUST_SATS:
        raise ValueError(
            f"Reveal return ({return_value} sats) below dust threshold ({BPUB_RETURN_DUST_SATS} sats)"
        )
    tx.vout[0].nValue = return_value

    pub = control_key.pub
    for i, rs in enumerate(redeem_scripts):
        amt, _ = spent_outputs[i]
        if sign_mode == "unified":
            sighash = unified_signature_hash(
                tx,
                i,
                SIGHASH_ALL_UNIFIED,
                spent_outputs,
                script_type=UNIFIED_SCRIPT_TYPE_WITNESS_V0,
                script_code=bytes(rs),
            )
            if sighash is None:
                raise RuntimeError("Failed computing unified sighash")
            sig_type_byte = bytes([SIGHASH_ALL_UNIFIED])
        elif sign_mode == "btc":
            sighash = SignatureHash(
                rs, tx, i, SIGHASH_ALL, amount=amt, sigversion=SIGVERSION_WITNESS_V0
            )
            sig_type_byte = bytes([SIGHASH_ALL])
        else:
            raise ValueError(f"Unknown sign_mode: {sign_mode}")

        der_sig = control_key.sign(sighash)
        if not pub.verify(sighash, der_sig):
            raise RuntimeError(f"Local ECDSA verification failed on reveal input {i}")
        tx.wit.vtxinwit[i].scriptWitness = CScriptWitness(
            [b"", der_sig + sig_type_byte, bytes(rs)]
        )

    final_weight = _tx_weight(tx)
    if final_weight > BPUB_MAX_STANDARD_WEIGHT:
        raise ValueError(f"Signed reveal weight {final_weight} exceeds 400,000 WU")
    return tx.GetTxid()[::-1].hex(), tx.serialize(include_witness=True).hex(), math.ceil(
        final_weight / 4
    )


# ---------------------------------------------------------------------------
# Knots / Bitcoin Core RPC Wallet Funding Backend
# ---------------------------------------------------------------------------


class RpcWalletBackend:
    """
    Funds and signs custodial funding transactions via the configured node RPC
    wallet, keeping wallet keys strictly inside bitcoind.
    """

    def __init__(self, rpc_url: str, broadcast_url: str = ""):
        self.rpc_url = rpc_url
        self.broadcast_url = broadcast_url

    @classmethod
    def from_env(cls, cfg: OrderConfig) -> Optional["RpcWalletBackend"]:
        user = os.getenv("BITCOIN_RPC_USER", "").strip()
        pw = os.getenv("BITCOIN_RPC_PASSWORD", "").strip()
        host = os.getenv("BITCOIN_RPC_HOST", "127.0.0.1").strip()
        port = os.getenv("BITCOIN_RPC_PORT", "8332").strip()
        if not user or not pw:
            return None
        wallet_path = f"/wallet/{cfg.rpc_wallet}" if cfg.rpc_wallet else ""
        return cls(
            rpc_url=f"http://{user}:{pw}@{host}:{port}{wallet_path}",
            broadcast_url=cfg.broadcast_url,
        )

    def _rpc(self):
        from bitcoinrpc.authproxy import AuthServiceProxy

        return AuthServiceProxy(self.rpc_url)

    def get_return_scriptpubkey(self) -> bytes:
        rpc = self._rpc()
        addr = rpc.getrawchangeaddress()
        info = rpc.getaddressinfo(addr)
        return bytes.fromhex(info["scriptPubKey"])

    def get_confirmed_balance_sats(self) -> Tuple[int, str]:
        rpc = self._rpc()
        bals = rpc.getbalances()
        trusted_btc = float(bals.get("mine", {}).get("trusted") or 0.0)
        return int(round(trusted_btc * 100_000_000)), ""

    def fund_and_sign_funding_tx(
        self,
        outputs: List[Tuple[bytes, int]],
        feerate_sat_vb: int,
    ) -> Tuple[str, str]:
        """
        Build a funding tx whose first `len(outputs)` outputs are EXACTLY `outputs`
        (in order, preserving vout indices 0..N-1 for data + N for owner), funded
        and signed by the node wallet (change appended after `len(outputs)`).
        """
        rpc = self._rpc()
        base_tx = CMutableTransaction(
            [],
            [CMutableTxOut(val, CScript(spk)) for spk, val in outputs],
        )
        raw_base = base_tx.serialize().hex()
        funded = rpc.fundrawtransaction(
            raw_base,
            {
                "fee_rate": feerate_sat_vb,
                "changePosition": len(outputs),
                "replaceable": True,
            },
        )
        signed = rpc.signrawtransactionwithwallet(funded["hex"])
        if not signed.get("complete"):
            raise RuntimeError(f"Wallet failed to sign funding tx: {signed.get('errors')}")
        raw_hex = signed["hex"]
        tx = CTransaction.deserialize(bytes.fromhex(raw_hex))
        return tx.GetTxid()[::-1].hex(), raw_hex

    def broadcast_tx(self, raw_hex: str) -> str:
        rpc = self._rpc()
        try:
            return str(rpc.sendrawtransaction(raw_hex))
        except Exception as rpc_err:
            if not self.broadcast_url:
                raise
            resp = requests.post(
                self.broadcast_url,
                data=raw_hex,
                headers={"Content-Type": "text/plain"},
                timeout=15,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"RPC broadcast failed ({rpc_err}); explorer rejected: {resp.text[:200]}"
                ) from rpc_err
            return resp.text.strip()

    def get_confirmations(self, txid: str) -> int:
        rpc = self._rpc()
        try:
            info = rpc.gettransaction(txid)
            return int(info.get("confirmations") or 0)
        except Exception:
            try:
                raw = rpc.getrawtransaction(txid, True)
                return int(raw.get("confirmations") or 0)
            except Exception:
                return 0


class EsploraHotWalletBackend:
    """
    Node-less custodial hot wallet backed by one or more Esplora / mempool APIs
    (e.g. mempool.kilombino.com + mempool.guide) and a single dedicated P2WPKH
    WIF (`ORDER_HOT_WIF`). Round-robins & fails over across configured explorers,
    signs with BLAKE2b `SIGHASH_UNIFIED` (0x21) or Bitcoin BIP143 (0x01).
    """

    def __init__(
        self,
        wif: str,
        explorer_base_url,
        broadcast_url: str = "",
        sign_mode: str = "unified",
        timeout: int = 15,
    ):
        secret = CBitcoinSecret(wif.strip())
        self.key = CKey.from_secret_bytes(secret.secret_bytes)
        self.pub = bytes(self.key.pub)
        self.h160 = hashlib.new("ripemd160", hashlib.sha256(self.pub).digest()).digest()
        self.spk = b"\x00\x14" + self.h160
        self.script_code = bytes(
            CScript([OP_DUP, OP_HASH160, self.h160, OP_EQUALVERIFY, OP_CHECKSIG])
        )
        self.address = str(P2WPKHBitcoinAddress.from_scriptPubKey(CScript(self.spk)))
        if isinstance(explorer_base_url, str):
            urls = [u.strip().rstrip("/") for u in explorer_base_url.split(",") if u.strip()]
        else:
            urls = [str(u).strip().rstrip("/") for u in explorer_base_url if str(u).strip()]
        if not urls:
            raise ValueError("At least one Esplora URL is required")
        self.apis = [f"{u}/api" for u in urls]
        self.api = self.apis[0]
        self._rr = 0
        burls = [u.strip() for u in (broadcast_url or "").split(",") if u.strip()]
        self.broadcast_urls = burls if burls else [f"{a}/tx" for a in self.apis]
        self.sign_mode = sign_mode
        self.timeout = timeout
        self._spent_outpoints = set()

    @classmethod
    def from_env(cls, cfg: OrderConfig) -> Optional["EsploraHotWalletBackend"]:
        wif = os.getenv("ORDER_HOT_WIF", "").strip()
        if not wif:
            return None
        esplora_urls = os.getenv(
            "ESPLORA_URLS",
            os.getenv("EXPLORER_BASE_URL", "https://mempool.kilombino.com,https://mempool.guide"),
        ).strip()
        return cls(
            wif=wif,
            explorer_base_url=esplora_urls,
            broadcast_url=os.getenv("BROADCAST_URLS", "").strip(),
            sign_mode=cfg.sign_mode,
        )

    def _ordered_apis(self) -> List[str]:
        n = len(self.apis)
        start = self._rr % n
        self._rr = (self._rr + 1) % n
        return [self.apis[(start + i) % n] for i in range(n)]

    def get_return_scriptpubkey(self) -> bytes:
        return self.spk

    def get_confirmed_balance_sats(self) -> Tuple[int, str]:
        utxos = self._fetch_utxos()
        return sum(int(u["value"]) for u in utxos), self.address

    def _fetch_utxos(self) -> List[Dict[str, Any]]:
        last_err = None
        utxos = None
        for api in self._ordered_apis():
            try:
                resp = requests.get(
                    f"{api}/address/{self.address}/utxo", timeout=self.timeout
                )
            except requests.RequestException as e:
                last_err = e
                continue
            if resp.status_code in (429,) or resp.status_code >= 500:
                last_err = RuntimeError(f"HTTP {resp.status_code} from {api}")
                continue
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Esplora UTXO lookup failed HTTP {resp.status_code}: {resp.text[:200]}"
                )
            utxos = resp.json()
            break
        if utxos is None:
            raise RuntimeError(f"All Esplora backends failed UTXO lookup: {last_err}")
        # Require >= 1 confirmation (matches Knots/BcashJr BPUB funding rule).
        confirmed = [
            u
            for u in utxos
            if u.get("status", {}).get("confirmed")
            and f"{u['txid']}:{u['vout']}" not in self._spent_outpoints
        ]
        confirmed.sort(key=lambda u: int(u["value"]), reverse=True)
        return confirmed

    def fund_and_sign_funding_tx(
        self,
        outputs: List[Tuple[bytes, int]],
        feerate_sat_vb: int,
    ) -> Tuple[str, str]:
        utxos = self._fetch_utxos()
        if not utxos:
            raise InsufficientLiquidityError(
                f"No confirmed UTXOs available in hot wallet ({self.address})"
            )

        out_total = sum(v for _, v in outputs)
        selected: List[Dict[str, Any]] = []
        selected_total = 0

        for u in utxos:
            selected.append(u)
            selected_total += int(u["value"])
            # Exact P2WPKH funding vsize estimate (11 + 68*in + 43*p2wsh_out + 31*p2wpkh_change)
            est_vsize = 11 + len(selected) * 68 + len(outputs) * 43 + 31
            est_fee = math.ceil(est_vsize * feerate_sat_vb)
            if selected_total >= out_total + est_fee + BPUB_RETURN_DUST_SATS:
                break

        est_vsize = 11 + len(selected) * 68 + len(outputs) * 43 + 31
        fee = math.ceil(est_vsize * feerate_sat_vb)
        change = selected_total - out_total - fee
        if change < BPUB_RETURN_DUST_SATS:
            raise InsufficientLiquidityError(
                f"Insufficient confirmed hot-wallet balance ({selected_total} sats; "
                f"need {out_total + fee + BPUB_RETURN_DUST_SATS} sats in {self.address})"
            )

        txins = [
            CMutableTxIn(COutPoint(lx(u["txid"]), int(u["vout"])), nSequence=0xFFFFFFFD)
            for u in selected
        ]
        txouts = [CMutableTxOut(val, CScript(spk)) for spk, val in outputs]
        txouts.append(CMutableTxOut(change, CScript(self.spk)))
        tx = CMutableTransaction(txins, txouts)

        spent_outputs = [(int(u["value"]), self.spk) for u in selected]
        for i, (amt, _) in enumerate(spent_outputs):
            if self.sign_mode == "unified":
                sighash = unified_signature_hash(
                    tx,
                    i,
                    SIGHASH_ALL_UNIFIED,
                    spent_outputs,
                    script_type=UNIFIED_SCRIPT_TYPE_WITNESS_V0,
                    script_code=self.script_code,
                )
                if sighash is None:
                    raise RuntimeError("Failed computing unified sighash for funding input")
                sig_type = bytes([SIGHASH_ALL_UNIFIED])
            elif self.sign_mode == "btc":
                sighash = SignatureHash(
                    CScript(self.script_code),
                    tx,
                    i,
                    SIGHASH_ALL,
                    amount=amt,
                    sigversion=SIGVERSION_WITNESS_V0,
                )
                sig_type = bytes([SIGHASH_ALL])
            else:
                raise ValueError(f"Unknown sign_mode: {self.sign_mode}")

            der_sig = self.key.sign(sighash)
            if not self.key.pub.verify(sighash, der_sig):
                raise RuntimeError(f"Local ECDSA verify failed on funding input {i}")
            tx.wit.vtxinwit[i].scriptWitness = CScriptWitness([der_sig + sig_type, self.pub])

        for u in selected:
            self._spent_outpoints.add(f"{u['txid']}:{u['vout']}")
        return tx.GetTxid()[::-1].hex(), tx.serialize(include_witness=True).hex()

    def broadcast_tx(self, raw_hex: str) -> str:
        last_err = None
        for url in self.broadcast_urls:
            try:
                resp = requests.post(
                    url,
                    data=raw_hex,
                    headers={"Content-Type": "text/plain"},
                    timeout=self.timeout,
                )
            except requests.RequestException as e:
                last_err = e
                continue
            if resp.status_code == 200:
                return resp.text.strip()
            if resp.status_code == 429 or resp.status_code >= 500:
                last_err = RuntimeError(f"HTTP {resp.status_code} from {url}: {resp.text[:200]}")
                continue
            raise RuntimeError(
                f"Esplora broadcast rejected HTTP {resp.status_code}: {resp.text[:300]}"
            )
        raise RuntimeError(f"All Esplora broadcast endpoints failed: {last_err}")

    def get_confirmations(self, txid: str) -> int:
        for api in self._ordered_apis():
            try:
                resp = requests.get(f"{api}/tx/{txid}/status", timeout=self.timeout)
                if resp.status_code != 200:
                    continue
                st = resp.json()
                if not st.get("confirmed"):
                    return 0
                tip_resp = requests.get(f"{api}/blocks/tip/height", timeout=self.timeout)
                if tip_resp.status_code == 200 and st.get("block_height"):
                    return max(1, int(tip_resp.text.strip()) - int(st["block_height"]) + 1)
                return 1
            except Exception:
                continue
        return 0


# ---------------------------------------------------------------------------
# Order Service (Create + Poll + Fulfill)
# ---------------------------------------------------------------------------


class OrderService:
    """Manages custodial Lightning -> padv3 inscription orders securely."""

    def __init__(
        self,
        db: BpubDB,
        payload_dir: Path,
        lnd: LndClient,
        wallet_backend: Optional[Any],
        cfg: OrderConfig,
    ):
        self.db = db
        self.payload_dir = Path(payload_dir)
        self.payload_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.payload_dir, 0o700)
        except OSError:
            pass
        self.lnd = lnd
        self.wallet = wallet_backend
        self.cfg = cfg
        self._fulfill_lock = threading.Lock()

    def _safe_unlink_payload(self, path_str: Optional[str]) -> None:
        if not path_str:
            return
        try:
            resolved_dir = self.payload_dir.resolve()
            target = Path(path_str).resolve()
            if target.parent == resolved_dir and target.is_file():
                target.unlink()
        except OSError:
            pass

    def quote(self, data: bytes, filename: str, mime: str, compress: bool = True) -> Dict[str, Any]:
        return quote_padv3_inscription(data, filename, mime, compress, self.cfg)

    def refresh_hot_wallet_liquidity(self) -> Optional[int]:
        """Publish the hot wallet's confirmed BTCB2 balance into SQLite."""
        if self.wallet is None or not hasattr(self.wallet, "get_confirmed_balance_sats"):
            return None
        try:
            confirmed_sats, addr = self.wallet.get_confirmed_balance_sats()
            self.db.set_hot_wallet_state(confirmed_sats, address=addr)
            return confirmed_sats
        except Exception:
            return None

    def available_liquidity_sats(self) -> Optional[int]:
        """
        Return confirmed hot-wallet sats minus all sats currently reserved by
        live unpaid invoices, paid orders, and awaiting_liquidity retries.
        Returns None if the worker's liquidity heartbeat is missing or stale.
        """
        if self.wallet is not None and hasattr(self.wallet, "get_confirmed_balance_sats"):
            self.refresh_hot_wallet_liquidity()
        hw = self.db.get_hot_wallet_state()
        if hw is None:
            return None
        if int(time.time()) - int(hw["updated_at"]) > HOT_WALLET_STALE_SEC:
            return None
        reserved = self.db.reserved_upfront_sats()
        return max(0, int(hw["confirmed_sats"]) - reserved)

    def create_order(
        self,
        *,
        data: bytes,
        filename: str,
        mime: str,
        compress: bool,
        client_ip: str,
    ) -> Dict[str, Any]:
        with self._fulfill_lock:
            # Anti-DoS invoice-flooding caps + daily on-chain budget circuit breaker.
            if self.db.count_pending_orders_for_ip(client_ip) >= self.cfg.max_pending_per_ip:
                raise ValueError(
                    f"Too many unpaid invoices pending for your IP (max {self.cfg.max_pending_per_ip}). "
                    "Pay or wait for an existing invoice to expire."
                )
            if self.db.count_total_pending_orders() >= self.cfg.max_total_pending:
                raise ValueError("Service is busy with pending invoices; please try again shortly.")

            q = self.quote(data, filename, mime, compress)
            spent_24h = self.db.daily_onchain_spend_sats()
            if spent_24h + q["est_onchain_sats"] > self.cfg.daily_onchain_budget_sats:
                raise ValueError("Daily inscription capacity reached; please try again tomorrow.")

            # Pre-invoice liquidity check: never issue a Lightning invoice unless
            # unreserved confirmed BTCB2 liquidity covers this order's upfront funding.
            avail = self.available_liquidity_sats()
            if avail is None:
                raise InsufficientLiquidityError(
                    "Inscription hot-wallet worker is currently unavailable; please try again shortly."
                )
            if avail < q["upfront_funding_sats"]:
                raise InsufficientLiquidityError(
                    f"Insufficient service BTCB2 liquidity for this file size right now "
                    f"(need {q['upfront_funding_sats']} sats upfront, {avail} sats currently unreserved). "
                    "Try a smaller file or check back after pending confirmations clear."
                )

            order_id = secrets.token_hex(16)
            memo = f"BPUB padv3: {filename[:40]} ({order_id[:8]})"
            inv = self.lnd.create_invoice(
                amount_sats=q["ln_amount_sats"],
                memo=memo,
                expiry_sec=self.cfg.invoice_expiry_sec,
            )

            # Persist private upload bytes outside /media (0600) until reveal completes.
            payload_file = self.payload_dir / f"{order_id}.bin"
            fd = os.open(str(payload_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)

            now = int(time.time())
            control_privkey_hex = secrets.token_bytes(32).hex()
            try:
                return self.db.create_order(
                    {
                        "order_id": order_id,
                        "status": "awaiting_payment",
                        "created_at": now,
                        "expires_at": now + self.cfg.invoice_expiry_sec,
                        "updated_at": now,
                        "client_ip": client_ip,
                        "filename": filename[:120],
                        "mime": mime[:100],
                        "compress": q["compress"],
                        "size_bytes": len(data),
                        "payload_sha256": hashlib.sha256(data).hexdigest(),
                        "payload_path": str(payload_file),
                        "bpub_id": q["bpub_id"],
                        "data_outputs_count": q["data_outputs_count"],
                        "feerate_sat_vb": q["feerate_sat_vb"],
                        "est_onchain_sats": q["est_onchain_sats"],
                        "upfront_funding_sats": q["upfront_funding_sats"],
                        "ln_amount_sats": q["ln_amount_sats"],
                        "r_hash": inv["r_hash"],
                        "payment_request": inv["payment_request"],
                        "control_privkey_hex": control_privkey_hex,
                        "needs_funding_conf": q["needs_funding_conf"],
                    }
                )
            except Exception:
                self._safe_unlink_payload(str(payload_file))
                raise

    def process_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        """
        Advance a single order through its state machine (idempotent, serialized).
        """
        with self._fulfill_lock:
            order = self.db.get_order_internal(order_id)
            if order is None:
                return None

            status = order["status"]
            now = int(time.time())

            if status == "awaiting_payment":
                try:
                    inv = self.lnd.lookup_invoice(order["r_hash"])
                except LndError:
                    return self.db.get_order_public(order_id)

                if inv["settled"] and inv["amt_paid_sat"] >= order["ln_amount_sats"]:
                    self.db.update_order(
                        order_id, expected_status="awaiting_payment", status="paid"
                    )
                    order = self.db.get_order_internal(order_id)
                    status = order["status"]
                elif inv["canceled"] or now > int(order["expires_at"]):
                    self._safe_unlink_payload(order.get("payload_path"))
                    self.db.update_order(
                        order_id,
                        expected_status="awaiting_payment",
                        status="expired",
                        clear_secrets=True,
                    )
                    return self.db.get_order_public(order_id)
                else:
                    return self.db.get_order_public(order_id)

            if status in ("paid", "awaiting_liquidity"):
                if self.wallet is None:
                    return self.db.get_order_public(order_id)
                self._fulfill_paid_order(order)
                return self.db.get_order_public(order_id)

            if status == "awaiting_funding_conf":
                if self.wallet is None:
                    return self.db.get_order_public(order_id)
                self._try_broadcast_waiting_reveal(order)
                return self.db.get_order_public(order_id)

            return self.db.get_order_public(order_id)

    def _fulfill_paid_order(self, order: Dict[str, Any]) -> None:
        order_id = order["order_id"]
        try:
            payload_path = order.get("payload_path")
            if not payload_path or not Path(payload_path).is_file():
                raise RuntimeError("Order payload file missing")
            data = Path(payload_path).read_bytes()
            if hashlib.sha256(data).hexdigest() != order["payload_sha256"]:
                raise RuntimeError("Order payload integrity mismatch")

            ctrl_hex = order.get("control_privkey_hex")
            if not ctrl_hex:
                raise RuntimeError("Order control key missing")
            ctrl_key = CKey.from_secret_bytes(bytes.fromhex(ctrl_hex))
            ctrl_pub = bytes(ctrl_key.pub)

            stream = bpub.build_stream_v5(
                data,
                order["mime"],
                order["filename"],
                compress=bool(order["compress"]),
            )
            bpub_id = bpub.compute_bpub_v5_id(data)
            data_pubkeys = bpub.encode_stream_to_pubkeys(stream)
            chunks = list(
                bpub.chunk_data_pubkeys(data_pubkeys, max_pubkeys=bpub.MAX_PUBKEYS_PER_SCRIPT)
            )
            redeem_scripts = [
                bpub.build_multisig_script(c, ctrl_pub, pad_suffix=True) for c in chunks
            ]

            # Size data outputs to cover reveal fee + return dust (uniform O(n) >= 547 sats).
            q = quote_padv3_inscription(
                data,
                order["filename"],
                order["mime"],
                bool(order["compress"]),
                self.cfg,
            )
            per_out = q["per_output_sats"]

            # Ownership out of scope for v1: minimal 330-sat v5 owner output locked to
            # a deterministic hash of the ephemeral control key (valid BPUB v5 on-chain).
            owner_h160 = hashlib.new("ripemd160", hashlib.sha256(ctrl_pub).digest()).digest()
            owner_rs = bpub.build_owner_redeem_script(bpub_id, owner_h160)
            outputs: List[Tuple[bytes, int]] = [
                (bpub.p2wsh_scriptpubkey(rs), per_out) for rs in redeem_scripts
            ]
            outputs.append((bpub.p2wsh_scriptpubkey(owner_rs), self.cfg.owner_value_sats))

            feerate = int(order["feerate_sat_vb"])
            funding_txid, funding_raw_hex = self.wallet.fund_and_sign_funding_tx(
                outputs, feerate
            )
            funding_tx = CTransaction.deserialize(bytes.fromhex(funding_raw_hex))
            funding_vsize = math.ceil(_tx_weight(funding_tx) / 4)

            return_spk = self.wallet.get_return_scriptpubkey()
            reveal_txid, reveal_raw_hex, reveal_vsize = build_and_sign_padv3_reveal(
                funding_tx=funding_tx,
                redeem_scripts=redeem_scripts,
                control_key=ctrl_key,
                return_spk=return_spk,
                feerate_sat_vb=feerate,
                sign_mode=self.cfg.sign_mode,
            )

            # Persist both signed transactions BEFORE broadcasting (crash-safe durability).
            needs_conf = (funding_vsize + reveal_vsize) > BPUB_ANCESTOR_VSIZE_LIMIT
            self.db.update_order(
                order_id,
                expected_status=order["status"],
                status="funding_broadcast",
                funding_txid=funding_txid,
                funding_raw_hex=funding_raw_hex,
                reveal_txid=reveal_txid,
                reveal_raw_hex=reveal_raw_hex,
                error_message="",
            )

            self.wallet.broadcast_tx(funding_raw_hex)
            # Refresh hot-wallet confirmed liquidity immediately after spending inputs.
            self.refresh_hot_wallet_liquidity()

            if needs_conf:
                self._safe_unlink_payload(payload_path)
                self.db.update_order(
                    order_id,
                    status="awaiting_funding_conf",
                    clear_secrets=True,
                )
            else:
                self.wallet.broadcast_tx(reveal_raw_hex)
                self._safe_unlink_payload(payload_path)
                self.db.update_order(
                    order_id,
                    status="completed",
                    clear_secrets=True,
                )
        except InsufficientLiquidityError as e:
            # Transient confirmed-UTXO shortage (e.g., waiting for change/top-up to confirm).
            # Keep reserved in `awaiting_liquidity` so new invoices cannot over-subscribe.
            self.db.update_order(
                order_id,
                status="awaiting_liquidity",
                error_message=str(e),
            )
        except Exception as e:
            self.db.update_order(
                order_id,
                status="failed",
                error_message=str(e),
            )

    def _try_broadcast_waiting_reveal(self, order: Dict[str, Any]) -> None:
        order_id = order["order_id"]
        funding_txid = order.get("funding_txid")
        reveal_raw_hex = order.get("reveal_raw_hex")
        if not funding_txid or not reveal_raw_hex:
            return
        confs = self.wallet.get_confirmations(funding_txid)
        if confs < 1:
            return
        try:
            self.wallet.broadcast_tx(reveal_raw_hex)
            self.db.update_order(order_id, status="completed", clear_secrets=True)
        except Exception as e:
            self.db.update_order(order_id, error_message=f"Reveal broadcast retry pending: {e}")

    def poll_all_active(self) -> int:
        self.refresh_hot_wallet_liquidity()
        processed = 0
        for order in self.db.list_active_orders():
            self.process_order(order["order_id"])
            processed += 1
        return processed
