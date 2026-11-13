#!/usr/bin/env python3
"""
End-to-end relay check of BPUB script variants against a real node.

Starts a bitcoind (recent Knots build) on regtest, then:

  - funds BPUB outputs for the padded and legacy script variants
    (both must be ACCEPTED),
  - checks the padded reveal is ACCEPTED by testmempoolaccept, mines it,
    and recovers the embedded data from the chain,
  - checks the legacy variants are REJECTED (negative control proving
    the node enforces the current relay policy).

Environment:
  BPUB_NODE_BINDIR      directory containing bitcoind/bitcoin-cli (required)
  BPUB_SECP256K1_PATH   path to a python-bitcointx-compatible libsecp256k1
                        (e.g. v0.3.x) if the system one is too new
  BPUB_NODE_DATADIR     regtest datadir (default: a fresh dir under /tmp)
  BPUB_NODE_MODE        "policy" (default): expects v2 reveal ALLOWED and
                        both plain variants (legacy 1-of-15, plain 1-of-11)
                        REJECTED (txn-datacarrier-*).
                        "deadbranch": expects v2 reveal ALLOWED and the v1
                        suffix reveal REJECTED (txn-datacarrier-nonstandard).
  BPUB_NODE_EXTRA_ARGS  extra bitcoind args (space-separated)

Example:
  BPUB_NODE_BINDIR=/tmp/knots/build/bin \
  BPUB_SECP256K1_PATH=/path/to/libsecp256k1.so \
  python3 tests/regtest_relay.py
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bitcointx

if os.environ.get("BPUB_SECP256K1_PATH"):
    bitcointx.set_custom_secp256k1_path(os.environ["BPUB_SECP256K1_PATH"])

from bitcointx import select_chain_params, BitcoinRegtestParams
from bitcointx.core import (
    lx,
    COutPoint,
    CMutableTxIn,
    CMutableTxOut,
    CMutableTransaction,
)
from bitcointx.core.key import CKey
from bitcointx.core.script import (
    CScript,
    CScriptWitness,
    SignatureHash,
    SIGHASH_ALL,
    SIGVERSION_WITNESS_V0,
)

import bpub
from bpub import (
    build_multisig_script,
    build_stream_v5,
    bpub_output_values,
    chunk_data_pubkeys,
    encode_stream_to_pubkeys,
    estimate_fee_reveal,
    make_pad_items,
    p2wsh_scriptpubkey,
)

select_chain_params(BitcoinRegtestParams)

BINDIR = os.environ.get("BPUB_NODE_BINDIR")
if not BINDIR:
    sys.exit("Set BPUB_NODE_BINDIR to a bin/ dir with bitcoind+bitcoin-cli")
DATADIR = os.environ.get("BPUB_NODE_DATADIR", "/tmp/bpub-relay-regtest")
CLI = [f"{BINDIR}/bitcoin-cli", "-regtest", f"-datadir={DATADIR}"]
MODE = os.environ.get("BPUB_NODE_MODE", "policy")
EXTRA_ARGS = os.environ.get("BPUB_NODE_EXTRA_ARGS", "").split()


def cli(*args):
    r = subprocess.run(CLI + [str(a) for a in args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"bitcoin-cli {' '.join(args)}: {r.stderr}")
    return r.stdout.strip()


def run_checks():
    version = subprocess.run(
        [f"{BINDIR}/bitcoind", "--version"], capture_output=True, text=True
    ).stdout.splitlines()[0]
    print(f"node under test: {version}")
    if "Knots" not in version:
        sys.exit("expected a Knots bitcoind for the policy expectations")

    mine_key = CKey.from_secret_bytes(hashlib.sha256(b"regtest mine").digest())
    control_key = CKey.from_secret_bytes(hashlib.sha256(b"regtest control").digest())
    control_pub = bytes(control_key.pub)

    mine_spk = b"\x00\x14" + bitcointx.core.Hash160(bytes(mine_key.pub))
    mine_desc = json.loads(cli("getdescriptorinfo", f"raw({mine_spk.hex()})"))[
        "descriptor"
    ]

    # Mine 103 blocks so the first three coinbases mature (one per variant).
    print("mining 103 blocks ...")
    for _ in range(103):
        cli("generateblock", mine_desc, "[]")
    height = int(cli("getblockcount"))
    assert height == 103, height

    # Find the block-1..3 coinbases paying to mine_spk.
    coinbases = []
    for h in (1, 2, 3):
        b = json.loads(cli("getblock", cli("getblockhash", h), 2))
        cb = b["tx"][0]
        vout = next(
            i for i, o in enumerate(cb["vout"])
            if o["scriptPubKey"]["hex"] == mine_spk.hex()
        )
        value = int(round(cb["vout"][vout]["value"] * 1e8))
        coinbases.append((cb["txid"], vout, value))
        print(f"coinbase {cb['txid']}:{vout} = {value} sats")

    # --- Build the BPUB data + scripts (all variants) ----------------------
    data = os.urandom(1000)
    stream = build_stream_v5(data, "application/octet-stream", "regtest.bin")
    data_pubkeys = encode_stream_to_pubkeys(stream)
    chunks = list(chunk_data_pubkeys(data_pubkeys))
    chunks10 = [data_pubkeys[i : i + 10] for i in range(0, len(data_pubkeys), 10)]
    print(f"{len(data)} bytes -> {len(chunks)} 15-key scripts, "
          f"{len(chunks10)} 11-key scripts")

    def build_variant(name):
        """Returns (scripts, values) for a variant."""
        if name == "padded":  # current v2 suffix
            scripts = [
                build_multisig_script(c, control_pub, pad_suffix=True)
                for c in chunks
            ]
        elif name == "v1":  # original suffix; no longer publicly buildable
            scripts = []
            for c in chunks:
                base = bytes(
                    build_multisig_script(c, control_pub, pad_suffix=False)
                )
                scripts.append(
                    CScript(base + bpub._serialize_elems(bpub._pad_suffix_elems(1)))
                )
        elif name == "eleven":  # plain 1-of-11
            scripts = [
                build_multisig_script(c, control_pub, pad_suffix=False)
                for c in chunks10
            ]
        else:  # legacy, no suffix
            scripts = [
                build_multisig_script(c, control_pub, pad_suffix=False)
                for c in chunks
            ]
        return scripts, bpub_output_values(len(scripts), 1)

    # (variant, expect_allowed, expect_reject_reason)
    if MODE == "deadbranch":
        plan = [
            ("padded", True, None),
            ("v1", False, "txn-datacarrier-nonstandard"),
        ]
    else:
        # Default relay policy: plain variants are rejected; only the padded
        # reveal passes.
        plan = [
            ("padded", True, None),
            ("legacy", False, "txn-datacarrier"),
            ("eleven", False, "txn-datacarrier"),
        ]

    change_spk = mine_spk

    results = {}
    reasons = {}
    for variant_idx, (name, expect_allowed, expect_reason) in enumerate(plan):
        scripts, values = build_variant(name)
        n = len(scripts)
        spks = [p2wsh_scriptpubkey(rs) for rs in scripts]
        cb_txid, cb_vout, cb_value = coinbases[variant_idx]
        # --- Funding tx ---
        fee_fund = 1000
        total_out = sum(values)
        fund = CMutableTransaction(
            [CMutableTxIn(COutPoint(lx(cb_txid), cb_vout))],
            [CMutableTxOut(v, CScript(spk)) for v, spk in zip(values, spks)]
            + [CMutableTxOut(cb_value - total_out - fee_fund, CScript(change_spk))],
        )
        # P2WPKH spend: scriptCode is the implied P2PKH script.
        script_code = CScript(
            b"\x76\xa9\x14" + mine_spk[2:] + b"\x88\xac"
        )
        sigh = SignatureHash(
            script_code, fund, 0, SIGHASH_ALL, cb_value, SIGVERSION_WITNESS_V0
        )
        sig = mine_key.sign(sigh) + bytes([SIGHASH_ALL])
        fund.wit.vtxinwit[0].scriptWitness = CScriptWitness(
            [sig, bytes(mine_key.pub)]
        )
        fund_hex = fund.serialize(include_witness=True).hex()

        res = json.loads(cli("testmempoolaccept", json.dumps([fund_hex])))[0]
        print(f"[{name}] funding  testmempoolaccept: allowed={res.get('allowed')} "
              f"reason={res.get('reject-reason')}")
        results[f"{name}-funding"] = res.get("allowed")

        txid = cli("sendrawtransaction", fund_hex)
        cli("generateblock", mine_desc, json.dumps([txid]))

        # --- Reveal tx ---
        has_pad = name in ("padded", "v1")
        fee_reveal = estimate_fee_reveal(n, 1, 1, pad_suffix=has_pad)
        reveal = CMutableTransaction(
            [CMutableTxIn(COutPoint(lx(txid), i)) for i in range(n)],
            [CMutableTxOut(total_out - fee_reveal, CScript(change_spk))],
        )
        for idx, rs in enumerate(scripts):
            rs_bytes = bytes(rs)
            sigh = SignatureHash(
                rs, reveal, idx, SIGHASH_ALL, values[idx], SIGVERSION_WITNESS_V0
            )
            rsig = control_key.sign(sigh) + bytes([SIGHASH_ALL])
            stack = [b"", rsig, rs_bytes]
            if has_pad:
                stack = make_pad_items(rs_bytes) + stack
            reveal.wit.vtxinwit[idx].scriptWitness = CScriptWitness(stack)
        reveal_hex = reveal.serialize(include_witness=True).hex()

        res = json.loads(cli("testmempoolaccept", json.dumps([reveal_hex])))[0]
        print(f"[{name}] reveal   testmempoolaccept: allowed={res.get('allowed')} "
              f"reason={res.get('reject-reason')}")
        results[f"{name}-reveal"] = res.get("allowed")
        reasons[f"{name}-reveal"] = res.get("reject-reason")

        if res.get("allowed"):
            rtxid = cli("sendrawtransaction", reveal_hex)
            blk = json.loads(cli("generateblock", mine_desc, json.dumps([rtxid])))
            print(f"[{name}] reveal mined: {rtxid}")
            if name == "padded":
                # recover the data straight from the chain
                raw = cli("getrawtransaction", rtxid, "false", blk["hash"])
                all_pks = []
                from bitcointx.core import CTransaction
                tx = CTransaction.deserialize(bytes.fromhex(raw))
                for i in range(len(tx.vin)):
                    ws = tx.wit.vtxinwit[i].scriptWitness.stack
                    parsed = bpub.parse_bpub_multisig(bytes(ws[-1]))
                    assert parsed and parsed[2] == "padv2"
                    all_pks.extend(parsed[0])
                meta, content = bpub.decode_stream(
                    bpub.decode_pubkeys_to_stream(all_pks)
                )
                assert content == data, "recovered data mismatch!"
                print(f"[{name}] data recovered from chain OK "
                      f"({meta['size']} bytes, bpub_id={meta['bpub_id'].hex()[:16]}...)")
        else:
            # clean the spent outputs so the next variant can try: they were
            # not spent (reveal rejected), so nothing to do.
            pass

    print()
    print("== SUMMARY ==")
    for k, v in results.items():
        print(f"  {k}: {'ALLOWED' if v else 'REJECTED'}")

    ok = True
    for name, expect_allowed, expect_reason in plan:
        got = results.get(f"{name}-reveal")
        if got is not expect_allowed:
            ok = False
        if expect_reason and expect_reason not in (reasons.get(f"{name}-reveal") or ""):
            ok = False
    ok = ok and all(results.get(f"{name}-funding") for name, _, _ in plan)
    print("VERDICT:", "PASS" if ok else "FAIL")
    return ok


def main():
    shutil.rmtree(DATADIR, ignore_errors=True)
    os.makedirs(DATADIR, exist_ok=True)
    node_args = [
        f"{BINDIR}/bitcoind",
        "-regtest",
        f"-datadir={DATADIR}",
        "-daemon",
        "-server",
        "-fallbackfee=0.00001",
    ]
    if MODE == "policy":
        node_args.append("-datacarrierfullcount=1")
    node_args += EXTRA_ARGS
    subprocess.run(node_args, check=True, capture_output=True)
    for _ in range(100):
        try:
            cli("getblockcount")
            break
        except Exception:
            time.sleep(0.2)
    else:
        sys.exit("bitcoind did not come up")

    try:
        ok = run_checks()
    finally:
        subprocess.run(CLI + ["stop"], capture_output=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
