#!/usr/bin/env python3
"""
Unit & end-to-end tests for BPUB Multipart v1 support (wire-compatible with
@bitfiles/bpub):
  - Core protocol primitives (plan, manifest encode/parse, assemble, bpub_id)
  - Indexer part hiding, in-order & out-of-order reassembly, SAFE_EXTENSIONS,
    and chain reorg rollback
  - Custodial LND multipart order lifecycle (quote, invoice, liquidity pause/
    resume across parts, manifest broadcast, secret wipe, and indexer reassembly)
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import bitcointx

_secp_path = os.environ.get("BPUB_SECP256K1_PATH")
if _secp_path:
    bitcointx.set_custom_secp256k1_path(_secp_path)

from bitcointx.core import (
    COutPoint,
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    CTransaction,
    lx,
)
from bitcointx.core.key import CKey
from bitcointx.core.script import CScript, CScriptWitness
from fastapi.testclient import TestClient

import bpub
import indexer
import orders
import server
from db import BpubDB
from lnd import LndClient


def _secp256k1_available() -> bool:
    try:
        k = CKey.from_secret_bytes(b"\x01" * 32)
        _ = k.pub
        return True
    except Exception:
        return False


SECP256K1 = _secp256k1_available()


def _noise(length: int, seed: int = 1) -> bytes:
    """Deterministic incompressible bytes (xorshift32, matching @bitfiles/bpub tests)."""
    out = bytearray(length)
    x = seed & 0xFFFFFFFF
    for i in range(length):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        out[i] = x & 0xFF
    return bytes(out)


def _fake_padv3_reveal(
    data: bytes,
    mime: str,
    compress: bool,
    salt: int,
    filename: str = "",
):
    ctrl_pub = bytes.fromhex(
        "0388a5c118e856a90cf025cef167c00c224e96e2184229e450b6f59cd60dc2dda9"
    )
    stream = bpub.build_stream_v5(data, mime, filename, compress=compress)
    pks = bpub.encode_stream_to_pubkeys(stream)
    chunks = list(bpub.chunk_data_pubkeys(pks, max_pubkeys=bpub.MAX_PUBKEYS_PER_SCRIPT))
    scripts = [bpub.build_multisig_script(c, ctrl_pub, pad_suffix=True) for c in chunks]
    prev_txid_le = bytes([salt & 0xFF]) * 32
    tx = CMutableTransaction(
        [CMutableTxIn(COutPoint(prev_txid_le, i)) for i in range(len(scripts))],
        [CMutableTxOut(1000, CScript(b"\x00\x14" + b"\x00" * 20))],
    )
    for i, rs in enumerate(scripts):
        tx.wit.vtxinwit[i].scriptWitness = CScriptWitness([b"", b"\x30" * 71, bytes(rs)])
    raw_hex = tx.serialize(include_witness=True).hex()
    txid = tx.GetTxid()[::-1].hex()
    tx_dict = {
        "txid": txid,
        "hex": raw_hex,
        "vin": [
            {"txinwitness": ["", "30" * 71, bytes(rs).hex()]} for rs in scripts
        ],
    }
    return txid, raw_hex, tx_dict


class MultipartProtocolTest(unittest.TestCase):
    def test_plan_keeps_every_part_stream_within_limit(self):
        text = b"the quick brown fox jumps over the lazy dog\n" * 2000
        cases = [
            (_noise(20_000), "auto"),
            (_noise(20_000), True),
            (text, False),
        ]
        for data, compress in cases:
            plan = bpub.plan_multipart(data, max_stream_bytes=1_500, compress=compress)
            self.assertGreater(len(plan["parts"]), 1)
            for part in plan["parts"]:
                stream = bpub.build_stream_v5(part, bpub.MULTIPART_PART_MIME, "", compress=False)
                self.assertLessEqual(len(stream), 1_500)

    def test_plan_compression_modes(self):
        text = b"the quick brown fox jumps over the lazy dog\n" * 2000
        rnd = _noise(5_000)
        self.assertEqual(
            bpub.plan_multipart(text, max_stream_bytes=4_000)["compression"], "deflate-raw"
        )
        self.assertEqual(
            bpub.plan_multipart(rnd, max_stream_bytes=4_000)["compression"], "none"
        )
        self.assertEqual(
            bpub.plan_multipart(text, max_stream_bytes=4_000, compress=False)["compression"],
            "none",
        )
        self.assertEqual(
            bpub.plan_multipart(rnd, max_stream_bytes=4_000, compress=True)["compression"],
            "deflate-raw",
        )

    def test_manifest_canonical_json_roundtrip_and_bpub_id_equivalence(self):
        text = b"the quick brown fox jumps over the lazy dog\n" * 2000
        for data, mime, fname in [
            (_noise(12_000), "application/octet-stream", "noise.bin"),
            (text, "text/plain", "fox.txt"),
        ]:
            plan = bpub.plan_multipart(data, max_stream_bytes=1_500)
            txids = [f"{i:064x}" for i in range(len(plan["parts"]))]
            built = bpub.build_manifest(plan, txids, mime=mime, filename=fname)
            encoded = bpub.encode_manifest(built)
            # Key order must match @bitfiles/bpub wire spec exactly.
            parsed_raw = json.loads(encoded.decode("utf-8"))
            self.assertEqual(
                list(parsed_raw.keys()),
                ["bpub_manifest", "mime", "filename", "size", "sha256", "compression", "parts"],
            )
            parsed = bpub.parse_manifest(encoded)
            self.assertEqual(parsed["mime"], mime)
            self.assertEqual(parsed["filename"], fname)
            self.assertEqual(parsed["parts"], txids)
            reassembled = bpub.assemble_multipart(parsed, plan["parts"])
            self.assertEqual(reassembled, data)

            meta = bpub.manifest_file_meta(parsed)
            expected_id = bpub.compute_bpub_v5_id(data)
            self.assertEqual(meta["bpub_id"], expected_id)
            self.assertEqual(plan["bpub_id"], expected_id)
            self.assertEqual(meta["size"], len(data))

    def test_assemble_rejects_missing_reordered_and_bomb(self):
        plan = bpub.plan_multipart(_noise(5_000), max_stream_bytes=1_500)
        manifest = bpub.build_manifest(plan, ["cd" * 32] * len(plan["parts"]))
        parts = plan["parts"]

        with self.assertRaises(ValueError):
            bpub.assemble_multipart(manifest, parts[1:])
        with self.assertRaises(ValueError):
            bpub.assemble_multipart(manifest, [parts[1], parts[0], *parts[2:]])

        # Decompression bomb (> MAX_CONTENT_DECOMPRESSED_BYTES) must be rejected.
        bomb_plain = b"\x00" * (bpub.MAX_CONTENT_DECOMPRESSED_BYTES + 4096)
        bomb_deflated = bpub._raw_deflate(bomb_plain)
        fake_manifest = {
            "version": 1,
            "size": 100,
            "sha256": hashlib.sha256(b"x" * 100).digest(),
            "compression": "deflate-raw",
            "parts": ["aa" * 32],
        }
        with self.assertRaises(ValueError):
            bpub.assemble_multipart(fake_manifest, [bomb_deflated])

    def test_parse_manifest_rejects_malformed(self):
        valid = {
            "bpub_manifest": 1,
            "size": 3,
            "sha256": "00" * 32,
            "compression": "none",
            "parts": ["11" * 32],
        }
        enc = lambda d: json.dumps(d).encode("utf-8")
        bpub.parse_manifest(enc(valid))

        for bad in [
            b"{",
            b"[]",
            enc({**valid, "bpub_manifest": 2}),
            enc({**valid, "bpub_manifest": True}),
            enc({**valid, "compression": "zstd"}),
            enc({**valid, "parts": []}),
            enc({**valid, "parts": ["11" * 32] * (bpub.MAX_MULTIPART_PARTS + 1)}),
            enc({**valid, "parts": ["not-a-txid"]}),
            enc({**valid, "size": 0}),
            enc({**valid, "size": True}),
            enc({**valid, "size": bpub.MAX_CONTENT_DECOMPRESSED_BYTES + 1}),
            enc({**valid, "sha256": "zz" * 32}),
        ]:
            with self.assertRaises(ValueError):
                bpub.parse_manifest(bad)


class MultipartIndexerTest(unittest.TestCase):
    def test_in_order_out_of_order_safe_ext_and_reorg_rollback(self):
        data = _noise(5_000, seed=42)
        plan = bpub.plan_multipart(data, max_stream_bytes=2_000)
        self.assertGreaterEqual(len(plan["parts"]), 3)

        part_txs = []
        part_txids = []
        for idx, pbytes in enumerate(plan["parts"]):
            ptxid, _, pdict = _fake_padv3_reveal(
                pbytes, bpub.MULTIPART_PART_MIME, False, salt=10 + idx
            )
            part_txids.append(ptxid)
            part_txs.append(pdict)

        # Malicious .html filename must be downgraded to .bin via SAFE_EXTENSIONS.
        manifest = bpub.build_manifest(
            plan, part_txids, mime="text/html", filename="evil.html"
        )
        mtxid, _, mdict = _fake_padv3_reveal(
            bpub.encode_manifest(manifest),
            bpub.MULTIPART_MANIFEST_MIME,
            True,
            salt=99,
        )

        with tempfile.TemporaryDirectory() as tmp:
            gdir = Path(tmp)
            media_dir = gdir / "media"
            parts_dir = gdir / "parts"
            db = BpubDB(gdir / "bpub.db")

            # --- Case A: Out-of-order (manifest arrives in block 100, parts in 101) ---
            rev0, _ = indexer.index_block(
                db, media_dir, {"hash": "11" * 32, "time": 1700000100, "tx": [mdict]}, 100
            )
            self.assertEqual(rev0, 0)
            self.assertIsNone(db.get_item_by_txid(mtxid))

            # First N-1 parts arrive in block 101 -> still hidden & pending.
            rev1, _ = indexer.index_block(
                db, media_dir, {"hash": "22" * 32, "time": 1700000200, "tx": part_txs[:-1]}, 101
            )
            self.assertEqual(rev1, 0)
            items_now, total_now = db.list_items()
            self.assertEqual(total_now, 0)
            self.assertEqual(len(list(media_dir.iterdir())), 0)
            self.assertEqual(len(list(parts_dir.iterdir())), len(part_txs) - 1)

            # Final part arrives in block 102 -> auto-assembles manifest!
            rev2, _ = indexer.index_block(
                db, media_dir, {"hash": "33" * 32, "time": 1700000300, "tx": [part_txs[-1]]}, 102
            )
            self.assertEqual(rev2, 1)

            item = db.get_item_by_txid(mtxid)
            self.assertIsNotNone(item)
            self.assertEqual(item["parts_count"], len(part_txs))
            self.assertEqual(item["part_txids"], part_txids)
            self.assertEqual(item["bpub_id"], bpub.compute_bpub_v5_id(data).hex())
            self.assertTrue(item["stored_filename"].endswith(".bin"))
            self.assertEqual((media_dir / item["stored_filename"]).read_bytes(), data)
            # Raw parts are never exposed as items.
            for ptxid in part_txids:
                self.assertIsNone(db.get_item_by_txid(ptxid))

            # --- Reorg rollback above block 101 removes final part AND reverts manifest! ---
            rb = db.rollback_above(101, media_dir=media_dir)
            self.assertEqual(rb["parts_removed"], 1)
            self.assertEqual(rb["items_removed"], 1)
            self.assertIsNone(db.get_item_by_txid(mtxid))
            self.assertFalse((media_dir / item["stored_filename"]).exists())
            self.assertFalse((parts_dir / f"{part_txids[-1]}.part").exists())

            # Re-indexing block 102 reassembles cleanly again!
            rev2_again, _ = indexer.index_block(
                db, media_dir, {"hash": "44" * 32, "time": 1700000305, "tx": [part_txs[-1]]}, 102
            )
            self.assertEqual(rev2_again, 1)
            self.assertIsNotNone(db.get_item_by_txid(mtxid))


class MultipartCustodialOrderTest(unittest.TestCase):
    @unittest.skipUnless(SECP256K1, "libsecp256k1 not available")
    def test_multipart_order_end_to_end_with_liquidity_retry_and_indexer_reassembly(self):
        class FakeLnd(LndClient):
            def __init__(self):
                self.invoices = {}
                self.n = 0

            def create_invoice(self, amount_sats, memo, expiry_sec=900):
                self.n += 1
                rh = hashlib.sha256(f"mp-inv-{self.n}".encode()).hexdigest()
                self.invoices[rh] = {
                    "state": "OPEN",
                    "settled": False,
                    "canceled": False,
                    "amt_paid_sat": 0,
                }
                return {"r_hash": rh, "payment_request": f"lnbc{amount_sats}n1mp{self.n}"}

            def lookup_invoice(self, r_hash_hex):
                return self.invoices[r_hash_hex]

        class FakeWallet:
            def __init__(self, balance_sats):
                self.balance_sats = balance_sats
                self.broadcasts = []
                self.fund_calls = 0
                self.pause_after_first = True

            def get_confirmed_balance_sats(self):
                return self.balance_sats, "bc1qmpwallet"

            def get_return_scriptpubkey(self):
                return b"\x00\x14" + b"\x77" * 20

            def fund_and_sign_funding_tx(self, outputs, feerate_sat_vb):
                if self.pause_after_first and self.fund_calls >= 1:
                    raise orders.InsufficientLiquidityError("Waiting for change confirmation")
                self.fund_calls += 1
                salt = self.fund_calls
                tx = CMutableTransaction(
                    [CMutableTxIn(COutPoint(lx(f"{salt:064x}"), 0))],
                    [CMutableTxOut(val, CScript(spk)) for spk, val in outputs]
                    + [CMutableTxOut(20_000, CScript(b"\x00\x14" + b"\x88" * 20))],
                )
                return tx.GetTxid()[::-1].hex(), tx.serialize().hex()

            def broadcast_tx(self, raw_hex):
                self.broadcasts.append(raw_hex)
                return CTransaction.deserialize(bytes.fromhex(raw_hex)).GetTxid()[::-1].hex()

            def get_confirmations(self, txid):
                return 1

        with tempfile.TemporaryDirectory() as tmp:
            gdir = Path(tmp)
            media_dir = gdir / "media"
            db = BpubDB(gdir / "bpub.db")
            fake_lnd = FakeLnd()
            wallet = FakeWallet(balance_sats=5_000_000)
            cfg = orders.OrderConfig(
                feerate_sat_vb=2,
                price_base_sats=100,
                price_per_kb_sats=0,
                onchain_to_ln_ratio=0.01,
                min_ln_sats=100,
                sign_mode="unified",
                multipart_max_stream_bytes=2_000,
            )
            svc = orders.OrderService(db, gdir / "order_payloads", fake_lnd, wallet, cfg)
            app = server.create_app(
                gallery_dir=gdir,
                broadcast_url="https://mempool.kilombino.com/api/tx",
                explorer_base_url="https://mempool.kilombino.com",
                order_service=svc,
                rate_limits={
                    "read": (1000, 60),
                    "embed": (1000, 60),
                    "order": (1000, 60),
                    "broadcast": (1000, 60),
                    "media": (1000, 60),
                },
            )
            client = TestClient(app)

            payload = _noise(5_200, seed=7)
            expected_bpub_id = bpub.compute_bpub_v5_id(payload).hex()

            # 1) Quote should switch automatically to multipart (>= 3 parts).
            rq = client.post(
                "/api/orders/quote",
                files={"file": ("clip.png", payload, "image/png")},
                data={"filename": "clip.png", "mime": "image/png", "compress": "true"},
            )
            self.assertEqual(rq.status_code, 200, rq.text)
            q = rq.json()
            self.assertTrue(q["is_multipart"])
            self.assertGreaterEqual(q["parts_count"], 3)
            self.assertEqual(q["bpub_id"], expected_bpub_id)

            # 2) Create order -> BOLT11 invoice + QR data URI.
            rc = client.post(
                "/api/orders",
                files={"file": ("clip.png", payload, "image/png")},
                data={"filename": "clip.png", "mime": "image/png", "compress": "true"},
            )
            self.assertEqual(rc.status_code, 200, rc.text)
            ord_created = rc.json()
            order_id = ord_created["order_id"]
            self.assertEqual(ord_created["parts_count"], q["parts_count"])
            self.assertTrue(ord_created["payment_request_qr"].startswith("data:image/png;base64,"))

            # 3) Settle invoice -> part 1 broadcasts, part 2 pauses on awaiting_liquidity.
            fake_lnd.invoices[ord_created["r_hash"]] = {
                "state": "SETTLED",
                "settled": True,
                "canceled": False,
                "amt_paid_sat": ord_created["ln_amount_sats"],
            }
            svc.poll_all_active()
            mid = client.get(f"/api/orders/{order_id}").json()
            self.assertEqual(mid["status"], "awaiting_liquidity")
            self.assertEqual(mid["parts_broadcast"], 1)
            self.assertEqual(len(mid["part_txids"]), 1)

            # 4) Once change confirms, next poll resumes from part 2, completes all parts + manifest, wipes secrets!
            wallet.pause_after_first = False
            svc.poll_all_active()
            done = client.get(f"/api/orders/{order_id}").json()
            self.assertEqual(done["status"], "completed")
            self.assertEqual(done["parts_broadcast"], q["parts_count"])
            self.assertEqual(len(done["part_txids"]), q["parts_count"])
            self.assertIsNotNone(done["reveal_txid"])
            self.assertIsNone(done["payment_request_qr"])

            internal = db.get_order_internal(order_id)
            self.assertIsNone(internal["control_privkey_hex"])
            self.assertIsNone(internal["payload_path"])

            # 5) Feed ALL broadcast txs into indexer.index_block() -> exact file reassembled!
            #    (wallet.broadcasts holds funding+reveal pairs for each part + manifest)
            self.assertEqual(len(wallet.broadcasts), (q["parts_count"] + 1) * 2)
            block_txs = []
            for raw_hex in wallet.broadcasts:
                tx = CTransaction.deserialize(bytes.fromhex(raw_hex))
                vins = []
                wit = getattr(tx, "wit", None)
                for i in range(len(tx.vin)):
                    vd = {}
                    if wit is not None and i < len(wit.vtxinwit):
                        st = list(wit.vtxinwit[i].scriptWitness.stack)
                        if st:
                            vd["txinwitness"] = [bytes(x).hex() for x in st]
                    vins.append(vd)
                block_txs.append(
                    {"txid": tx.GetTxid()[::-1].hex(), "hex": raw_hex, "vin": vins}
                )

            revs, _ = indexer.index_block(
                db, media_dir, {"hash": "ab" * 32, "time": 1700001000, "tx": block_txs}, 500
            )
            self.assertEqual(revs, 1)

            # Gallery API returns the single reassembled multipart item under manifest txid!
            r_item = client.get(f"/api/items/{done['reveal_txid']}")
            self.assertEqual(r_item.status_code, 200, r_item.text)
            item = r_item.json()
            self.assertEqual(item["bpub_id"], expected_bpub_id)
            self.assertEqual(item["parts_count"], q["parts_count"])
            self.assertEqual(item["part_txids"], done["part_txids"])
            self.assertEqual(item["filename"], "clip.png")
            self.assertEqual(item["mime"], "image/png")
            self.assertEqual((media_dir / item["stored_filename"]).read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
