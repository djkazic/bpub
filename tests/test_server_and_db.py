#!/usr/bin/env python3
"""
Tests for SQLite storage (db.py), SQLite block indexing (indexer.py),
and the hardened FastAPI gallery & padv3 embed server (server.py).
"""

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bitcointx

_secp_path = os.environ.get("BPUB_SECP256K1_PATH")
if _secp_path:
    bitcointx.set_custom_secp256k1_path(_secp_path)

import bpub  # noqa: E402
from db import BpubDB  # noqa: E402
import indexer  # noqa: E402
from lnd import LndClient  # noqa: E402
import orders  # noqa: E402

try:
    from fastapi.testclient import TestClient
    import server  # noqa: E402

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

CONTROL_SECRET = hashlib.sha256(b"bpub server test control key").digest()


def _secp_ok():
    try:
        from bitcointx.core.key import CKey

        CKey.from_secret_bytes(CONTROL_SECRET)
        return True
    except Exception:
        return False


SECP256K1 = _secp_ok()


class SQLiteAndIndexerTest(unittest.TestCase):
    def test_fast_prefilters(self):
        # P2WPKH witness (33-byte pubkey) must be skipped by both pre-filters.
        p2wpkh_tx = {"vin": [{"txinwitness": ["30" * 71, "02" + "11" * 32]}]}
        self.assertFalse(indexer._tx_maybe_bpub_reveal(p2wpkh_tx))
        self.assertFalse(indexer._tx_maybe_bpub_owner(p2wpkh_tx))

        # Coinbase tx must be skipped.
        coinbase_tx = {"vin": [{"coinbase": "031234"}]}
        self.assertFalse(indexer._tx_maybe_bpub_reveal(coinbase_tx))
        self.assertFalse(indexer._tx_maybe_bpub_owner(coinbase_tx))

        # Valid padv3 script starts with 5121 and is >= 70 bytes.
        stream = bpub.build_stream_v5(b"hi", "text/plain", "hi.txt")
        pks = bpub.encode_stream_to_pubkeys(stream)
        rs = bytes(bpub.build_multisig_script(pks, b"\x02" + b"\x11" * 32, pad_suffix=True))
        reveal_tx = {"vin": [{"txinwitness": ["", "30" * 71, rs.hex()]}]}
        self.assertTrue(indexer._tx_maybe_bpub_reveal(reveal_tx))
        self.assertFalse(indexer._tx_maybe_bpub_owner(reveal_tx))

        # Valid 59-byte v5 owner redeem script.
        owner_rs = bytes(bpub.build_owner_redeem_script(b"\xaa" * 32, b"\x11" * 20))
        owner_tx = {"vin": [{"txinwitness": ["30" * 70, "02" * 33, owner_rs.hex()]}]}
        self.assertFalse(indexer._tx_maybe_bpub_reveal(owner_tx))
        self.assertTrue(indexer._tx_maybe_bpub_owner(owner_tx))

    def test_sqlite_block_indexing_and_ownership_history(self):
        from bitcointx.core import (
            COutPoint,
            CMutableTransaction,
            CMutableTxIn,
            CMutableTxOut,
            lx,
        )
        from bitcointx.core.script import CScript, CScriptWitness
        from bitcointx.wallet import P2WPKHBitcoinAddress

        with tempfile.TemporaryDirectory() as tmp:
            gdir = os.path.join(tmp, "gallery")
            media_dir = os.path.join(gdir, "media")
            db = BpubDB(os.path.join(gdir, "bpub.db"))

            payload = b"sqlite indexed padv3 file"
            stream = bpub.build_stream_v5(payload, "image/png", "art.png")
            data_pks = bpub.encode_stream_to_pubkeys(stream)
            ctrl = b"\x02" + b"\x11" * 32
            chunks = list(bpub.chunk_data_pubkeys(data_pks))
            scripts = [bpub.build_multisig_script(c, ctrl, pad_suffix=True) for c in chunks]

            funding_txid = "11" * 32
            reveal_tx = CMutableTransaction(
                [CMutableTxIn(COutPoint(lx(funding_txid), i)) for i in range(len(scripts))],
                [CMutableTxOut(546, CScript(b"\x00\x14" + b"\x22" * 20))],
            )
            for i, rs in enumerate(scripts):
                reveal_tx.wit.vtxinwit[i].scriptWitness = CScriptWitness(
                    [b"", b"\x30" * 70, bytes(rs)]
                )
            reveal_hex = reveal_tx.serialize(include_witness=True).hex()
            reveal_txid = reveal_tx.GetTxid()[::-1].hex()

            # Same-block owner self-transfer from funding_txid + Eve hijack attempt.
            bpub_id = bpub.compute_bpub_v5_id(payload)
            alice_h160 = b"\x11" * 20
            eve_h160 = b"\x33" * 20
            alice_rs = bytes(bpub.build_owner_redeem_script(bpub_id, alice_h160))
            eve_rs = bytes(bpub.build_owner_redeem_script(bpub_id, eve_h160))
            alice_spk = bpub.p2wsh_scriptpubkey(CScript(alice_rs))
            eve_spk = bpub.p2wsh_scriptpubkey(CScript(eve_rs))
            alice_addr = str(
                P2WPKHBitcoinAddress.from_scriptPubKey(CScript(b"\x00\x14" + alice_h160))
            )

            def make_owner(prev_txid, prev_vout, rs_bytes, out_spk):
                tx = CMutableTransaction(
                    [CMutableTxIn(COutPoint(lx(prev_txid), prev_vout))],
                    [CMutableTxOut(9000, CScript(out_spk))],
                )
                tx.wit.vtxinwit[0].scriptWitness = CScriptWitness(
                    [b"\x30" * 70, b"\x02" * 33, rs_bytes]
                )
                return tx.GetTxid()[::-1].hex(), tx.serialize(include_witness=True).hex()

            t1_txid, t1_hex = make_owner(funding_txid, 1, alice_rs, alice_spk)
            eve_txid, eve_hex = make_owner("99" * 32, 0, eve_rs, eve_spk)

            block = {
                "hash": "aa" * 32,
                "time": 1760000000,
                "tx": [
                    {"txid": eve_txid, "hex": eve_hex, "vin": [{"txinwitness": ["30" * 70, "02" * 33, eve_rs.hex()]}]},
                    {"txid": t1_txid, "hex": t1_hex, "vin": [{"txinwitness": ["30" * 70, "02" * 33, alice_rs.hex()]}]},
                    {"txid": reveal_txid, "hex": reveal_hex, "vin": [{"txinwitness": ["", "30" * 70, bytes(scripts[0]).hex()]}]},
                ],
            }
            reveals, owners = indexer.index_block(db, indexer.Path(media_dir), block, 950000)
            self.assertEqual((reveals, owners), (1, 1))
            self.assertEqual(db.get_next_height(0), 950001)

            item = db.get_item_by_txid(reveal_txid)
            self.assertIsNotNone(item)
            self.assertEqual(item["script_suffix"], "padv3")
            self.assertEqual(item["bpub_id"], bpub_id.hex())
            self.assertEqual(item["ownership"]["current_owner_p2wpkh"], alice_addr)
            self.assertEqual(len(item["ownership_history"]), 1)
            self.assertEqual(item["ownership_history"][0]["txid"], t1_txid)

            # Query & filter tests
            items, total = db.list_items(q="art.png", mime_group="image", version="5")
            self.assertEqual(total, 1)
            self.assertEqual(items[0]["txid"], reveal_txid)
            _, total_none = db.list_items(mime_group="text")
            self.assertEqual(total_none, 0)

    def test_migrate_legacy_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            gdir = indexer.Path(tmp)
            (gdir / "manifest.json").write_text(
                json.dumps(
                    [
                        {
                            "txid": "ab" * 32,
                            "block_height": 930000,
                            "block_hash": "cd" * 32,
                            "filename": "old.jpg",
                            "stored_filename": f"{'ab' * 32}_old.jpg",
                            "mime": "image/jpeg",
                            "size": 123,
                            "bpub_version": 5,
                            "bpub_id": "ef" * 32,
                        }
                    ]
                )
            )
            (gdir / "indexer_state.json").write_text(json.dumps({"next_height": 930005}))
            db = BpubDB(gdir / "bpub.db")
            migrated = db.migrate_legacy_json(gdir)
            self.assertEqual(migrated["items"], 1)
            self.assertEqual(migrated["state"], 1)
            self.assertEqual(db.get_next_height(0), 930005)
            self.assertIsNotNone(db.get_item_by_txid("ab" * 32))

    def test_like_wildcard_escaping_and_reorg_rollback(self):
        from bitcointx.core import COutPoint, CMutableTransaction, CMutableTxIn, CMutableTxOut, lx
        from bitcointx.core.script import CScript, CScriptWitness

        with tempfile.TemporaryDirectory() as tmp:
            gdir = indexer.Path(tmp)
            media_dir = gdir / "media"
            db = BpubDB(gdir / "bpub.db")

            def make_reveal_block(height, bhash, payload, fname):
                stream = bpub.build_stream_v5(payload, "text/plain", fname)
                pks = bpub.encode_stream_to_pubkeys(stream)
                ctrl = b"\x02" + b"\x11" * 32
                chunks = list(bpub.chunk_data_pubkeys(pks))
                scripts = [bpub.build_multisig_script(c, ctrl, pad_suffix=True) for c in chunks]
                tx = CMutableTransaction(
                    [CMutableTxIn(COutPoint(lx(bhash), i)) for i in range(len(scripts))],
                    [CMutableTxOut(546, CScript(b"\x00\x14" + b"\x22" * 20))],
                )
                for i, rs in enumerate(scripts):
                    tx.wit.vtxinwit[i].scriptWitness = CScriptWitness(
                        [b"", b"\x30" * 70, bytes(rs)]
                    )
                txid = tx.GetTxid()[::-1].hex()
                return txid, {
                    "hash": bhash,
                    "time": 1760000000 + height,
                    "tx": [
                        {
                            "txid": txid,
                            "hex": tx.serialize(include_witness=True).hex(),
                            "vin": [{"txinwitness": ["", "30" * 70, bytes(scripts[0]).hex()]}],
                        }
                    ],
                }

            tx1, b1 = make_reveal_block(100, "11" * 32, b"keep me", "100%_real.txt")
            tx2, b2 = make_reveal_block(101, "22" * 32, b"orphan me", "orphan_file.txt")
            indexer.index_block(db, media_dir, b1, 100)
            indexer.index_block(db, media_dir, b2, 101)

            # Literal '%' search must match only "100%_real.txt", NOT "orphan_file.txt".
            rows, total = db.list_items(q="%")
            self.assertEqual(total, 1)
            self.assertEqual(rows[0]["txid"], tx1)

            # Simulate chain reorg at height 101 (block 100 stays "11"*32, block 101 becomes "33"*32).
            class FakeRpc:
                hashes = {100: "11" * 32, 101: "33" * 32}

                def getblockhash(self, h):
                    return self.hashes[h]

            orphan_item = db.get_item_by_txid(tx2)
            orphan_file = media_dir / orphan_item["stored_filename"]
            self.assertTrue(orphan_file.is_file())

            resume_h = indexer.reconcile_reorg(FakeRpc(), db, media_dir, 102, 100)
            self.assertEqual(resume_h, 101)
            self.assertEqual(db.get_next_height(0), 101)
            self.assertIsNotNone(db.get_item_by_txid(tx1))
            self.assertIsNone(db.get_item_by_txid(tx2))
            self.assertFalse(orphan_file.exists())

    def test_parse_raw_block_handles_80b_and_164b_blake2b_headers(self):
        import struct
        from bitcointx.core import COutPoint, CMutableTransaction, CMutableTxIn, CMutableTxOut, lx
        from bitcointx.core.script import CScript, CScriptWitness

        stream = bpub.build_stream_v5(b"blake raw block", "text/plain", "b2.txt")
        pks = bpub.encode_stream_to_pubkeys(stream)
        ctrl = b"\x02" + b"\x11" * 32
        rs = bpub.build_multisig_script(pks, ctrl, pad_suffix=True)

        cb = CMutableTransaction(
            [CMutableTxIn(COutPoint(b"\x00" * 32, 0xFFFFFFFF), CScript(b"\x03\x01\x00\x00"))],
            [CMutableTxOut(50_0000_0000, CScript(b"\x00\x14" + b"\x11" * 20))],
        )
        rev = CMutableTransaction(
            [CMutableTxIn(COutPoint(lx("aa" * 32), 0))],
            [CMutableTxOut(547, CScript(b"\x00\x14" + b"\x22" * 20))],
        )
        rev.wit.vtxinwit[0].scriptWitness = CScriptWitness([b"", b"\x30" * 70, bytes(rs)])
        body = b"\x02" + cb.serialize(include_witness=True) + rev.serialize(include_witness=True)

        # 1) Standard 80-byte Bitcoin header (version = 0x20000000)
        hdr80 = bytearray(80)
        struct.pack_into("<I", hdr80, 0, 0x20000000)
        struct.pack_into("<I", hdr80, 68, 1760000100)
        b80 = indexer.parse_raw_block(bytes(hdr80) + body, blockhash="aa" * 32)
        self.assertEqual(b80["time"], 1760000100)
        self.assertEqual(len(b80["tx"]), 2)
        self.assertTrue(indexer._tx_maybe_bpub_reveal(b80["tx"][1]))

        # 2) 164-byte BLAKE2b header (version bit 0x80000000 set, e.g. 0xa0000000)
        hdr164 = bytearray(164)
        struct.pack_into("<I", hdr164, 0, 0xA0000000)
        struct.pack_into("<I", hdr164, 68, 1795474210)
        b164 = indexer.parse_raw_block(bytes(hdr164) + body, blockhash="bb" * 32)
        self.assertEqual(b164["time"], 1795474210)
        self.assertEqual(len(b164["tx"]), 2)
        self.assertTrue(indexer._tx_maybe_bpub_reveal(b164["tx"][1]))
        meta, recovered = indexer.try_extract_bpub_from_tx(b164["tx"][1]["hex"])
        self.assertEqual(recovered, b"blake raw block")
        self.assertEqual(meta["script_suffix"], "padv3")

    def test_esplora_round_robin_and_failover(self):
        client = indexer.EsploraBlockClient(
            ["https://a.invalid", "https://b.invalid"], request_delay=0.0
        )
        calls = []

        def fake_get(url, timeout=30):
            calls.append(url)
            if url.startswith("https://a.invalid") and len(calls) == 1:
                return SimpleNamespace(status_code=429, headers={"Retry-After": "10"}, text="", content=b"")
            return SimpleNamespace(status_code=200, headers={}, text="983282", content=b"")

        with mock.patch.object(client._session, "get", side_effect=fake_get):
            # First call hits a.invalid -> 429 -> immediately fails over to b.invalid.
            self.assertEqual(client.getblockcount(), 983282)
            # Next call skips cooling-down a.invalid and goes straight to b.invalid.
            self.assertEqual(client.getblockcount(), 983282)
        self.assertEqual(
            calls,
            [
                "https://a.invalid/api/blocks/tip/height",
                "https://b.invalid/api/blocks/tip/height",
                "https://b.invalid/api/blocks/tip/height",
            ],
        )


@unittest.skipUnless(HAS_FASTAPI, "fastapi/httpx not installed")
class ServerSecurityAndApiTest(unittest.TestCase):
    def _make_client(self, tmpdir, rate_limits=None, trust_proxy=False, order_service=None):
        app = server.create_app(
            gallery_dir=indexer.Path(tmpdir),
            broadcast_url="https://mempool.kilombino.com/api/tx",
            explorer_base_url="https://mempool.kilombino.com",
            trust_proxy=trust_proxy,
            rate_limits=rate_limits,
            order_service=order_service,
        )
        return app, TestClient(app)

    def test_security_headers_and_safe_media_serving(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, client = self._make_client(tmp)
            txid = "aa" * 32
            (app.state.media_dir / f"{txid}_pic.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            (app.state.media_dir / f"{txid}_doc.bin").write_bytes(b"<script>alert(1)</script>")
            (app.state.media_dir / f"{txid}_evil.html").write_bytes(b"<html></html>")

            # Index page strict headers (no unsafe-inline in script-src)
            r = client.get("/")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers["x-content-type-options"], "nosniff")
            self.assertEqual(r.headers["x-frame-options"], "DENY")
            self.assertIn("script-src 'self'", r.headers["content-security-policy"])
            self.assertNotIn("unsafe-inline", r.headers["content-security-policy"])

            # Safe PNG served inline with sandbox CSP
            r_png = client.get(f"/media/{txid}_pic.png")
            self.assertEqual(r_png.status_code, 200)
            self.assertEqual(r_png.headers["content-type"], "image/png")
            self.assertEqual(r_png.headers["content-security-policy"], "sandbox; default-src 'none'")
            self.assertNotIn("attachment", r_png.headers.get("content-disposition", ""))

            # Safe MP4 served inline with media-src 'self' + script-src 'none' (playable in direct tab)
            (app.state.media_dir / f"{txid}_clip.mp4").write_bytes(b"\x00\x00\x00\x18ftypmp42")
            r_mp4 = client.get(f"/media/{txid}_clip.mp4")
            self.assertEqual(r_mp4.status_code, 200)
            self.assertEqual(r_mp4.headers["content-type"], "video/mp4")
            self.assertIn("media-src 'self'", r_mp4.headers["content-security-policy"])
            self.assertIn("script-src 'none'", r_mp4.headers["content-security-policy"])
            self.assertNotIn("attachment", r_mp4.headers.get("content-disposition", ""))

            # Binary file served as attachment with sandbox CSP
            r_bin = client.get(f"/media/{txid}_doc.bin")
            self.assertEqual(r_bin.status_code, 200)
            self.assertIn("attachment", r_bin.headers["content-disposition"])

            # Disallowed active extension rejected with 403
            self.assertEqual(client.get(f"/media/{txid}_evil.html").status_code, 403)
            # Traversal / bad filename rejected
            self.assertIn(client.get("/media/..%2Fserver.py").status_code, (400, 404))
            self.assertEqual(client.get("/media/not_valid..png").status_code, 400)

            # Health endpoint supports both GET and HEAD (for uptime monitors)
            r_get = client.get("/api/health")
            self.assertEqual(r_get.status_code, 200)
            self.assertEqual(r_get.json()["status"], "ok")
            r_head = client.head("/api/health")
            self.assertEqual(r_head.status_code, 200)
            self.assertEqual(r_head.content, b"")
            self.assertEqual(r_head.headers["x-content-type-options"], "nosniff")

    def test_rate_limiting_and_proxy_header_spoof_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, client = self._make_client(
                tmp, rate_limits={"read": (3, 60)}, trust_proxy=False
            )
            for i in range(3):
                r = client.get(
                    "/api/stats",
                    headers={"X-Forwarded-For": f"1.2.3.{i}"},
                )
                self.assertEqual(r.status_code, 200)
            # 4th request must hit 429 even with spoofed X-Forwarded-For!
            r4 = client.get("/api/stats", headers={"X-Forwarded-For": "9.9.9.9"})
            self.assertEqual(r4.status_code, 429)
            self.assertIn("retry-after", r4.headers)

    def test_upload_size_cap_and_broadcast_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, client = self._make_client(tmp)

            # Oversized upload rejected with 413
            oversized = b"x" * (server.MAX_UPLOAD_BYTES + 1024)
            r = client.post(
                "/api/embed/fund-psbt",
                files={"file": ("huge.bin", oversized, "application/octet-stream")},
                data={
                    "control_pubkey": "02" + "11" * 32,
                    "owner_address": "bc1q" + "q" * 38,
                    "utxo": "aa" * 32 + ":0",
                    "value": "500000",
                    "prev_address": "bc1q" + "q" * 38,
                    "change": "bc1q" + "q" * 38,
                    "feerate": "1",
                },
            )
            self.assertEqual(r.status_code, 413)

            # Broadcast rejects malformed hex / garbage tx
            self.assertEqual(
                client.post("/api/tx/broadcast", json={"raw_hex": "deadbeef" * 4}).status_code,
                400,
            )

            # Broadcast forwards valid tx to mempool.kilombino.com
            from bitcointx.core import COutPoint, CMutableTransaction, CMutableTxIn, CMutableTxOut, lx
            from bitcointx.core.script import CScript

            tx = CMutableTransaction(
                [CMutableTxIn(COutPoint(lx("11" * 32), 0))],
                [CMutableTxOut(1000, CScript(b"\x00\x14" + b"\x22" * 20))],
            )
            raw_hex = tx.serialize().hex()
            expected_txid = tx.GetTxid()[::-1].hex()

            fake_resp = SimpleNamespace(status_code=200, text=expected_txid)
            with mock.patch.object(server.requests, "post", return_value=fake_resp) as m_post:
                rb = client.post("/api/tx/broadcast", json={"raw_hex": raw_hex})
            self.assertEqual(rb.status_code, 200)
            self.assertEqual(rb.json()["txid"], expected_txid)
            self.assertEqual(
                rb.json()["explorer_url"],
                f"https://mempool.kilombino.com/tx/{expected_txid}",
            )
            m_post.assert_called_once()
            self.assertEqual(m_post.call_args.args[0], "https://mempool.kilombino.com/api/tx")

    @unittest.skipUnless(SECP256K1, "libsecp256k1 not available")
    def test_padv3_embed_fund_reveal_sign_verify_via_api(self):
        from bitcointx.core import CTransaction
        from bitcointx.core.key import CKey
        from bitcointx.core.psbt import PartiallySignedTransaction as PSBT
        from bitcointx.core.script import CScript
        from bitcointx.core.scripteval import (
            SCRIPT_VERIFY_CLEANSTACK,
            SCRIPT_VERIFY_DERSIG,
            SCRIPT_VERIFY_LOW_S,
            SCRIPT_VERIFY_MINIMALIF,
            SCRIPT_VERIFY_NULLDUMMY,
            SCRIPT_VERIFY_NULLFAIL,
            SCRIPT_VERIFY_P2SH,
            SCRIPT_VERIFY_STRICTENC,
            SCRIPT_VERIFY_WITNESS,
            SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
            VerifyScript,
        )
        from bitcointx.wallet import CBitcoinSecret, P2WPKHBitcoinAddress

        key = CKey.from_secret_bytes(CONTROL_SECRET)
        other = CKey.from_secret_bytes(hashlib.sha256(b"owner-change").digest())
        addr = str(P2WPKHBitcoinAddress.from_pubkey(other.pub))
        wif = str(CBitcoinSecret.from_secret_bytes(key.secret_bytes))
        payload = os.urandom(900)

        with tempfile.TemporaryDirectory() as tmp:
            _, client = self._make_client(tmp)

            est = client.post(
                "/api/embed/estimate",
                json={"size_bytes": len(payload), "feerate": 1, "reveal_feerate": 1},
            )
            self.assertEqual(est.status_code, 200)
            self.assertEqual(est.json()["pad_version"], "padv3")
            self.assertTrue(est.json()["fits_single_tx"])

            rf = client.post(
                "/api/embed/fund-psbt",
                files={"file": ("sample.bin", payload, "application/octet-stream")},
                data={
                    "filename": "sample.bin",
                    "mime": "application/octet-stream",
                    "compress": "false",
                    "control_pubkey": bytes(key.pub).hex(),
                    "owner_address": addr,
                    "utxo": "aa" * 32 + ":0",
                    "value": "200000",
                    "prev_address": addr,
                    "change": addr,
                    "feerate": "1",
                    "reveal_feerate": "1",
                },
            )
            self.assertEqual(rf.status_code, 200, rf.text)
            fdata = rf.json()
            self.assertEqual(fdata["pad_version"], "padv3")
            self.assertEqual(fdata["per_output_sats"], 547)
            fund_tx = PSBT.from_base64(fdata["funding_psbt"]).unsigned_tx

            rr = client.post(
                "/api/embed/reveal-psbt",
                files={"file": ("sample.bin", payload, "application/octet-stream")},
                data={
                    "filename": "sample.bin",
                    "mime": "application/octet-stream",
                    "compress": "false",
                    "control_pubkey": bytes(key.pub).hex(),
                    "bpub_utxos": "\n".join(fdata["bpub_utxos"]),
                    "change": addr,
                    "feerate": "1",
                },
            )
            self.assertEqual(rr.status_code, 200, rr.text)
            rdata = rr.json()

            # Sign the API-built reveal PSBT with bpub.cmd_signreveal and verify scripts!
            out_buf = io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(io.StringIO()):
                bpub.cmd_signreveal(
                    SimpleNamespace(
                        psbt=rdata["reveal_psbt"],
                        wif=wif,
                        control_pubkey=bytes(key.pub).hex(),
                    )
                )
            raw_hex = out_buf.getvalue().strip()
            rev_tx = CTransaction.deserialize(bytes.fromhex(raw_hex))
            flags = {
                SCRIPT_VERIFY_P2SH,
                SCRIPT_VERIFY_WITNESS,
                SCRIPT_VERIFY_NULLDUMMY,
                SCRIPT_VERIFY_CLEANSTACK,
                SCRIPT_VERIFY_DERSIG,
                SCRIPT_VERIFY_LOW_S,
                SCRIPT_VERIFY_STRICTENC,
                SCRIPT_VERIFY_NULLFAIL,
                SCRIPT_VERIFY_MINIMALIF,
                SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
            }
            for idx, txin in enumerate(rev_tx.vin):
                prevout = fund_tx.vout[txin.prevout.n]
                VerifyScript(
                    CScript(b""),
                    prevout.scriptPubKey,
                    rev_tx,
                    idx,
                    flags=flags,
                    amount=prevout.nValue,
                    witness=rev_tx.wit.vtxinwit[idx].scriptWitness,
                )

    def test_cf_connecting_ip_and_content_length_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, client = self._make_client(
                tmp, rate_limits={"read": (2, 60)}, trust_proxy=True
            )
            # Separate CF-Connecting-IP values get separate rate-limit buckets when trust_proxy=True.
            self.assertEqual(
                client.get("/api/stats", headers={"CF-Connecting-IP": "203.0.113.1"}).status_code,
                200,
            )
            self.assertEqual(
                client.get("/api/stats", headers={"CF-Connecting-IP": "203.0.113.1"}).status_code,
                200,
            )
            self.assertEqual(
                client.get("/api/stats", headers={"CF-Connecting-IP": "203.0.113.1"}).status_code,
                429,
            )
            self.assertEqual(
                client.get("/api/stats", headers={"CF-Connecting-IP": "203.0.113.2"}).status_code,
                200,
            )
            # Pre-buffering Content-Length cap rejects oversized JSON immediately with 413.
            r_big = client.post(
                "/api/tx/broadcast",
                content=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(server.MAX_JSON_BODY_BYTES + 100),
                    "CF-Connecting-IP": "203.0.113.9",
                },
            )
            self.assertEqual(r_big.status_code, 413)

    @unittest.skipUnless(SECP256K1, "libsecp256k1 not available")
    def test_custodial_lnd_order_lifecycle_and_security(self):
        from bitcointx.core import COutPoint, CMutableTransaction, CMutableTxIn, CMutableTxOut, CTransaction, lx
        from bitcointx.core.script import CScript

        class FakeLnd(LndClient):
            def __init__(self):
                self.invoices = {}
                self.counter = 0

            def create_invoice(self, amount_sats, memo, expiry_sec=900):
                self.counter += 1
                rh = hashlib.sha256(f"inv-{self.counter}".encode()).hexdigest()
                pr = f"lnbc{amount_sats}n1fakeinvoice{self.counter}"
                self.invoices[rh] = {"state": "OPEN", "settled": False, "canceled": False, "amt_paid_sat": 0}
                return {"r_hash": rh, "payment_request": pr}

            def lookup_invoice(self, r_hash_hex):
                return self.invoices[r_hash_hex]

        class FakeWallet:
            def __init__(self, balance_sats=500_000):
                self.broadcasts = []
                self.confs = {}
                self.balance_sats = balance_sats

            def get_confirmed_balance_sats(self):
                return self.balance_sats, "bc1qtest"

            def get_return_scriptpubkey(self):
                return b"\x00\x14" + b"\x44" * 20

            def fund_and_sign_funding_tx(self, outputs, feerate_sat_vb):
                needed = sum(v for _, v in outputs) + 1000
                if self.balance_sats < needed:
                    raise orders.InsufficientLiquidityError("Not enough confirmed sats")
                tx = CMutableTransaction(
                    [CMutableTxIn(COutPoint(lx("aa" * 32), 0))],
                    [CMutableTxOut(val, CScript(spk)) for spk, val in outputs]
                    + [CMutableTxOut(50_000, CScript(b"\x00\x14" + b"\x55" * 20))],
                )
                return tx.GetTxid()[::-1].hex(), tx.serialize().hex()

            def broadcast_tx(self, raw_hex):
                self.broadcasts.append(raw_hex)
                return CTransaction.deserialize(bytes.fromhex(raw_hex)).GetTxid()[::-1].hex()

            def get_confirmations(self, txid):
                return self.confs.get(txid, 0)

        with tempfile.TemporaryDirectory() as tmp:
            gdir = indexer.Path(tmp)
            db = BpubDB(gdir / "bpub.db")
            fake_lnd = FakeLnd()
            fake_wallet = FakeWallet()
            cfg = orders.OrderConfig(
                feerate_sat_vb=2,
                price_base_sats=500,
                price_per_kb_sats=100,
                min_ln_sats=500,
                max_pending_per_ip=2,
                daily_onchain_budget_sats=1_000_000,
                sign_mode="unified",
            )
            svc = orders.OrderService(
                db=db,
                payload_dir=gdir / "order_payloads",
                lnd=fake_lnd,
                wallet_backend=fake_wallet,
                cfg=cfg,
            )
            _, client = self._make_client(tmp, order_service=svc)

            self.assertTrue(client.get("/api/stats").json()["orders_enabled"])

            payload = b"hello custodial padv3 on blake2b!" * 20
            rq = client.post(
                "/api/orders/quote",
                files={"file": ("hello.txt", payload, "text/plain")},
                data={"filename": "hello.txt", "mime": "text/plain", "compress": "true"},
            )
            self.assertEqual(rq.status_code, 200, rq.text)
            qdata = rq.json()
            self.assertEqual(qdata["pad_version"], "padv3")
            self.assertGreaterEqual(qdata["ln_amount_sats"], 500)

            ro = client.post(
                "/api/orders",
                files={"file": ("hello.txt", payload, "text/plain")},
                data={"filename": "hello.txt", "mime": "text/plain", "compress": "true"},
            )
            self.assertEqual(ro.status_code, 200, ro.text)
            odata = ro.json()
            order_id = odata["order_id"]
            self.assertEqual(odata["status"], "awaiting_payment")
            self.assertTrue(odata["payment_request"].startswith("lnbc"))
            if server.segno is not None:
                self.assertIsInstance(odata["payment_request_qr"], str)
                self.assertTrue(
                    odata["payment_request_qr"].startswith("data:image/png;base64,iVBORw0KGgo")
                )
            # Secrets must never leak in API responses.
            self.assertNotIn("control_privkey_hex", odata)
            self.assertNotIn("payload_path", odata)

            # Enforce per-IP pending cap (max 2 unpaid invoices).
            ro2 = client.post(
                "/api/orders",
                files={"file": ("two.txt", payload, "text/plain")},
                data={"filename": "two.txt", "mime": "text/plain"},
            )
            self.assertEqual(ro2.status_code, 200)
            ro3 = client.post(
                "/api/orders",
                files={"file": ("three.txt", payload, "text/plain")},
                data={"filename": "three.txt", "mime": "text/plain"},
            )
            self.assertEqual(ro3.status_code, 400)

            # Settle the first invoice -> automatic funding + unified-sighash padv3 reveal!
            internal_before = db.get_order_internal(order_id)
            payload_path = indexer.Path(internal_before["payload_path"])
            self.assertTrue(payload_path.is_file())
            fake_lnd.invoices[odata["r_hash"]] = {
                "state": "SETTLED",
                "settled": True,
                "canceled": False,
                "amt_paid_sat": odata["ln_amount_sats"],
            }

            rstat = client.get(f"/api/orders/{order_id}")
            self.assertEqual(rstat.status_code, 200)
            sdata = rstat.json()
            self.assertEqual(sdata["status"], "completed")
            self.assertIsNone(sdata["payment_request_qr"])
            self.assertIsNotNone(sdata["funding_txid"])
            self.assertIsNotNone(sdata["reveal_txid"])
            self.assertEqual(len(fake_wallet.broadcasts), 2)

            # Verify reveal tx uses padv3 (3 witness items, 0x21 SIGHASH_ALL_UNIFIED) and recovers exact bytes!
            rev_hex = fake_wallet.broadcasts[1]
            rev_tx = CTransaction.deserialize(bytes.fromhex(rev_hex))
            for i in range(len(rev_tx.vin)):
                stack = list(rev_tx.wit.vtxinwit[i].scriptWitness.stack)
                self.assertEqual(len(stack), 3)
                self.assertEqual(stack[0], b"")
                self.assertEqual(stack[1][-1], orders.SIGHASH_ALL_UNIFIED)
                _, _, suf = bpub.parse_bpub_multisig(bytes(stack[2]))
                self.assertEqual(suf, "padv3")
            meta, recovered = indexer.try_extract_bpub_from_tx(rev_hex)
            self.assertEqual(recovered, payload)
            self.assertEqual(meta["script_suffix"], "padv3")

            # Private payload file and ephemeral control key must be wiped on completion!
            self.assertFalse(payload_path.exists())
            internal_after = db.get_order_internal(order_id)
            self.assertIsNone(internal_after["control_privkey_hex"])
            self.assertIsNone(internal_after["payload_path"])

    @unittest.skipUnless(SECP256K1, "libsecp256k1 not available")
    def test_pre_invoice_liquidity_reservation_and_awaiting_liquidity_retry(self):
        from bitcointx.core import COutPoint, CMutableTransaction, CMutableTxIn, CMutableTxOut, CTransaction, lx
        from bitcointx.core.script import CScript

        class FakeLnd(LndClient):
            def __init__(self):
                self.invoices = {}
                self.created = 0

            def create_invoice(self, amount_sats, memo, expiry_sec=900):
                self.created += 1
                rh = hashlib.sha256(f"liq-{self.created}".encode()).hexdigest()
                self.invoices[rh] = {"state": "OPEN", "settled": False, "canceled": False, "amt_paid_sat": 0}
                return {"r_hash": rh, "payment_request": f"lnbc{amount_sats}n1liq{self.created}"}

            def lookup_invoice(self, r_hash_hex):
                return self.invoices[r_hash_hex]

        class FakeWallet:
            def __init__(self, balance_sats):
                self.balance_sats = balance_sats
                self.broadcasts = []

            def get_confirmed_balance_sats(self):
                return self.balance_sats, "bc1qliq"

            def get_return_scriptpubkey(self):
                return b"\x00\x14" + b"\x44" * 20

            def fund_and_sign_funding_tx(self, outputs, feerate_sat_vb):
                needed = sum(v for _, v in outputs) + 1000
                if self.balance_sats < needed:
                    raise orders.InsufficientLiquidityError("Insufficient confirmed sats")
                tx = CMutableTransaction(
                    [CMutableTxIn(COutPoint(lx("aa" * 32), 0))],
                    [CMutableTxOut(val, CScript(spk)) for spk, val in outputs]
                    + [CMutableTxOut(10_000, CScript(b"\x00\x14" + b"\x55" * 20))],
                )
                return tx.GetTxid()[::-1].hex(), tx.serialize().hex()

            def broadcast_tx(self, raw_hex):
                self.broadcasts.append(raw_hex)
                return CTransaction.deserialize(bytes.fromhex(raw_hex)).GetTxid()[::-1].hex()

            def get_confirmations(self, txid):
                return 1

        with tempfile.TemporaryDirectory() as tmp:
            gdir = indexer.Path(tmp)
            db = BpubDB(gdir / "bpub.db")
            fake_lnd = FakeLnd()
            # 1) Balance too low -> pre-invoice check rejects with 503 and creates ZERO LND invoices.
            wallet = FakeWallet(balance_sats=500)
            cfg = orders.OrderConfig(feerate_sat_vb=2, max_pending_per_ip=5)
            svc = orders.OrderService(db, gdir / "order_payloads", fake_lnd, wallet, cfg)
            _, client = self._make_client(tmp, order_service=svc)

            payload = b"liquidity reservation test payload" * 10
            q = svc.quote(payload, "liq.txt", "text/plain", False)
            r_low = client.post(
                "/api/orders",
                files={"file": ("liq.txt", payload, "text/plain")},
                data={"filename": "liq.txt", "mime": "text/plain", "compress": "false"},
            )
            self.assertEqual(r_low.status_code, 503)
            self.assertEqual(fake_lnd.created, 0)

            # 2) Enough balance for ONE order, NOT two -> 1st succeeds, 2nd rejected with 503!
            wallet.balance_sats = q["upfront_funding_sats"] + 200
            r1 = client.post(
                "/api/orders",
                files={"file": ("liq1.txt", payload, "text/plain")},
                data={"filename": "liq1.txt", "mime": "text/plain", "compress": "false"},
            )
            self.assertEqual(r1.status_code, 200, r1.text)
            o1 = r1.json()
            r2 = client.post(
                "/api/orders",
                files={"file": ("liq2.txt", payload, "text/plain")},
                data={"filename": "liq2.txt", "mime": "text/plain", "compress": "false"},
            )
            self.assertEqual(r2.status_code, 503)
            self.assertEqual(fake_lnd.created, 1)

            # 3) Simulate temporary UTXO lock when order 1 settles -> awaiting_liquidity keeps reservation,
            #    still blocks new over-subscribed orders, then auto-completes once liquidity confirms!
            wallet.balance_sats = 500
            fake_lnd.invoices[o1["r_hash"]] = {
                "state": "SETTLED",
                "settled": True,
                "canceled": False,
                "amt_paid_sat": o1["ln_amount_sats"],
            }
            svc.poll_all_active()
            self.assertEqual(db.get_order_public(o1["order_id"])["status"], "awaiting_liquidity")
            # Even if wallet gets just enough for order 1, order 1's reservation blocks a new order 3!
            wallet.balance_sats = q["upfront_funding_sats"] + 500
            r3 = client.post(
                "/api/orders",
                files={"file": ("liq3.txt", payload, "text/plain")},
                data={"filename": "liq3.txt", "mime": "text/plain", "compress": "false"},
            )
            self.assertEqual(r3.status_code, 503)

            # Next worker tick auto-fulfills order 1!
            svc.poll_all_active()
            done = db.get_order_public(o1["order_id"])
            self.assertEqual(done["status"], "completed")
            self.assertIsNotNone(done["reveal_txid"])
            self.assertEqual(len(wallet.broadcasts), 2)

    def test_unified_sighash_vectors_match_consensus_reference(self):
        # Cross-verify our Python unified_signature_hash against official vectors if mounted.
        candidates = [
            indexer.Path("/unified_sighash.json"),
            indexer.Path("/Users/kevincai/Projects/bcashjr-wallet/testdata/unified_sighash.json"),
        ]
        vec_path = next((p for p in candidates if p.is_file()), None)
        if vec_path is None:
            # Minimal deterministic self-check when sibling repo is absent.
            from bitcointx.core import COutPoint, CMutableTransaction, CMutableTxIn, CMutableTxOut, lx
            from bitcointx.core.script import CScript

            tx = CMutableTransaction(
                [CMutableTxIn(COutPoint(lx("11" * 32), 0))],
                [CMutableTxOut(500, CScript(b"\x00\x14" + b"\x22" * 20))],
            )
            h = orders.unified_signature_hash(
                tx,
                0,
                orders.SIGHASH_ALL_UNIFIED,
                [(1000, b"\x00\x20" + b"\x33" * 32)],
                script_type=orders.UNIFIED_SCRIPT_TYPE_WITNESS_V0,
                script_code=b"\x51\x87",
            )
            self.assertEqual(len(h), 32)
            self.assertIsNone(
                orders.unified_signature_hash(
                    tx, 0, 0x01, [(1000, b"\x00\x20" + b"\x33" * 32)]
                )
            )
            return

        from bitcointx.core import CTransaction

        vectors = json.loads(vec_path.read_text())
        checked = 0
        for row in vectors[1:]:
            script_code_hex, raw_tx_hex, inp_idx, hash_type, script_type, spent_rows, expected = row
            tx = CTransaction.deserialize(bytes.fromhex(raw_tx_hex))
            spent = [(int(amt), bytes.fromhex(spk)) for amt, spk in spent_rows]
            sc = bytes.fromhex(script_code_hex)
            got = orders.unified_signature_hash(
                tx,
                inp_idx,
                hash_type,
                spent,
                script_type=script_type,
                script_code=sc,
                leaf_script=sc if script_type == 3 else None,
            )
            self.assertIsNotNone(got, f"Vector {checked + 1} returned None")
            self.assertEqual(got.hex(), expected, f"Vector {checked + 1} mismatch")
            checked += 1
        self.assertGreaterEqual(checked, 140)

    @unittest.skipUnless(SECP256K1, "libsecp256k1 not available")
    def test_esplora_hot_wallet_funds_and_signs_unified_padv3(self):
        from bitcointx.core import CTransaction
        from bitcointx.core.key import CKey
        from bitcointx.wallet import CBitcoinSecret

        hot_secret = hashlib.sha256(b"bpub esplora hot wallet test").digest()
        hot_wif = str(CBitcoinSecret.from_secret_bytes(hot_secret))
        wallet = orders.EsploraHotWalletBackend(
            wif=hot_wif,
            explorer_base_url="https://mempool.kilombino.com",
            sign_mode="unified",
        )
        self.assertTrue(wallet.address.startswith("bc1q"))

        fake_utxos = [
            {"txid": "11" * 32, "vout": 0, "value": 100_000, "status": {"confirmed": False}},
            {"txid": "22" * 32, "vout": 1, "value": 50_000, "status": {"confirmed": True}},
        ]
        fake_resp = SimpleNamespace(status_code=200, json=lambda: fake_utxos, text="")
        outputs = [(b"\x00\x20" + b"\xaa" * 32, 547), (b"\x00\x20" + b"\xbb" * 32, 330)]
        with mock.patch.object(orders.requests, "get", return_value=fake_resp):
            ftxid, fhex = wallet.fund_and_sign_funding_tx(outputs, feerate_sat_vb=2)

        ftx = CTransaction.deserialize(bytes.fromhex(fhex))
        self.assertEqual(ftx.GetTxid()[::-1].hex(), ftxid)
        # Must select ONLY the confirmed UTXO ("22"*32:1), not the unconfirmed one!
        self.assertEqual(len(ftx.vin), 1)
        self.assertEqual(ftx.vin[0].prevout.hash[::-1].hex(), "22" * 32)
        self.assertEqual(ftx.vin[0].prevout.n, 1)
        # Signature must end with SIGHASH_ALL_UNIFIED (0x21) and verify against unified sighash!
        wit_stack = list(ftx.wit.vtxinwit[0].scriptWitness.stack)
        self.assertEqual(len(wit_stack), 2)
        self.assertEqual(wit_stack[0][-1], orders.SIGHASH_ALL_UNIFIED)
        sh = orders.unified_signature_hash(
            ftx,
            0,
            orders.SIGHASH_ALL_UNIFIED,
            [(50_000, wallet.spk)],
            script_type=orders.UNIFIED_SCRIPT_TYPE_WITNESS_V0,
            script_code=wallet.script_code,
        )
        self.assertTrue(CKey.from_secret_bytes(hot_secret).pub.verify(sh, wit_stack[0][:-1]))


if __name__ == "__main__":
    unittest.main()
