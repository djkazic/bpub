#!/usr/bin/env python3
"""
SQLite storage layer for the BPUB indexer and gallery website.

Replaces the legacy flat JSON files (manifest.json, ownership.json,
indexer_state.json) with a single WAL-mode SQLite database (`bpub.db`).
"""

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS indexer_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
    txid TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    block_time INTEGER,
    filename TEXT,
    stored_filename TEXT NOT NULL,
    mime TEXT,
    size INTEGER,
    bpub_version TEXT,
    script_suffix TEXT,
    bpub_id TEXT,
    funding_txids_json TEXT,
    indexed_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_items_height_txid
    ON items (block_height DESC, txid DESC);
CREATE INDEX IF NOT EXISTS idx_items_bpub_id
    ON items (bpub_id);
CREATE INDEX IF NOT EXISTS idx_items_mime
    ON items (mime);

CREATE TABLE IF NOT EXISTS ownership (
    bpub_id TEXT PRIMARY KEY,
    funding_txids_json TEXT NOT NULL,
    current_outpoint TEXT,
    current_owner_p2wpkh TEXT,
    current_owner_p2wsh TEXT,
    last_signer_p2wpkh TEXT,
    txid TEXT,
    block_height INTEGER,
    block_hash TEXT,
    block_time INTEGER,
    outputs_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ownership_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bpub_id TEXT NOT NULL,
    txid TEXT NOT NULL,
    spent_outpoint TEXT NOT NULL,
    next_outpoint TEXT,
    signer_p2wpkh TEXT,
    new_owner_p2wpkh TEXT,
    new_owner_p2wsh TEXT,
    block_height INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    block_time INTEGER,
    UNIQUE(bpub_id, txid, spent_outpoint)
);

CREATE INDEX IF NOT EXISTS idx_own_hist_bpub_id
    ON ownership_history (bpub_id, block_height DESC, id DESC);

CREATE TABLE IF NOT EXISTS indexed_blocks (
    height INTEGER PRIMARY KEY,
    block_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    order_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    client_ip TEXT NOT NULL,
    filename TEXT NOT NULL,
    mime TEXT NOT NULL,
    compress INTEGER NOT NULL DEFAULT 1,
    size_bytes INTEGER NOT NULL,
    payload_sha256 TEXT NOT NULL,
    payload_path TEXT,
    bpub_id TEXT NOT NULL,
    data_outputs_count INTEGER NOT NULL,
    feerate_sat_vb INTEGER NOT NULL,
    est_onchain_sats INTEGER NOT NULL,
    upfront_funding_sats INTEGER NOT NULL DEFAULT 0,
    ln_amount_sats INTEGER NOT NULL,
    r_hash TEXT UNIQUE NOT NULL,
    payment_request TEXT NOT NULL,
    control_privkey_hex TEXT,
    funding_txid TEXT,
    funding_raw_hex TEXT,
    reveal_txid TEXT,
    reveal_raw_hex TEXT,
    needs_funding_conf INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_orders_status
    ON orders (status, expires_at);
CREATE INDEX IF NOT EXISTS idx_orders_ip_status
    ON orders (client_ip, status);
CREATE INDEX IF NOT EXISTS idx_orders_created
    ON orders (created_at);
"""


def _connect(db_path: Path, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        uri = f"file:{db_path.resolve()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0, check_same_thread=False)
    else:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    if not readonly:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


class BpubDB:
    """Thread-safe SQLite wrapper for BPUB items, ownership, and indexer state."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.init_schema()

    def init_schema(self) -> None:
        conn = _connect(self.db_path, readonly=False)
        try:
            conn.executescript(SCHEMA_SQL)
            # Safe live migration for existing SQLite DBs missing newer columns.
            cols = {
                r["name"] for r in conn.execute("PRAGMA table_info(orders)").fetchall()
            }
            if "upfront_funding_sats" not in cols:
                conn.execute(
                    "ALTER TABLE orders ADD COLUMN upfront_funding_sats INTEGER NOT NULL DEFAULT 0"
                )
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def transaction(self):
        conn = _connect(self.db_path, readonly=False)
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def read_conn(self):
        conn = _connect(self.db_path, readonly=True)
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Indexer state
    # ------------------------------------------------------------------

    def get_state(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT value FROM indexer_state WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row is not None else default

    def get_next_height(self, default_height: int) -> int:
        val = self.get_state("next_height")
        if val is None:
            return default_height
        try:
            return int(val)
        except ValueError:
            return default_height

    @staticmethod
    def set_state_tx(conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            "INSERT INTO indexer_state (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )

    @staticmethod
    def record_block_tx(conn: sqlite3.Connection, height: int, block_hash: str) -> None:
        if not block_hash:
            return
        conn.execute(
            "INSERT INTO indexed_blocks (height, block_hash) VALUES (?, ?) "
            "ON CONFLICT(height) DO UPDATE SET block_hash = excluded.block_hash",
            (int(height), str(block_hash)),
        )

    def get_block_hash(self, height: int) -> Optional[str]:
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT block_hash FROM indexed_blocks WHERE height = ?",
                (int(height),),
            ).fetchone()
            return row["block_hash"] if row is not None else None

    def rollback_above(self, fork_height: int, media_dir: Optional[Path] = None) -> Dict[str, int]:
        """
        Atomically roll back all indexed items, ownership transitions, and
        block hashes strictly above `fork_height` (chain reorg recovery).
        Rebuilds `ownership` cleanly from remaining items and ownership_history.
        """
        orphan_files: List[str] = []
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT stored_filename FROM items WHERE block_height > ?",
                (int(fork_height),),
            ).fetchall()
            candidate_files = {r["stored_filename"] for r in rows if r["stored_filename"]}

            del_items = conn.execute(
                "DELETE FROM items WHERE block_height > ?", (int(fork_height),)
            ).rowcount
            del_hist = conn.execute(
                "DELETE FROM ownership_history WHERE block_height > ?", (int(fork_height),)
            ).rowcount
            del_blocks = conn.execute(
                "DELETE FROM indexed_blocks WHERE height > ?", (int(fork_height),)
            ).rowcount

            if candidate_files:
                kept = {
                    r["stored_filename"]
                    for r in conn.execute("SELECT stored_filename FROM items").fetchall()
                }
                orphan_files = sorted(candidate_files - kept)

            # Rebuild ownership table from surviving items + surviving history.
            conn.execute("DELETE FROM ownership")
            for item_row in conn.execute(
                "SELECT bpub_id, funding_txids_json FROM items WHERE bpub_id IS NOT NULL "
                "ORDER BY block_height ASC, txid ASC"
            ).fetchall():
                try:
                    ftxids = json.loads(item_row["funding_txids_json"] or "[]")
                except Exception:
                    ftxids = []
                self.register_genesis_tx(conn, item_row["bpub_id"], ftxids)

            for h in conn.execute(
                "SELECT bpub_id, txid, spent_outpoint, next_outpoint, signer_p2wpkh, "
                "new_owner_p2wpkh, new_owner_p2wsh, block_height, block_hash, block_time "
                "FROM ownership_history ORDER BY block_height ASC, id ASC"
            ).fetchall():
                conn.execute(
                    """
                    UPDATE ownership SET
                        current_outpoint = ?,
                        current_owner_p2wpkh = ?,
                        current_owner_p2wsh = ?,
                        last_signer_p2wpkh = ?,
                        txid = ?,
                        block_height = ?,
                        block_hash = ?,
                        block_time = ?,
                        outputs_json = '[]'
                    WHERE bpub_id = ?
                    """,
                    (
                        h["next_outpoint"],
                        h["new_owner_p2wpkh"],
                        h["new_owner_p2wsh"],
                        h["signer_p2wpkh"],
                        h["txid"],
                        h["block_height"],
                        h["block_hash"],
                        h["block_time"],
                        h["bpub_id"],
                    ),
                )

            self.set_state_tx(conn, "next_height", str(int(fork_height) + 1))
            parent_row = conn.execute(
                "SELECT block_hash FROM indexed_blocks WHERE height = ?",
                (int(fork_height),),
            ).fetchone()
            if parent_row is not None:
                self.set_state_tx(conn, "last_block_hash", parent_row["block_hash"])
            else:
                conn.execute("DELETE FROM indexer_state WHERE key = 'last_block_hash'")

        removed_files = 0
        if media_dir is not None and orphan_files:
            resolved = Path(media_dir).resolve()
            for fname in orphan_files:
                target = (resolved / fname).resolve()
                if target.parent == resolved and target.is_file():
                    try:
                        target.unlink()
                        removed_files += 1
                    except OSError:
                        pass

        return {
            "items_removed": int(del_items),
            "history_removed": int(del_hist),
            "blocks_removed": int(del_blocks),
            "files_removed": removed_files,
        }

    # ------------------------------------------------------------------
    # Items
    # ------------------------------------------------------------------

    def has_item(self, txid: str) -> bool:
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM items WHERE txid = ?", (txid,)
            ).fetchone()
            return row is not None

    @staticmethod
    def has_item_tx(conn: sqlite3.Connection, txid: str) -> bool:
        row = conn.execute("SELECT 1 FROM items WHERE txid = ?", (txid,)).fetchone()
        return row is not None

    @staticmethod
    def insert_item_tx(conn: sqlite3.Connection, entry: Dict[str, Any]) -> bool:
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO items (
                txid, block_height, block_hash, block_time,
                filename, stored_filename, mime, size,
                bpub_version, script_suffix, bpub_id,
                funding_txids_json, indexed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry["txid"],
                int(entry.get("block_height") or 0),
                str(entry.get("block_hash") or ""),
                entry.get("time"),
                entry.get("filename"),
                entry["stored_filename"],
                entry.get("mime"),
                entry.get("size"),
                str(entry.get("bpub_version"))
                if entry.get("bpub_version") is not None
                else None,
                entry.get("script_suffix"),
                entry.get("bpub_id"),
                json.dumps(entry.get("funding_txids") or []),
                int(entry.get("indexed_at") or time.time()),
            ),
        )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Ownership (verified chain-of-custody)
    # ------------------------------------------------------------------

    @staticmethod
    def register_genesis_tx(
        conn: sqlite3.Connection, bpub_id_hex: str, funding_txids: List[str]
    ) -> bool:
        if not bpub_id_hex:
            return False
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO ownership (
                bpub_id, funding_txids_json, current_outpoint,
                current_owner_p2wpkh, current_owner_p2wsh,
                last_signer_p2wpkh, txid, block_height, block_hash,
                block_time, outputs_json
            ) VALUES (?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '[]')
            """,
            (bpub_id_hex, json.dumps(sorted(set(funding_txids or [])))),
        )
        return cur.rowcount > 0

    @staticmethod
    def apply_owner_update_tx(
        conn: sqlite3.Connection,
        owner_info: Dict[str, Any],
        txid: str,
        block_height: int,
        block_hash: str,
        block_time: Optional[int],
    ) -> bool:
        bpub_id_hex = owner_info.get("bpub_id")
        if not bpub_id_hex:
            return False

        row = conn.execute(
            "SELECT funding_txids_json, current_outpoint FROM ownership WHERE bpub_id = ?",
            (bpub_id_hex,),
        ).fetchone()
        if row is None:
            return False

        tracked_outpoint = row["current_outpoint"]
        try:
            funding_txids = json.loads(row["funding_txids_json"] or "[]")
        except Exception:
            funding_txids = []

        if tracked_outpoint is None:
            if owner_info.get("spent_txid") not in funding_txids:
                return False
        else:
            if owner_info.get("spent_outpoint") != tracked_outpoint:
                return False

        dest_vout = owner_info.get("dest_vout")
        next_outpoint = f"{txid}:{dest_vout}" if dest_vout is not None else None
        conn.execute(
            """
            UPDATE ownership SET
                current_outpoint = ?,
                current_owner_p2wpkh = ?,
                current_owner_p2wsh = ?,
                last_signer_p2wpkh = ?,
                txid = ?,
                block_height = ?,
                block_hash = ?,
                block_time = ?,
                outputs_json = ?
            WHERE bpub_id = ?
            """,
            (
                next_outpoint,
                owner_info.get("owner_p2wpkh"),
                owner_info.get("owner_p2wsh"),
                owner_info.get("signer_p2wpkh"),
                txid,
                int(block_height),
                str(block_hash),
                block_time,
                json.dumps(owner_info.get("owner_outputs") or []),
                bpub_id_hex,
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO ownership_history (
                bpub_id, txid, spent_outpoint, next_outpoint,
                signer_p2wpkh, new_owner_p2wpkh, new_owner_p2wsh,
                block_height, block_hash, block_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                bpub_id_hex,
                txid,
                str(owner_info.get("spent_outpoint") or ""),
                next_outpoint,
                owner_info.get("signer_p2wpkh"),
                owner_info.get("owner_p2wpkh"),
                owner_info.get("owner_p2wsh"),
                int(block_height),
                str(block_hash),
                block_time,
            ),
        )
        return True

    # ------------------------------------------------------------------
    # Read queries for the gallery API
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_item(row: sqlite3.Row) -> Dict[str, Any]:
        item = {
            "txid": row["txid"],
            "block_height": row["block_height"],
            "block_hash": row["block_hash"],
            "time": row["block_time"],
            "filename": row["filename"],
            "stored_filename": row["stored_filename"],
            "mime": row["mime"],
            "size": row["size"],
            "bpub_version": row["bpub_version"],
            "script_suffix": row["script_suffix"],
            "bpub_id": row["bpub_id"],
        }
        if "current_owner_p2wpkh" in row.keys():
            owner_addr = row["current_owner_p2wpkh"] or row["current_owner_p2wsh"]
            if owner_addr or row["current_outpoint"]:
                item["ownership"] = {
                    "current_owner_p2wpkh": row["current_owner_p2wpkh"],
                    "current_owner_p2wsh": row["current_owner_p2wsh"],
                    "current_outpoint": row["current_outpoint"],
                    "last_signer_p2wpkh": row["last_signer_p2wpkh"],
                    "txid": row["owner_txid"],
                    "block_height": row["owner_block_height"],
                }
            else:
                item["ownership"] = None
        return item

    def list_items(
        self,
        limit: int = 24,
        offset: int = 0,
        q: Optional[str] = None,
        mime_group: Optional[str] = None,
        version: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        where: List[str] = []
        params: List[Any] = []

        if q:
            q_clean = q.strip()
            if q_clean:
                escaped = (
                    q_clean.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                like = f"%{escaped}%"
                where.append(
                    "(i.filename LIKE ? ESCAPE '\\' OR i.txid LIKE ? ESCAPE '\\' "
                    "OR i.bpub_id LIKE ? ESCAPE '\\' OR i.mime LIKE ? ESCAPE '\\' "
                    "OR o.current_owner_p2wpkh LIKE ? ESCAPE '\\')"
                )
                params.extend([like, like, like, like, like])

        if mime_group == "image":
            where.append("LOWER(COALESCE(i.mime, '')) LIKE 'image/%'")
        elif mime_group == "text":
            where.append(
                "(LOWER(COALESCE(i.mime, '')) LIKE 'text/%' OR LOWER(COALESCE(i.mime, '')) = 'application/json')"
            )
        elif mime_group == "other":
            where.append(
                "LOWER(COALESCE(i.mime, '')) NOT LIKE 'image/%' "
                "AND LOWER(COALESCE(i.mime, '')) NOT LIKE 'text/%' "
                "AND LOWER(COALESCE(i.mime, '')) != 'application/json'"
            )

        if version:
            where.append("i.bpub_version = ?")
            params.append(str(version))

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        with self.read_conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM items i LEFT JOIN ownership o ON i.bpub_id = o.bpub_id {where_sql}",
                params,
            ).fetchone()["c"]

            rows = conn.execute(
                f"""
                SELECT
                    i.*,
                    o.current_outpoint,
                    o.current_owner_p2wpkh,
                    o.current_owner_p2wsh,
                    o.last_signer_p2wpkh,
                    o.txid AS owner_txid,
                    o.block_height AS owner_block_height
                FROM items i
                LEFT JOIN ownership o ON i.bpub_id = o.bpub_id
                {where_sql}
                ORDER BY i.block_height DESC, i.txid DESC
                LIMIT ? OFFSET ?
                """,
                [*params, int(limit), int(offset)],
            ).fetchall()

        return [self._row_to_item(r) for r in rows], int(total)

    def get_item_by_txid(self, txid: str) -> Optional[Dict[str, Any]]:
        with self.read_conn() as conn:
            row = conn.execute(
                """
                SELECT
                    i.*,
                    o.current_outpoint,
                    o.current_owner_p2wpkh,
                    o.current_owner_p2wsh,
                    o.last_signer_p2wpkh,
                    o.txid AS owner_txid,
                    o.block_height AS owner_block_height
                FROM items i
                LEFT JOIN ownership o ON i.bpub_id = o.bpub_id
                WHERE i.txid = ?
                """,
                (txid,),
            ).fetchone()
            if row is None:
                return None
            item = self._row_to_item(row)
            if item.get("bpub_id"):
                hist_rows = conn.execute(
                    """
                    SELECT txid, spent_outpoint, next_outpoint, signer_p2wpkh,
                           new_owner_p2wpkh, new_owner_p2wsh, block_height,
                           block_hash, block_time
                    FROM ownership_history
                    WHERE bpub_id = ?
                    ORDER BY block_height DESC, id DESC
                    LIMIT 100
                    """,
                    (item["bpub_id"],),
                ).fetchall()
                item["ownership_history"] = [dict(h) for h in hist_rows]
            else:
                item["ownership_history"] = []
            return item

    def get_item_by_bpub_id(self, bpub_id: str) -> Optional[Dict[str, Any]]:
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT txid FROM items WHERE bpub_id = ? ORDER BY block_height ASC, txid ASC LIMIT 1",
                (bpub_id,),
            ).fetchone()
        if row is None:
            return None
        return self.get_item_by_txid(row["txid"])

    def get_stats(self) -> Dict[str, Any]:
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS total_items, COALESCE(SUM(size), 0) AS total_bytes FROM items"
            ).fetchone()
            own_row = conn.execute(
                "SELECT COUNT(*) AS owned FROM ownership WHERE current_outpoint IS NOT NULL"
            ).fetchone()
            st_row = conn.execute(
                "SELECT value FROM indexer_state WHERE key = 'next_height'"
            ).fetchone()
        indexed_height = None
        if st_row is not None:
            try:
                indexed_height = max(0, int(st_row["value"]) - 1)
            except ValueError:
                indexed_height = None
        return {
            "total_items": int(row["total_items"]),
            "total_bytes": int(row["total_bytes"]),
            "v5_owned_count": int(own_row["owned"]),
            "indexed_height": indexed_height,
        }

    # ------------------------------------------------------------------
    # Custodial LND Orders
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_public_order(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "order_id": row["order_id"],
            "status": row["status"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "updated_at": row["updated_at"],
            "filename": row["filename"],
            "mime": row["mime"],
            "compress": bool(row["compress"]),
            "size_bytes": row["size_bytes"],
            "bpub_id": row["bpub_id"],
            "data_outputs_count": row["data_outputs_count"],
            "feerate_sat_vb": row["feerate_sat_vb"],
            "est_onchain_sats": row["est_onchain_sats"],
            "ln_amount_sats": row["ln_amount_sats"],
            "r_hash": row["r_hash"],
            "payment_request": row["payment_request"]
            if row["status"] == "awaiting_payment"
            else None,
            "funding_txid": row["funding_txid"],
            "reveal_txid": row["reveal_txid"],
            "needs_funding_conf": bool(row["needs_funding_conf"]),
            "error_message": row["error_message"],
        }

    def create_order(self, order: Dict[str, Any]) -> Dict[str, Any]:
        now = int(time.time())
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO orders (
                    order_id, status, created_at, expires_at, updated_at,
                    client_ip, filename, mime, compress, size_bytes,
                    payload_sha256, payload_path, bpub_id, data_outputs_count,
                    feerate_sat_vb, est_onchain_sats, upfront_funding_sats, ln_amount_sats,
                    r_hash, payment_request, control_privkey_hex,
                    needs_funding_conf
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    order["order_id"],
                    order.get("status", "awaiting_payment"),
                    int(order.get("created_at", now)),
                    int(order["expires_at"]),
                    int(order.get("updated_at", now)),
                    str(order["client_ip"]),
                    str(order["filename"]),
                    str(order["mime"]),
                    1 if order.get("compress", True) else 0,
                    int(order["size_bytes"]),
                    str(order["payload_sha256"]),
                    order.get("payload_path"),
                    str(order["bpub_id"]),
                    int(order["data_outputs_count"]),
                    int(order["feerate_sat_vb"]),
                    int(order["est_onchain_sats"]),
                    int(order.get("upfront_funding_sats") or order["est_onchain_sats"]),
                    int(order["ln_amount_sats"]),
                    str(order["r_hash"]),
                    str(order["payment_request"]),
                    order.get("control_privkey_hex"),
                    1 if order.get("needs_funding_conf") else 0,
                ),
            )
            row = conn.execute(
                "SELECT * FROM orders WHERE order_id = ?", (order["order_id"],)
            ).fetchone()
        return self._row_to_public_order(row)

    def set_hot_wallet_state(
        self, confirmed_sats: int, address: str = "", updated_at: Optional[int] = None
    ) -> None:
        ts = int(updated_at if updated_at is not None else time.time())
        with self.transaction() as conn:
            self.set_state_tx(conn, "hot_wallet_confirmed_sats", str(max(0, int(confirmed_sats))))
            self.set_state_tx(conn, "hot_wallet_updated_at", str(ts))
            if address:
                self.set_state_tx(conn, "hot_wallet_address", str(address))

    def get_hot_wallet_state(self) -> Optional[Dict[str, Any]]:
        with self.read_conn() as conn:
            rows = conn.execute(
                "SELECT key, value FROM indexer_state WHERE key IN "
                "('hot_wallet_confirmed_sats', 'hot_wallet_updated_at', 'hot_wallet_address')"
            ).fetchall()
        data = {r["key"]: r["value"] for r in rows}
        if "hot_wallet_confirmed_sats" not in data or "hot_wallet_updated_at" not in data:
            return None
        try:
            return {
                "confirmed_sats": int(data["hot_wallet_confirmed_sats"]),
                "updated_at": int(data["hot_wallet_updated_at"]),
                "address": data.get("hot_wallet_address", ""),
            }
        except ValueError:
            return None

    def reserved_upfront_sats(self, now: Optional[int] = None) -> int:
        """
        Sum of upfront BTCB2 funding sats reserved by:
          - live unpaid invoices (awaiting_payment and not yet expired)
          - paid orders waiting to be broadcast (paid, awaiting_liquidity)
        Prevents concurrent orders and retrying orders from over-subscribing
        the hot wallet's confirmed liquidity.
        """
        ts = int(now if now is not None else time.time())
        with self.read_conn() as conn:
            row = conn.execute(
                """
                SELECT COALESCE(SUM(
                    CASE
                        WHEN upfront_funding_sats > 0 THEN upfront_funding_sats
                        ELSE est_onchain_sats + data_outputs_count * 547
                    END
                ), 0) AS s
                FROM orders
                WHERE status IN ('paid', 'awaiting_liquidity')
                   OR (status = 'awaiting_payment' AND expires_at >= ?)
                """,
                (ts,),
            ).fetchone()
        return int(row["s"])

    def get_order_public(self, order_id: str) -> Optional[Dict[str, Any]]:
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT * FROM orders WHERE order_id = ?", (order_id,)
            ).fetchone()
        return self._row_to_public_order(row) if row is not None else None

    def get_order_internal(self, order_id: str) -> Optional[Dict[str, Any]]:
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT * FROM orders WHERE order_id = ?", (order_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def list_active_orders(self) -> List[Dict[str, Any]]:
        with self.read_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM orders WHERE status IN "
                "('awaiting_payment', 'paid', 'awaiting_liquidity', 'funding_broadcast', 'awaiting_funding_conf') "
                "ORDER BY created_at ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def count_pending_orders_for_ip(self, client_ip: str) -> int:
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM orders WHERE client_ip = ? AND status = 'awaiting_payment'",
                (client_ip,),
            ).fetchone()
        return int(row["c"])

    def count_total_pending_orders(self) -> int:
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM orders WHERE status = 'awaiting_payment'"
            ).fetchone()
        return int(row["c"])

    def daily_onchain_spend_sats(self, since_ts: Optional[int] = None) -> int:
        cutoff = int(since_ts if since_ts is not None else time.time() - 86400)
        with self.read_conn() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(est_onchain_sats), 0) AS s FROM orders "
                "WHERE created_at >= ? AND status IN "
                "('paid', 'awaiting_liquidity', 'funding_broadcast', 'awaiting_funding_conf', 'completed')",
                (cutoff,),
            ).fetchone()
        return int(row["s"])

    def update_order(
        self,
        order_id: str,
        *,
        expected_status: Optional[str] = None,
        status: Optional[str] = None,
        funding_txid: Optional[str] = None,
        funding_raw_hex: Optional[str] = None,
        reveal_txid: Optional[str] = None,
        reveal_raw_hex: Optional[str] = None,
        error_message: Optional[str] = None,
        clear_secrets: bool = False,
    ) -> bool:
        sets = ["updated_at = ?"]
        params: List[Any] = [int(time.time())]
        if status is not None:
            sets.append("status = ?")
            params.append(status)
        if funding_txid is not None:
            sets.append("funding_txid = ?")
            params.append(funding_txid)
        if funding_raw_hex is not None:
            sets.append("funding_raw_hex = ?")
            params.append(funding_raw_hex)
        if reveal_txid is not None:
            sets.append("reveal_txid = ?")
            params.append(reveal_txid)
        if reveal_raw_hex is not None:
            sets.append("reveal_raw_hex = ?")
            params.append(reveal_raw_hex)
        if error_message is not None:
            sets.append("error_message = ?")
            params.append(error_message[:500])
        if clear_secrets:
            sets.append("control_privkey_hex = NULL")
            sets.append("payload_path = NULL")

        where = "order_id = ?"
        params.append(order_id)
        if expected_status is not None:
            where += " AND status = ?"
            params.append(expected_status)

        with self.transaction() as conn:
            cur = conn.execute(f"UPDATE orders SET {', '.join(sets)} WHERE {where}", params)
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # One-time migration from legacy flat JSON files
    # ------------------------------------------------------------------

    def migrate_legacy_json(self, gallery_dir: Path) -> Dict[str, int]:
        """
        Import existing legacy manifest.json / ownership.json /
        indexer_state.json into SQLite when the DB is still empty.
        Returns counts of imported records.
        """
        stats = self.get_stats()
        if stats["total_items"] > 0 or self.get_state("next_height") is not None:
            return {"items": 0, "ownership": 0, "state": 0}

        gallery_dir = Path(gallery_dir)
        imported = {"items": 0, "ownership": 0, "state": 0}

        manifest_path = gallery_dir / "manifest.json"
        ownership_path = gallery_dir / "ownership.json"
        state_path = gallery_dir / "indexer_state.json"

        with self.transaction() as conn:
            if manifest_path.exists():
                try:
                    manifest = json.loads(manifest_path.read_text())
                    if isinstance(manifest, list):
                        for entry in manifest:
                            if not isinstance(entry, dict) or not entry.get("txid") or not entry.get("stored_filename"):
                                continue
                            if self.insert_item_tx(conn, entry):
                                imported["items"] += 1
                except Exception:
                    pass

            if ownership_path.exists():
                try:
                    ownership = json.loads(ownership_path.read_text())
                    if isinstance(ownership, dict):
                        for bpub_id_hex, rec in ownership.items():
                            if not isinstance(rec, dict) or not isinstance(bpub_id_hex, str):
                                continue
                            cur = conn.execute(
                                """
                                INSERT OR IGNORE INTO ownership (
                                    bpub_id, funding_txids_json, current_outpoint,
                                    current_owner_p2wpkh, current_owner_p2wsh,
                                    last_signer_p2wpkh, txid, block_height,
                                    block_hash, block_time, outputs_json
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    bpub_id_hex,
                                    json.dumps(rec.get("funding_txids") or []),
                                    rec.get("current_outpoint"),
                                    rec.get("current_owner_p2wpkh"),
                                    rec.get("current_owner_p2wsh"),
                                    rec.get("last_signer_p2wpkh"),
                                    rec.get("txid"),
                                    rec.get("block_height"),
                                    rec.get("block_hash"),
                                    rec.get("time"),
                                    json.dumps(rec.get("outputs") or []),
                                ),
                            )
                            if cur.rowcount > 0:
                                imported["ownership"] += 1
                except Exception:
                    pass

            if state_path.exists():
                try:
                    st = json.loads(state_path.read_text())
                    if isinstance(st, dict) and "next_height" in st:
                        self.set_state_tx(conn, "next_height", str(int(st["next_height"])))
                        imported["state"] = 1
                except Exception:
                    pass

        return imported
