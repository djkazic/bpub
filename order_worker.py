#!/usr/bin/env python3
"""
Standalone background worker for custodial BPUB Lightning inscription orders.

Polls LND for settled invoices, funds & signs `padv3` funding + reveal txs via
the configured Knots/Bitcoin RPC wallet, broadcasts them, and handles waiting
for 1 funding confirmation on large (>101k vB) pairs.

If LND_REST_URL is not configured, idles cleanly without crashing so
docker-compose stacks work out of the box for gallery-only deployments too.
"""

import os
import sys
import time
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from db import BpubDB
from lnd import LndClient
from orders import EsploraHotWalletBackend, OrderConfig, OrderService, RpcWalletBackend


def main():
    gdir = Path(os.getenv("GALLERY_DIR", "gallery"))
    db_path = Path(os.getenv("BPUB_DB_PATH", str(gdir / "bpub.db")))
    payload_dir = Path(os.getenv("ORDER_PAYLOAD_DIR", str(gdir / "order_payloads")))
    poll_sec = max(2, int(os.getenv("ORDER_POLL_INTERVAL", "5")))

    lnd = LndClient.from_env()
    if lnd is None:
        sys.stderr.write(
            "[INFO] LND_REST_URL not set; custodial order worker is idle.\n"
        )
        while True:
            time.sleep(60)

    cfg = OrderConfig.from_env()
    wallet = EsploraHotWalletBackend.from_env(cfg)
    if wallet is not None:
        sys.stderr.write(
            f"[INFO] Using Esplora hot wallet ({wallet.address}) via {wallet.api}\n"
        )
    else:
        wallet = RpcWalletBackend.from_env(cfg)
        if wallet is None:
            sys.exit(
                "Set ORDER_HOT_WIF (Esplora mode) or BITCOIN_RPC_USER/BITCOIN_RPC_PASSWORD (RPC mode)"
            )
        sys.stderr.write("[INFO] Using Bitcoin/Knots RPC wallet backend\n")

    db = BpubDB(db_path)
    svc = OrderService(
        db=db,
        payload_dir=payload_dir,
        lnd=lnd,
        wallet_backend=wallet,
        cfg=cfg,
    )
    sys.stderr.write(
        f"[INFO] BPUB order worker running (sign_mode={cfg.sign_mode}, "
        f"feerate={cfg.feerate_sat_vb} sat/vB, poll={poll_sec}s)\n"
    )

    while True:
        try:
            svc.poll_all_active()
        except Exception as e:
            sys.stderr.write(f"[ERROR] Order worker tick failed: {e}\n")
        time.sleep(poll_sec)


if __name__ == "__main__":
    main()
