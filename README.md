# bpub

`bpub` is a method for embedding data on Bitcoin using fake pubkeys that *appear* to be real compressed secp256k1 pubkeys.

Telegram group: https://t.me/+64cfGs_A0JA1ODhh

Dependencies:
```
# Ubuntu
sudo apt update
sudo apt install -y python3.12-dev libsecp256k1-dev

# Python
pip install secp256k1 python-bitcointx bip-utils requests
```

Usage:
```
# create funding PSBT
$ python3 bpub.py fundpsbt monkey.jpg \
  --mime image/jpeg \
  --filename monkey.jpg \
  --control-pubkey CONTROL_PUBKEY \
  --owner-address bc1q... \
  --utxo txid:index \
  --value 12345 \
  --change bc1q... \
  --feerate 1 \
  --prev-address bc1q... > funding.psbt

<sign the funding PSBT and broadcast the funding tx>

# create the reveal PSBT
# NOTE: each --bpub-utxo VALUE must be that output's real value in the
# funding tx. Data outputs are sized for the reveal fee (floored at 547
# sats, larger for smaller files or higher feerates), so they are NOT
# 546; a wrong value yields an invalid signature.
$ python3 bpub.py revealpsbt monkey.jpg \
  --mime image/jpeg \
  --filename monkey.jpg \
  --control-pubkey CONTROL_PUBKEY \
  --bpub-utxo <funding_txid>:0:547 \
  --bpub-utxo <funding_txid>:1:547 \
  --bpub-utxo <funding_txid>:2:547 \
  --bpub-utxo <funding_txid>:3:547 \
  --bpub-utxo <funding_txid>:4:547 \
  --bpub-utxo <funding_txid>:5:547 \
  --bpub-utxo <funding_txid>:6:547 \
  --bpub-utxo <funding_txid>:7:547 \
  --bpub-utxo <funding_txid>:8:547 \
  --bpub-utxo <funding_txid>:9:547 \
  --bpub-utxo <funding_txid>:10:547 \
  --bpub-utxo <funding_txid>:11:547 \
  --bpub-utxo <funding_txid>:12:547 \
  --bpub-utxo <funding_txid>:13:547 \
  --bpub-utxo <funding_txid>:14:547 \
  --bpub-utxo <funding_txid>:15:547 \
  --bpub-utxo <funding_txid>:16:547 \
  --bpub-utxo <funding_txid>:17:547 \
  --bpub-utxo <funding_txid>:18:547 \
  --bpub-utxo <funding_txid>:19:547 \
  --bpub-utxo <funding_txid>:20:547 \
  --bpub-utxo <funding_txid>:21:547 \
  --bpub-utxo <funding_txid>:22:547 \
  --bpub-utxo <funding_txid>:23:547 \
  --bpub-utxo <funding_txid>:24:547 \
  --bpub-utxo <funding_txid>:25:547 \
  --change bc1q... --feerate 1 > reveal.psbt

# sign the reveal PSBT
$ python3 bpub.py signreveal reveal.psbt \
  --wif CONTROL_KEY_WIF \
  --control-pubkey CONTROL_PUBKEY > reveal.hex

<broadcast reveal tx>

# recover from tx hex to file
$ python3 bpub.py txrecover reveal.hex > monkey.jpg

# create transfer ownership PSBT (self -> self transfer reveals owner)
$ python3 bpub.py ownertransferpsbt \
  --bpub-id 822228cfc784c88df8f9299508961a26cf3ade55930aa2a42089b271598991ba \
  --current-owner-address bc1q... \
  --new-owner-address bc1q... \
  --feerate 1 \
  --owner-utxo <funding_txid>:26:10000 > owner-transfer.psbt

# sign transfer ownership PSBT
$ python3 bpub.py signreveal \
  owner-transfer.psbt --wif <owner-address-wif> > owner-transfer.hex

<broadcast transfer tx>

# run indexer (scans for embedded data on-chain into SQLite `gallery/bpub.db`)
$ python3 indexer.py

# run gallery web server + padv3 embed API (defaults to 0.0.0.0:8888)
$ uvicorn server:app --host 0.0.0.0 --port 8888
```

## Gallery Website, SQLite Indexer & Custodial LND Inscriptions

Copy `.env.sample` to `.env`, configure your Bitcoin/BLAKE2b Knots RPC credentials, and launch the full stack with Docker Compose:

```bash
cp .env.sample .env
docker compose up -d --build
```

Services started by `docker-compose.yml`:
- `web`: FastAPI gallery UI, `/media/*`, `padv3` PSBT studio, broadcaster (`mempool.kilombino.com`), and Lightning order API on `0.0.0.0:8888`. Point `cloudflared` at port `8888` with `BPUB_TRUST_PROXY=1` (reads `CF-Connecting-IP`).
- `indexer`: Scans blocks from either `INDEXER_SOURCE=esplora` (default when RPC is unset — 1 `/api/block/{hash}/raw` request per block from `EXPLORER_BASE_URL`, supporting both 80-byte Bitcoin and 164-byte BLAKE2b headers) or local `bitcoind` RPC, stores reveals & verified v5 ownership into WAL-mode SQLite (`bpub.db`), auto-migrates legacy JSON files, and rolls back orphaned blocks on chain reorgs.
- `order-worker`: Optional custodial Lightning (`LND_REST_URL` + least-privilege `invoice.macaroon`) fulfillment worker that creates `padv3` inscriptions on behalf of users using either a dedicated Esplora hot wallet (`ORDER_HOT_WIF`, no local Knots node needed) or a local Knots RPC wallet, signing with `SIGHASH_UNIFIED` (`ORDER_SIGN_MODE=unified`, or `btc` for standard Bitcoin). Leave `LND_REST_URL` empty to disable custodial orders cleanly.

