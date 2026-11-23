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
# funding tx. Data outputs are sized for the reveal fee and staggered by
# 1 sat, so they are NOT all 546; a wrong value yields an invalid signature.
$ python3 bpub.py revealpsbt monkey.jpg \
  --mime image/jpeg \
  --filename monkey.jpg \
  --control-pubkey CONTROL_PUBKEY \
  --bpub-utxo <funding_txid>:0:546 \
  --bpub-utxo <funding_txid>:1:547 \
  --bpub-utxo <funding_txid>:2:548 \
  --bpub-utxo <funding_txid>:3:549 \
  --bpub-utxo <funding_txid>:4:550 \
  --bpub-utxo <funding_txid>:5:551 \
  --bpub-utxo <funding_txid>:6:552 \
  --bpub-utxo <funding_txid>:7:553 \
  --bpub-utxo <funding_txid>:8:554 \
  --bpub-utxo <funding_txid>:9:555 \
  --bpub-utxo <funding_txid>:10:556 \
  --bpub-utxo <funding_txid>:11:557 \
  --bpub-utxo <funding_txid>:12:558 \
  --bpub-utxo <funding_txid>:13:559 \
  --bpub-utxo <funding_txid>:14:560 \
  --bpub-utxo <funding_txid>:15:561 \
  --bpub-utxo <funding_txid>:16:562 \
  --bpub-utxo <funding_txid>:17:563 \
  --bpub-utxo <funding_txid>:18:564 \
  --bpub-utxo <funding_txid>:19:565 \
  --bpub-utxo <funding_txid>:20:566 \
  --bpub-utxo <funding_txid>:21:567 \
  --bpub-utxo <funding_txid>:22:568 \
  --bpub-utxo <funding_txid>:23:569 \
  --bpub-utxo <funding_txid>:24:570 \
  --bpub-utxo <funding_txid>:25:571 \
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

# run indexer (scans for embedded data on-chain)
$ python3 indexer.py
```
