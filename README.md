# bpub

`bpub` is a method for embedding data on Bitcoin using fake pubkeys that *appear* to be real compressed secp256k1 pubkeys.

Dependencies:
```
# Ubuntu
sudo apt update
sudo apt install -y python3.12-dev libsecp256k1-dev

# Python
pip install secp256k1 python-bitcointx
```

Usage:
```
# create funding PSBT
$ python3 bpub.py fundpsbt monkey.jpg \
  --mime image/jpeg \
  --filename monkey.jpg \
  --control-pubkey CONTROL_PUBKEY \
  --utxo txid:index \
  --value 12345 \
  --change bc1q... \
  --feerate 1 \
  --prev-address bc1q... > funding.psbt

<sign the funding PSBT and broadcast the funding tx>

# create the reveal PSBT
$ python3 bpub.py revealpsbt monkey.jpg \
  --mime image/jpeg \
  --filename monkey.jpg \
  --control-pubkey CONTROL_PUBKEY \
  --bpub-utxo <funding_txid>:0:546 \
  --bpub-utxo <funding_txid>:1:546 \
  --bpub-utxo <funding_txid>:2:546 \
  --bpub-utxo <funding_txid>:3:546 \
  --bpub-utxo <funding_txid>:4:546 \
  --bpub-utxo <funding_txid>:5:546 \
  --bpub-utxo <funding_txid>:6:546 \
  --bpub-utxo <funding_txid>:7:546 \
  --bpub-utxo <funding_txid>:8:546 \
  --bpub-utxo <funding_txid>:9:546 \
  --bpub-utxo <funding_txid>:10:546 \
  --bpub-utxo <funding_txid>:11:546 \
  --bpub-utxo <funding_txid>:12:546 \
  --bpub-utxo <funding_txid>:13:546 \
  --bpub-utxo <funding_txid>:14:546 \
  --bpub-utxo <funding_txid>:15:546 \
  --bpub-utxo <funding_txid>:16:546 \
  --bpub-utxo <funding_txid>:17:546 \
  --bpub-utxo <funding_txid>:18:546 \
  --bpub-utxo <funding_txid>:19:546 \
  --bpub-utxo <funding_txid>:20:546 \
  --bpub-utxo <funding_txid>:21:546 \
  --bpub-utxo <funding_txid>:22:546 \
  --bpub-utxo <funding_txid>:23:546 \
  --bpub-utxo <funding_txid>:24:546 \
  --bpub-utxo <funding_txid>:25:546 \
  --change bc1q... --feerate 1 > reveal.psbt

# sign the reveal PSBT
$ python3 bpub.py signreveal reveal.psbt \
  --wif CONTROL_KEY_WIF \
  --control-pubkey CONTROL_PUBKEY > reveal.hex

<broadcast reveal tx>

# recover from tx hex to file
$ python3 bpub.py txrecover reveal.hex > monkey.jpg

# run indexer (scans for embedded data on-chain)
$ python3 indexer.py
```
