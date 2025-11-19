# bpub

`bpub` is a method for embedding data on Bitcoin using fake pubkeys that *appear* to be real compressed secp256k1 pubkeys.

Usage:
```
# Encode file
python3 bpub.py encode --filename monkey.jpg monkey.jpg > pubkeys.json

# Output unsigned tx
python3 bpub.py txbuild pubkeys.json --utxo txid:outpoint --value 12345 --change bc1q... > tx.hex

# Write PSBT for signing to disk
python3 bpub.py txpsbt pubkeys.json --utxo txid:outpoint --value 12345 --change bc1q... --prev-address bc1...

# Now sign the PSBT and broadcast!

# To recover from tx hex to file
python3 bpub.py txrecover tx.final > monkey.jpg
```
