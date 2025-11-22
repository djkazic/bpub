## Introduction

This handbook is a practical guide to **BPUB** (current version: **v5**),  
a method of embedding arbitrary data into Bitcoin transactions by grinding
nonce values to produce valid compressed secp256k1 public keys.

Unlike OP_RETURN or ordinal-style inscriptions, BPUB stores data **inside the
redeem script of a 1-of-N P2WSH multisig**, giving fine-grained control over
how data is revealed and who owns it. Version 5 introduces mandatory ownership,
a standardized stream format, and deterministic metadata handling.

This repository includes tooling to construct, fund, reveal, and transfer BPUB
inscriptions safely using real Bitcoin transactions.