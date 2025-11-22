# Quick Start — BPUB v5 (First Inscription)

This guide walks you through **one full BPUB inscription**, from seed phrase
to reveal.

---

## Requirements

Install dependencies (see `README.md`).

## Step 1
Prepare your seed, and put it in `seed.txt` at the root of this repo.

> If `seed.txt` is missing, the wizard will prompt you and save it automatically.

## Step 2
Run the wizard:
```
$ python3 wizard.py
```

## Step 3
You will need to designate a control address (used to spend the multisig outputs) and an owner address (used to denote ownership of the asset).

After signing the funding PSBT with your wallet of choice, broadcast the transaction. This is your *funding tx*.

## Step 4

Proceed with creating and signing the reveal PSBT. Note that this is done within the wizard; your wallet from the earlier step will not know how to sign this PSBT.

## Step 5

Broadcast the signed reveal txn.

## Step 6

Now you will be prompted to create and sign an *ownership transfer* txn. You may skip this if you wish for the asset's owner to remain sealed. Note that the owner address specified owns the asset regardless of if you choose to reveal it.
