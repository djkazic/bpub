#!/usr/bin/env python3

import sys
import os
import textwrap
from types import SimpleNamespace
import getpass
from typing import Optional, Tuple
import io
import contextlib
import json

import requests
from bip_utils import (
    Bip39SeedGenerator,
    Bip84,
    Bip84Coins,
    Bip44Changes,
)

from bitcointx import select_chain_params, BitcoinMainnetParams
from bitcointx.wallet import CBitcoinSecret, P2WPKHBitcoinAddress
from bitcointx.core import b2x
from bitcointx.core.psbt import PartiallySignedTransaction as PSBT

import bpub

select_chain_params(BitcoinMainnetParams)

SEED_FILE = "seed.txt"
DUST_SATS = 546


def _normalize_mnemonic(m: str) -> str:
    return " ".join(m.strip().split())


def _bip84_ctx_from_seed(seed_bytes: bytes):
    return Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)


def derive_bip84_key_at(seed_bytes: bytes, account: int, change: int, index: int):
    ctx = _bip84_ctx_from_seed(seed_bytes)
    acct = ctx.Purpose().Coin().Account(account)
    ch = acct.Change(Bip44Changes.CHAIN_INT if change else Bip44Changes.CHAIN_EXT)
    addr_ctx = ch.AddressIndex(index)

    wif = addr_ctx.PrivateKey().ToWif()
    pubkey_bytes = addr_ctx.PublicKey().RawCompressed().ToBytes()
    addr = addr_ctx.PublicKey().ToAddress()

    sec = CBitcoinSecret(wif)
    bt_addr = P2WPKHBitcoinAddress.from_pubkey(sec.pub)
    if str(bt_addr) != addr:
        raise RuntimeError("bip_utils / bitcointx address mismatch")

    path = f"m/84'/0'/{account}'/{change}/{index}"
    return {
        "path": path,
        "wif": wif,
        "pubkey_hex": pubkey_bytes.hex(),
        "p2wpkh_addr": addr,
    }


def find_bip84_address(
    seed_bytes: bytes,
    target_addr: str,
    max_account: int = 3,
    max_change: int = 1,
    max_index: int = 50,
):
    target_addr = target_addr.strip()
    if not target_addr:
        return None

    ctx = _bip84_ctx_from_seed(seed_bytes)

    for account in range(max_account + 1):
        acct = ctx.Purpose().Coin().Account(account)
        for change in range(max_change + 1):
            ch = acct.Change(
                Bip44Changes.CHAIN_INT if change else Bip44Changes.CHAIN_EXT
            )
            for index in range(max_index + 1):
                addr_ctx = ch.AddressIndex(index)
                addr = addr_ctx.PublicKey().ToAddress()
                if addr == target_addr:
                    wif = addr_ctx.PrivateKey().ToWif()
                    pubkey_bytes = addr_ctx.PublicKey().RawCompressed().ToBytes()

                    sec = CBitcoinSecret(wif)
                    bt_addr = P2WPKHBitcoinAddress.from_pubkey(sec.pub)
                    if str(bt_addr) != addr:
                        raise RuntimeError("bip_utils / bitcointx address mismatch")

                    path = f"m/84'/0'/{account}'/{change}/{index}"
                    return {
                        "path": path,
                        "wif": wif,
                        "pubkey_hex": pubkey_bytes.hex(),
                        "p2wpkh_addr": addr,
                    }

    return None


def find_bip84_pubkey(
    seed_bytes: bytes,
    target_pub_hex: str,
    max_account: int = 3,
    max_change: int = 1,
    max_index: int = 50,
):
    try:
        target_pub = bytes.fromhex(target_pub_hex.strip())
    except ValueError:
        print("Invalid pubkey hex")
        return None

    if len(target_pub) != 33:
        print("Compressed pubkey must be 33 bytes")
        return None

    ctx = _bip84_ctx_from_seed(seed_bytes)

    for account in range(max_account + 1):
        acct = ctx.Purpose().Coin().Account(account)
        for change in range(max_change + 1):
            ch = acct.Change(
                Bip44Changes.CHAIN_INT if change else Bip44Changes.CHAIN_EXT
            )
            for index in range(max_index + 1):
                addr_ctx = ch.AddressIndex(index)
                pub_bytes = addr_ctx.PublicKey().RawCompressed().ToBytes()
                if pub_bytes == target_pub:
                    wif = addr_ctx.PrivateKey().ToWif()
                    addr = addr_ctx.PublicKey().ToAddress()

                    sec = CBitcoinSecret(wif)
                    bt_addr = P2WPKHBitcoinAddress.from_pubkey(sec.pub)
                    if str(bt_addr) != addr:
                        raise RuntimeError("bip_utils / bitcointx address mismatch")

                    path = f"m/84'/0'/{account}'/{change}/{index}"
                    return {
                        "path": path,
                        "wif": wif,
                        "pubkey_hex": pub_bytes.hex(),
                        "p2wpkh_addr": addr,
                    }

    return None


def prompt_multiline(prompt: str) -> str:
    print(prompt)
    lines = []
    while True:
        line = input("> ").strip()
        if not line:
            break
        lines.append(line)
    return " ".join(lines)


def prompt_passphrase() -> str:
    pw = getpass.getpass("BIP39 passphrase (blank if none): ")
    return pw or ""


def get_or_create_seed(context: str) -> Optional[Tuple[bytes, str, str]]:
    if os.path.exists(SEED_FILE):
        try:
            with open(SEED_FILE, "r") as f:
                data = json.load(f)
            mnemonic = data.get("mnemonic", "")
            passphrase = data.get("passphrase", "")
            if not mnemonic.strip():
                raise ValueError("mnemonic missing in seed.txt")

            mnemonic_norm = _normalize_mnemonic(mnemonic)
            seed_bytes = Bip39SeedGenerator(mnemonic_norm).Generate(passphrase)
            print(f"\nLoaded seed from {SEED_FILE} for {context}.")
            return seed_bytes, mnemonic_norm, passphrase
        except Exception as e:
            print(
                f"\nExisting {SEED_FILE} is invalid: {e}\n"
                "You'll be prompted for a new seed (overwrites seed.txt)."
            )

    print(f"\n=== Seed setup for {context} ===\n")
    mnemonic = prompt_multiline(
        "Enter BIP39 seed phrase (one or more lines, blank line to finish):"
    )
    if not mnemonic.strip():
        print("No mnemonic entered, aborting.")
        return None

    mnemonic_norm = _normalize_mnemonic(mnemonic)
    passphrase = prompt_passphrase()

    try:
        seed_bytes = Bip39SeedGenerator(mnemonic_norm).Generate(passphrase)
    except Exception as e:
        print(f"Invalid mnemonic: {e}")
        return None

    try:
        with open(SEED_FILE, "w") as f:
            json.dump(
                {"mnemonic": mnemonic_norm, "passphrase": passphrase},
                f,
                indent=2,
            )
        print(f"\nSeed stored in {SEED_FILE} (PLAINTEXT). Keep it secure.\n")
    except OSError as e:
        print(f"WARNING: Failed to write {SEED_FILE}: {e}")

    return seed_bytes, mnemonic_norm, passphrase


def prompt_yes_no(msg: str, default: bool = True) -> bool:
    default_str = "Y/n" if default else "y/N"
    while True:
        ans = input(f"{msg} [{default_str}]: ").strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False


def prompt_int(msg: str, default: Optional[int] = None) -> int:
    while True:
        if default is not None:
            raw = input(f"{msg} [{default}]: ").strip()
        else:
            raw = input(msg + ": ").strip()

        if not raw and default is not None:
            return default
        try:
            return int(raw)
        except ValueError:
            print("Please enter an integer.")


def prompt_nonempty(msg: str, default: Optional[str] = None) -> str:
    while True:
        if default is not None:
            raw = input(f"{msg} [{default}]: ").strip()
        else:
            raw = input(msg + ": ").strip()

        if raw:
            return raw
        if default is not None:
            return default
        print("Value cannot be empty.")


def choose_keys_from_seed() -> Tuple[Optional[bytes], Optional[dict], Optional[dict]]:
    res = get_or_create_seed("control/owner selection")
    if res is None:
        return None, None, None
    seed_bytes, _mnemonic, _passphrase = res

    print("\n--- CONTROL KEY ---")
    control_addr = prompt_nonempty("Control address (bc1q...)")

    ctrl = find_bip84_address(seed_bytes, control_addr)
    if not ctrl:
        print(
            "\nCould not locate that control address in BIP84 search "
            "(accounts 0-3, change 0-1, indexes 0-50)."
        )
        return None, None, None
    print(f"Found control address at path {ctrl['path']}")

    print("\n--- OWNER KEY ---")
    owner_addr = prompt_nonempty("Owner address (bc1q...)")

    owner = find_bip84_address(seed_bytes, owner_addr)
    if not owner:
        print(
            "\nCould not locate that owner address in BIP84 search "
            "(accounts 0-3, change 0-1, indexes 0-50)."
        )
        return None, None, None
    print(f"Found owner address at path {owner['path']}")

    print("\nSummary of keys:")
    print("CONTROL:")
    print(f"  path     : {ctrl['path']}")
    print(f"  address  : {ctrl['p2wpkh_addr']}")
    print(f"  pubkey   : {ctrl['pubkey_hex']}")
    print("\nOWNER:")
    print(f"  path     : {owner['path']}")
    print(f"  address  : {owner['p2wpkh_addr']}")
    print(f"  pubkey   : {owner['pubkey_hex']}")

    return seed_bytes, ctrl, owner


def derive_signing_key_from_seed(role_label: str) -> Optional[dict]:
    res = get_or_create_seed(f"{role_label} signing")
    if res is None:
        return None
    seed_bytes, _mnemonic, _passphrase = res

    print(f"\n=== Derive {role_label} signing key from seed ===\n")

    while True:
        mode = (
            input(
                f"Identify the {role_label} key by address or pubkey? [a=address, p=pubkey]: "
            )
            .strip()
            .lower()
        )
        if mode in ("a", "p"):
            break
        print("Please enter 'a' or 'p'.")

    if mode == "a":
        addr = prompt_nonempty(f"{role_label} address (bc1q...)")
        info = find_bip84_address(seed_bytes, addr)
        if not info:
            print(
                "\nCould not locate that address in BIP84 search "
                "(accounts 0-3, change 0-1, indexes 0-50)."
            )
            return None
        print(
            f"Found {role_label} address at path {info['path']} "
            f"(addr={info['p2wpkh_addr']}, pubkey={info['pubkey_hex']})"
        )
        return info

    pub_hex = prompt_nonempty(f"{role_label} compressed pubkey (33-byte hex)")
    info = find_bip84_pubkey(seed_bytes, pub_hex)
    if not info:
        print(
            "\nCould not locate that pubkey in BIP84 search "
            "(accounts 0-3, change 0-1, indexes 0-50)."
        )
        return None
    print(
        f"Found {role_label} pubkey at path {info['path']} "
        f"(addr={info['p2wpkh_addr']}, pubkey={info['pubkey_hex']})"
    )
    return info


def fetch_tx_from_mempool(txid: str) -> Optional[dict]:
    url = f"https://mempool.space/api/tx/{txid}"
    try:
        resp = requests.get(url, timeout=10)
    except Exception as e:
        print(f"mempool.space lookup failed: {e}")
        return None

    if resp.status_code != 200:
        print(f"mempool.space returned status {resp.status_code} for tx {txid}")
        return None

    try:
        return resp.json()
    except Exception as e:
        print(f"Failed to decode mempool.space JSON: {e}")
        return None


def lookup_utxo_details_from_mempool(utxo: str) -> Optional[dict]:
    try:
        txid_str, vout_str = utxo.split(":")
        vout = int(vout_str)
    except Exception:
        print("Could not parse UTXO as TXID:VOUT for mempool lookup.")
        return None

    tx = fetch_tx_from_mempool(txid_str)
    if tx is None:
        return None

    vouts = tx.get("vout", [])
    if not isinstance(vouts, list):
        print("Unexpected mempool.space format for vout.")
        return None

    if vout < 0 or vout >= len(vouts):
        print(f"UTXO vout index {vout} out of range for this transaction.")
        return None

    out = vouts[vout]
    addr = out.get("scriptpubkey_address")
    value = out.get("value")
    return {"address": addr, "value": value}


def _parse_vout_range(r: str) -> Tuple[int, int]:
    r = r.strip()
    sep = ":" if ":" in r else "-"
    parts = r.split(sep)
    if len(parts) != 2:
        raise ValueError("Range must be of the form start:end or start-end")
    start = int(parts[0])
    end = int(parts[1])
    if start < 0 or end < start:
        raise ValueError("Invalid range")
    return start, end


def flow_new_inscription():
    print("\n=== New inscription pipeline (funding + reveal + sign) ===")

    seed_bytes, control_info, owner_info = choose_keys_from_seed()
    if seed_bytes is None:
        return

    control_pubkey = control_info["pubkey_hex"]
    owner_addr = owner_info["p2wpkh_addr"]

    print("\nUsing:")
    print(f"  Control pubkey : {control_pubkey}")
    print(f"  Owner address  : {owner_addr}\n")

    file_path = prompt_nonempty("File to inscribe (path)")
    default_filename = os.path.basename(file_path)
    filename = prompt_nonempty(
        "Filename to embed in BPUB metadata", default=default_filename
    )
    mime = prompt_nonempty("MIME type", default="image/jpeg")
    compress = prompt_yes_no(
        "Compress content inside BPUB (raw DEFLATE + XOR)?",
        default=True,
    )

    utxo = prompt_nonempty("Funding UTXO (TXID:VOUT)")

    value = None
    prev_addr = None
    print("\nAttempting to detect UTXO details via mempool.space API ...")
    details = lookup_utxo_details_from_mempool(utxo)
    if details:
        value = details.get("value")
        prev_addr = details.get("address")
        if value is not None:
            print(f"  Detected UTXO value: {value} sats")
        if prev_addr:
            print(f"  Detected prev address: {prev_addr}")
    else:
        print("  mempool.space lookup failed; entering manually.")

    if value is None:
        value = prompt_int("Funding UTXO value in sats")

    feerate = prompt_int("Target feerate for funding tx (sats/vbyte)", default=1)
    change_addr = prompt_nonempty("Change address for funding tx (bech32)")

    if prev_addr:
        use_auto = prompt_yes_no(
            "Use detected prev address as funding UTXO's prev address?",
            default=True,
        )
        if not use_auto:
            prev_addr = prompt_nonempty("Prev address (funding UTXO's address, bech32)")
    else:
        prev_addr = prompt_nonempty("Prev address (funding UTXO's address, bech32)")

    print("\nSummary (funding stage):")
    print(f"  File         : {file_path}")
    print(f"  Filename     : {filename}")
    print(f"  MIME         : {mime}")
    print(f"  Compress     : {compress}")
    print(f"  Control key  : {control_pubkey}")
    print(f"  Owner addr   : {owner_addr}")
    print(f"  UTXO         : {utxo} ({value} sats)")
    print(f"  Feerate      : {feerate} sats/vbyte")
    print(f"  Change addr  : {change_addr}")
    print(f"  Prev address : {prev_addr}")
    if not prompt_yes_no("\nProceed to build funding PSBT?", default=True):
        print("Aborted.")
        return

    args = SimpleNamespace(
        file=file_path,
        mime=mime,
        filename=filename,
        compress=compress,
        legacy_v3=False,
        v4=False,
        control_pubkey=control_pubkey,
        owner_address=owner_addr,
        utxo=utxo,
        value=value,
        feerate=feerate,
        change=change_addr,
        prev_address=prev_addr,
        prev_spk=None,
    )

    print("\nBuilding funding PSBT via bpub...\n")

    fbuf = io.StringIO()
    fund_psbt_b64 = None
    auto_funding_txid = None
    auto_out_count = None
    fund_unsigned_tx = None
    try:
        with contextlib.redirect_stdout(fbuf):
            bpub.cmd_fundpsbt(args)
        fund_psbt_b64 = fbuf.getvalue().strip()
    except SystemExit as e:
        print(f"\nfundpsbt exited with code {e.code}", file=sys.stderr)
        return

    if not fund_psbt_b64:
        print("No PSBT data captured from bpub.fundpsbt; aborting.")
        return

    print("--- Funding PSBT (base64) ---\n")
    print(fund_psbt_b64)
    print()

    try:
        psbt_obj = PSBT.from_base64(fund_psbt_b64)
        unsigned_tx = psbt_obj.unsigned_tx
        fund_unsigned_tx = unsigned_tx
        auto_funding_txid = b2x(unsigned_tx.GetTxid()[::-1])
        auto_out_count = len(unsigned_tx.vout)
        print("Unsigned funding txid from PSBT:")
        print(f"  {auto_funding_txid}\n")
        print(
            f"Unsigned funding transaction has {auto_out_count} outputs.\n"
            "For BPUB v5 with owner+change, first N-2 outputs are BPUB data,\n"
            "vout N-2 is owner, vout N-1 is change.\n"
        )
    except Exception as e:
        print(f"Could not parse funding txid/output count from PSBT: {e}")
        auto_funding_txid = None
        auto_out_count = None
        fund_unsigned_tx = None

    print(
        "Sign this funding PSBT in your wallet (e.g. Sparrow), finalize, and broadcast.\n"
    )

    if not prompt_yes_no(
        "After (or before) broadcasting, build the reveal PSBT and optionally sign it?",
        default=True,
    ):
        print(
            "\nYou can re-run the wizard later and use 'Reveal BPUB data' and\n"
            "'Sign BPUB PSBT' once you have the funding txid.\n"
        )
        return

    if auto_funding_txid:
        funding_txid = prompt_nonempty(
            "Funding transaction ID (txid)", default=auto_funding_txid
        )
    else:
        funding_txid = prompt_nonempty("Funding transaction ID (txid)")

    if auto_out_count is not None:
        out_count = auto_out_count
    else:
        out_count = prompt_int("How many outputs does the funding transaction have?")

    if out_count < 3:
        print(
            f"Funding tx has {out_count} outputs; need at least data+owner+change. "
            "Aborting reveal stage."
        )
        return

    num_data_outputs = out_count - 2
    start_vout = 0
    end_vout = num_data_outputs - 1
    print(
        f"Assuming BPUB data outputs are vout {start_vout}..{end_vout} "
        f"(total {num_data_outputs}), last two are owner+change."
    )

    bpub_utxos = [
        f"{funding_txid}:{vout}:{DUST_SATS}" for vout in range(start_vout, end_vout + 1)
    ]

    print("\nBPUB data UTXOs (assuming 546 sats each):")
    for u in bpub_utxos:
        print("  ", u)

    reveal_feerate = feerate
    reveal_change_addr = change_addr

    print("\nSummary (reveal stage):")
    print(f"  File        : {file_path}")
    print(f"  Filename    : {filename}")
    print(f"  MIME        : {mime}")
    print(f"  Compress    : {compress}")
    print(f"  Control key : {control_pubkey}")
    print(f"  Change addr : {reveal_change_addr}")
    print(f"  Feerate     : {reveal_feerate} sats/vbyte")
    if not prompt_yes_no("\nProceed to build reveal PSBT?", default=True):
        print("Reveal stage aborted.")
        return

    reveal_args = SimpleNamespace(
        file=file_path,
        mime=mime,
        filename=filename,
        compress=compress,
        legacy_v3=False,
        v4=False,
        control_pubkey=control_pubkey,
        bpub_utxo=bpub_utxos,
        change=reveal_change_addr,
        feerate=reveal_feerate,
    )

    reveal_out_file = prompt_nonempty(
        "Filename to save reveal PSBT (base64)", default="reveal.psbt"
    )

    print("\nBuilding reveal PSBT via bpub...")

    rbuf = io.StringIO()
    try:
        with contextlib.redirect_stdout(rbuf):
            bpub.cmd_revealpsbt(reveal_args)
    except SystemExit as e:
        print(f"\nrevealpsbt exited with code {e.code}", file=sys.stderr)
        return

    reveal_psbt_b64 = rbuf.getvalue().strip()
    if not reveal_psbt_b64:
        print("No PSBT data captured from bpub.revealpsbt; aborting.")
        return

    try:
        with open(reveal_out_file, "w") as f:
            f.write(reveal_psbt_b64 + "\n")
    except OSError as e:
        print(f"Failed to write reveal PSBT to '{reveal_out_file}': {e}")
        return

    print(f"\nReveal PSBT saved to: {reveal_out_file}")

    if prompt_yes_no("Sign the reveal PSBT now using the CONTROL key?", default=True):
        sign_psbt_with_role_and_psbt(
            psbt_b64=reveal_psbt_b64,
            role_label="CONTROL",
            default_outfile="signed-reveal-tx.hex",
            key_info=control_info,
        )
    else:
        print(
            "\nYou can run 'Sign BPUB PSBT' later and point it at "
            f"'{reveal_out_file}'.\n"
        )

    # Optional owner-reveal (self-transfer) to make owner public
    if not prompt_yes_no(
        "Do you also want to reveal the OWNER of this BPUB via an owner-transfer "
        "from the owner address to itself?",
        default=True,
    ):
        return

    if (
        fund_unsigned_tx is not None
        and auto_funding_txid is not None
        and funding_txid == auto_funding_txid
    ):
        owner_vout_index = len(fund_unsigned_tx.vout) - 2
        if owner_vout_index < 0 or owner_vout_index >= len(fund_unsigned_tx.vout):
            print(
                "Could not derive owner vout index from funding PSBT; "
                "please re-run or use manual owner-transfer."
            )
            return
        owner_utxo_value = fund_unsigned_tx.vout[owner_vout_index].nValue
        print(
            f"\nDerived owner UTXO from funding PSBT:\n"
            f"  vout index : {owner_vout_index}\n"
            f"  value      : {owner_utxo_value} sats"
        )
    else:
        owner_vout_index = out_count - 2
        print(
            "\nCannot safely derive owner UTXO value from funding PSBT "
            "(txid/output mismatch or PSBT unavailable)."
        )
        owner_utxo_value = prompt_int("Owner UTXO value in sats")

    owner_utxo_str = f"{funding_txid}:{owner_vout_index}:{owner_utxo_value}"

    print("\nOwner-reveal (self-transfer) setup:")
    print(f"  BPUB file           : {file_path}")
    print(f"  Current owner addr  : {owner_addr}")
    print(f"  New owner addr      : {owner_addr}")
    print(f"  Owner UTXO          : {owner_utxo_str}")
    owner_feerate = prompt_int(
        "Target feerate for owner-transfer (sats/vbyte)", default=1
    )

    ot_args = SimpleNamespace(
        file=file_path,
        bpub_id=None,
        current_owner_address=owner_addr,
        new_owner_address=owner_addr,
        owner_utxo=owner_utxo_str,
        feerate=owner_feerate,
    )

    owner_psbt_file = prompt_nonempty(
        "Filename to save owner-reveal PSBT (base64)",
        default="owner-reveal.psbt",
    )

    print("\nBuilding owner-reveal (self-transfer) PSBT via bpub...")

    obuf = io.StringIO()
    try:
        with contextlib.redirect_stdout(obuf):
            bpub.cmd_ownertransferpsbt(ot_args)
    except SystemExit as e:
        print(f"\nownertransferpsbt exited with code {e.code}", file=sys.stderr)
        return

    owner_psbt_b64 = obuf.getvalue().strip()
    if not owner_psbt_b64:
        print("No PSBT data captured from ownertransferpsbt; aborting.")
        return

    try:
        with open(owner_psbt_file, "w") as f:
            f.write(owner_psbt_b64 + "\n")
    except OSError as e:
        print(f"Failed to write owner-reveal PSBT to '{owner_psbt_file}': {e}")
        return

    print(f"\nOwner-reveal PSBT saved to: {owner_psbt_file}")

    if prompt_yes_no(
        "Sign the owner-reveal PSBT now using the OWNER key?", default=True
    ):
        sign_psbt_with_role_and_psbt(
            psbt_b64=owner_psbt_b64,
            role_label="OWNER",
            default_outfile="signed-owner-reveal-tx.hex",
            key_info=owner_info,
        )
    else:
        print(
            "\nYou can run 'Sign BPUB PSBT' later and point it at "
            f"'{owner_psbt_file}'.\n"
        )


def flow_reveal():
    print("\n=== Reveal BPUB data (build reveal PSBT) ===\n")

    if prompt_yes_no(
        "Derive CONTROL pubkey from seed by specifying control/owner addresses?",
        default=True,
    ):
        seed_bytes, control_info, _owner_info = choose_keys_from_seed()
        if seed_bytes is None:
            return
        control_pubkey = control_info["pubkey_hex"]
    else:
        control_pubkey = prompt_nonempty("Control pubkey (compressed 33-byte hex)")

    file_path = prompt_nonempty("Original file path (used for funding)")
    default_filename = os.path.basename(file_path)
    filename = prompt_nonempty(
        "Filename used in BPUB metadata", default=default_filename
    )
    mime = prompt_nonempty("MIME type used in BPUB", default="image/jpeg")
    compress = prompt_yes_no("Was BPUB content compressed?", default=True)

    print(
        "\nNeed the BPUB data UTXOs. Either:\n"
        "  - auto-generate from TXID + vout range, or\n"
        "  - enter TXID:VOUT:VALUE manually.\n"
    )

    bpub_utxos = []

    if prompt_yes_no("Auto-generate from a vout range?", default=True):
        txid = prompt_nonempty("Funding TXID for BPUB outputs")
        value_each = DUST_SATS
        print(f"Assuming each BPUB data output is {DUST_SATS} sats.")
        while True:
            try:
                rng = prompt_nonempty("Vout range (e.g. 0:19 or 0-19)")
                start, end = _parse_vout_range(rng)
                break
            except Exception as e:
                print(f"Invalid range: {e}")

        for vout in range(start, end + 1):
            bpub_utxos.append(f"{txid}:{vout}:{value_each}")

        print(f"\nGenerated {len(bpub_utxos)} BPUB UTXOs:")
        for u in bpub_utxos:
            print("  ", u)
    else:
        print("Enter each BPUB UTXO as TXID:VOUT:VALUE, blank line to finish.")
        while True:
            line = input("> ").strip()
            if not line:
                break
            bpub_utxos.append(line)

    if not bpub_utxos:
        print("No BPUB UTXOs provided, aborting.")
        return

    change_addr = prompt_nonempty("Change address to receive swept funds (bech32)")
    feerate = prompt_int("Target feerate (sats/vbyte)", default=1)

    print("\nSummary:")
    print(f"  File        : {file_path}")
    print(f"  Filename    : {filename}")
    print(f"  MIME        : {mime}")
    print(f"  Compress    : {compress}")
    print(f"  Control key : {control_pubkey}")
    print("  BPUB UTXOs  :")
    for u in bpub_utxos:
        print(f"    - {u}")
    print(f"  Change addr : {change_addr}")
    print(f"  Feerate     : {feerate} sats/vbyte")
    if not prompt_yes_no("\nProceed to build reveal PSBT?", default=True):
        print("Aborted.")
        return

    args = SimpleNamespace(
        file=file_path,
        mime=mime,
        filename=filename,
        compress=compress,
        legacy_v3=False,
        v4=False,
        control_pubkey=control_pubkey,
        bpub_utxo=bpub_utxos,
        change=change_addr,
        feerate=feerate,
    )

    out_file = prompt_nonempty(
        "Filename to save reveal PSBT (base64)", default="reveal.psbt"
    )

    print("\nBuilding reveal PSBT via bpub...")

    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            bpub.cmd_revealpsbt(args)
    except SystemExit as e:
        print(f"\nrevealpsbt exited with code {e.code}", file=sys.stderr)
        return

    psbt_b64 = buf.getvalue().strip()
    if not psbt_b64:
        print("No PSBT data captured from bpub.revealpsbt; aborting.")
        return

    try:
        with open(out_file, "w") as f:
            f.write(psbt_b64 + "\n")
    except OSError as e:
        print(f"Failed to write reveal PSBT to '{out_file}': {e}")
        return

    print(f"\nReveal PSBT saved to: {out_file}")


def sign_psbt_with_role_and_psbt(
    psbt_b64: str,
    role_label: str,
    default_outfile: str,
    key_info: Optional[dict] = None,
):
    if key_info is None:
        key_info = derive_signing_key_from_seed(role_label)
        if not key_info:
            print("Could not derive signing key from seed; aborting.")
            return

    wif = key_info["wif"]
    pub_hex = key_info["pubkey_hex"]

    args = SimpleNamespace(
        psbt=psbt_b64,
        wif=wif,
        control_pubkey=pub_hex,
    )

    out_file = prompt_nonempty(
        "Filename to save signed raw transaction hex",
        default=default_outfile,
    )

    print("\nSigning PSBT via bpub...")

    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            bpub.cmd_signreveal(args)
    except SystemExit as e:
        print(f"\nsignreveal exited with code {e.code}", file=sys.stderr)
        return

    raw_hex = buf.getvalue().strip()
    if not raw_hex:
        print("No raw transaction hex captured from signreveal; aborting.")
        return

    try:
        with open(out_file, "w") as f:
            f.write(raw_hex + "\n")
    except OSError as e:
        print(f"Failed to write signed transaction to '{out_file}': {e}")
        return

    print(f"\nSigned raw transaction saved to: {out_file}")

    if prompt_yes_no("Also print the raw transaction hex to stdout?", default=False):
        print("\n--- Signed raw transaction hex ---\n")
        print(raw_hex)


def flow_sign_psbt():
    print("\n=== Sign BPUB PSBT (derive WIF from seed) ===\n")

    src = prompt_nonempty(
        "PSBT source (filename, e.g. reveal.psbt, or paste base64 directly)"
    )
    try:
        with open(src, "r") as f:
            psbt_arg = f.read().strip()
    except OSError:
        psbt_arg = src.strip()

    print(
        "\nWhat type of BPUB PSBT is this?\n"
        "  1) Reveal / multisig spend (CONTROL key)\n"
        "  2) Owner-transfer / owner-reveal (OWNER key)\n"
    )
    while True:
        choice = input("Select 1 or 2: ").strip()
        if choice in ("1", "2"):
            break
        print("Please enter 1 or 2.")

    if choice == "1":
        role_label = "CONTROL"
        default_outfile = "signed-reveal-tx.hex"
    else:
        role_label = "OWNER"
        default_outfile = "signed-owner-reveal-tx.hex"

    sign_psbt_with_role_and_psbt(
        psbt_b64=psbt_arg,
        role_label=role_label,
        default_outfile=default_outfile,
        key_info=None,
    )


def flow_ownertransfer():
    print("\n=== Transfer BPUB v5 ownership (build owner-transfer PSBT) ===\n")

    use_file = prompt_yes_no(
        "Derive BPUB v5 ID from a file (same content as original BPUB)?",
        default=True,
    )

    file_arg = None
    bpub_id_arg = None

    if use_file:
        file_arg = prompt_nonempty("File whose BPUB v5 ID should be used")
    else:
        bpub_id_arg = prompt_nonempty(
            "Explicit BPUB v5 ID (hex, 32 bytes / 64 hex chars)"
        )

    current_owner = prompt_nonempty("Current owner address (P2WPKH bc1q...)")
    new_owner = prompt_nonempty("New owner address (P2WPKH bc1q...)")
    owner_utxo = prompt_nonempty("Owner UTXO (TXID:VOUT:VALUE)")
    feerate = prompt_int("Target feerate (sats/vbyte)", default=1)

    print("\nSummary:")
    print(f"  Use file for BPUB_ID : {use_file}")
    if file_arg:
        print(f"  File               : {file_arg}")
    if bpub_id_arg:
        print(f"  BPUB_ID            : {bpub_id_arg}")
    print(f"  Current owner addr : {current_owner}")
    print(f"  New owner addr     : {new_owner}")
    print(f"  Owner UTXO         : {owner_utxo}")
    print(f"  Feerate            : {feerate} sats/vbyte")

    if not prompt_yes_no("\nProceed to build owner-transfer PSBT?", default=True):
        print("Aborted.")
        return

    args = SimpleNamespace(
        file=file_arg,
        bpub_id=bpub_id_arg,
        current_owner_address=current_owner,
        new_owner_address=new_owner,
        owner_utxo=owner_utxo,
        feerate=feerate,
    )

    out_file = prompt_nonempty(
        "Filename to save owner-transfer PSBT (base64)",
        default="owner-transfer.psbt",
    )

    print("\nBuilding owner-transfer PSBT via bpub...")

    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            bpub.cmd_ownertransferpsbt(args)
    except SystemExit as e:
        print(f"\nownertransferpsbt exited with code {e.code}", file=sys.stderr)
        return

    psbt_b64 = buf.getvalue().strip()
    if not psbt_b64:
        print("No PSBT data captured from ownertransferpsbt; aborting.")
        return

    try:
        with open(out_file, "w") as f:
            f.write(psbt_b64 + "\n")
    except OSError as e:
        print(f"Failed to write owner-transfer PSBT to '{out_file}': {e}")
        return

    print(f"\nOwner-transfer PSBT saved to: {out_file}")
    print(
        "\nNext: sign this PSBT with the OWNER key using 'Sign BPUB PSBT' (menu 3),\n"
        "then broadcast the resulting raw transaction.\n"
    )


def flow_check_reveal_tx():
    print("\n=== Check reveal transaction (decode & verify data) ===\n")

    src = prompt_nonempty(
        "Reveal transaction source (filename with raw hex, or paste raw hex)"
    )
    try:
        with open(src, "r") as f:
            rawtx_hex = f.read().strip()
    except OSError:
        rawtx_hex = src.strip()

    control_pk = prompt_nonempty(
        "Control pubkey hex used in BPUB scripts, or 'auto' to autodetect",
        default="auto",
    )

    args = SimpleNamespace(
        rawtx=rawtx_hex,
        control_pubkey=control_pk,
    )

    print("\nRunning bpub.txrecover; recovered bytes go to /dev/null.\n")

    try:
        dn = open(os.devnull, "wb")
    except OSError as e:
        print(f"Failed to open /dev/null: {e}")
        return

    class _DevNullStdout:
        def __init__(self, buf):
            self.buffer = buf

        def write(self, s):
            return 0

        def flush(self):
            pass

    old_stdout = sys.stdout
    sys.stdout = _DevNullStdout(dn)
    try:
        try:
            bpub.cmd_txrecover(args)
        except SystemExit as e:
            sys.stdout = old_stdout
            dn.close()
            if e.code == 0:
                print("\nTxrecover exited with code 0; treating as success.")
                return
            print(
                f"\nTxrecover failed with exit code {e.code}. "
                "Reveal tx did NOT reconstruct successfully."
            )
            return
    finally:
        sys.stdout = old_stdout
        dn.close()

    print(
        "\nTxrecover completed successfully. Data appears to reconstruct.\n"
        "(Recovered bytes were discarded; use txrecover directly to write them.)"
    )


def flow_decode_transfer_tx():
    print("\n=== Decode owner-transfer transaction ===\n")

    src = prompt_nonempty(
        "Owner-transfer tx source (filename with raw hex, or paste raw hex)"
    )
    try:
        with open(src, "r") as f:
            rawtx_hex = f.read().strip()
    except OSError:
        rawtx_hex = src.strip()

    args = SimpleNamespace(rawtx=rawtx_hex)

    print("\nRunning bpub.decodetransfer...\n")
    try:
        bpub.cmd_decodetransfer(args)
    except SystemExit as e:
        print(
            f"\ndecodetransfer exited with code {e.code}. "
            "If this wasn't an owner-transfer tx, that's expected.",
            file=sys.stderr,
        )


def main_menu():
    menu = textwrap.dedent(
        """
        === BPUB Wizard ===

        1) New inscription pipeline (funding => reveal => sign)
        2) Reveal BPUB data
        3) Sign BPUB PSBTs
        4) Transfer BPUB ownership
        5) Decode reveal transaction
        6) Decode owner-transfer transaction
        0) Quit
        """
    )

    while True:
        print(menu)
        choice = input("Select an option: ").strip()
        if choice == "1":
            flow_new_inscription()
        elif choice == "2":
            flow_reveal()
        elif choice == "3":
            flow_sign_psbt()
        elif choice == "4":
            flow_ownertransfer()
        elif choice == "5":
            flow_check_reveal_tx()
        elif choice == "6":
            flow_decode_transfer_tx()
        elif choice == "0":
            print("Bye.")
            return
        else:
            print("Unknown choice, please try again.\n")


if __name__ == "__main__":
    main_menu()
