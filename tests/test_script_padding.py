#!/usr/bin/env python3
"""
Tests for the multisig script padding and funding economics.

Covers:
  - a Python model of current relay-policy byte accounting for witness
    scripts, parameterized on its per-script tolerance
  - shape and size of the padding witness items
  - lenient multisig script parsing (none / padv1 / padv2 / unknown suffix)
  - reveal-share-aware funding output sizing
  - wizard-style SimpleNamespace callers (no argparse attributes)
  - real script execution of all script variants via python-bitcointx
    VerifyScript, including a 546-sat fund-then-reveal case (requires
    libsecp256k1)

Tests that need libsecp256k1 are skipped when no compatible library is
available. Point BPUB_SECP256K1_PATH at a compatible build (e.g. v0.3.x)
if the system one is too new for python-bitcointx.

Run:  python3 -m unittest discover -s tests -v
      python3 tests/test_script_padding.py
"""

import hashlib
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bitcointx

_secp_path = os.environ.get("BPUB_SECP256K1_PATH")
if _secp_path:
    bitcointx.set_custom_secp256k1_path(_secp_path)

from bitcointx.core.script import CScript  # noqa: E402

import bpub  # noqa: E402
from bpub import (  # noqa: E402
    BPUB_DUST,
    REVEAL_INPUT_VBYTES,
    build_multisig_script,
    build_stream_v5,
    bpub_output_values,
    chunk_data_pubkeys,
    decode_pubkeys_to_stream,
    decode_stream,
    encode_stream_to_pubkeys,
    estimate_fee_reveal,
    make_pad_items,
    parse_bpub_multisig,
    reveal_feerate_budget,
)

# ---------------------------------------------------------------------------
# Python model of current relay-policy byte accounting for witness scripts:
# which pushes count as keys, which named operations count as authorized,
# and which leftover pushes count as payload.
# ---------------------------------------------------------------------------

OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_RESERVED = 0x50
OP_1 = 0x51
OP_16 = 0x60
OP_IF = 0x63
OP_NOTIF = 0x64
OP_ENDIF = 0x68
OP_2DROP = 0x6D
OP_DROP = 0x75
OP_FALSE = 0x00
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF
OP_INVALIDOPCODE = 0xFF
# for the odd-push accounting
OP_NOP = 0x61
OP_NOP1 = 0xB0
OP_NOP10 = 0xB9
OP_CHECKLOCKTIMEVERIFY = 0xB1
OP_CHECKSEQUENCEVERIFY = 0xB2
OP_CODESEPARATOR = 0xAB
OP_RIPEMD160 = 0xA6
OP_SHA1 = 0xA7
OP_SHA256 = 0xA8
OP_HASH160 = 0xA9
OP_HASH256 = 0xAA
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
MAX_PUBKEYS_PER_MULTISIG = 20
# Per-script key tolerance in the relay model: originally 2, currently 10.
MAX_UNPROVEN_PUBKEYS_OLD = 2
MAX_UNPROVEN_PUBKEYS_NEW = 10
COMPRESSED_PUBKEY_SIZE = 33
POLICY_BUDGET_BYTES = 83


def get_op(script, pos):
    """Mimic CScript::GetOp. Returns (opcode, push_data, new_pos) or None."""
    if pos >= len(script):
        return None
    opcode = script[pos]
    pos += 1
    push = b""
    if opcode <= OP_PUSHDATA4:
        if opcode < OP_PUSHDATA1:
            size = opcode
        elif opcode == OP_PUSHDATA1:
            if pos + 1 > len(script):
                return None
            size = script[pos]
            pos += 1
        elif opcode == OP_PUSHDATA2:
            if pos + 2 > len(script):
                return None
            size = int.from_bytes(script[pos : pos + 2], "little")
            pos += 2
        else:
            if pos + 4 > len(script):
                return None
            size = int.from_bytes(script[pos : pos + 4], "little")
            pos += 4
        if pos + size > len(script):
            return None
        push = script[pos : pos + size]
        pos += size
    return opcode, push, pos


def small_int_value(opcode):
    if opcode < OP_1 or opcode > OP_16:
        return -1
    return opcode - (OP_1 - 1)


def multisig_count(opcode, push):
    small = small_int_value(opcode)
    if small > 0:
        return small
    if opcode == 1 and len(push) == 1 and 16 < push[0] <= MAX_PUBKEYS_PER_MULTISIG:
        return push[0]
    return -1


def is_pubkey_push(opcode, push):
    if opcode > OP_PUSHDATA4:
        return False
    return len(push) in (33, 65)


def is_run_push(opcode):
    return opcode <= OP_16 and opcode != OP_RESERVED


def count_witness_signatures(stack):
    count = 0
    for i in range(len(stack) - 1):
        if 64 <= len(stack[i]) <= 73:
            count += 1
    return count


def is_stack_neutral_nop(opcode):
    return opcode == OP_NOP or OP_NOP1 <= opcode <= OP_NOP10


def is_noop(opcode):
    return opcode == OP_CODESEPARATOR or (
        is_stack_neutral_nop(opcode)
        and opcode not in (OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY)
    )


def is_short_push(opcode, push):
    return opcode <= OP_PUSHDATA4 and len(push) <= 5


def is_odd_push(opcode, push, segwit_multisig):
    if opcode > OP_PUSHDATA4 or len(push) <= 5 or len(push) == 33:
        return False
    return segwit_multisig or len(push) != 65


def digest_size(opcode):
    if opcode in (OP_RIPEMD160, OP_SHA1, OP_HASH160):
        return 20
    if opcode in (OP_SHA256, OP_HASH256):
        return 32
    return 0


def odd_run_bytes(run_bytes, last_bytes, last_is_digest, next_op):
    if next_op in (OP_EQUAL, OP_EQUALVERIFY) and last_is_digest:
        return run_bytes - last_bytes
    if next_op in (OP_DROP, OP_2DROP):
        return 0
    return run_bytes


# ---------------------------------------------------------------------------
# Model of the relay policy that recognizes streams reassembled from the
# keys of same-control 1-of-N multisig inputs whose scripts end exactly at
# OP_CHECKMULTISIG, when the stream opens with a recognized header.
# ---------------------------------------------------------------------------

MAX_BLOCK_SERIALIZED_SIZE = 4_000_000


def is_bpub_header(head):
    if len(head) < 10:
        return False
    if head[:4] == b"BPUB":
        return head[4] == 1
    if head[4] not in (4, 5):
        return False
    body_len = int.from_bytes(head[0:4], "big")
    return (
        body_len >= 44
        and body_len <= MAX_BLOCK_SERIALIZED_SIZE
        and int.from_bytes(head[6:10], "big") == 0
    )


def bpub_bytes(tx_witness_stacks):
    """Port of policy.cpp BPUBBytes: count the script sizes of inputs whose
    witness ends in a 1-of-N multisig script (ending exactly at
    OP_CHECKMULTISIG) sharing a control key, when the stream opened by the
    data keys has a known BPUB header."""
    inputs = []
    for stack in tx_witness_stacks:
        if len(stack) < 2:
            continue
        script = bytes(stack[-1])
        res = get_op(script, 0)
        if res is None or res[0] != OP_1:
            continue
        pos = res[2]
        control = b""
        head = b""
        compressed_keys = True
        keys = 0
        parsed = True
        while True:
            res = get_op(script, pos)
            if res is None:
                parsed = False
                break
            opcode, push, pos = res
            if not (opcode > 0 and opcode <= OP_PUSHDATA4):
                break
            if keys and len(head) < 10 and len(control) > 2:
                take = min(10 - len(head), len(control) - 2)
                head += control[1 : 1 + take]
            compressed_keys = compressed_keys and len(push) == 33
            control = push
            keys += 1
        if not parsed or keys < 2 or opcode != 0x50 + keys:
            continue
        compressed_keys = compressed_keys and keys <= 16
        res = get_op(script, pos)
        if res is None or res[0] != OP_CHECKMULTISIG or res[2] != len(script):
            continue
        inputs.append(
            {
                "control": control,
                "head": head,
                "compressed_keys": compressed_keys,
                "bytes": len(script),
            }
        )

    inputs.sort(key=lambda i: i["control"])
    total = 0
    i = 0
    while i < len(inputs):
        j = i
        while j < len(inputs) and inputs[j]["control"] == inputs[i]["control"]:
            j += 1
        head = b""
        compressed_head = b""
        stream_bytes = 0
        for inp in inputs[i:j]:
            if len(head) < 10:
                head += inp["head"]
            if inp["compressed_keys"] and len(compressed_head) < 10:
                compressed_head += inp["head"]
            stream_bytes += inp["bytes"]
        if is_bpub_header(head) or is_bpub_header(compressed_head):
            total += stream_bytes
        i = j
    return total


def unproven_pubkey_bytes(
    script, witness_stack, max_unproven=MAX_UNPROVEN_PUBKEYS_OLD, verified_keys=None
):
    """Model of the key-accounting rule (including Knots v29.5.1 PR #470
    verified-key recounting), scoped to what P2WSH multisig scripts contain."""
    pubkeys = 0
    provable = 0
    unverified_bytes = 0
    push_run_unverified_bytes = 0
    run_keys = 0
    push_run_keys = 0
    run_opened_by = -1
    last_count = -1
    inside_noop = 0
    last_is_push = False
    last_opcode = OP_INVALIDOPCODE

    odd_bytes = 0
    odd_run = 0
    odd_last = 0
    odd_last_is_digest = False
    short_bytes = 0
    short_carried = False

    # prescan: does the script run OP_CHECKMULTISIG (outside envelopes)?
    has_multisig = False
    env = 0
    pos = 0
    last = OP_INVALIDOPCODE
    while pos < len(script):
        res = get_op(script, pos)
        if res is None:
            return 0
        op, _d, pos = res
        if env:
            if op in (OP_IF, OP_NOTIF):
                env += 1
            elif op == OP_ENDIF:
                env -= 1
        elif op == OP_IF and last == OP_FALSE:
            env = 1
        elif op in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
            has_multisig = True
        last = op
    segwit_multisig = has_multisig and bool(witness_stack)

    pos = 0
    while pos < len(script):
        res = get_op(script, pos)
        if res is None:
            return 0
        opcode, push, pos = res
        enveloped = inside_noop != 0
        is_pubkey = is_pubkey_push(opcode, push) and not (
            segwit_multisig and len(push) == 65
        )
        count = multisig_count(opcode, push)
        is_verified = verified_keys is not None and is_pubkey and push in verified_keys

        if inside_noop:
            if opcode in (OP_IF, OP_NOTIF):
                inside_noop += 1
            elif opcode == OP_ENDIF:
                inside_noop -= 1
        elif opcode == OP_IF and last_opcode == OP_FALSE:
            inside_noop = 1
        elif is_pubkey:
            if not run_keys:
                run_opened_by = last_count
            run_keys += 1
            push_run_keys += 1
            pubkeys += 1
            if not is_verified:
                push_run_unverified_bytes += len(push)
                unverified_bytes += len(push)
        elif opcode in (OP_DROP, OP_2DROP) and last_is_push:
            pubkeys -= push_run_keys
            unverified_bytes -= push_run_unverified_bytes
            run_keys = 0
        elif opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
            provable += 1
            run_keys = 0
        elif opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
            if run_opened_by > 0 and last_count > 0 and last_count == run_keys:
                provable += run_opened_by
            run_keys = 0
        elif count < 0:
            run_keys = 0

        is_push = is_run_push(opcode)
        if not is_push:
            push_run_keys = 0
            push_run_unverified_bytes = 0

        # odd-push accounting: only where the script runs
        # OP_CHECKMULTISIG, and never inside an OP_FALSE OP_IF envelope.
        if has_multisig and not enveloped:
            if is_push:
                if short_carried:
                    odd_bytes += short_bytes
                else:
                    odd_run += short_bytes
                short_bytes = (
                    len(push) if (is_short_push(opcode, push) and count < 0) else 0
                )
                short_carried = False
                odd_last = (
                    len(push) if is_odd_push(opcode, push, segwit_multisig) else 0
                )
                odd_last_is_digest = bool(odd_last) and digest_size(last_opcode) == len(push)
                odd_run += odd_last
            else:
                odd_bytes += odd_run_bytes(
                    odd_run, odd_last, odd_last_is_digest, opcode
                )
                odd_run = odd_last = 0
                odd_last_is_digest = False
                if is_noop(opcode):
                    short_carried = True
                else:
                    short_bytes = 0

        last_opcode = opcode
        last_count = count
        last_is_push = is_push

    if witness_stack:
        provable = min(provable, count_witness_signatures(witness_stack))

    if has_multisig:
        odd_bytes += odd_run_bytes(
            odd_run, odd_last, odd_last_is_digest, OP_INVALIDOPCODE
        )

    static_charge = (
        0
        if pubkeys < provable + max_unproven
        else (pubkeys - provable - max_unproven) * COMPRESSED_PUBKEY_SIZE
    ) + odd_bytes
    if verified_keys is None:
        return static_charge

    allowance = max_unproven * COMPRESSED_PUBKEY_SIZE
    verified_charge = (
        0 if unverified_bytes < allowance else unverified_bytes - allowance
    ) + odd_bytes
    return max(static_charge, verified_charge)


def pushrun_payload_bytes(script):
    """Bytes in push runs balanced by drops or inside constant-skipped
    envelopes, per the relay model."""
    counted = 0
    inside_noop = 0
    last_opcode = OP_INVALIDOPCODE
    data_began = None

    pos = 0
    it_start = 0
    while pos < len(script):
        res = get_op(script, pos)
        if res is None:
            break
        opcode_it = it_start
        opcode, _push, pos = res

        def is_push(op):
            return op <= OP_16 and op != OP_RESERVED

        if inside_noop:
            if opcode in (OP_IF, OP_NOTIF):
                inside_noop += 1
            elif opcode == OP_ENDIF:
                inside_noop -= 1
                if not inside_noop:
                    counted += pos - data_began
        elif opcode == OP_IF and last_opcode == OP_FALSE:
            inside_noop = 1
            data_began = opcode_it
        elif is_push(opcode):
            if not is_push(last_opcode):
                data_began = opcode_it
        elif opcode in (OP_DROP, OP_2DROP) and is_push(last_opcode):
            counted += pos - data_began

        last_opcode = opcode
        it_start = pos

    return counted


def strict_der_check(item):
    """Structural strict-DER check for a signature + sighash byte."""
    if len(item) < 9:
        return False
    der, sighash = item[:-1], item[-1]
    if sighash not in (1, 2, 3, 0x81, 0x82, 0x83):
        return False
    if der[0] != 0x30 or der[1] != len(der) - 2:
        return False
    if der[2] != 0x02:
        return False
    rlen = der[3]
    if rlen == 0 or 5 + rlen >= len(der):
        return False
    r = der[4 : 4 + rlen]
    if der[4 + rlen] != 0x02:
        return False
    slen = der[5 + rlen]
    if slen == 0 or 6 + rlen + slen != len(der):
        return False
    s = der[6 + rlen :]
    for v in (r, s):
        if v[0] == 0x00 and len(v) > 1 and not (v[1] & 0x80):
            return False  # non-minimal padding
        if v[0] & 0x80:
            return False  # negative
    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CONTROL_SECRET = hashlib.sha256(b"bpub test control key").digest()
SIG_STANDIN = b"\x30" + b"\x01" * 71  # 72 bytes, signature-sized


def make_scripts(data, version):
    """version: 0 = legacy 1-of-15 (no suffix), 1 = padv1, 2 = padv2, 3 = padv3 (1-of-11)."""
    stream = build_stream_v5(data, "application/octet-stream", "test.bin")
    data_pubkeys = encode_stream_to_pubkeys(stream)
    # A 33-byte stand-in control pubkey; parsing/encoding tests never verify it.
    control_pubkey = b"\x02" + b"\x11" * 32
    max_pk = (
        bpub.MAX_PUBKEYS_PER_SCRIPT
        if version == 3
        else bpub.MAX_PUBKEYS_PER_SCRIPT_LEGACY
    )
    chunks = list(chunk_data_pubkeys(data_pubkeys, max_pubkeys=max_pk))
    scripts = [
        bytes(build_multisig_script(c, control_pubkey, pad_suffix=version))
        for c in chunks
    ]
    return data_pubkeys, chunks, scripts


def secp256k1_available():
    try:
        from bitcointx.core.key import CKey

        CKey.from_secret_bytes(CONTROL_SECRET)
        return True
    except Exception:
        return False


SECP256K1 = secp256k1_available()
SECP_SKIP = "no compatible libsecp256k1 (set BPUB_SECP256K1_PATH)"

# wizard.py needs bip-utils and requests on top of python-bitcointx.
try:
    import wizard  # noqa: E402
except ImportError:
    wizard = None
WIZARD_SKIP = "wizard.py dependencies (bip-utils, requests) not installed"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class RelayModelTest(unittest.TestCase):
    def test_legacy_script_charged(self):
        _, _, scripts = make_scripts(os.urandom(500), 0)
        rs = scripts[0]  # full 15-key script
        stack = [b"", SIG_STANDIN, rs]
        # tolerance 2: (15-1-2)*33; tolerance 10:
        # (15-1-10)*33 — still over the 83-byte budget either way.
        self.assertEqual(
            unproven_pubkey_bytes(rs, stack, MAX_UNPROVEN_PUBKEYS_OLD), 396
        )
        self.assertEqual(
            unproven_pubkey_bytes(rs, stack, MAX_UNPROVEN_PUBKEYS_NEW), 132
        )
        self.assertGreater(132, POLICY_BUDGET_BYTES)

    def test_padded_script_free(self):
        for version in (1, 2):
            _, _, scripts = make_scripts(os.urandom(1000), version)
            for rs in scripts:
                stack = make_pad_items(rs) + [b"", SIG_STANDIN, rs]
                for tol in (MAX_UNPROVEN_PUBKEYS_OLD, MAX_UNPROVEN_PUBKEYS_NEW):
                    self.assertEqual(
                        unproven_pubkey_bytes(rs, stack, tol), 0, f"v{version}"
                    )
                self.assertEqual(pushrun_payload_bytes(rs), 0, f"v{version}")

    def test_padding_items_required(self):
        # sanity check: without the padding items the script is charged
        for version in (1, 2):
            _, _, scripts = make_scripts(os.urandom(500), version)
            rs = scripts[0]
            stack = [b"", SIG_STANDIN, rs]
            self.assertEqual(
                unproven_pubkey_bytes(rs, stack, MAX_UNPROVEN_PUBKEYS_OLD),
                396,
                f"v{version}",
            )

    def test_pad_count_boundary(self):
        # The witness cap tracks 64..73-byte items: each missing pad lowers
        # the credit. (Only the top pad is execution-checked; the model does
        # not care about lower pads' content, only their size.)
        _, _, scripts = make_scripts(os.urandom(500), 2)
        rs = scripts[0]
        pads = make_pad_items(rs)
        for n_pads, expected in ((13, 0), (3, 33), (2, 66), (1, 99), (0, 132)):
            stack = pads[:n_pads] + [b"", SIG_STANDIN, rs]
            self.assertEqual(
                unproven_pubkey_bytes(rs, stack, MAX_UNPROVEN_PUBKEYS_NEW),
                expected,
                f"n_pads={n_pads}",
            )

    def test_plain_1of11_within_tolerance(self):
        # At tolerance 10 a plain 1-of-11 multisig — 10 data keys, no
        # suffix, no padding items — is charged nothing by the key-accounting
        # rule. (The stream-recognition rule counts it anyway; see
        # test_plain_scripts_counted.)
        stream = build_stream_v5(os.urandom(500), "application/octet-stream", "")
        data_pubkeys = encode_stream_to_pubkeys(stream)
        control = b"\x02" + b"\x11" * 32
        rs = bytes(
            build_multisig_script(data_pubkeys[:10], control, pad_suffix=False)
        )
        stack = [b"", SIG_STANDIN, rs]
        self.assertEqual(unproven_pubkey_bytes(rs, stack, MAX_UNPROVEN_PUBKEYS_NEW), 0)
        # ... whereas tolerance 2 would have charged (11-1-2)*33 = 264.
        self.assertEqual(
            unproven_pubkey_bytes(rs, stack, MAX_UNPROVEN_PUBKEYS_OLD), 264
        )
        # 1-of-12 is charged 33 bytes per script, so only
        # two such inputs fit the budget.
        rs12 = bytes(
            build_multisig_script(data_pubkeys[:11], control, pad_suffix=False)
        )
        stack12 = [b"", SIG_STANDIN, rs12]
        self.assertEqual(
            unproven_pubkey_bytes(rs12, stack12, MAX_UNPROVEN_PUBKEYS_NEW), 33
        )

    def test_plain_scripts_counted(self):
        # A reveal tx spending plain 1-of-N BPUB scripts (ending exactly at
        # OP_CHECKMULTISIG) with one shared control key is counted in full.
        data = os.urandom(1000)
        _, _, scripts = make_scripts(data, 0)
        stacks = [[b"", SIG_STANDIN, rs] for rs in scripts]
        self.assertEqual(bpub_bytes(stacks), sum(len(s) for s in scripts))

    def test_padv3_free_under_verified_key_recount(self):
        # padv3 (1-of-11 + OP_1 OP_EQUAL, no padding witness items) passes both
        # static accounting and Knots v29.5.1 verified-key recounting (PR #470)
        # with 0 bytes charged, and skips BPUBBytes and push-drop checks.
        control = b"\x02" + b"\x11" * 32
        _, _, scripts = make_scripts(os.urandom(1000), 3)
        stacks = [[b"", SIG_STANDIN, rs] for rs in scripts]
        for rs, stack in zip(scripts, stacks):
            self.assertEqual(
                unproven_pubkey_bytes(rs, stack, MAX_UNPROVEN_PUBKEYS_NEW), 0
            )
            self.assertEqual(
                unproven_pubkey_bytes(
                    rs, stack, MAX_UNPROVEN_PUBKEYS_NEW, verified_keys={control}
                ),
                0,
            )
            self.assertEqual(pushrun_payload_bytes(rs), 0)
        self.assertEqual(bpub_bytes(stacks), 0)

    def test_padv2_charged_under_verified_key_recount(self):
        # Under Knots v29.5.1 (PR #470), padv2's 13 unexecuted OP_CHECKSIGs no
        # longer credit decoy keys: 14 unverified keys * 33 - 10 * 33 = 132 B.
        control = b"\x02" + b"\x11" * 32
        _, _, scripts = make_scripts(os.urandom(500), 2)
        rs = scripts[0]
        stack = make_pad_items(rs) + [b"", SIG_STANDIN, rs]
        self.assertEqual(
            unproven_pubkey_bytes(rs, stack, MAX_UNPROVEN_PUBKEYS_NEW), 0
        )
        self.assertEqual(
            unproven_pubkey_bytes(
                rs, stack, MAX_UNPROVEN_PUBKEYS_NEW, verified_keys={control}
            ),
            132,
        )

    def test_suffixed_scripts_skipped(self):
        # The suffixes mean the script does not end at OP_CHECKMULTISIG, so
        # the stream-recognition rule skips them entirely.
        for version in (1, 2, 3):
            _, _, scripts = make_scripts(os.urandom(1000), version)
            stacks = [
                (make_pad_items(rs) if version in (1, 2) else [])
                + [b"", SIG_STANDIN, rs]
                for rs in scripts
            ]
            self.assertEqual(bpub_bytes(stacks), 0, f"v{version}")

    def test_is_bpub_header(self):
        # Our own stream formats are recognized by the header check (the
        # v4/v5 header is structural, the XOR salt does not hide it).
        v5 = build_stream_v5(os.urandom(500), "application/octet-stream", "")
        self.assertTrue(is_bpub_header(v5[:10]))
        v35 = bpub.build_stream_v3_5(os.urandom(100), "text/plain", "")
        self.assertTrue(is_bpub_header(v35[:10]))
        self.assertFalse(is_bpub_header(b"\x00" * 32))

    def test_odd_push_controls(self):
        # Positive controls for the odd-push accounting.
        key = b"\x02" + b"\x22" * 32
        # A 40-byte blob in a CHECKMULTISIG script: an odd push, charged in
        # full outside the tolerance.
        script = (
            bytes([0x51, 0x21]) + key + bytes([0x28]) + b"\xaa" * 40
            + bytes([0x52, 0xAE])
        )
        stack = [b"", SIG_STANDIN, script]
        for tol in (MAX_UNPROVEN_PUBKEYS_OLD, MAX_UNPROVEN_PUBKEYS_NEW):
            self.assertEqual(unproven_pubkey_bytes(script, stack, tol), 40)
        # ...but a 32-byte push compared after OP_SHA256 is a hash-lock
        # digest and exempt.
        script2 = (
            bytes([0x51, 0x21]) + key + bytes([0x52, 0xAE, 0xA8, 0x20])
            + b"\xbb" * 32 + bytes([0x88])
        )
        stack2 = [b"", SIG_STANDIN, script2]
        for tol in (MAX_UNPROVEN_PUBKEYS_OLD, MAX_UNPROVEN_PUBKEYS_NEW):
            self.assertEqual(unproven_pubkey_bytes(script2, stack2, tol), 0)


class PadItemTest(unittest.TestCase):
    def test_items_shaped_and_sized(self):
        _, _, scripts = make_scripts(os.urandom(500), 2)
        items = make_pad_items(scripts[0])
        self.assertEqual(len(items), 13)
        for d in items:
            # exactly 64 bytes, strict-DER-shaped
            self.assertEqual(len(d), 64)
            self.assertTrue(strict_der_check(d), d.hex())

    def test_items_deterministic(self):
        _, _, scripts = make_scripts(os.urandom(500), 2)
        self.assertEqual(
            make_pad_items(scripts[0]), make_pad_items(scripts[0])
        )

    def test_items_golden_vector(self):
        # Pins the exact derivation (domain separator, sizes, masking) so an
        # accidental change is caught even though item content is arbitrary.
        items = make_pad_items(b"\x51" + b"\x02" * 33 + b"\x52\xae")
        self.assertEqual(
            items[0].hex(),
            "303d021c15b5f45032a7a7b3033b851e00aaa10fa4d9fe29541f3a05b38bc1da"
            "021d0163ef8fa6ecac919d7bba17ae8ed89c98592e0df9aa2f2ab8488f075201",
        )
        self.assertEqual(
            items[1].hex(),
            "303d021c17ad7fda1d2b71c50c057b9dc1df05534c6f09491c3f7a8f43d984f0"
            "021d71dd791715fb537102ff7968e0a6437e835e2573357964d333c029e17201",
        )
        self.assertEqual(len(items), 13)

    def test_guard_value_matches_item_size(self):
        # Protocol invariant: the v2 branch guard must assert the exact
        # padding item size. If a refactor ever separates the two, the guard
        # stops selecting the unexecuted branch and every v2 reveal fails.
        _, _, scripts = make_scripts(os.urandom(500), 2)
        elems = list(CScript(scripts[0]))
        idx = elems.index(bpub._OP_SIZE)
        guard = elems[idx + 1]
        self.assertIsInstance(guard, (bytes, bytearray))
        self.assertEqual(bytes(guard), bytes([bpub.PAD_ITEM_SIZE]))
        for d in make_pad_items(scripts[0]):
            self.assertEqual(len(d), bpub.PAD_ITEM_SIZE)


class ParseTest(unittest.TestCase):
    def test_roundtrip_all_variants(self):
        data = os.urandom(1000)
        for version, kind in ((0, "none"), (1, "padv1"), (2, "padv2"), (3, "padv3")):
            data_pubkeys, chunks, scripts = make_scripts(data, version)
            recovered = []
            for rs, chunk in zip(scripts, chunks):
                parsed = parse_bpub_multisig(rs)
                self.assertIsNotNone(parsed)
                dpk, cpk, suffix = parsed
                self.assertEqual(suffix, kind, f"version={version}")
                self.assertEqual(dpk, list(chunk))
                recovered.extend(dpk)
            meta, content = decode_stream(decode_pubkeys_to_stream(recovered))
            self.assertEqual(content, data)
            self.assertEqual(meta["size"], len(data))

    def test_unknown_suffix_lenient(self):
        for version, expected_keys in ((2, 14), (3, 10)):
            _, _, scripts = make_scripts(os.urandom(500), version)
            rs = scripts[0] + b"\x61"  # OP_NOP trailing
            parsed = parse_bpub_multisig(rs)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed[2], "unknown")
            self.assertEqual(len(parsed[0]), expected_keys)

    def test_rejects_non_bpub(self):
        self.assertIsNone(parse_bpub_multisig(b""))
        self.assertIsNone(parse_bpub_multisig(b"\x51\x21" + b"\x02" * 33))
        # op_n > OP_16 (e.g. 17 pushes + OP_NOP 0x61 + OP_CHECKMULTISIG) must not match.
        bogus = bytes([0x51]) + (bytes([0x21]) + b"\x02" * 33) * 17 + bytes([0x61, 0xAE])
        self.assertIsNone(parse_bpub_multisig(bogus))


class FundingEconomicsTest(unittest.TestCase):
    def test_values_above_dust_and_linear(self):
        for feerate in (1, 2, 5, 20):
            for n in (1, 2, 7, 26, 250):
                values = bpub_output_values(n, feerate)
                self.assertEqual(len(values), n)
                # Every output sits strictly above BPUB_DUST (546), so zero
                # outputs share a value <= 546.
                self.assertTrue(all(v > BPUB_DUST for v in values))
                # Sub-quadratic (linear O(n)) upfront capital: uniform values
                # with at most 1 sat/output over the dust floor (or 0 over the
                # reveal-share sizing).
                self.assertEqual(len(set(values)), 1)
                fixed_share = (
                    (bpub.REVEAL_BASE_VBYTES + 34) * feerate + BPUB_DUST + n - 1
                ) // n
                share = REVEAL_INPUT_VBYTES * feerate + fixed_share
                self.assertLessEqual(sum(values) - n * max(BPUB_DUST, share), n)

    def test_sized_outputs_cover_reveal(self):
        # A reveal at the funding feerate must always leave a non-dust change
        # output.
        for feerate in (1, 2, 5, 20):
            for n in (1, 2, 7, 26, 50, 250):
                values = bpub_output_values(n, feerate)
                fee = estimate_fee_reveal(n, 1, feerate, pad_suffix=True)
                change = sum(values) - fee
                self.assertGreaterEqual(
                    change,
                    BPUB_DUST,
                    f"feerate={feerate} n={n} change={change}",
                )

    def test_546_floor_case(self):
        # At 1 sat/vB with padv3 (175 vB/input), only n=1 is sized above the
        # 547-sat floor (855 sats); every multi-output reveal (n >= 2) sits
        # directly on the 547-sat floor.
        for n in range(1, 9):
            values = bpub_output_values(n, 1)
            if n == 1:
                self.assertGreater(min(values), BPUB_DUST + 1, f"n={n}")
            else:
                self.assertEqual(min(values), BPUB_DUST + 1, f"n={n}")
            change = sum(values) - estimate_fee_reveal(n, 1, 1)
            self.assertGreaterEqual(change, BPUB_DUST, f"n={n} change={change}")

    def test_override_exact(self):
        self.assertEqual(bpub_output_values(5, 1, bpub_value=1000), [1000] * 5)

    def test_reveal_feerate_budget_staggered(self):
        # Current bpub_output_values() is uniform (O(n)); reserved == ceiling.
        for feerate in (1, 2, 5, 20):
            for n in (1, 2, 8, 50, 250):
                values = bpub_output_values(n, feerate)
                reserved, ceiling = reveal_feerate_budget(values, pad_suffix=True)
                self.assertGreaterEqual(reserved, feerate)
                self.assertEqual(ceiling, reserved)

        # Earlier 1-sat-staggered fundings remain supported regardless of input
        # order: at n=400, 1 sat/vB, the stagger adds enough sats to raise the
        # dust ceiling above the reserved feerate.
        legacy_staggered = [BPUB_DUST + i for i in range(400)]
        reserved, ceiling = reveal_feerate_budget(legacy_staggered, pad_suffix=True)
        self.assertGreater(ceiling, reserved)
        self.assertEqual(
            reveal_feerate_budget(list(reversed(legacy_staggered)), pad_suffix=True),
            (reserved, ceiling),
        )

    def test_reveal_feerate_budget_unstaggered(self):
        # Uniform --bpub-value 546 (no stagger): 250 padv3 inputs (175 vB each)
        # cover 3 sat/vB (total_in=136500, total_vb=43884); must not subtract
        # phantom stagger.
        reserved, ceiling = reveal_feerate_budget([BPUB_DUST] * 250, pad_suffix=True)
        self.assertEqual((reserved, ceiling), (3, 3))

        # Uniform legacy 546-sat outputs (no stagger): 400 legacy inputs cover
        # 2 sat/vB (previously under-reported as 1 sat/vB).
        reserved, ceiling = reveal_feerate_budget([BPUB_DUST] * 400, pad_suffix=False)
        self.assertEqual((reserved, ceiling), (2, 2))

        # Arbitrary custom values (non-staggered) use their real total.
        reserved, ceiling = reveal_feerate_budget([BPUB_DUST, 50000], pad_suffix=True)
        self.assertEqual((reserved, ceiling), (103, 103))

    @unittest.skipUnless(SECP256K1, SECP_SKIP)
    def test_revealpsbt_no_spurious_warning_for_unstaggered_utxos(self):
        import contextlib
        import io
        import tempfile

        from bitcointx.wallet import P2WPKHBitcoinAddress

        # ~250 uniform 546-sat padv3 UTXOs at 1 sat/vB leave ample change and
        # must neither under-report nor emit a margin warning.
        payload = b"\x42" * 77_000
        stream = build_stream_v5(payload, "application/octet-stream", "big.bin")
        n_chunks = len(list(chunk_data_pubkeys(encode_stream_to_pubkeys(stream))))
        self.assertGreaterEqual(n_chunks, 245)

        control_pubkey = "02" + "11" * 32
        change_addr = str(
            P2WPKHBitcoinAddress.from_scriptPubKey(CScript([0, b"\x11" * 20]))
        )
        fake = "aa" * 32
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "big.bin")
            with open(path, "wb") as f:
                f.write(payload)
            args = SimpleNamespace(
                file=path,
                mime="application/octet-stream",
                filename="big.bin",
                compress=False,
                legacy_v3=False,
                v4=False,
                control_pubkey=control_pubkey,
                bpub_utxo=[f"{fake}:{i}:{BPUB_DUST}" for i in range(n_chunks)],
                change=change_addr,
                feerate=1,
                legacy_scripts=False,
            )
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                bpub.cmd_revealpsbt(args)

        self.assertTrue(out_buf.getvalue().strip())
        err = err_buf.getvalue()
        self.assertIn("reserve ~3 sat/vB", err)
        self.assertNotIn("WARNING: requested feerate exceeds", err)


class WizardNamespaceTest(unittest.TestCase):
    @unittest.skipUnless(SECP256K1, SECP_SKIP)
    def test_revealpsbt_without_new_attrs(self):
        # wizard.py builds args via SimpleNamespace; it must not need the
        # new argparse attributes (getattr defaults).
        import contextlib
        import io
        import tempfile

        from bitcointx.core.key import CKey
        from bitcointx.wallet import P2WPKHBitcoinAddress

        payload = os.urandom(400)
        key = CKey.from_secret_bytes(CONTROL_SECRET)
        change = CKey.from_secret_bytes(hashlib.sha256(b"change").digest())
        change_addr = str(P2WPKHBitcoinAddress.from_pubkey(change.pub))
        fake = "aa" * 32
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wizard_test.bin")
            with open(path, "wb") as f:
                f.write(payload)
            args = SimpleNamespace(
                file=path,
                mime="application/octet-stream",
                filename="",
                compress=False,
                legacy_v3=False,
                v4=False,
                control_pubkey=bytes(key.pub).hex(),
                bpub_utxo=[f"{fake}:0:2000", f"{fake}:1:2000"],
                change=change_addr,
                feerate=1,
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(
                io.StringIO()
            ):
                bpub.cmd_revealpsbt(args)
        self.assertTrue(buf.getvalue().strip())


class WizardRevealValuesTest(unittest.TestCase):
    """
    The wizard must feed revealpsbt the real funded value of every BPUB
    data output. Funding outputs are sized for the reveal fee (floored at
    547 sats), so assuming 546 sats either trips the change-is-dust check
    or (worse) produces BIP143 signatures committing to the wrong amount.
    """

    FUND_TXID = "bb" * 32

    def _fund(self, tmpdir, size, feerate=1):
        from bitcointx.core.key import CKey
        from bitcointx.core.psbt import PartiallySignedTransaction as PSBT
        from bitcointx.wallet import P2WPKHBitcoinAddress

        import contextlib
        import io

        path = os.path.join(tmpdir, "payload.bin")
        with open(path, "wb") as f:
            f.write(os.urandom(size))
        key = CKey.from_secret_bytes(CONTROL_SECRET)
        other = CKey.from_secret_bytes(hashlib.sha256(b"change").digest())
        addr = str(P2WPKHBitcoinAddress.from_pubkey(other.pub))
        common = dict(
            file=path,
            mime="application/octet-stream",
            filename="payload.bin",
            compress=False,
            legacy_v3=False,
            v4=False,
            control_pubkey=bytes(key.pub).hex(),
            change=addr,
            feerate=feerate,
            legacy_scripts=False,
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(
            io.StringIO()
        ):
            bpub.cmd_fundpsbt(
                SimpleNamespace(
                    owner_address=addr,
                    utxo=f"{'aa' * 32}:0",
                    value=1_000_000,
                    prev_address=addr,
                    prev_spk=None,
                    **common,
                )
            )
        fund_tx = PSBT.from_base64(buf.getvalue().strip()).unsigned_tx
        return key, common, fund_tx

    def _reveal_and_verify(self, key, common, fund_tx, bpub_utxos):
        import contextlib
        import io

        from bitcointx.core import CTransaction, x
        from bitcointx.core.scripteval import (
            VerifyScript,
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
        )
        from bitcointx.wallet import CBitcoinSecret

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

        def run(cmd, args):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(
                io.StringIO()
            ):
                cmd(args)
            return buf.getvalue().strip()

        reveal_psbt = run(
            bpub.cmd_revealpsbt, SimpleNamespace(bpub_utxo=bpub_utxos, **common)
        )
        wif = str(CBitcoinSecret.from_secret_bytes(key.secret_bytes))
        raw_hex = run(
            bpub.cmd_signreveal,
            SimpleNamespace(
                psbt=reveal_psbt, wif=wif, control_pubkey=common["control_pubkey"]
            ),
        )
        tx = CTransaction.deserialize(x(raw_hex))
        self.assertEqual(len(tx.vin), len(bpub_utxos))
        # Verify every input against the REAL funding output it spends.
        for idx, txin in enumerate(tx.vin):
            prevout = fund_tx.vout[txin.prevout.n]
            VerifyScript(
                CScript(b""),
                prevout.scriptPubKey,
                tx,
                idx,
                flags=flags,
                amount=prevout.nValue,
                witness=tx.wit.vtxinwit[idx].scriptWitness,
            )

    @unittest.skipUnless(SECP256K1, SECP_SKIP)
    @unittest.skipUnless(wizard is not None, WIZARD_SKIP)
    def test_wizard_values_sign_validly(self):
        import tempfile

        from bitcointx.core.scripteval import VerifyScriptError

        # (payload size, expected data outputs): n=1 is sized above the
        # 547-sat floor (855 sats); n=8 sits on the 547-sat floor (still != 546).
        for size, n, expected_err in (
            (100, 1, SystemExit),
            (2200, 8, VerifyScriptError),
        ):
            with self.subTest(n=n), tempfile.TemporaryDirectory() as tmp:
                key, common, fund_tx = self._fund(tmp, size)
                self.assertEqual(len(fund_tx.vout), n + 2)
                expected = bpub_output_values(n, 1)
                self.assertEqual(
                    [o.nValue for o in fund_tx.vout[:n]], expected
                )

                utxos = wizard.bpub_utxos_from_tx(
                    fund_tx, self.FUND_TXID, 0, n - 1
                )
                self.assertEqual(
                    utxos,
                    [f"{self.FUND_TXID}:{i}:{v}" for i, v in enumerate(expected)],
                )
                self._reveal_and_verify(key, common, fund_tx, utxos)

                # The old behaviour (546 for every output) must not verify.
                assumed = [f"{self.FUND_TXID}:{i}:{BPUB_DUST}" for i in range(n)]
                with self.assertRaises(expected_err):
                    self._reveal_and_verify(key, common, fund_tx, assumed)

    @unittest.skipUnless(wizard is not None, WIZARD_SKIP)
    def test_utxos_from_tx_range_checked(self):
        tx = SimpleNamespace(
            vout=[SimpleNamespace(nValue=v) for v in (790, 791, 10000, 5000)]
        )
        self.assertEqual(
            wizard.bpub_utxos_from_tx(tx, "ab", 0, 1), ["ab:0:790", "ab:1:791"]
        )
        with self.assertRaises(ValueError):
            wizard.bpub_utxos_from_tx(tx, "ab", 0, 4)

    @unittest.skipUnless(wizard is not None, WIZARD_SKIP)
    def test_utxos_from_mempool(self):
        import contextlib
        import io
        from unittest import mock

        def lookup(response, start, end):
            with mock.patch.object(
                wizard, "fetch_tx_from_mempool", return_value=response
            ), contextlib.redirect_stdout(io.StringIO()):
                return wizard.bpub_utxos_from_mempool("ab", start, end)

        tx = {"vout": [{"value": 546}, {"value": 547}, {"value": 10000}]}
        self.assertEqual(lookup(tx, 0, 1), ["ab:0:546", "ab:1:547"])
        # Lookup failure, out-of-range and malformed values never fall
        # back to an assumed value.
        self.assertIsNone(lookup(None, 0, 1))
        self.assertIsNone(lookup(tx, 0, 3))
        self.assertIsNone(lookup({"vout": [{"value": None}]}, 0, 0))
        self.assertIsNone(lookup({"vout": [{}]}, 0, 0))


class ScriptExecutionTest(unittest.TestCase):
    @unittest.skipUnless(SECP256K1, SECP_SKIP)
    def test_fund_then_reveal_546(self):
        # Full execution of a reveal spending 546-sat funding outputs,
        # for both script variants.
        from bitcointx.core import (
            lx,
            COutPoint,
            CMutableTxIn,
            CMutableTxOut,
            CMutableTransaction,
            CTransaction,
        )
        from bitcointx.core.key import CKey
        from bitcointx.core.script import (
            CScript as BCScript,
            CScriptWitness,
            SignatureHash,
            SIGHASH_ALL,
            SIGVERSION_WITNESS_V0,
        )
        from bitcointx.core.scripteval import (
            VerifyScript,
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
        )

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

        import contextlib
        import io
        from bitcointx.core.psbt import PartiallySignedTransaction as PSBT
        from bitcointx.core import CTxOut
        from bitcointx.wallet import CBitcoinSecret
        import indexer

        key = CKey.from_secret_bytes(CONTROL_SECRET)
        control_pubkey = bytes(key.pub)
        wif = str(CBitcoinSecret.from_secret_bytes(key.secret_bytes))

        for version, expected_kind in (
            (0, "none"),
            (1, "padv1"),
            (2, "padv2"),
            (3, "padv3"),
        ):
            data = os.urandom(600)
            stream = build_stream_v5(data, "application/octet-stream", "t.bin")
            data_pubkeys = encode_stream_to_pubkeys(stream)
            max_pk = (
                bpub.MAX_PUBKEYS_PER_SCRIPT
                if version == 3
                else bpub.MAX_PUBKEYS_PER_SCRIPT_LEGACY
            )
            chunks = list(chunk_data_pubkeys(data_pubkeys, max_pubkeys=max_pk))
            self.assertGreaterEqual(len(chunks), 2)
            scripts = [
                build_multisig_script(c, control_pubkey, pad_suffix=version)
                for c in chunks
            ]
            spks = [bpub.p2wsh_scriptpubkey(rs) for rs in scripts]
            values = [BPUB_DUST + 1] * len(scripts)

            fund = CMutableTransaction(
                [CMutableTxIn(COutPoint(lx("00" * 32), 0))],
                [CMutableTxOut(v, BCScript(spk)) for v, spk in zip(values, spks)],
            )
            reveal = CMutableTransaction(
                [CMutableTxIn(COutPoint(fund.GetTxid(), i)) for i in range(len(scripts))],
                [
                    CMutableTxOut(
                        sum(values) - 450 * len(scripts),
                        BCScript(b"\x00\x14" + b"\x11" * 20),
                    )
                ],
            )
            psbt = PSBT(unsigned_tx=reveal)
            for idx, (rs, spk, val) in enumerate(zip(scripts, spks, values)):
                psbt.set_utxo(CTxOut(val, BCScript(spk)), idx, force_witness_utxo=True)
                psbt.inputs[idx].witness_script = rs

            out_buf = io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(
                io.StringIO()
            ):
                bpub.cmd_signreveal(
                    SimpleNamespace(
                        psbt=psbt.to_base64(),
                        wif=wif,
                        control_pubkey=control_pubkey.hex(),
                    )
                )
            raw_hex = out_buf.getvalue().strip()
            final_tx = CTransaction.deserialize(bytes.fromhex(raw_hex))

            for idx in range(len(scripts)):
                wit = final_tx.wit.vtxinwit[idx].scriptWitness
                # padv3 and none carry no padding witness items (3 stack items);
                # legacy padv1/padv2 carry 13 pad items (16 stack items).
                expected_items = 16 if version in (1, 2) else 3
                self.assertEqual(len(wit.stack), expected_items, f"v{version}")
                VerifyScript(
                    BCScript(b""),
                    BCScript(spks[idx]),
                    final_tx,
                    idx,
                    flags=flags,
                    amount=values[idx],
                    witness=wit,
                )

            # Indexer must recognize and extract every variant, including padv3.
            extracted = indexer.try_extract_bpub_from_tx(raw_hex)
            self.assertIsNotNone(extracted, f"indexer missed v{version}")
            meta, content = extracted
            self.assertEqual(content, data, f"indexer content mismatch v{version}")
            self.assertEqual(meta["script_suffix"], expected_kind)

        # signreveal must refuse an unknown suffix rather than guess a witness.
        rs_unknown = BCScript(bytes(scripts[0]) + b"\x61")
        spk_unknown = bpub.p2wsh_scriptpubkey(rs_unknown)
        tx_u = CMutableTransaction(
            [CMutableTxIn(COutPoint(lx("11" * 32), 0))],
            [CMutableTxOut(546, BCScript(b"\x00\x14" + b"\x11" * 20))],
        )
        psbt_u = PSBT(unsigned_tx=tx_u)
        psbt_u.set_utxo(CTxOut(2000, BCScript(spk_unknown)), 0, force_witness_utxo=True)
        psbt_u.inputs[0].witness_script = rs_unknown
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            bpub.cmd_signreveal(
                SimpleNamespace(
                    psbt=psbt_u.to_base64(),
                    wif=wif,
                    control_pubkey=control_pubkey.hex(),
                )
            )


class IndexerHardeningTest(unittest.TestCase):
    def test_decompression_bomb_rejected(self):
        # Content exceeding MAX_CONTENT_DECOMPRESSED_BYTES must be rejected
        # without inflating past the cap.
        big_plain = b"\x00" * (bpub.MAX_CONTENT_DECOMPRESSED_BYTES + 4096)
        big_deflated = bpub._raw_deflate(big_plain)
        with self.assertRaises(ValueError):
            bpub._raw_inflate(big_deflated)

        # Metadata exceeding MAX_META_DECOMPRESSED_BYTES must be dropped cleanly.
        big_meta = bpub._raw_deflate(b'{"filename":"' + b"a" * (bpub.MAX_META_DECOMPRESSED_BYTES + 100) + b'"}')
        content = b"hello"
        body = bytearray()
        body.append(5)
        body.append(0x02)
        body.extend(len(content).to_bytes(8, "big"))
        body.extend(hashlib.sha256(content).digest())
        meta_enc = bpub._xor_obfuscate(big_meta)
        body.extend(len(meta_enc).to_bytes(2, "big"))
        body.extend(meta_enc)
        body.extend(bpub._xor_obfuscate(content))
        stream = len(body).to_bytes(4, "big") + bytes(body)
        meta, recovered = decode_stream(stream)
        self.assertEqual(recovered, content)
        self.assertNotIn("filename", meta)

        # Header claiming > MAX_CONTENT_DECOMPRESSED_BYTES is rejected up front.
        fake_size = bpub.MAX_CONTENT_DECOMPRESSED_BYTES + 1
        bad_body = (
            bytes([5, 0x01])
            + fake_size.to_bytes(8, "big")
            + b"\x00" * 32
            + (0).to_bytes(2, "big")
            + bpub._xor_obfuscate(big_deflated)
        )
        with self.assertRaises(ValueError):
            decode_stream(len(bad_body).to_bytes(4, "big") + bad_body)

    def test_canonical_bpub_id_and_string_meta_types(self):
        import json

        content = b"canonical test payload"
        forged_meta = json.dumps(
            {
                "bpub_id": "ff" * 32,
                "filename": 12345,
                "mime": ["image/png"],
            }
        ).encode("utf-8")
        meta_enc = bpub._xor_obfuscate(bpub._raw_deflate(forged_meta))
        body = (
            bytes([5, 0x02])
            + len(content).to_bytes(8, "big")
            + hashlib.sha256(content).digest()
            + len(meta_enc).to_bytes(2, "big")
            + meta_enc
            + bpub._xor_obfuscate(content)
        )
        meta, recovered = decode_stream(len(body).to_bytes(4, "big") + body)
        self.assertEqual(recovered, content)
        self.assertEqual(meta["bpub_id"], bpub.compute_bpub_v5_id(content))
        self.assertNotIn("filename", meta)
        self.assertNotIn("mime", meta)

    def test_safe_stored_filenames(self):
        import indexer

        txid = "ab" * 32
        for fname, mime in (
            ("x.html", "text/html"),
            ("x.svg", "image/svg+xml"),
            ("evil.html.svg", "image/svg+xml"),
            ("script.js", "application/javascript"),
            ("../../../etc/passwd", "application/octet-stream"),
            ("..", None),
            (12345, ["bad"]),
            ("a" * 500 + ".png", "image/png"),
        ):
            stored = indexer.make_stored_filename(txid, fname, mime)
            self.assertLessEqual(len(stored), 200, stored)
            self.assertNotIn("/", stored)
            self.assertNotIn("..", stored)
            ext = os.path.splitext(stored)[1].lower()
            self.assertIn(ext, indexer.SAFE_EXTENSIONS, stored)
            self.assertNotIn(ext, (".html", ".svg", ".js"))

        self.assertTrue(
            indexer.make_stored_filename(txid, "pic.jpg", "image/jpeg").endswith(".jpg")
        )
        self.assertTrue(
            indexer.make_stored_filename(txid, "photo", "image/png").endswith(".png")
        )

    def test_ownership_chain_of_custody(self):
        from bitcointx.core import (
            lx,
            COutPoint,
            CMutableTxIn,
            CMutableTxOut,
            CMutableTransaction,
        )
        from bitcointx.core.script import CScript as BCScript, CScriptWitness
        from bitcointx.wallet import P2WPKHBitcoinAddress, P2WSHBitcoinAddress
        import indexer

        bpub_id = bpub.compute_bpub_v5_id(b"owned-art")
        bpub_id_hex = bpub_id.hex()
        alice_h160 = b"\x11" * 20
        bob_h160 = b"\x22" * 20
        eve_h160 = b"\x33" * 20

        alice_rs = bytes(bpub.build_owner_redeem_script(bpub_id, alice_h160))
        bob_rs = bytes(bpub.build_owner_redeem_script(bpub_id, bob_h160))
        eve_rs = bytes(bpub.build_owner_redeem_script(bpub_id, eve_h160))

        alice_spk = bpub.p2wsh_scriptpubkey(BCScript(alice_rs))
        bob_spk = bpub.p2wsh_scriptpubkey(BCScript(bob_rs))
        eve_spk = bpub.p2wsh_scriptpubkey(BCScript(eve_rs))

        alice_p2wpkh = str(
            P2WPKHBitcoinAddress.from_scriptPubKey(BCScript(b"\x00\x14" + alice_h160))
        )
        bob_p2wpkh = str(
            P2WPKHBitcoinAddress.from_scriptPubKey(BCScript(b"\x00\x14" + bob_h160))
        )
        bob_p2wsh = str(P2WSHBitcoinAddress.from_scriptPubKey(BCScript(bob_spk)))

        def make_owner_tx(prev_txid, prev_vout, input_rs, out_spk):
            tx = CMutableTransaction(
                [CMutableTxIn(COutPoint(lx(prev_txid), prev_vout))],
                [CMutableTxOut(9000, BCScript(out_spk))],
            )
            tx.wit.vtxinwit[0].scriptWitness = CScriptWitness(
                [b"\x30" * 70, b"\x02" * 33, input_rs]
            )
            return tx.serialize(include_witness=True).hex()

        ownership = {}
        funding_txid = "10" * 32
        bogus_txid = "99" * 32

        # Unknown bpub_id cannot be pre-registered via owner spend.
        eve_tx = make_owner_tx(bogus_txid, 0, eve_rs, eve_spk)
        self.assertFalse(
            indexer.apply_owner_update(
                ownership,
                indexer.try_extract_owner_from_tx(eve_tx),
                "e1" * 32,
                100,
                "bh",
                1,
            )
        )

        # Register genesis reveal anchored to funding_txid.
        self.assertTrue(
            indexer.register_bpub_genesis(ownership, bpub_id_hex, [funding_txid])
        )

        # Eve's spend from an unrelated txid must be rejected.
        self.assertFalse(
            indexer.apply_owner_update(
                ownership,
                indexer.try_extract_owner_from_tx(eve_tx),
                "e2" * 32,
                101,
                "bh",
                2,
            )
        )

        # Alice's genesis self-transfer from funding_txid succeeds.
        t1_txid = "a1" * 32
        t1_hex = make_owner_tx(funding_txid, 3, alice_rs, alice_spk)
        self.assertTrue(
            indexer.apply_owner_update(
                ownership,
                indexer.try_extract_owner_from_tx(t1_hex),
                t1_txid,
                102,
                "bh",
                3,
            )
        )
        self.assertEqual(ownership[bpub_id_hex]["current_owner_p2wpkh"], alice_p2wpkh)
        self.assertEqual(ownership[bpub_id_hex]["current_outpoint"], f"{t1_txid}:0")

        # Eve still cannot hijack after genesis by spending a different outpoint.
        self.assertFalse(
            indexer.apply_owner_update(
                ownership,
                indexer.try_extract_owner_from_tx(eve_tx),
                "e3" * 32,
                103,
                "bh",
                4,
            )
        )

        # Alice transfers to Bob (T1:0 -> Bob's P2WSH): current_owner_p2wpkh
        # clears (no longer Alice) and tracks Bob's P2WSH + outpoint T2:0.
        t2_txid = "b2" * 32
        t2_hex = make_owner_tx(t1_txid, 0, alice_rs, bob_spk)
        self.assertTrue(
            indexer.apply_owner_update(
                ownership,
                indexer.try_extract_owner_from_tx(t2_hex),
                t2_txid,
                104,
                "bh",
                5,
            )
        )
        self.assertIsNone(ownership[bpub_id_hex]["current_owner_p2wpkh"])
        self.assertEqual(ownership[bpub_id_hex]["current_owner_p2wsh"], bob_p2wsh)
        self.assertEqual(ownership[bpub_id_hex]["current_outpoint"], f"{t2_txid}:0")

        # Bob self-transfers T2:0 -> T3:0, revealing Bob's P2WPKH as current owner.
        t3_txid = "b3" * 32
        t3_hex = make_owner_tx(t2_txid, 0, bob_rs, bob_spk)
        self.assertTrue(
            indexer.apply_owner_update(
                ownership,
                indexer.try_extract_owner_from_tx(t3_hex),
                t3_txid,
                105,
                "bh",
                6,
            )
        )
        self.assertEqual(ownership[bpub_id_hex]["current_owner_p2wpkh"], bob_p2wpkh)
        self.assertEqual(ownership[bpub_id_hex]["current_outpoint"], f"{t3_txid}:0")


if __name__ == "__main__":
    unittest.main()
