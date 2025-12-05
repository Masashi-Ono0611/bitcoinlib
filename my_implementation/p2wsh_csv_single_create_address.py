#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual P2WSH single-key timelock (CSV, relative) address example

This script constructs a P2WSH address whose witnessScript enforces a
relative locktime using OP_CHECKSEQUENCEVERIFY (CSV).

witnessScript (conceptually):

    <sequence> OP_CHECKSEQUENCEVERIFY OP_DROP <pubkey> OP_CHECKSIG

- The *funding transaction* that pays to this P2WSH address can be mined
  immediately.
- Any *spending transaction* must:
  - use an input sequence >= <sequence> (relative lock value)
  - and the UTXO must have enough confirmations for the relative lock
    to be satisfied, otherwise script evaluation will fail at CSV.

All inputs are CLI-based; no wallet DB is used.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from bitcoinlib.keys import Key, Address
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op


def read_key_and_sequence() -> tuple[Key, int]:
    """Read a single WIF key and a relative lock sequence (in blocks) from CLI.

    - WIF must be valid for Signet
    - sequence is interpreted as a simple relative lock in blocks (integer >= 0)
    """
    print("=== P2WSH CSV (single-key) - Key and Relative Lock ===")

    wif = input("WIF for signing key (Signet, required): ").strip()
    seq_str = input("Relative lock (blocks, e.g. 5): ").strip()

    if not wif or not seq_str:
        raise ValueError("Both WIF and relative lock sequence are required.")

    try:
        key = Key(import_key=wif, network="signet")
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"Invalid WIF: {e}") from e

    try:
        sequence = int(seq_str)
    except ValueError as e:  # noqa: BLE001
        raise ValueError(f"Relative lock sequence must be an integer (blocks): {e}") from e

    if sequence < 0:
        raise ValueError("Relative lock sequence (blocks) must be non-negative")

    print("[Key]")
    print(f"  WIF : {key.wif()}")
    print(f"  Pub : {key.public_hex}")
    print("[CSV Relative Lock]")
    print(f"  Blocks: {sequence}")

    return key, sequence


def build_csv_witness_script(key: Key, sequence: int) -> bytes:
    """Build a single-key CSV witnessScript.

    Conceptual script:

        <sequence> OP_CHECKSEQUENCEVERIFY OP_DROP <pubkey> OP_CHECKSIG

    - sequence is pushed as data (ScriptNum) so it is interpreted as a
      relative lock value by CSV.
    """
    pubkey_bytes = bytes.fromhex(key.public_hex)

    # For small integers 0..16, use OP_0 / OP_1..OP_16 to satisfy MINIMALDATA.
    # For larger values, encode as ScriptNum bytes and push as data.
    if sequence == 0:
        seq_cmd = op.op_0
    elif 1 <= sequence <= 16:
        # op_1, op_2, ..., op_16 are defined in bitcoinlib.config.opcodes.op
        seq_cmd = getattr(op, f"op_{sequence}")
    else:
        seq_cmd = sequence.to_bytes((sequence.bit_length() + 7) // 8 or 1, "little", signed=False)

    ws_obj = Script([seq_cmd, op.op_checksequenceverify, op.op_drop, pubkey_bytes, op.op_checksig])
    witness_script = ws_obj.serialize()

    print("\n=== CSV WitnessScript (single-key) ===")
    print(f"WitnessScript (hex): {witness_script.hex()}")
    print("WitnessScript (ASM-like):")
    print(f"  {sequence} OP_CHECKSEQUENCEVERIFY OP_DROP <pubkey> OP_CHECKSIG")

    return witness_script


def build_p2wsh_scriptpubkey_and_address(witness_script: bytes) -> tuple[str, str]:
    """Return (scriptPubKey_hex, p2wsh_address) for a native P2WSH CSV script on Signet.

    P2WSH ScriptPubKey:
      OP_0 <32-byte-SHA256(witness_script)>
    """
    ws_hash = hashlib.sha256(witness_script).digest()

    # Build P2WSH scriptPubKey: OP_0 <32-byte-hash>
    script = Script([op.op_0, ws_hash])
    scriptpubkey_hex = script.serialize().hex()

    # Build a bech32 P2WSH address from the witnessScript
    addr = Address(
        witness_script,
        script_type="p2wsh",
        encoding="bech32",
        network="signet",
    ).address

    print("\n=== P2WSH CSV Address (native, single-key) ===")
    print(f"P2WSH address        : {addr}")
    print(f"P2WSH scriptPubKey   : {scriptpubkey_hex}")
    print(f"SHA256(witnessScript): {ws_hash.hex()}")

    return scriptpubkey_hex, addr


def main() -> None:
    """Demo workflow for constructing a native P2WSH single-key CSV address on Signet.

    Steps:
      1. Read one WIF private key (no wallet DB)
      2. Read a relative lock value in blocks
      3. Build the CSV witnessScript
      4. Derive the corresponding native P2WSH scriptPubKey and address

    Next steps (separate script):
      - Fund this P2WSH address on Signet
      - After the required number of blocks has passed, manually construct and
        sign a spending transaction that satisfies the CSV condition.
    """
    print("=== P2WSH CSV (single-key) Address Demo ===\n")

    # Log creation timestamp so that you can later correlate the
    # approximate funding block height on a block explorer.
    now_utc = datetime.now(timezone.utc)
    print("[Creation Timestamp]")
    print(f"  UTC ISO8601 : {now_utc.isoformat()}")
    print(f"  Unix epoch  : {int(now_utc.timestamp())}")

    key, sequence = read_key_and_sequence()
    witness_script = build_csv_witness_script(key, sequence)
    build_p2wsh_scriptpubkey_and_address(witness_script)

    print("\n=== Demo Setup Complete ===")
    print("Send Signet coins to the P2WSH address above.")
    print("Only after the relative lock (in blocks) has passed will the spend script succeed.")


if __name__ == "__main__":
    main()
