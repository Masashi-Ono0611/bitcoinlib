#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual P2WSH single-key timelock (CLTV) address example

This script constructs a P2WSH address whose witnessScript enforces an
absolute locktime using OP_CHECKLOCKTIMEVERIFY (CLTV).

witnessScript (conceptually):

    <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG

- The *funding transaction* that pays to this P2WSH address can be mined
  immediately.
- Any *spending transaction* must:
  - set nLockTime >= <locktime>
  - have at least one input with sequence < 0xffffffff
  or script evaluation will fail at CLTV.

All inputs are CLI-based; no wallet DB is used.
"""

from __future__ import annotations

import hashlib

from bitcoinlib.keys import Key, Address
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op


def read_key_and_locktime() -> tuple[Key, int]:
    """Read a single WIF key and an absolute locktime (block height) from CLI.

    - WIF must be valid for Signet
    - locktime is interpreted as a block height (integer >= 0)
    """
    print("=== P2WSH CLTV (single-key) - Key and Locktime ===")

    wif = input("WIF for signing key (Signet, required): ").strip()
    locktime_str = input("Absolute locktime (block height, e.g. 281350): ").strip()

    if not wif or not locktime_str:
        raise ValueError("Both WIF and locktime are required.")

    try:
        key = Key(import_key=wif, network="signet")
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"Invalid WIF: {e}") from e

    try:
        locktime = int(locktime_str)
    except ValueError as e:  # noqa: BLE001
        raise ValueError(f"Locktime must be an integer block height: {e}") from e

    if locktime < 0:
        raise ValueError("Locktime (block height) must be non-negative")

    print("[Key]")
    print(f"  WIF : {key.wif()}")
    print(f"  Pub : {key.public_hex}")
    print("[Locktime]")
    print(f"  Height: {locktime}")

    return key, locktime


def build_cltv_witness_script(key: Key, locktime: int) -> bytes:
    """Build a single-key CLTV witnessScript.

    Conceptual script:

        <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG

    - locktime is pushed as a ScriptNum (bitcoinlib Script will handle int → pushdata)
    - CLTV checks tx.nLockTime against this value
    - OP_DROP removes the locktime from the stack before CHECKSIG
    """
    pubkey_bytes = bytes.fromhex(key.public_hex)

    # Encode locktime as data (ScriptNum) so it is pushed onto the stack,
    # not interpreted as an opcode value.
    # Minimal little-endian encoding is sufficient for this educational demo.
    locktime_bytes = locktime.to_bytes((locktime.bit_length() + 7) // 8 or 1, "little", signed=False)

    # Order: <locktime>, CLTV, DROP, <pubkey>, CHECKSIG
    ws_obj = Script([locktime_bytes, op.op_checklocktimeverify, op.op_drop, pubkey_bytes, op.op_checksig])
    witness_script = ws_obj.serialize()

    print("\n=== CLTV WitnessScript (single-key) ===")
    print(f"WitnessScript (hex): {witness_script.hex()}")
    print("WitnessScript (ASM-like):")
    print(f"  {locktime} OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG")

    return witness_script


def build_p2wsh_scriptpubkey_and_address(witness_script: bytes) -> tuple[str, str]:
    """Return (scriptPubKey_hex, p2wsh_address) for a native P2WSH CLTV script on Signet.

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

    print("\n=== P2WSH CLTV Address (native, single-key) ===")
    print(f"P2WSH address        : {addr}")
    print(f"P2WSH scriptPubKey   : {scriptpubkey_hex}")
    print(f"SHA256(witnessScript): {ws_hash.hex()}")

    return scriptpubkey_hex, addr


def main() -> None:
    """Demo workflow for constructing a native P2WSH single-key CLTV address on Signet.

    Steps:
      1. Read one WIF private key (no wallet DB)
      2. Read an absolute block-height locktime
      3. Build the CLTV witnessScript
      4. Derive the corresponding native P2WSH scriptPubKey and address

    Next steps (separate script):
      - Fund this P2WSH address on Signet
      - After the specified height is reached, manually construct and sign a spending
        transaction that satisfies the CLTV condition.
    """
    print("=== P2WSH CLTV (single-key) Address Demo ===\n")

    key, locktime = read_key_and_locktime()
    witness_script = build_cltv_witness_script(key, locktime)
    build_p2wsh_scriptpubkey_and_address(witness_script)

    print("\n=== Demo Setup Complete ===")
    print("Send Signet coins to the P2WSH address above.")
    print("Only after the specified block height will the spend script succeed.")


if __name__ == "__main__":
    main()
