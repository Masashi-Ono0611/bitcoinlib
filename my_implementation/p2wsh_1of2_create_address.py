#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual P2WSH Multisig (1-of-2) Address Example

This script is the SegWit (P2WSH) counterpart of `p2sh_1of2_create_address.py`.

It demonstrates how to:
- Construct a 1-of-2 multisig *witnessScript* from two WIF private keys
- Derive the corresponding **native P2WSH** address on Bitcoin Signet
- Show the P2WSH scriptPubKey (locking script): OP_0 <32-byte SHA256(witnessScript)>

No wallet DB is used; everything is driven by CLI WIF input.
"""

from __future__ import annotations

from bitcoinlib.keys import Key, Address
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op
from bitcoinlib.encoding import varstr
import hashlib


def create_multisig_keys_from_wif() -> tuple[Key, Key]:
    """Read two WIF private keys from CLI and return Key objects for Signet.

    - Two WIFs are required
    - No wallet/DB access is performed
    - If either WIF is invalid, the function raises and stops
    """
    print("=== Multisig Keys (1-of-2, P2WSH) ===")

    wif1 = input("WIF for Key 1 (required): ").strip()
    wif2 = input("WIF for Key 2 (required): ").strip()

    if not wif1 or not wif2:
        raise ValueError("Both WIFs are required for Key 1 and Key 2.")

    try:
        key1 = Key(import_key=wif1, network="signet")
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"Invalid WIF for Key 1: {e}") from e

    try:
        key2 = Key(import_key=wif2, network="signet")
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"Invalid WIF for Key 2: {e}") from e

    print("[Key 1]")
    print(f"  WIF : {key1.wif()}")
    print(f"  Pub : {key1.public_hex}")
    print("[Key 2]")
    print(f"  WIF : {key2.wif()}")
    print(f"  Pub : {key2.public_hex}")

    return key1, key2


def build_witness_script_1of2(key1: Key, key2: Key) -> bytes:
    """Build the 1-of-2 multisig witnessScript from the two provided keys.

    WitnessScript format (standard 1-of-2):
      OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG

    This is structurally identical to the legacy P2SH redeemScript, but in
    P2WSH it lives in the witness instead of scriptSig.
    """
    # Order of public keys matters; for demo we use [key1, key2] as-is
    ws_obj = Script(keys=[key1, key2], sigs_required=1, script_types=["multisig"])
    witness_script = ws_obj.serialize()

    print("\n=== WitnessScript (1-of-2) ===")
    print(f"WitnessScript (hex): {witness_script.hex()}")

    # Also show the script as pushes for intuition
    print("WitnessScript (ASM-like):")
    # Simple decode: OP_1 <pub1> <pub2> OP_2 OP_CHECKMULTISIG
    print("  OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG")

    return witness_script


def build_p2wsh_scriptpubkey_and_address(witness_script: bytes) -> tuple[str, str]:
    """Return (scriptPubKey_hex, p2wsh_address) for a native P2WSH 1-of-2 multisig on signet.

    P2WSH ScriptPubKey:
      OP_0 <32-byte-SHA256(witness_script)>
    """
    # 32-byte SHA256 of the witnessScript
    ws_hash = hashlib.sha256(witness_script).digest()

    # Build P2WSH scriptPubKey: OP_0 <32-byte-hash>
    script = Script([op.op_0, ws_hash])
    scriptpubkey_hex = script.serialize().hex()

    # Build a bech32 P2WSH address from the witnessScript
    # Address will internally hash the script with SHA256 for p2wsh
    addr = Address(
        witness_script,
        script_type="p2wsh",
        encoding="bech32",
        network="signet",
    ).address

    print("\n=== P2WSH Address (native, 1-of-2) ===")
    print(f"P2WSH address     : {addr}")
    print(f"P2WSH scriptPubKey: {scriptpubkey_hex}")
    print(f"SHA256(witnessScript): {ws_hash.hex()}")

    return scriptpubkey_hex, addr


def main() -> None:
    """Demo workflow for constructing a native P2WSH 1-of-2 multisig address on Signet.

    Steps:
      1. Read two WIF private keys (no wallet DB)
      2. Build the 1-of-2 multisig witnessScript
      3. Derive the corresponding native P2WSH scriptPubKey and address

    Next steps (separate script):
      - Fund this P2WSH address on Signet
      - Manually construct and sign a spending transaction with one signature
        and a custom witness stack
    """
    print("=== P2WSH Multisig (1-of-2) Address Demo ===\n")

    # 1. Keys for 1-of-2 multisig
    key1, key2 = create_multisig_keys_from_wif()

    # 2. Build 1-of-2 witnessScript
    witness_script = build_witness_script_1of2(key1, key2)

    # 3. Build native P2WSH scriptPubKey and address
    build_p2wsh_scriptpubkey_and_address(witness_script)

    print("\n=== Demo Setup Complete ===")
    print("Send Signet coins to the P2WSH address above,")
    print("then use the spend script to manually build and sign a P2WSH 1-of-2 spend.")


if __name__ == "__main__":
    main()
