#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P2SH-P2WSH Multisig (1-of-2) Address Example

This script is the nested SegWit counterpart of `p2sh_1of2_create_address.py`
and `p2wsh_1of2_create_address.py`.

It demonstrates how to:
- Construct a 1-of-2 multisig *witnessScript* from two WIF private keys
- Wrap it in a P2WSH redeemScript:  OP_0 <32-byte SHA256(witnessScript)>
- Derive the corresponding **P2SH-P2WSH** scriptPubKey and P2SH address on Bitcoin Signet

No wallet DB is used; everything is driven by CLI WIF input.
"""

from __future__ import annotations

import hashlib

from bitcoinlib.keys import Key, Address
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op
from bitcoinlib.encoding import hash160, varstr


def create_multisig_keys_from_wif() -> tuple[Key, Key]:
    """Read two WIF private keys from CLI and return Key objects for Signet.

    - Two WIFs are required
    - No wallet/DB access is performed
    - If either WIF is invalid, the function raises and stops
    """
    print("=== Multisig Keys (1-of-2, P2SH-P2WSH) ===")

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

    This is the same multisig policy used by the legacy P2SH and native P2WSH
    examples; only its placement (redeemScript vs witnessScript) changes.
    """
    ws_obj = Script(keys=[key1, key2], sigs_required=1, script_types=["multisig"])
    witness_script = ws_obj.serialize()

    print("\n=== WitnessScript (1-of-2) ===")
    print(f"WitnessScript (hex): {witness_script.hex()}")
    print("WitnessScript (ASM-like):")
    print("  OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG")

    return witness_script


def build_p2sh_p2wsh_scripts_and_address(witness_script: bytes) -> tuple[str, str, str]:
    """Return (redeemScript_hex, p2sh_scriptPubKey_hex, p2sh_address) for P2SH-P2WSH 1-of-2 on Signet.

    Structure:
      - witnessScript:  OP_1 <pub1> <pub2> OP_2 OP_CHECKMULTISIG
      - redeemScript:   OP_0 <32-byte-SHA256(witnessScript)>
      - outer script:   OP_HASH160 <20-byte-hash160(redeemScript)> OP_EQUAL
    """
    # 1. Hash the witnessScript for P2WSH
    ws_hash = hashlib.sha256(witness_script).digest()  # 32 bytes

    # 2. P2WSH redeemScript (this script is pushed by P2SH scriptSig)
    #    redeemScript bytes:  00 20 <32-byte-hash>
    redeem_script = b"\x00" + varstr(ws_hash)
    redeemscript_hex = redeem_script.hex()

    # 3. Outer P2SH scriptPubKey
    redeem_hash = hash160(redeem_script)  # 20 bytes
    script = Script([op.op_hash160, redeem_hash, op.op_equal])
    scriptpubkey_hex = script.serialize().hex()

    # 4. P2SH address (Signet) for the outer script
    addr = Address(
        hashed_data=redeem_hash,
        script_type="p2sh",
        encoding="base58",
        network="signet",
    ).address

    print("\n=== P2SH-P2WSH Address (nested, 1-of-2) ===")
    print(f"P2SH-P2WSH address  : {addr}")
    print(f"RedeemScript (P2WSH): {redeemscript_hex}")
    print(f"P2SH scriptPubKey   : {scriptpubkey_hex}")
    print(f"SHA256(witnessScript): {ws_hash.hex()}")

    return redeemscript_hex, scriptpubkey_hex, addr


def main() -> None:
    """Demo workflow for constructing a P2SH-P2WSH 1-of-2 multisig address on Signet.

    Steps:
      1. Read two WIF private keys (no wallet DB)
      2. Build the 1-of-2 multisig witnessScript
      3. Wrap it as a P2WSH redeemScript
      4. Derive the outer P2SH scriptPubKey and address

    Next steps (separate script):
      - Fund this P2SH-P2WSH address on Signet
      - Manually construct and sign a spend transaction which uses:
        - scriptSig = <redeemScript>
        - witness = [OP_0, <sig1>, <witnessScript>]
    """
    print("=== P2SH-P2WSH Multisig (1-of-2) Address Demo ===\n")

    # 1. Keys for 1-of-2 multisig
    key1, key2 = create_multisig_keys_from_wif()

    # 2. Build 1-of-2 witnessScript
    witness_script = build_witness_script_1of2(key1, key2)

    # 3. Build P2SH-P2WSH redeemScript, scriptPubKey and address
    build_p2sh_p2wsh_scripts_and_address(witness_script)

    print("\n=== Demo Setup Complete ===")
    print("Send Signet coins to the P2SH-P2WSH address above,")
    print("then use the spend script to manually build and sign a nested P2SH-P2WSH 1-of-2 spend.")


if __name__ == "__main__":
    main()
