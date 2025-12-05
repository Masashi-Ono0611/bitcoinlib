#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual P2SH Legacy Multisig (1-of-2) Example

This script demonstrates how to:
- Construct a 1-of-2 legacy P2SH multisig redeem script
- Derive the corresponding P2SH address on Bitcoin Signet
- (Next step) Manually build and sign a spending transaction from that multisig UTXO

It is intentionally similar in structure to `manual_scriptpubkey_manual_sign_example.py`,
but focused on legacy P2SH multisig instead of P2WPKH.
"""

from bitcoinlib.keys import Key, Address
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op
from bitcoinlib.encoding import hash160


def create_multisig_keys():
    """Get two keys for a 1-of-2 multisig example from WIF input.

    This function is intentionally simple and wallet/DB agnostic:
      - It reads two WIF private keys from CLI.
      - It does not fall back to random key generation.
      - If either WIF is missing or invalid, it raises an error and stops.
    """

    print("=== Multisig Keys (1-of-2, legacy P2SH) ===")

    wif1 = input("WIF for Key 1 (required): ").strip()
    wif2 = input("WIF for Key 2 (required): ").strip()

    if not wif1 or not wif2:
        raise ValueError("Both WIFs are required for Key 1 and Key 2.")

    try:
        key1 = Key(import_key=wif1, network="signet")
    except Exception as e:
        raise ValueError(f"Invalid WIF for Key 1: {e}")

    try:
        key2 = Key(import_key=wif2, network="signet")
    except Exception as e:
        raise ValueError(f"Invalid WIF for Key 2: {e}")

    print("[Key 1]")
    print(f"  WIF : {key1.wif()}")
    print(f"  Pub : {key1.public_hex}")
    print("[Key 2]")
    print(f"  WIF : {key2.wif()}")
    print(f"  Pub : {key2.public_hex}")

    return key1, key2


def build_redeemscript_1of2(key1: Key, key2: Key) -> bytes:
    """Build a 1-of-2 multisig redeem script using the two provided keys.

    RedeemScript format (standard 1-of-2):
      OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
    """
    # Order of public keys matters; for demo we use [key1, key2] as-is
    redeem_script_obj = Script(keys=[key1, key2], sigs_required=1, script_types=['multisig'])
    redeemscript = redeem_script_obj.serialize()

    print("\n=== RedeemScript (1-of-2) ===")
    print(f"RedeemScript (hex): {redeemscript.hex()}")
    return redeemscript


def build_p2sh_scriptpubkey_and_address(redeemscript: bytes) -> tuple[str, str]:
    """Return (scriptPubKey_hex, p2sh_address) for a legacy P2SH multisig on signet.

    P2SH ScriptPubKey:
      OP_HASH160 <hash160(redeemscript)> OP_EQUAL
    """
    redeem_hash = hash160(redeemscript)  # 20 bytes
    script = Script([op.op_hash160, redeem_hash, op.op_equal])
    scriptpubkey_hex = script.serialize().hex()

    # Build a P2SH address from redeemscript hash
    addr = Address(
        hashed_data=redeem_hash,
        script_type='p2sh',
        encoding='base58',
        network='signet',
    ).address

    print("\n=== P2SH Address (legacy, 1-of-2) ===")
    print(f"P2SH address     : {addr}")
    print(f"P2SH scriptPubKey: {scriptpubkey_hex}")

    return scriptpubkey_hex, addr


def main():
    """Demo workflow for constructing a legacy P2SH 1-of-2 multisig address on Signet.

    Next steps (to be implemented):
      - Assume a UTXO sent to this P2SH address
      - Manually construct and sign a spending transaction with 1-of-2 signatures
      - Log scriptSig and other details for learning
    """
    print("=== P2SH Legacy Multisig (1-of-2) Demo ===\n")

    # 1. Create two demo keys for the multisig
    key1, key2 = create_multisig_keys()

    # 2. Build 1-of-2 redeem script
    redeemscript = build_redeemscript_1of2(key1, key2)

    # 3. Build legacy P2SH scriptPubKey and address
    build_p2sh_scriptpubkey_and_address(redeemscript)

    print("\n=== Demo Setup Complete ===")
    print("Send Signet coins to the P2SH address above,")
    print("then we can extend this script to spend from that UTXO with manual signing.")


if __name__ == "__main__":
    main()
