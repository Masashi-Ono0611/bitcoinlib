#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual P2SH Legacy Multisig (1-of-2) Spend Example

This script assumes you already have:
- A 1-of-2 legacy P2SH multisig redeem script built from two keys
- A UTXO on Signet that pays to the corresponding P2SH address

What this script does:
- Reconstruct the 1-of-2 redeemScript from two WIF private keys
- Build a legacy P2SH spending transaction for a single input / single output
- Manually compute the signature hash
- Create a single signature (1-of-2)
- Manually assemble the scriptSig: OP_0 <sig1> <redeemScript>
- Print all relevant pieces (txid, raw tx, scriptSig) and verify the transaction

It does NOT broadcast the transaction by default. You can copy the raw hex
and push it via your own tooling if desired.
"""

from bitcoinlib.keys import Key
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op
from bitcoinlib.encoding import hash160, varstr
from bitcoinlib.transactions import Transaction, sign as tx_sign, SIGHASH_ALL
from bitcoinlib.services.services import Service


def read_utxo_and_dest() -> tuple[str, int, int, str, int, int]:
    """Read UTXO and destination info from CLI.

    For this simple demo:
      - fee_sats is fixed to 1000
      - send_value_sats is automatically computed as utxo_value_sats - fee_sats

    Returns:
      prev_txid_hex, vout_index, utxo_value_sats,
      dest_address, send_value_sats, fee_sats
    """
    print("=== UTXO and Destination Info ===")

    prev_txid_hex = input("Prev txid (hex, big-endian): ").strip()
    vout_str = input("Prev output index (vout): ").strip()
    value_str = input("Prev output value (sats): ").strip()

    dest_address = input("Destination address (P2PKH/P2WPKH etc.): ").strip()

    if not prev_txid_hex or not vout_str or not value_str or not dest_address:
        raise ValueError("Prev txid, vout, value, and destination address are required.")

    vout = int(vout_str)
    utxo_value = int(value_str)

    fee = 1000
    if utxo_value <= fee:
        raise ValueError(f"UTXO value must be greater than fixed fee {fee} sats, got {utxo_value}")

    send_value = utxo_value - fee

    print(f"Using fixed fee       : {fee} sats")
    print(f"Computed send amount  : {send_value} sats (utxo {utxo_value} - fee {fee})")

    return prev_txid_hex, vout, utxo_value, dest_address, send_value, fee


def create_multisig_keys_from_wif() -> tuple[Key, Key]:
    """Read two WIF private keys from CLI and return Key objects.

    The same convention as in manual_p2sh_legacy_multisig_1of2.py is used:
    - Two WIFs are required
    - No wallet/DB access is performed
    """
    print("=== Multisig Keys for Spending (1-of-2, legacy P2SH) ===")

    wif1 = input("WIF for Key 1 (required, used for signing in this demo): ").strip()
    wif2 = input("WIF for Key 2 (required, used only in redeemScript/policy): ").strip()

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
    """Rebuild the 1-of-2 multisig redeem script from the two provided keys.

    RedeemScript format (standard 1-of-2):
      OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
    """
    redeem_script_obj = Script(keys=[key1, key2], sigs_required=1, script_types=['multisig'])
    redeemscript = redeem_script_obj.serialize()

    print("\n=== RedeemScript (1-of-2) ===")
    print(f"RedeemScript (hex): {redeemscript.hex()}")
    return redeemscript


def derive_p2sh_address(redeemscript: bytes) -> str:
    """Derive the legacy P2SH address from the given redeemscript (for sanity check)."""
    redeem_hash = hash160(redeemscript)
    script = Script([op.op_hash160, redeem_hash, op.op_equal])
    scriptpubkey_hex = script.serialize().hex()

    from bitcoinlib.keys import Address  # imported here to keep top imports minimal

    addr = Address(
        hashed_data=redeem_hash,
        script_type='p2sh',
        encoding='base58',
        network='signet',
    ).address

    print("\n=== P2SH Address (derived from redeemScript) ===")
    print(f"P2SH address     : {addr}")
    print(f"P2SH scriptPubKey: {scriptpubkey_hex}")

    return addr


def build_and_sign_spend_tx(
    key_to_sign: Key,
    key_other: Key,
    redeemscript: bytes,
    prev_txid_hex: str,
    vout: int,
    utxo_value: int,
    dest_address: str,
    send_value: int,
    fee: int,
) -> Transaction:
    """Build and sign a simple 1-input / 1-output P2SH 1-of-2 multisig spend transaction.

    - Uses legacy P2SH (no segwit)
    - scriptSig = OP_0 <sig1> <redeemScript>
    - Assumes send_value + fee == utxo_value
    """
    print("\n=== Building P2SH 1-of-2 Spend Transaction ===")

    # 1. Create Transaction object
    tx = Transaction(network='signet', witness_type='legacy')

    # 2. Add the P2SH input
    # NOTE: Transaction.add_input expects the txid in normal (big-endian) order as hex/bytes
    # and will handle internal endianness itself. We therefore do NOT reverse bytes here.
    prev_txid_bytes = bytes.fromhex(prev_txid_hex)

    # For simplicity we only use key_to_sign and key_other here. script_type 'p2sh_multisig'
    tx.add_input(
        prev_txid_bytes,
        vout,
        value=utxo_value,
        script_type='p2sh_multisig',
        keys=[key_to_sign, key_other],
        sigs_required=1,
    )

    # 3. Add the output
    tx.add_output(send_value, dest_address)

    print("Input total  :", utxo_value, "sats")
    print("Send value   :", send_value, "sats")
    print("Fee          :", fee, "sats")

    # 4. Manually sign the single input with key_to_sign
    inp = tx.inputs[0]

    # Compute signature hash (legacy P2SH)
    tx_hash = tx.signature_hash(inp.index_n, SIGHASH_ALL, inp.witness_type)
    if not tx_hash:
        raise ValueError("Could not create transaction hash for signing")

    print("\n=== Manual Signing Details ===")
    print(f"witness_type  : {inp.witness_type}")
    print(f"script_type   : {inp.script_type}")
    print(f"tx_hash       : {tx_hash.hex()}")
    print(f"pubkey(sign)  : {key_to_sign.public_hex}")

    sig_obj = tx_sign(tx_hash, key_to_sign, hash_type=SIGHASH_ALL)
    sig_bytes = sig_obj.as_der_encoded()
    print(f"signature_der : {sig_bytes.hex()}")

    # Attach signature object to input (for consistency with library)
    inp.signatures = [sig_obj]

    # 5. Manually construct scriptSig for P2SH 1-of-2 multisig
    # scriptSig = OP_0 <sig1> <redeemScript>
    sig_push = varstr(sig_bytes)
    redeem_push = varstr(redeemscript)
    unlocking_script = b"\x00" + sig_push + redeem_push
    inp.unlocking_script = unlocking_script

    print("\n=== scriptSig (unlocking_script) ===")
    print(f"scriptSig (hex): {unlocking_script.hex()}")

    # 6. Finalize tx fields and verify
    tx.txid = tx.signature_hash()[::-1].hex()
    tx.size = len(tx.raw())
    tx.calc_weight_units()
    tx.update_totals()

    print("\n=== Transaction Summary ===")
    print(f"TxID        : {tx.txid}")
    print(f"Raw (hex)   : {tx.raw().hex()}")
    print(f"Size (bytes): {tx.size}")

    if not tx.verify():
        raise ValueError("Transaction verification failed")
    print("Verification : OK")

    return tx


def main():
    """End-to-end demo for spending from a P2SH 1-of-2 multisig UTXO on Signet.

    Steps:
      1. Read two WIFs for the 1-of-2 multisig keys
      2. Rebuild redeemScript and show the corresponding P2SH address
      3. Read UTXO and destination info (1 input / 1 output)
      4. Build and sign the legacy P2SH spend transaction with one signature
      5. Print txid, raw tx, and scriptSig for learning
    """
    print("=== P2SH Legacy Multisig (1-of-2) Spend Demo ===\n")

    # 1. Keys for 1-of-2 multisig (signer provides two WIFs)
    key1, key2 = create_multisig_keys_from_wif()

    # 2. Rebuild redeemScript and P2SH address from those keys
    redeemscript = build_redeemscript_1of2(key1, key2)

    # From the signer's perspective: they know the P2SH address that holds funds.
    # We ask for that address and verify that it matches the address implied by the
    # provided keys/policy. If it does not match, we stop early.
    expected_p2sh = input("P2SH funding address (the one holding the UTXO, required): ").strip()
    if not expected_p2sh:
        raise ValueError("P2SH funding address is required.")

    derived_p2sh = derive_p2sh_address(redeemscript)
    if expected_p2sh != derived_p2sh:
        raise ValueError(
            f"Provided P2SH address {expected_p2sh} does not match address derived from keys {derived_p2sh}."
        )

    # 3. Read UTXO & destination info
    (
        prev_txid_hex,
        vout,
        utxo_value,
        dest_address,
        send_value,
        fee,
    ) = read_utxo_and_dest()

    # 4. Build and sign spend tx using key1 (1-of-2)
    tx = build_and_sign_spend_tx(
        key_to_sign=key1,
        key_other=key2,
        redeemscript=redeemscript,
        prev_txid_hex=prev_txid_hex,
        vout=vout,
        utxo_value=utxo_value,
        dest_address=dest_address,
        send_value=send_value,
        fee=fee,
    )

    # 5. Broadcast transaction to Signet
    print("\n=== Broadcasting Transaction to Signet ===")
    try:
        srv = Service(network="signet")
        # tx.raw() returns bytes; convert to hex string for sendrawtransaction
        raw_hex = tx.raw().hex()
        res = srv.sendrawtransaction(raw_hex)
        print(f"Broadcast result: {res}")

        txid_broadcast = res.get("txid") if isinstance(res, dict) else None
        if txid_broadcast:
            print(f"Broadcasted TxID : {txid_broadcast}")
            print(f"View on explorer : https://mempool.space/signet/tx/{txid_broadcast}")
        else:
            print("No 'txid' field in broadcast response; please check service configuration.")
    except Exception as e:
        print(f"Error while broadcasting transaction: {e}")

    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()
