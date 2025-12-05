#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual P2WSH Multisig (1-of-2) Spend Example

This script assumes you already have:
- A 1-of-2 P2WSH multisig *witnessScript* built from two keys
- A UTXO on Signet that pays to the corresponding native P2WSH address

What this script does:
- Reconstructs the 1-of-2 witnessScript from two WIF private keys
- Verifies that the keys/policy actually correspond to the given P2WSH address
- Builds a native P2WSH spending transaction for a single input / single output
- Manually computes the SegWit (BIP143-style) signature hash
- Creates a single signature (1-of-2)
- Manually assembles the witness stack: [OP_0, <sig1>, <witnessScript>]
- Prints all relevant pieces (txid, raw tx, witness contents) and verifies the transaction
- Attempts to broadcast the transaction to Signet via bitcoinlib's Service layer

This is the SegWit analogue of `p2sh_1of2_spend_manual_sign.py`.
"""

from __future__ import annotations

from bitcoinlib.keys import Key, Address
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op
from bitcoinlib.encoding import varstr
from bitcoinlib.transactions import Transaction, sign as tx_sign, SIGHASH_ALL
from bitcoinlib.services.services import Service
import hashlib


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

    dest_address = input("Destination address (P2WPKH/P2PKH etc.): ").strip()

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

    Convention:
      - Key 1 will actually sign in this demo
      - Key 2 is used only as part of the witnessScript/policy (1-of-2)
    """
    print("=== Multisig Keys for Spending (1-of-2, P2WSH) ===")

    wif1 = input("WIF for Key 1 (required, used for signing in this demo): ").strip()
    wif2 = input("WIF for Key 2 (required, used only in witnessScript/policy): ").strip()

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
    """Rebuild the 1-of-2 multisig witnessScript from the two provided keys.

    WitnessScript format (standard 1-of-2):
      OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
    """
    ws_obj = Script(keys=[key1, key2], sigs_required=1, script_types=["multisig"])
    witness_script = ws_obj.serialize()

    print("\n=== WitnessScript (1-of-2) ===")
    print(f"WitnessScript (hex): {witness_script.hex()}")
    return witness_script


def derive_p2wsh_address(witness_script: bytes) -> str:
    """Derive the native P2WSH address from the given witnessScript (for sanity check)."""
    ws_hash = hashlib.sha256(witness_script).digest()
    script = Script([op.op_0, ws_hash])
    scriptpubkey_hex = script.serialize().hex()

    addr = Address(
        witness_script,
        script_type="p2wsh",
        encoding="bech32",
        network="signet",
    ).address

    print("\n=== P2WSH Address (derived from witnessScript) ===")
    print(f"P2WSH address     : {addr}")
    print(f"P2WSH scriptPubKey: {scriptpubkey_hex}")
    print(f"SHA256(witnessScript): {ws_hash.hex()}")

    return addr


def build_and_sign_spend_tx(
    key_to_sign: Key,
    key_other: Key,
    witness_script: bytes,
    prev_txid_hex: str,
    vout: int,
    utxo_value: int,
    dest_address: str,
    send_value: int,
    fee: int,
) -> Transaction:
    """Build and sign a simple 1-input / 1-output P2WSH 1-of-2 multisig spend transaction.

    - Uses native P2WSH (SegWit)
    - scriptSig is empty
    - Witness stack: [OP_0, <sig1>, <witnessScript>]
    """
    print("\n=== Building P2WSH 1-of-2 Spend Transaction ===")

    # 1. Create Transaction object (SegWit)
    tx = Transaction(network="signet", witness_type="segwit")

    # 2. Add the P2WSH input
    # Transaction.add_input expects the txid in normal (big-endian) order as bytes
    prev_txid_bytes = bytes.fromhex(prev_txid_hex)

    # We use script_type 'p2sh_multisig' here with witness_type='segwit'; in this context,
    # together with a multisig witnessScript, this corresponds to a native P2WSH multisig spend.
    tx.add_input(
        prev_txid_bytes,
        vout,
        value=utxo_value,
        script_type="p2sh_multisig",
        keys=[key_to_sign, key_other],
        sigs_required=1,
        witness_type="segwit",
    )

    # 3. Add the output
    tx.add_output(send_value, dest_address)

    print("Input total  :", utxo_value, "sats")
    print("Send value   :", send_value, "sats")
    print("Fee          :", fee, "sats")

    # 4. Manually sign the single input with key_to_sign
    inp = tx.inputs[0]

    # Ensure the witness_script is attached so signature_hash can use it
    inp.redeemscript = witness_script

    # Compute signature hash (SegWit, BIP143 style)
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

    # 5. Manually construct witness stack for P2WSH 1-of-2 multisig
    # Witness stack (top to bottom):
    #   0: OP_0 (dummy for CHECKMULTISIG bug)
    #   1: <sig1>
    #   2: <witnessScript>
    dummy = b"\x00"
    inp.witnesses = [dummy, sig_bytes, witness_script]
    inp.unlocking_script = b""  # native P2WSH has empty scriptSig

    print("\n=== Witness Stack ===")
    for i, w in enumerate(inp.witnesses):
        try:
            w_bytes = bytes(w) if not isinstance(w, (bytes, bytearray)) else w
            w_hex = w_bytes.hex()
        except TypeError:
            w_hex = str(w)
        print(f"witness[{i}] : {w_hex}")

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


def main() -> None:
    """End-to-end demo for spending from a P2WSH 1-of-2 multisig UTXO on Signet.

    Steps (signer perspective):
      1. Read two WIFs for the 1-of-2 multisig keys
      2. Rebuild witnessScript and show the corresponding P2WSH address
      3. Verify that the provided funding address matches the derived P2WSH address
      4. Read UTXO and destination info (1 input / 1 output)
      5. Build and sign the P2WSH spend transaction with one signature
      6. Print txid, raw tx, and witness details for learning
      7. Attempt to broadcast the transaction to Signet
    """
    print("=== P2WSH Multisig (1-of-2) Spend Demo ===\n")

    # 1. Keys for 1-of-2 multisig (signer provides two WIFs)
    key1, key2 = create_multisig_keys_from_wif()

    # 2. Rebuild witnessScript and P2WSH address from those keys
    witness_script = build_witness_script_1of2(key1, key2)

    # From the signer's perspective: they know the P2WSH address that holds funds.
    # We ask for that address and verify that it matches the address implied by the
    # provided keys/policy. If it does not match, we stop early.
    expected_p2wsh = input("P2WSH funding address (the one holding the UTXO, required): ").strip()
    if not expected_p2wsh:
        raise ValueError("P2WSH funding address is required.")

    derived_p2wsh = derive_p2wsh_address(witness_script)
    if expected_p2wsh != derived_p2wsh:
        raise ValueError(
            f"Provided P2WSH address {expected_p2wsh} does not match address derived from keys {derived_p2wsh}."
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
        witness_script=witness_script,
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
        raw_hex = tx.raw().hex()
        res = srv.sendrawtransaction(raw_hex)
        print(f"Broadcast result: {res}")

        txid_broadcast = res.get("txid") if isinstance(res, dict) else None
        if txid_broadcast:
            print(f"Broadcasted TxID : {txid_broadcast}")
            print(f"View on explorer : https://mempool.space/signet/tx/{txid_broadcast}")
        else:
            print("No 'txid' field in broadcast response; please check service configuration.")
    except Exception as e:  # noqa: BLE001
        print(f"Error while broadcasting transaction: {e}")

    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()
