#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual P2WSH single-key timelock (CSV, relative) spend example

This script assumes you already have:
- A single-key P2WSH *witnessScript* of the form:

    <sequence> OP_CHECKSEQUENCEVERIFY OP_DROP <pubkey> OP_CHECKSIG

- A UTXO on Signet that pays to the corresponding native P2WSH address

What this script does:
- Rebuilds the CSV witnessScript from a WIF key and the relative sequence
- Verifies that the script corresponds to the given P2WSH address
- Builds a native P2WSH spending transaction (1 input / 1 output)
- Sets the input sequence to the same relative lock value
- Manually computes the SegWit (BIP143-style) signature hash
- Creates a single signature
- Manually assembles the witness stack: [<sig>, <witnessScript>]
- Prints all relevant pieces (txid, raw tx, witness contents) and verifies the transaction
- Attempts to broadcast the transaction to Signet via bitcoinlib's Service layer

Notes:
- Unlike nLockTime (absolute), CSV enforces a *relative* lock based on the age of
  the UTXO and the input sequence value.
- If the UTXO does not yet have enough confirmations relative to the CSV value,
  script evaluation will fail and the node will reject the transaction.
"""

from __future__ import annotations

import hashlib

from bitcoinlib.keys import Key, Address
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op
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
    print("=== UTXO and Destination Info (CSV P2WSH) ===")

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


def read_key_and_sequence() -> tuple[Key, int]:
    """Read the single WIF key and the CSV relative lock (in blocks) from CLI."""
    print("=== P2WSH CSV (single-key) - Spend Key and Relative Lock ===")

    wif = input("WIF for signing key (Signet, required): ").strip()
    seq_str = input("CSV relative lock (blocks, must match funding script): ").strip()

    if not wif or not seq_str:
        raise ValueError("WIF and CSV relative lock are required.")

    try:
        key = Key(import_key=wif, network="signet")
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"Invalid WIF: {e}") from e

    try:
        sequence = int(seq_str)
    except ValueError as e:  # noqa: BLE001
        raise ValueError(f"CSV relative lock must be an integer (blocks): {e}") from e

    if sequence < 0:
        raise ValueError("CSV relative lock (blocks) must be non-negative")

    print("[Key]")
    print(f"  WIF : {key.wif()}")
    print(f"  Pub : {key.public_hex}")
    print("[CSV Relative Lock]")
    print(f"  Blocks: {sequence}")

    return key, sequence


def build_csv_witness_script(key: Key, sequence: int) -> bytes:
    """Rebuild the CSV witnessScript.

    <sequence> OP_CHECKSEQUENCEVERIFY OP_DROP <pubkey> OP_CHECKSIG
    """
    pubkey_bytes = bytes.fromhex(key.public_hex)

    # For small integers 0..16, use OP_0 / OP_1..OP_16 to satisfy MINIMALDATA.
    # For larger values, encode as ScriptNum bytes and push as data.
    if sequence == 0:
        seq_cmd = op.op_0
    elif 1 <= sequence <= 16:
        seq_cmd = getattr(op, f"op_{sequence}")
    else:
        seq_cmd = sequence.to_bytes((sequence.bit_length() + 7) // 8 or 1, "little", signed=False)

    ws_obj = Script([seq_cmd, op.op_checksequenceverify, op.op_drop, pubkey_bytes, op.op_checksig])
    witness_script = ws_obj.serialize()

    print("\n=== CSV WitnessScript (reconstructed) ===")
    print(f"WitnessScript (hex): {witness_script.hex()}")
    print("WitnessScript (ASM-like):")
    print(f"  {sequence} OP_CHECKSEQUENCEVERIFY OP_DROP <pubkey> OP_CHECKSIG")

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

    print("\n=== P2WSH Address (derived from CSV witnessScript) ===")
    print(f"P2WSH address     : {addr}")
    print(f"P2WSH scriptPubKey: {scriptpubkey_hex}")
    print(f"SHA256(witnessScript): {ws_hash.hex()}")

    return addr


def build_and_sign_csv_spend_tx(
    key: Key,
    witness_script: bytes,
    sequence: int,
    prev_txid_hex: str,
    vout: int,
    utxo_value: int,
    dest_address: str,
    send_value: int,
    fee: int,
) -> Transaction:
    """Build and sign a simple 1-input / 1-output CSV P2WSH spend transaction.

    - Uses native P2WSH (SegWit)
    - scriptSig is empty
    - Witness stack: [<sig>, <witnessScript>]
    - Input sequence is set to the CSV relative lock value.
    """
    print("\n=== Building P2WSH CSV Spend Transaction ===")

    # 1. Create Transaction object (SegWit). We do not use nLockTime here; CSV is
    # purely relative, based on the input sequence and UTXO age.
    tx = Transaction(network="signet", witness_type="segwit")
    # BIP68 / BIP112 (CSV) semantics require transaction version >= 2.
    # bitcoinlib stores version as 4-byte big-endian and reverses it when serializing,
    # so store 2 as big-endian bytes (b"\x00\x00\x00\x02"). This yields 0x02000000
    # on the wire, which is the standard encoding.
    tx.version = (2).to_bytes(4, "big")

    # 2. Add the P2WSH input
    prev_txid_bytes = bytes.fromhex(prev_txid_hex)

    tx.add_input(
        prev_txid_bytes,
        vout,
        value=utxo_value,
        script_type="p2sh_multisig",  # we will manually supply the witnessScript
        keys=[key],
        sigs_required=1,
        witness_type="segwit",
    )

    inp = tx.inputs[0]
    # Set the input sequence to the CSV relative lock value.
    inp.sequence = sequence

    # 3. Add the output
    tx.add_output(send_value, dest_address)

    print("Input total  :", utxo_value, "sats")
    print("Send value   :", send_value, "sats")
    print("Fee          :", fee, "sats")
    print("CSV lock     :", sequence, "blocks")

    # 4. Manually sign the single input
    inp.redeemscript = witness_script

    # SegWit (BIP143-style) signature hash
    tx_hash = tx.signature_hash(inp.index_n, SIGHASH_ALL, inp.witness_type)
    if not tx_hash:
        raise ValueError("Could not create transaction hash for signing")

    print("\n=== Manual Signing Details (CSV P2WSH) ===")
    print(f"witness_type  : {inp.witness_type}")
    print(f"script_type   : {inp.script_type}")
    print(f"tx_hash       : {tx_hash.hex()}")
    print(f"pubkey(sign)  : {key.public_hex}")

    sig_obj = tx_sign(tx_hash, key, hash_type=SIGHASH_ALL)
    sig_bytes = sig_obj.as_der_encoded()
    print(f"signature_der : {sig_bytes.hex()}")

    inp.signatures = [sig_obj]

    # 5. Manually construct witness stack for P2WSH single-key CSV
    # For P2WSH, witness stack items are arbitrary; the last item is the witnessScript.
    # Stack (top to bottom): [<sig>, <witnessScript>]
    inp.witnesses = [sig_bytes, witness_script]
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
    """End-to-end demo for spending from a P2WSH single-key CSV UTXO on Signet.

    Steps (signer perspective):
      1. Read WIF for the single key and the CSV relative lock (in blocks)
      2. Rebuild the CSV witnessScript and show the corresponding P2WSH address
      3. Verify that the provided funding address matches the derived P2WSH address
      4. Read UTXO and destination info (1 input / 1 output)
      5. Build and sign the P2WSH CSV spend transaction
      6. Print txid, raw tx, and witness details for learning
      7. Attempt to broadcast the transaction to Signet
    """
    print("=== P2WSH CSV (single-key) Spend Demo ===\n")
    print("NOTE:")
    print("  - CSV (OP_CHECKSEQUENCEVERIFY) enforces a *relative* lock based on the input")
    print("    sequence and the age of the UTXO.")
    print("  - Even if the sequence is set correctly, the node will still reject the")
    print("    transaction if the UTXO does not yet have enough confirmations.")
    print("")

    key, sequence = read_key_and_sequence()
    witness_script = build_csv_witness_script(key, sequence)
    derived_addr = derive_p2wsh_address(witness_script)

    funding_addr = input("Funding P2WSH address (must match the address that received the UTXO): ").strip()
    if not funding_addr:
        raise ValueError("Funding P2WSH address is required to verify key+CSV relative lock against the actual UTXO.")
    if funding_addr != derived_addr:
        raise ValueError("Provided funding address does not match derived P2WSH address from key+CSV relative lock")
    print("Funding address matches derived P2WSH address.")

    prev_txid_hex, vout, utxo_value, dest_address, send_value, fee = read_utxo_and_dest()

    tx = build_and_sign_csv_spend_tx(
        key=key,
        witness_script=witness_script,
        sequence=sequence,
        prev_txid_hex=prev_txid_hex,
        vout=vout,
        utxo_value=utxo_value,
        dest_address=dest_address,
        send_value=send_value,
        fee=fee,
    )

    # Broadcast via bitcoinlib Service (Signet)
    print("\nBroadcasting via Service (Signet)...")
    service = Service(network="signet")
    raw_hex = tx.raw().hex()
    try:
        txid = service.sendrawtransaction(raw_hex)
        print("\n✅ Transaction sent successfully via Service!")
        print(f"TxID: {txid}")
        print(f"View on block explorer: https://mempool.space/signet/tx/{txid}")
    except Exception as e:  # noqa: BLE001
        print(f"❌ Broadcast failed via Service: {e}")
        print("You can still push the raw tx manually using the hex above.")


if __name__ == "__main__":
    main()
