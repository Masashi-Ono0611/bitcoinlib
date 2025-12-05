#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual P2WSH single-key timelock (CLTV) spend example

This script assumes you already have:
- A single-key P2WSH *witnessScript* of the form:

    <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG

- A UTXO on Signet that pays to the corresponding native P2WSH address

What this script does:
- Rebuilds the CLTV witnessScript from a WIF key and the locktime
- Optionally verifies that the script corresponds to the given P2WSH address
- Builds a native P2WSH spending transaction (1 input / 1 output)
- Sets nLockTime to the same (or higher) block height as in the script
- Manually computes the SegWit (BIP143-style) signature hash
- Creates a single signature
- Manually assembles the witness stack: [<sig>, <witnessScript>]
- Prints all relevant pieces (txid, raw tx, witness contents) and verifies the transaction
- Attempts to broadcast the transaction to Signet via bitcoinlib's Service layer

Notes:
- Unlike the nLockTime-only demo, here the funding transaction is already mined.
- The CLTV condition lives inside the witnessScript, so the UTXO exists on-chain
  but cannot be spent until the height condition is satisfied.
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
    print("=== UTXO and Destination Info (CLTV P2WSH) ===")

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


def read_key_and_locktime() -> tuple[Key, int, int]:
    """Read the single WIF key, CLTV locktime, and tx-level nLockTime from CLI."""
    print("=== P2WSH CLTV (single-key) - Spend Key and Locktime ===")

    wif = input("WIF for signing key (Signet, required): ").strip()
    cltv_locktime_str = input("CLTV locktime (block height, must match funding script): ").strip()
    tx_locktime_str = input(
        "Transaction nLockTime (block height, 0 = disabled for testing *always fails* ; to succeed must be >= CLTV locktime): "
    ).strip()

    if not wif or not cltv_locktime_str:
        raise ValueError("WIF and CLTV locktime are required.")

    try:
        key = Key(import_key=wif, network="signet")
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"Invalid WIF: {e}") from e

    try:
        cltv_locktime = int(cltv_locktime_str)
    except ValueError as e:  # noqa: BLE001
        raise ValueError(f"CLTV locktime must be an integer block height: {e}") from e

    if cltv_locktime < 0:
        raise ValueError("CLTV locktime (block height) must be non-negative")

    tx_locktime = 0
    if tx_locktime_str:
        try:
            tx_locktime = int(tx_locktime_str)
        except ValueError as e:  # noqa: BLE001
            raise ValueError(f"Transaction nLockTime must be an integer block height: {e}") from e
        if tx_locktime < 0:
            raise ValueError("Transaction nLockTime (block height) must be non-negative")

    print("[Key]")
    print(f"  WIF : {key.wif()}")
    print(f"  Pub : {key.public_hex}")
    print("[CLTV Locktime]")
    print(f"  Height: {cltv_locktime}")
    print("[Tx nLockTime]")
    print(f"  Height: {tx_locktime} (0 means no nLockTime)")

    return key, cltv_locktime, tx_locktime


def build_cltv_witness_script(key: Key, locktime: int) -> bytes:
    """Rebuild the CLTV witnessScript.

    <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG
    """
    pubkey_bytes = bytes.fromhex(key.public_hex)

    # Encode locktime as data (ScriptNum) so it is pushed onto the stack,
    # not interpreted as an opcode value.
    locktime_bytes = locktime.to_bytes((locktime.bit_length() + 7) // 8 or 1, "little", signed=False)

    ws_obj = Script([locktime_bytes, op.op_checklocktimeverify, op.op_drop, pubkey_bytes, op.op_checksig])
    witness_script = ws_obj.serialize()

    print("\n=== CLTV WitnessScript (reconstructed) ===")
    print(f"WitnessScript (hex): {witness_script.hex()}")
    print("WitnessScript (ASM-like):")
    print(f"  {locktime} OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG")

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

    print("\n=== P2WSH Address (derived from CLTV witnessScript) ===")
    print(f"P2WSH address     : {addr}")
    print(f"P2WSH scriptPubKey: {scriptpubkey_hex}")
    print(f"SHA256(witnessScript): {ws_hash.hex()}")

    return addr


def build_and_sign_cltv_spend_tx(
    key: Key,
    witness_script: bytes,
    cltv_locktime: int,
    tx_locktime: int,
    prev_txid_hex: str,
    vout: int,
    utxo_value: int,
    dest_address: str,
    send_value: int,
    fee: int,
) -> Transaction:
    """Build and sign a simple 1-input / 1-output CLTV P2WSH spend transaction.

    - Uses native P2WSH (SegWit)
    - scriptSig is empty
    - Witness stack: [<sig>, <witnessScript>]
    - CLTV locktime (in the script) is given by cltv_locktime.
    - Transaction-level nLockTime is separately specified by tx_locktime.
    """
    print("\n=== Building P2WSH CLTV Spend Transaction ===")

    # 1. Create Transaction object (SegWit) with optional nLockTime set
    tx = Transaction(network="signet", witness_type="segwit")
    tx.locktime = tx_locktime
    if hasattr(tx, "locktime_int"):
        tx.locktime_int = tx_locktime

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
    # For nLockTime to be enforced, at least one input must have sequence < 0xffffffff.
    # If tx_locktime == 0, we leave sequence at its default (final) value so that
    # the transaction is not affected by nLockTime rules and only CLTV matters.
    if tx_locktime > 0:
        inp.sequence = 0xFFFFFFFE

    # 3. Add the output
    tx.add_output(send_value, dest_address)

    print("Input total  :", utxo_value, "sats")
    print("Send value   :", send_value, "sats")
    print("Fee          :", fee, "sats")
    print("CLTV lock    :", cltv_locktime)
    print("Tx nLockTime :", tx_locktime)

    # 4. Manually sign the single input
    inp.redeemscript = witness_script

    # SegWit (BIP143-style) signature hash
    tx_hash = tx.signature_hash(inp.index_n, SIGHASH_ALL, inp.witness_type)
    if not tx_hash:
        raise ValueError("Could not create transaction hash for signing")

    print("\n=== Manual Signing Details (CLTV P2WSH) ===")
    print(f"witness_type  : {inp.witness_type}")
    print(f"script_type   : {inp.script_type}")
    print(f"tx_hash       : {tx_hash.hex()}")
    print(f"pubkey(sign)  : {key.public_hex}")

    sig_obj = tx_sign(tx_hash, key, hash_type=SIGHASH_ALL)
    sig_bytes = sig_obj.as_der_encoded()
    print(f"signature_der : {sig_bytes.hex()}")

    inp.signatures = [sig_obj]

    # 5. Manually construct witness stack for P2WSH single-key CLTV
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
    """End-to-end demo for spending from a P2WSH single-key CLTV UTXO on Signet.

    Steps (signer perspective):
      1. Read WIF for the single key and the CLTV locktime
      2. Rebuild the CLTV witnessScript and show the corresponding P2WSH address
      3. (Optional) verify that the provided funding address matches the derived P2WSH address
      4. Read UTXO and destination info (1 input / 1 output)
      5. Build and sign the P2WSH CLTV spend transaction
      6. Print txid, raw tx, and witness details for learning
      7. Attempt to broadcast the transaction to Signet
    """
    print("=== P2WSH CLTV (single-key) Spend Demo ===\n")
    print("NOTE:")
    print("  - CLTV locktime is enforced by the script.")
    print("  - Even if you set nLockTime >= CLTV locktime, the node will still reject the")
    print("    transaction if the current block height is below the CLTV locktime.")
    print("")

    key, cltv_locktime, tx_locktime = read_key_and_locktime()
    witness_script = build_cltv_witness_script(key, cltv_locktime)
    derived_addr = derive_p2wsh_address(witness_script)

    funding_addr = input("Funding P2WSH address (must match the address that received the UTXO): ").strip()
    if not funding_addr:
        raise ValueError("Funding P2WSH address is required to verify key+CLTV locktime against the actual UTXO.")
    if funding_addr != derived_addr:
        raise ValueError("Provided funding address does not match derived P2WSH address from key+CLTV locktime")
    print("Funding address matches derived P2WSH address.")

    prev_txid_hex, vout, utxo_value, dest_address, send_value, fee = read_utxo_and_dest()

    tx = build_and_sign_cltv_spend_tx(
        key=key,
        witness_script=witness_script,
        cltv_locktime=cltv_locktime,
        tx_locktime=tx_locktime,
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
