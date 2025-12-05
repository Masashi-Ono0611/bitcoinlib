#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple P2WPKH fee rate demo (1-in 1-out).

This script constructs and signs a native P2WPKH transaction on Signet
with a single input and a single output, given:

- One WIF private key (Signet)
- A single funding UTXO (prev_txid, vout, value in sats)
- A destination address
- A *target* fee rate in sats/vB

The goal is to show, in a simple and robust way:

- The raw transaction size in bytes
- The fee chosen by the script in sats
- The *effective* fee rate (sats per byte,近似的な sats/vB)

For simplicity we build the transaction in a single pass:

- Use a rough provisional size guess to derive a fee from the
  requested feerate (fee ≈ feerate * size_guess)
- Build and sign a 1-in 1-out P2WPKH transaction with
  send_value = utxo_value - fee
- Measure the actual tx size in bytes and compute the effective
  sats/byte from that

This avoids relying on bitcoinlib's internal weight/vsize fields,
which can be confusing for educational purposes, while still making
the fee vs size relationship clear.
"""

from __future__ import annotations

from bitcoinlib.keys import Key
from bitcoinlib.transactions import Transaction


def read_inputs() -> tuple[Key, str, int, int, str, int]:
    """Read WIF, UTXO info, destination, and target feerate from CLI."""
    print("=== P2WPKH Fee Rate Demo (1-in 1-out) ===\n")

    wif = input("WIF for signing key (Signet, required): ").strip()
    prev_txid_hex = input("Prev txid (hex, big-endian): ").strip()
    vout_str = input("Prev output index (vout): ").strip()
    value_str = input("Prev output value (sats): ").strip()
    dest_address = input("Destination address (P2WPKH bech32 recommended): ").strip()
    feerate_str = input("Target fee rate (sats/vB, e.g. 1 or 5): ").strip()

    if not (wif and prev_txid_hex and vout_str and value_str and dest_address and feerate_str):
        raise ValueError("All fields are required.")

    key = Key(import_key=wif, network="signet")
    vout = int(vout_str)
    utxo_value = int(value_str)
    sats_per_vb = int(feerate_str)

    if utxo_value <= 0:
        raise ValueError("UTXO value must be positive")
    if sats_per_vb <= 0:
        raise ValueError("Target fee rate must be positive (sats/vB)")

    return key, prev_txid_hex, vout, utxo_value, dest_address, sats_per_vb


def build_signed_p2wpkh_tx(
    key: Key,
    prev_txid_hex: str,
    vout: int,
    utxo_value: int,
    dest_address: str,
    sats_per_vb: int,
) -> Transaction:
    """Build and sign a 1-in 1-out native P2WPKH transaction for fee demo.

    We:
    - Derive a rough fee from the requested feerate using a fixed
      provisional size guess (e.g. ~110 vB for a 1-in 1-out P2WPKH tx).
    - Build a single transaction with send_value = utxo_value - fee.
    - Sign it and measure the actual raw size in bytes.
    - Compute the effective sats/byte from (fee / size_bytes).
    """
    print("\n=== Building 1-in 1-out P2WPKH transaction ===")

    # Very rough size guess for 1-in 1-out P2WPKH (for educational purposes).
    # Real mainnet values are around 110 vB; we use 110 as a starting point.
    size_guess_vb = 110
    rough_fee = sats_per_vb * size_guess_vb
    if utxo_value <= rough_fee:
        raise ValueError(
            f"UTXO value {utxo_value} sats is not enough to pay rough fee {rough_fee} sats",
        )

    send_value = utxo_value - rough_fee
    print(f"Requested feerate : {sats_per_vb} sats/vB")
    print(f"Size guess (vB)   : {size_guess_vb}")
    print(f"Rough fee used    : {rough_fee} sats")
    print(f"Send value        : {send_value} sats (utxo {utxo_value} - fee {rough_fee})")

    tx = Transaction(network="signet", witness_type="segwit")
    prev_txid_bytes = bytes.fromhex(prev_txid_hex)

    tx.add_input(
        prev_txid_bytes,
        vout,
        value=utxo_value,
        # For native P2WPKH, bitcoinlib uses script_type='sig_pubkey' with
        # witness_type='segwit'.
        script_type="sig_pubkey",
        keys=[key],
        witness_type="segwit",
    )
    tx.add_output(send_value, dest_address)

    # Let bitcoinlib sign so scripts/witness are consistent
    tx.sign()

    # Effective fee is simply input - outputs
    tx.update_totals()
    fee_effective = tx.fee

    # Ensure txid is consistent with the final serialized transaction.
    # For segwit, txid is computed over the non-witness serialization.
    # bitcoinlib.signature_hash() without arguments returns this txid preimage hash.
    tx.txid = tx.signature_hash()[::-1].hex()

    raw = tx.raw()
    size_bytes = len(raw)
    feerate_effective = fee_effective / size_bytes if size_bytes > 0 else 0.0

    print("\n[Transaction fee / size]")
    print(f"  size (bytes)        : {size_bytes}")
    print(f"  requested feerate   : {sats_per_vb} sats/vB")
    print(f"  chosen fee          : {fee_effective} sats")
    print(f"  effective sats/byte : {feerate_effective:.3f} sats/byte")

    print("\n[Transaction summary]")
    print(f"  TxID        : {tx.txid}")
    print(f"  Raw (hex)   : {raw.hex()}")

    return tx


def main() -> None:
    """End-to-end demo for fee rate vs vsize on a simple P2WPKH tx."""
    key, prev_txid_hex, vout, utxo_value, dest_address, sats_per_vb = read_inputs()
    tx = build_signed_p2wpkh_tx(
        key=key,
        prev_txid_hex=prev_txid_hex,
        vout=vout,
        utxo_value=utxo_value,
        dest_address=dest_address,
        sats_per_vb=sats_per_vb,
    )

    # Note: We do not auto-broadcast here; the goal is to inspect fee and size.
    # You can copy the raw hex above and push it via a Signet block explorer.
    print("\n=== Fee rate demo complete (no automatic broadcast) ===")


if __name__ == "__main__":
    main()
