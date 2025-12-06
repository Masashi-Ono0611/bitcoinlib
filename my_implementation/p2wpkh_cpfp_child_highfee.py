#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P2WPKH CPFP demo - high-fee child transaction.

This script spends the low-fee parent output created by
`p2wpkh_cpfp_parent_lowfee.py` and pays a higher fee rate, so that miners
have an incentive to include both parent and child together in a block
(Child Pays For Parent).
"""

from __future__ import annotations

from bitcoinlib.keys import Key
from bitcoinlib.transactions import Transaction
from bitcoinlib.services.services import Service


def read_inputs() -> tuple[Key, str, int, int, str, int]:
    print("=== P2WPKH CPFP Demo - High-Fee Child Tx ===\n")

    wif = input("WIF for signing key (Signet, required): ").strip()
    parent_txid_hex = input("Parent txid (hex, big-endian): ").strip()
    parent_vout_str = input("Parent output index (vout, usually 0): ").strip()
    parent_value_str = input("Parent output value (sats): ").strip()
    dest_address = input("Child destination address (P2WPKH bech32): ").strip()
    feerate_str = input("High fee rate (sats/vB, e.g. 5 or 10): ").strip()

    if not (wif and parent_txid_hex and parent_vout_str and parent_value_str and dest_address and feerate_str):
        raise ValueError("All fields are required.")

    key = Key(import_key=wif, network="signet")
    parent_vout = int(parent_vout_str)
    parent_value = int(parent_value_str)
    sats_per_vb = int(feerate_str)

    if parent_value <= 0:
        raise ValueError("Parent output value must be positive")
    if sats_per_vb <= 0:
        raise ValueError("Fee rate must be positive (sats/vB)")

    return key, parent_txid_hex, parent_vout, parent_value, dest_address, sats_per_vb


def build_and_broadcast_child_tx(
    key: Key,
    parent_txid_hex: str,
    parent_vout: int,
    parent_value: int,
    dest_address: str,
    sats_per_vb: int,
) -> Transaction:
    print("\n=== Building high-fee child P2WPKH transaction (CPFP) ===")

    # Rough size guess for 1-in 1-out P2WPKH
    size_guess_vb = 110
    rough_fee = sats_per_vb * size_guess_vb
    if parent_value <= rough_fee:
        raise ValueError(
            f"Parent output value {parent_value} sats is not enough to pay child fee {rough_fee} sats",
        )

    send_value = parent_value - rough_fee
    print(f"Requested high feerate : {sats_per_vb} sats/vB")
    print(f"Size guess (vB)        : {size_guess_vb}")
    print(f"Child fee (approx)     : {rough_fee} sats")
    print(f"Child send value       : {send_value} sats")

    tx = Transaction(network="signet", witness_type="segwit")
    parent_txid_bytes = bytes.fromhex(parent_txid_hex)

    tx.add_input(
        parent_txid_bytes,
        parent_vout,
        value=parent_value,
        script_type="sig_pubkey",
        keys=[key],
        witness_type="segwit",
    )
    tx.add_output(send_value, dest_address)

    tx.sign()
    tx.update_totals()

    # Compute txid from non-witness serialization
    tx.txid = tx.signature_hash()[::-1].hex()

    raw = tx.raw()
    size_bytes = len(raw)
    fee_effective = tx.fee
    feerate_effective = fee_effective / size_bytes if size_bytes > 0 else 0.0

    print("\n[Child (high-fee) tx - fee / size]")
    print(f"  size (bytes)        : {size_bytes}")
    print(f"  chosen fee          : {fee_effective} sats")
    print(f"  effective sats/byte : {feerate_effective:.3f} sats/byte")

    print("\n[Child (high-fee) tx summary]")
    print(f"  Child TxID          : {tx.txid}")
    print(f"  Raw (hex)           : {raw.hex()}")

    print("\nBroadcasting child via Service (Signet)...")
    service = Service(network="signet")
    try:
        result = service.sendrawtransaction(raw.hex())
        print("\n✅ Child (high-fee) transaction sent!")
        print(f"Service result: {result}")
        print(f"View on block explorer: https://mempool.space/signet/tx/{tx.txid}")
    except Exception as e:  # noqa: BLE001
        print(f"❌ Broadcast failed via Service: {e}")
        print("You can still use the raw hex above to push manually.")

    return tx


def main() -> None:
    key, parent_txid_hex, parent_vout, parent_value, dest_address, sats_per_vb = read_inputs()
    build_and_broadcast_child_tx(
        key=key,
        parent_txid_hex=parent_txid_hex,
        parent_vout=parent_vout,
        parent_value=parent_value,
        dest_address=dest_address,
        sats_per_vb=sats_per_vb,
    )

    print("\n=== CPFP high-fee child tx demo complete ===")


if __name__ == "__main__":
    main()
