#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P2WPKH RBF demo - low-fee opt-in transaction.

This script builds and broadcasts a 1-in 1-out native P2WPKH transaction on
Signet with:

- sequence set to an RBF-eligible value
- a relatively low fee rate (sats/vB)

It is intended to be replaced later by a higher-fee transaction spending the
same UTXO (see p2wpkh_rbf_bump_fee.py).
"""

from __future__ import annotations

from bitcoinlib.keys import Key
from bitcoinlib.transactions import Transaction
from bitcoinlib.services.services import Service


def read_inputs() -> tuple[Key, str, int, int, str, int]:
    print("=== P2WPKH RBF Demo - Create Low-Fee Tx ===\n")

    wif = input("WIF for signing key (Signet, required): ").strip()
    prev_txid_hex = input("Prev txid (hex, big-endian): ").strip()
    vout_str = input("Prev output index (vout): ").strip()
    value_str = input("Prev output value (sats): ").strip()
    dest_address = input("Destination address (P2WPKH bech32 recommended): ").strip()
    feerate_str = input("Low fee rate (sats/vB, e.g. 1): ").strip()

    if not (wif and prev_txid_hex and vout_str and value_str and dest_address and feerate_str):
        raise ValueError("All fields are required.")

    key = Key(import_key=wif, network="signet")
    vout = int(vout_str)
    utxo_value = int(value_str)
    sats_per_vb = int(feerate_str)

    if utxo_value <= 0:
        raise ValueError("UTXO value must be positive")
    if sats_per_vb <= 0:
        raise ValueError("Fee rate must be positive (sats/vB)")

    return key, prev_txid_hex, vout, utxo_value, dest_address, sats_per_vb


def build_and_broadcast_lowfee_tx(
    key: Key,
    prev_txid_hex: str,
    vout: int,
    utxo_value: int,
    dest_address: str,
    sats_per_vb: int,
) -> Transaction:
    print("\n=== Building low-fee RBF-enabled P2WPKH transaction ===")

    # Rough size guess for 1-in 1-out P2WPKH
    size_guess_vb = 110
    rough_fee = sats_per_vb * size_guess_vb
    if utxo_value <= rough_fee:
        raise ValueError(
            f"UTXO value {utxo_value} sats is not enough to pay fee {rough_fee} sats",
        )

    send_value = utxo_value - rough_fee
    print(f"Requested feerate : {sats_per_vb} sats/vB")
    print(f"Size guess (vB)   : {size_guess_vb}")
    print(f"Fee (approx)      : {rough_fee} sats")
    print(f"Send value        : {send_value} sats (utxo {utxo_value} - fee {rough_fee})")

    tx = Transaction(network="signet", witness_type="segwit")
    prev_txid_bytes = bytes.fromhex(prev_txid_hex)

    tx.add_input(
        prev_txid_bytes,
        vout,
        value=utxo_value,
        script_type="sig_pubkey",
        keys=[key],
        witness_type="segwit",
    )
    tx.add_output(send_value, dest_address)

    # Opt-in RBF: set sequence < 0xfffffffe (here we use 0xfffffffd)
    tx.inputs[0].sequence = 0xFFFFFFFD

    tx.sign()
    tx.update_totals()

    # Compute txid from non-witness serialization
    tx.txid = tx.signature_hash()[::-1].hex()

    raw = tx.raw()
    size_bytes = len(raw)
    fee_effective = tx.fee
    feerate_effective = fee_effective / size_bytes if size_bytes > 0 else 0.0

    print("\n[Low-fee RBF tx - fee / size]")
    print(f"  size (bytes)        : {size_bytes}")
    print(f"  chosen fee          : {fee_effective} sats")
    print(f"  effective sats/byte : {feerate_effective:.3f} sats/byte")

    print("\n[Low-fee RBF tx summary]")
    print(f"  TxID        : {tx.txid}")
    print(f"  Raw (hex)   : {raw.hex()}")

    # Broadcast via Service
    print("\nBroadcasting via Service (Signet)...")
    service = Service(network="signet")
    try:
        result = service.sendrawtransaction(raw.hex())
        print("\n✅ Low-fee transaction sent!")
        print(f"Service result: {result}")
        print(f"View on block explorer: https://mempool.space/signet/tx/{tx.txid}")
    except Exception as e:  # noqa: BLE001
        print(f"❌ Broadcast failed via Service: {e}")
        print("You can still use the raw hex above to push manually.")

    return tx


def main() -> None:
    key, prev_txid_hex, vout, utxo_value, dest_address, sats_per_vb = read_inputs()
    build_and_broadcast_lowfee_tx(
        key=key,
        prev_txid_hex=prev_txid_hex,
        vout=vout,
        utxo_value=utxo_value,
        dest_address=dest_address,
        sats_per_vb=sats_per_vb,
    )

    print("\n=== RBF low-fee tx demo complete ===")


if __name__ == "__main__":
    main()
