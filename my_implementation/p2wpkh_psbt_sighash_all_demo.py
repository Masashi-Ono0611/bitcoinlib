#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Educational PSBT-style demo for a simple 1-in 1-out P2WPKH transaction
using SIGHASH_ALL.

This script does NOT rely on a dedicated PSBT class from bitcoinlib.
Instead, it builds a minimal "PSBT-like" Python dict that contains:

- the unsigned Transaction object
- the input UTXO information (scriptPubKey, value)
- the key (WIF) for signing

and then simulates a two-step flow:

1. "Online" part: construct the unsigned tx + PSBT-like container
2. "Signer" part: compute SIGHASH_ALL and add the signature into the tx

The resulting fully signed transaction is then broadcast on Signet.
"""

from bitcoinlib.keys import Key
from bitcoinlib.transactions import Transaction
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op
from bitcoinlib.encoding import addr_bech32_to_pubkeyhash
from bitcoinlib.services.services import Service
from bitcoinlib.transactions import sign as tx_sign


def build_p2wpkh_lock_script(address: str) -> bytes:
    """Build the P2WPKH lock script (scriptPubKey) for a bech32 address."""
    pubkey_hash = addr_bech32_to_pubkeyhash(address, as_hex=False)
    script = Script([op.op_0, pubkey_hash])
    return script.serialize()


def read_inputs():
    print("=== P2WPKH PSBT Demo - SIGHASH_ALL ===\n")

    wif = input("WIF for signing key (Signet, required): ").strip()
    prev_txid_hex = input("Prev txid (hex, big-endian): ").strip()
    vout_str = input("Prev output index (vout): ").strip()
    utxo_value_str = input("Prev output value (sats): ").strip()
    dest_address = input("Destination address (P2WPKH bech32): ").strip()
    feerate_str = input("Fee rate (sats/vB, e.g. 1-5): ").strip()

    if not (wif and prev_txid_hex and vout_str and utxo_value_str and dest_address and feerate_str):
        raise ValueError("All fields are required.")

    key = Key(import_key=wif, network="signet")
    vout = int(vout_str)
    utxo_value = int(utxo_value_str)
    sats_per_vb = int(feerate_str)

    if utxo_value <= 0:
        raise ValueError("UTXO value must be positive")
    if sats_per_vb <= 0:
        raise ValueError("Fee rate must be positive (sats/vB)")

    return key, prev_txid_hex, vout, utxo_value, dest_address, sats_per_vb


def build_unsigned_tx(key: Key, prev_txid_hex: str, vout: int, utxo_value: int, dest_address: str, sats_per_vb: int):
    """Construct an unsigned 1-in 1-out P2WPKH transaction and approximate fee by vsize guess."""
    size_guess_vb = 110
    rough_fee = sats_per_vb * size_guess_vb
    if utxo_value <= rough_fee:
        raise ValueError(
            f"UTXO value {utxo_value} sats is not enough to pay fee {rough_fee} sats",
        )

    send_value = utxo_value - rough_fee
    print("\n=== Building unsigned P2WPKH transaction (SIGHASH_ALL) ===")
    print(f"Requested feerate : {sats_per_vb} sats/vB")
    print(f"Size guess (vB)   : {size_guess_vb}")
    print(f"Fee (approx)      : {rough_fee} sats")
    print(f"Send value        : {send_value} sats")

    tx = Transaction(network="signet", witness_type="segwit")
    prev_txid_bytes = bytes.fromhex(prev_txid_hex)

    tx.add_input(
        prev_txid_bytes,
        vout,
        value=utxo_value,
        # Provide the key so bitcoinlib can derive the correct P2WPKH
        # locking_script / redeemscript and avoid 'Redeem script missing'.
        keys=[key],
        script_type="sig_pubkey",
        witness_type="segwit",
    )

    # For this simple P2WPKH demo, we let bitcoinlib construct the
    # scriptPubKey from the destination address, just like in
    # p2wpkh_fee_rate_demo_simple.py.
    tx.add_output(send_value, dest_address)

    return tx


def make_psbt_container(tx: Transaction, utxo_value: int, dest_address: str):
    """Build a minimal PSBT-like dict for educational purposes."""
    inp = tx.inputs[0]
    out = tx.outputs[0]

    psbt = {
        "unsigned_tx": tx,
        "inputs": [
            {
                "index": inp.index_n,
                "prev_txid": inp.prev_txid.hex(),
                "vout": inp.output_n_int,
                "value": utxo_value,
                "witness_type": inp.witness_type,
                "script_type": inp.script_type,
            }
        ],
        "outputs": [
            {
                "index": 0,
                "value": out.value,
                "destination": dest_address,
            }
        ],
    }

    print("\n[PSBT-like container summary]")
    print(f"  inputs[0].prev_txid : {psbt['inputs'][0]['prev_txid']}")
    print(f"  inputs[0].vout      : {psbt['inputs'][0]['vout']}")
    print(f"  inputs[0].value     : {psbt['inputs'][0]['value']} sats")
    print(f"  outputs[0].value    : {psbt['outputs'][0]['value']} sats")
    print(f"  outputs[0].dest     : {psbt['outputs'][0]['destination']}")

    return psbt


def signer_add_sighash_all_signature(psbt: dict, key: Key):
    """Simulate a signer that receives the PSBT-like object and adds a SIGHASH_ALL signature."""
    tx: Transaction = psbt["unsigned_tx"]
    inp = tx.inputs[0]

    # For this demo we rely on bitcoinlib's tx_sign helper, which supports arbitrary hash_type.
    # We keep the hash_type as the default SIGHASH_ALL on the input.
    tx_hash = tx.signature_hash(inp.index_n, inp.hash_type, inp.witness_type)
    print("\n[Signer] SIGHASH_ALL signing details:")
    print(f"  hash_type      : {inp.hash_type}")
    print(f"  tx_hash        : {tx_hash.hex()}")
    print(f"  pubkey         : {key.public_byte.hex()}")

    sig_obj = tx_sign(tx_hash, key, hash_type=inp.hash_type)
    sig_bytes = sig_obj.as_der_encoded()

    inp.signatures = [sig_obj]
    inp.witnesses = [sig_bytes, key.public_byte]
    inp.unlocking_script = b""

    # Update txid and fee-related fields without re-signing
    tx.txid = tx.signature_hash()[::-1].hex()
    tx.size = len(tx.raw())
    tx.calc_weight_units()
    tx.update_totals()
    if tx.fee:
        tx.fee_per_kb = int((tx.fee / float(tx.vsize)) * 1000)

    return tx


def broadcast_tx(tx: Transaction):
    print("\n[Final transaction]")
    print(f"  txid           : {tx.txid}")
    print(f"  size (bytes)   : {tx.size}")
    print(f"  vsize (vB)     : {tx.vsize}")
    print(f"  fee (sats)     : {tx.fee}")
    if tx.vsize:
        eff_rate = tx.fee / tx.vsize
        print(f"  fee rate       : {eff_rate:.3f} sats/vB")

    raw_hex = tx.raw_hex()
    print(f"\n  Raw (hex)      : {raw_hex}")

    print("\nBroadcasting via Service (Signet)...")
    srv = Service(network="signet")
    res = srv.sendrawtransaction(raw_hex)
    if not res or "txid" not in res:
        print("❌ Broadcast failed via Service:", srv.errors)
        print("You can still use the raw hex above to push manually.")
        return

    print("\n✅ Transaction sent!")
    print("Service result:", res)
    print(f"View on block explorer: https://mempool.space/signet/tx/{res['txid']}")


def main():
    key, prev_txid_hex, vout, utxo_value, dest_address, sats_per_vb = read_inputs()

    tx = build_unsigned_tx(key, prev_txid_hex, vout, utxo_value, dest_address, sats_per_vb)
    psbt = make_psbt_container(tx, utxo_value, dest_address)

    # In a real PSBT flow, the PSBT would now be serialized and sent to another
    # device (e.g. hardware wallet). Here we immediately act as the signer.
    signed_tx = signer_add_sighash_all_signature(psbt, key)

    if not signed_tx.verify():
        print("❌ Verification failed after signing")
        return

    print("\n✅ Transaction verified after signing")
    broadcast_tx(signed_tx)


if __name__ == "__main__":
    main()
