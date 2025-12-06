#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple Taproot (P2TR) single-key address demo on Signet.

This script:
- Reads a single Signet WIF from stdin
- Derives the corresponding public key
- Shows a "classic" P2WPKH bech32 address for comparison
- Constructs a Taproot-style P2TR address using the same key material

Note:
- bitcoinlib has partial Taproot support: Address(script_type='p2tr', encoding='bech32', witver=1).
- This script is for *address generation and comparison only*; spending from
  P2TR is not covered here.
"""

from bitcoinlib.keys import Key, Address


def main() -> None:
    print("=== Taproot (P2TR) Single-Key Address Demo (Signet) ===\n")

    wif = input("Signet WIF (private key, required): ").strip()
    if not wif:
        raise ValueError("WIF is required")

    # Derive key from WIF on Signet
    key = Key(import_key=wif, network="signet")

    print("\n[Key material]")
    print(f"  network        : {key.network.name}")
    print(f"  is_private     : {key.is_private}")
    print(f"  public key hex : {key.public_hex}")

    # Classic P2WPKH bech32 address (for comparison)
    # Key.address() takes (compressed, prefix, script_type, encoding).
    # For a native SegWit P2WPKH we use script_type="p2wpkh" and encoding="bech32".
    p2wpkh_addr = key.address(script_type="p2wpkh", encoding="bech32")
    print("\n[Classic native SegWit address]")
    print(f"  type           : P2WPKH (bech32, witness v0)")
    print(f"  address        : {p2wpkh_addr}")

    # Taproot P2TR address (bech32m, witness v1)
    # For this simple demo we use the public key bytes as `data` and let
    # Address(...) derive the SHA256 and encoding as configured for p2tr.
    taproot_addr_obj = Address(
        data=key.public_byte,
        script_type="p2tr",
        encoding="bech32",
        network="signet",
        witver=1,
    )

    print("\n[Taproot-style address]")
    print(f"  type           : P2TR (Taproot, bech32m, witness v1)")
    print(f"  address        : {taproot_addr_obj.address}")

    print("\n=== P2TR address demo complete ===")


if __name__ == "__main__":
    main()
