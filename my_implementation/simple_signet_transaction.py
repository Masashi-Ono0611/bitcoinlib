#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bitcoin Signet Transaction Example

This script demonstrates how to:
1. Create a signet wallet
2. Generate a new address
3. Send a transaction on Bitcoin signet
4. Broadcast the transaction

Requirements:
- BitcoinLib installed
- Signet Bitcoin (can be obtained from faucets)
"""

from bitcoinlib.wallets import Wallet, wallet_exists
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.transactions import Transaction
# Service import removed (unused)
from bitcoinlib.keys import HDKey, Key
# This wallet uses native SegWit (P2WPKH) bech32 addresses

def create_or_open_signet_wallet(wallet_name='SignetWallet1'):
    """Create a new signet wallet if it does not exist, otherwise open existing one.

    In both cases, show the first key's private key in WIF and HEX for inspection.
    """

    mnemonic = None

    if wallet_exists(wallet_name):
        print(f"Opening existing signet wallet: {wallet_name}")
        wallet = Wallet(wallet_name)
    else:
        print(f"Creating new signet wallet: {wallet_name}")
        mnemonic = Mnemonic().generate()
        
        # Create wallet (Signet) from mnemonic
        wallet = Wallet.create(
            name=wallet_name,
            keys=mnemonic,
            network='signet'
        )

    # ---- Parent HD key (wallet root/account) ----
    parent_wif = None
    parent_hex = None
    try:
        parent_wif = wallet.wif(is_private=True)
        parent_hd = HDKey(import_key=parent_wif, network=wallet.network.name, witness_type=wallet.witness_type)
        parent_hex = parent_hd.private_hex
    except Exception as e:
        print(f"Could not derive parent HD key material: {e}")

    print("\nParent HD key (wallet root/account):")
    if mnemonic:
        print(f"  MNEMONIC: {mnemonic}")
        print("  (Store this phrase securely; it is NOT saved in the wallet database.)")
    else:
        print("  MNEMONIC: <not available for existing wallets>")

    if parent_wif:
        print(f"  WIF (HD): {parent_wif}")
    else:
        print("  WIF (HD): <could not derive>")
    if parent_hex:
        print(f"  HEX (HD priv): {parent_hex}")
    else:
        print("  HEX (HD priv): <could not derive>")

    # ---- Child key for index 0 (first receive address) ----
    try:
        addresses = wallet.addresslist()
        if not addresses:
            # If there are no addresses yet, create the first one explicitly
            k = wallet.get_key()
            first_address = k.address
        else:
            first_address = addresses[0]

        wk = wallet.key(first_address)

        # WalletKey stores the private key bytes for this address
        child_hex = wk.key_private.hex() if wk.key_private else None
        child_wif = None
        if child_hex:
            # Interpret HEX as a single private key (not HD) and export as standard WIF
            child_key = Key(import_key=child_hex, network=wallet.network.name, compressed=True, is_private=True)
            child_wif = child_key.wif()

        print("\nChild key for index 0 (first receive address):")
        print(f"  ADDRESS: {first_address}")
        if child_wif:
            print(f"  WIF (single): {child_wif}")
        else:
            print("  WIF (single): <no private key bytes stored>")
        if child_hex:
            print(f"  HEX (single): {child_hex}")
        else:
            print("  HEX (single): <no private key bytes stored>")
    except Exception as e:
        print(f"Could not derive key material for first receive address: {e}")
    
    return wallet

def get_signet_address(wallet):
    """Show the first (index 0) receive address for this signet wallet.

    This does NOT advance the internal key cursor; it always returns the
    earliest external address so that the same receive address is shown
    on every run.
    """

    # Get all known external addresses (both used/unused). The first one
    # corresponds to the initial receive address derived for this wallet.
    addresses = wallet.addresslist()
    if not addresses:
        # If for some reason no addresses exist yet, create one explicitly
        key = wallet.get_key()
        first_address = key.address
    else:
        first_address = addresses[0]

    print(f"Signet address: {first_address}")
    print("Send signet Bitcoin to this address to fund the wallet")
    return first_address

def check_balance(wallet):
    """Check wallet balance"""
    wallet.utxos_update()
    balance = wallet.balance()
    print(f"Current balance: {balance} satoshis")
    return balance

def send_transaction(wallet, to_address, amount_satoshis, fee_satoshis=1000):
    """Create and send a transaction on signet"""
    if wallet.balance() < amount_satoshis + fee_satoshis:
        print("Insufficient balance!")
        return None
    
    # Create transaction
    try:
        transaction = wallet.send_to(
            to_address=to_address,
            amount=amount_satoshis,
            fee=fee_satoshis,
            broadcast=True  # Automatically broadcast
        )
        
        print(f"Transaction sent!")
        print(f"Transaction ID: {transaction.txid}")
        
        return transaction
        
    except Exception as e:
        print(f"Error sending transaction: {e}")
        return None

def sweep_wallet(wallet, to_address, fee_satoshis=1000):
    """Sweep all funds from wallet on signet"""
    wallet.utxos_update()
    
    if wallet.balance() == 0:
        print("No funds to sweep!")
        return None
    
    try:
        transaction = wallet.sweep(
            to_address=to_address,
            fee=fee_satoshis,
            broadcast=True
        )
        
        print(f"All funds swept!")
        print(f"Transaction ID: {transaction.txid}")
        
        return transaction
        
    except Exception as e:
        print(f"Error sweeping wallet: {e}")
        return None

def main():
    """Main function demonstrating signet transaction"""
    print("=== Bitcoin Signet Transaction Demo ===\n")
    
    # 1. Create or open wallet
    print("1. Creating or opening signet wallet...")
    wallet = create_or_open_signet_wallet()
    
    # 2. Get address
    print("\n2. Getting signet address...")
    address = get_signet_address(wallet)
    
    # 3. Check balance
    print("\n3. Checking balance...")
    check_balance(wallet)
    
    # 4. Example: Send transaction (uncomment when funded)
    print("\n4. Example transaction (uncomment when wallet is funded):")
    # Send 10,000 satoshis to another signet address
    recipient_address = 'tb1qy7wesaxe39pra897mreqt42g45z2c4wajr3mxu'
    amount_to_send = 10000  # 10,000 satoshis (0.0001 BTC)
    print(f"\nSending {amount_to_send} satoshis to {recipient_address}...")
    try:
        tx = send_transaction(wallet, recipient_address, amount_to_send)
        if tx:
            print(f"Transaction sent!")
            print(f"Transaction ID: {tx.txid}")
            print(f"View on block explorer: https://mempool.space/signet/tx/{tx.txid}")
    except Exception as e:
        print(f"Error sending transaction: {e}")
    
        
    print("\n=== Demo Complete ===")

if __name__ == "__main__":
    main()
