#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fixed Change Address Example (Signet)

This script demonstrates how to force transaction change to always return to a specific
address (Index 0) instead of generating new change addresses each time.

Behavior:
- Input: Automatically selects optimal UTXOs from all addresses managed by SignetWallet1
- Output (Change): Always hardcoded to Index 0 address (tb1qwaxaccl2h32kuem9p2mwstz8ych9ep88ueaay0)

This mimics single-address wallet behavior and is useful for understanding address reuse.
"""

from bitcoinlib.wallets import Wallet, wallet_exists
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.keys import HDKey, Key
from bitcoinlib.encoding import addr_bech32_to_pubkeyhash
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op


def create_or_open_signet_wallet(wallet_name='SignetWallet1'):
    """Create a new signet wallet if it does not exist, otherwise open existing one.

    The function prints the mnemonic (if newly created) and the HD root key in both WIF and HEX.
    """
    mnemonic = None
    if wallet_exists(wallet_name):
        print(f"Opening existing signet wallet: {wallet_name}")
        wallet = Wallet(wallet_name)
    else:
        print(f"Creating new signet wallet: {wallet_name}")
        mnemonic = Mnemonic().generate()
        wallet = Wallet.create(name=wallet_name, keys=mnemonic, network='signet')

    # ---- Parent HD key (wallet root/account) ----
    parent_wif = None
    parent_hex = None
    try:
        parent_wif = wallet.wif(is_private=True)
        parent_hd = HDKey(import_key=parent_wif,
                          network=wallet.network.name,
                          witness_type=wallet.witness_type)
        parent_hex = parent_hd.private_hex
    except Exception as e:
        print(f"Could not derive parent HD key material: {e}")

    print("\nParent HD key (wallet root/account):")
    if mnemonic:
        print(f"  MNEMONIC: {mnemonic}")
        print("  (Store this phrase securely; it is NOT saved in the wallet database.)")
    else:
        print("  MNEMONIC: <not available for existing wallets>")

    print(f"  WIF (HD): {parent_wif or '<could not derive>'}")
    print(f"  HEX (HD priv): {parent_hex or '<could not derive>'}")

    # ---- Child key for index 0 (first receive address) ----
    try:
        addresses = wallet.addresslist()
        first_address = addresses[0] if addresses else wallet.get_key().address
        wk = wallet.key(first_address)
        child_hex = wk.key_private.hex() if wk.key_private else None
        child_wif = None
        if child_hex:
            child_key = Key(import_key=child_hex,
                            network=wallet.network.name,
                            compressed=True,
                            is_private=True)
            child_wif = child_key.wif()

        print("\nChild key for index 0 (first receive address):")
        print(f"  ADDRESS: {first_address}")
        print(f"  WIF (single): {child_wif or '<no private key bytes stored>'}")
        print(f"  HEX (single): {child_hex or '<no private key bytes stored>'}")
    except Exception as e:
        print(f"Could not derive key material for first receive address: {e}")

    return wallet


def get_signet_address(wallet):
    """Show the first (index 0) receive address for this signet wallet.

    This does NOT advance the internal key cursor; it always returns the earliest external address so that the same receive address is shown on every run.
    """
    addresses = wallet.addresslist()
    first_address = addresses[0] if addresses else wallet.get_key().address
    print(f"Signet address: {first_address}")
    print("Send signet Bitcoin to this address to fund the wallet")
    return first_address


def check_balance(wallet):
    """Check wallet balance."""
    wallet.utxos_update()
    balance = wallet.balance()
    print(f"Current balance: {balance} satoshis")
    return balance


def send_with_fixed_change(wallet, to_address, amount_satoshis, change_address, fee_satoshis=1000):
    """
    Send a transaction with change always directed to the specified address.
    
    Args:
        wallet: Wallet object
        to_address: Recipient address
        amount_satoshis: Amount to send in satoshis
        change_address: Address to receive change (hardcoded to Index 0)
        fee_satoshis: Transaction fee in satoshis
    
    Returns:
        WalletTransaction object if successful, None otherwise
    """
    print(f"\n--- Transaction Details ---")
    print(f"Recipient : {to_address}")
    print(f"Amount    : {amount_satoshis:,} sat")
    print(f"Fee       : {fee_satoshis:,} sat")
    print(f"Change -> : {change_address} (Fixed to Index 0)")
    
    # Update UTXOs
    wallet.utxos_update()
    
    # Create transaction (auto-selects optimal UTXOs)
    print("\nCreating transaction...")
    try:
        tx = wallet.transaction_create(
            output_arr=[(to_address, amount_satoshis)],
            fee=fee_satoshis,
            number_of_change_outputs=1,
            min_confirms=0  # Allow spending unconfirmed outputs for testing
        )
        
        print(f"Selected {len(tx.inputs)} input(s), {len(tx.outputs)} output(s)")
        
        # Modify change output to use our fixed address
        change_found = False
        for output in tx.outputs:
            if output.change:
                print(f"\nChange output found: {output.value:,} sat")
                print(f"Original address: {output.address}")
                
                # Generate scriptPubKey for our fixed change address
                pubkey_hash = addr_bech32_to_pubkeyhash(change_address, as_hex=False)
                new_script = Script([op.op_0, pubkey_hash])
                output.lock_script = new_script.serialize()
                
                print(f"Updated to      : {change_address}")
                change_found = True
                break
        
        if not change_found:
            print("No change output found (exact amount or error).")

        # Sign and verify
        print("\nSigning transaction...")
        tx.sign()
        
        if not tx.verify():
            print("❌ Transaction verification failed!")
            return None
        
        print("✅ Transaction verified")
        
        # Broadcast
        print("\nBroadcasting...")
        tx.send()
        
        if tx.pushed:
            print(f"\n✅ Transaction sent successfully!")
            print(f"TxID: {tx.txid}")
            return tx
        else:
            print(f"❌ Broadcast failed: {tx.error}")
            return None

    except Exception as e:
        print(f"Error sending transaction: {e}")
        return None


def main():
    """Demo workflow demonstrating signet transaction with fixed change address."""
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

    # 4. Example transaction (uncomment when funded)
    print("\n4. Example transaction (uncomment when wallet is funded):")
    recipient_address = 'tb1qy7wesaxe39pra897mreqt42g45z2c4wajr3mxu'
    amount_to_send = 10_000  # 10,000 satoshis (0.0001 BTC)
    
    tx = send_with_fixed_change(
        wallet=wallet, 
        to_address=recipient_address, 
        amount_satoshis=amount_to_send,
        change_address=address  # <--- Fixed change address (Index 0)
    )
    
    if tx:
        print(f"View on block explorer: https://mempool.space/signet/tx/{tx.txid}")

    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()
