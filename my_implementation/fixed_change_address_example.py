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
from bitcoinlib.encoding import addr_bech32_to_pubkeyhash
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op


def create_or_open_signet_wallet(wallet_name='SignetWallet1'):
    """Create or open the signet wallet."""
    if wallet_exists(wallet_name):
        print(f"Opening existing wallet: {wallet_name}")
        wallet = Wallet(wallet_name)
    else:
        print(f"Creating new wallet: {wallet_name}")
        mnemonic = Mnemonic().generate()
        wallet = Wallet.create(name=wallet_name, keys=mnemonic, network='signet')
        print(f"Mnemonic: {mnemonic}")
        print("(Store this securely!)")
    return wallet


def get_index0_address(wallet):
    """Retrieve the Index 0 receive address."""
    addresses = wallet.addresslist()
    if not addresses:
        return wallet.get_key().address
    return addresses[0]


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
    tx = wallet.transaction_create(
        output_arr=[(to_address, amount_satoshis)],
        fee=fee_satoshis,
        number_of_change_outputs=1
    )
    
    print(f"Selected {len(tx.inputs)} input(s), {len(tx.outputs)} output(s)")
    
    # Modify change output to use our fixed address
    for output in tx.outputs:
        if output.change:
            print(f"\nChange output found: {output.value:,} sat")
            print(f"Original address: {output.address}")
            
            # Generate scriptPubKey for our fixed change address
            pubkey_hash = addr_bech32_to_pubkeyhash(change_address, as_hex=False)
            new_script = Script([op.op_0, pubkey_hash])
            output.lock_script = new_script.serialize()
            
            print(f"Updated to      : {change_address}")
            break
    
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
        print(f"Explorer: https://mempool.space/signet/tx/{tx.txid}")
        return tx
    else:
        print(f"❌ Broadcast failed: {tx.error}")
        return None


def main():
    print("=== Fixed Change Address Demo (Signet) ===\n")
    
    # 1. Open wallet
    wallet = create_or_open_signet_wallet()
    
    # 2. Get Index 0 address (fixed change destination)
    index0_address = get_index0_address(wallet)
    print(f"\nIndex 0 Address: {index0_address}")
    print("(All change will return to this address)")
    
    # 3. Check balance
    wallet.utxos_update()
    balance = wallet.balance()
    print(f"\nCurrent balance: {balance:,} satoshis")
    
    if balance == 0:
        print("\n⚠️  Wallet has no funds. Send signet BTC to the Index 0 address above.")
        return
    
    # 4. Send transaction
    recipient = 'tb1qy7wesaxe39pra897mreqt42g45z2c4wajr3mxu'
    amount = 10_000  # 0.0001 BTC
    
    tx = send_with_fixed_change(
        wallet=wallet,
        to_address=recipient,
        amount_satoshis=amount,
        change_address=index0_address,  # Hardcoded to Index 0
        fee_satoshis=1000
    )
    
    if tx:
        print("\n✅ Success! Check the block explorer to verify change went to Index 0.")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    main()
