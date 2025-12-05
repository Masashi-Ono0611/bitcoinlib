#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual ScriptPubKey Example (P2WPKH)

This script copies the original `simple_signet_transaction.py` demo and adds a helper
function that manually builds the exact scriptPubKey (locking script) for a native
SegWit (P2WPKH) address.
"""

from bitcoinlib.wallets import Wallet, wallet_exists
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.transactions import Transaction
# Service import removed (unused)
from bitcoinlib.keys import HDKey, Key

# ---------------------------------------------------------------------------
# Helper: generate P2WPKH scriptPubKey (native SegWit) from a bech32 address
# ---------------------------------------------------------------------------
from bitcoinlib.encoding import addr_bech32_to_pubkeyhash
from bitcoinlib.scripts import Script
from bitcoinlib.config.opcodes import op

def p2wpkh_scriptpubkey(bech32_addr: str) -> str:
    """Return the hex representation of the P2WPKH scriptPubKey for a bech32 address.

    Steps (mirrors what bitcoinlib does internally):
    1. Convert the bech32 address to the 20‑byte public‑key hash.
    2. Build a Script consisting of OP_0 followed by that hash.
    3. Return the script as a hex string.
    """
    # 1️⃣ bech32 → pubkey hash (20 bytes)
    pubkey_hash = addr_bech32_to_pubkeyhash(bech32_addr, as_hex=False)
    # 2️⃣ Build script: OP_0 <20‑byte‑hash>
    script = Script([op.op_0, pubkey_hash])
    return script.serialize().hex()

# ---------------------------------------------------------------------------
# Original wallet demo (unchanged apart from the added comment above)
# ---------------------------------------------------------------------------

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
    Send a transaction with change always directed to the specified address (Index 0).
    Uses the manual `p2wpkh_scriptpubkey` helper to construct the change output script.
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
                
                # Generate scriptPubKey for our fixed change address using our manual helper
                # This demonstrates the practical use of the helper function!
                script_hex = p2wpkh_scriptpubkey(change_address)
                
                # Convert hex string back to bytes for bitcoinlib
                output.lock_script = bytes.fromhex(script_hex)
                
                print(f"Updated to      : {change_address}")
                print(f"New ScriptPubKey: {script_hex}")
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
    """Demo workflow demonstrating signet transaction and manual scriptPubKey generation."""
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
    # Using our new function that uses manual scriptPubKey generation for change
    tx = send_with_fixed_change(
        wallet=wallet, 
        to_address=recipient_address, 
        amount_satoshis=amount_to_send,
        change_address=address  # <--- Fixed change address (Index 0)
    )
    
    if tx:
        print(f"View on block explorer: https://mempool.space/signet/tx/{tx.txid}")

    # 5. Manual scriptPubKey demonstration
    print("\n5. Manual scriptPubKey generation for the recipient address:")
    script_hex = p2wpkh_scriptpubkey(recipient_address)
    print(f"scriptPubKey (hex): {script_hex}")

    print("\n=== Demo Complete ===")

if __name__ == "__main__":
    main()
