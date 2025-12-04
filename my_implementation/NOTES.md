# Bitcoin Signet Wallet Notes

This file summarizes what was learned while testing `simple_signet_transaction.py` on Bitcoin Signet.
This wallet uses native SegWit (P2WPKH) bech32 addresses.

## 1. HD Wallet basics

- **HD (Hierarchical Deterministic) wallet**
  - One *root* (parent) key can deterministically generate many child keys and addresses.
  - The structure is usually written as paths like `m/84'/1'/0'/0/0`.

- **Parent HD key (root / account)**
  - Often stored as an extended private key (`xprv`, `vprv` for test/signet).
  - Example from the script:
    - `WIF (HD)`: an extended private key (contains depth, index, chain code, etc.).
    - `HEX (HD priv)`: the 32-byte raw private key part extracted from the HD key.
  - This parent key is *not* usually imported directly into simple wallets that expect a single WIF.

- **Child key (single private key) for an address**
  - For a specific address (e.g. index 0 receive address), the wallet derives a child private key.
  - This child key can be represented as:
    - `HEX (single)`: 32-byte private key in hex.
    - `WIF (single)`: standard WIF for that single key (e.g. starting with `c` on signet/testnet).
  - For **single keys**, `HEX` and `WIF` are 1:1 convertible:
    - From HEX → WIF: use the network prefix + compression flag + Base58Check.
    - From WIF → HEX: decode Base58Check and remove prefix / flags.

- **Important difference: HD WIF vs single WIF**
  - **HD WIF (`vprv...`)**:
    - Extended private key (BIP32).
    - Contains: version, depth, parent fingerprint, child index, chain code, private key.
    - Not a simple 32-byte key and cannot be trivially treated as a single-key HEX.
  - **Single WIF (`c...` on signet)**:
    - Encodes only one private key (plus compression + network info).
    - Directly corresponds to one address.

## 2. Transaction timing and UTXO considerations

- **UTXO (Unspent Transaction Output)**
  - Every incoming transaction creates one or more UTXOs.
  - When sending a new transaction, the wallet selects UTXOs as inputs.

- **Why "No unspent transaction outputs found" can happen**
  - Example error:
    - `Create transaction: No unspent transaction outputs found or no key available for UTXO's`
  - Possible reasons:
    - All UTXOs are already spent by previous transactions.
    - New transactions are broadcast but not yet confirmed and the wallet / service does not expose them as spendable.
    - The wallet does not have the private key for the UTXOs (wrong wallet or wrong derivation path).

- **Waiting time after sending a transaction**
  - After broadcasting, the transaction needs to be:
    1. Seen by the Signet network.
    2. Included in a block (confirmed).
  - Until the transaction is confirmed, some services / libraries may not let you spend the new UTXOs created by that transaction.
  - If you send transactions **too quickly in a row**, you may see errors like:
    - `No unspent transaction outputs found`.

- **Practical tips when testing on Signet**
  - Do not send many transactions back-to-back from the same wallet without waiting.
  - If you see UTXO-related errors:
    - Wait some time and try again.
    - Check the transaction status in a Signet block explorer using the `txid`.
  - Always check the wallet balance and UTXO state before constructing another transaction.

## 3. Script behavior summary

- Shows **parent HD key** information:
  - MNEMONIC (only when creating a new wallet).
  - `WIF (HD)` (extended private key).
  - `HEX (HD priv)` (raw 32-byte private key part of the HD key).
- Shows **child key for index 0**:
  - Address, `WIF (single)`, and `HEX (single)`.
- Sends a small Signet transaction (e.g. 10,000 satoshis) to another address when funded.

This file is meant to stay simple and practical, based on real behavior observed while running the script on Signet.

## 4. Python virtual environment (venv)

- **Why use venv**
  - Keeps this project’s Python packages isolated from the global system.
  - Avoids version conflicts between different projects.

- **How to create a venv (once per project)**
  ```bash
  python3 -m venv venv
  ```

- **How to activate the venv (macOS / Linux)**
  ```bash
  source venv/bin/activate
  ```
  - After activation, your shell prompt usually shows `(venv)`.

- **How to install dependencies inside the venv**
  ```bash
  pip install -r requirements.txt
  ```

- **How to run the Signet script inside the venv**
  ```bash
  source venv/bin/activate
  python simple_testnet_transaction.py
  ```

- **How to deactivate the venv**
  ```bash
  deactivate
  ```

- Keep all development and tests for this project inside the activated venv to make the environment reproducible.

## 5. Fixed Change Address Implementation (Address Reuse)

We implemented `fixed_change_address_example.py` to demonstrate how to force transaction change to return to a specific address (Index 0) instead of generating new change addresses.

### Why do this?
- **Standard HD Wallet Behavior**: Automatically generates a new "change address" for every transaction to protect privacy. This makes it hard to link all transactions to a single entity.
- **Single Address / Address Reuse Behavior**: Some users or specific use cases (like exchange deposit addresses or simple cold storage) prefer to consolidate all funds into a single known address.

### Implementation Details
The `bitcoinlib` library does not support a `change_address` parameter in its high-level `send_to()` method. We worked around this by manually modifying the transaction before signing:

1. **Create Transaction**: Use `wallet.transaction_create()` to let the library select optimal UTXOs and calculate fees.
2. **Identify Change Output**: Iterate through `tx.outputs` to find the output marked as `change=True`.
3. **Modify ScriptPubKey**:
   - The `Output.address` property is read-only in `bitcoinlib`.
   - We must manually construct the **P2WPKH ScriptPubKey** (lock script) for the target address.
   - Logic: `OP_0 <20-byte-pubkey-hash>`
   - We used `bitcoinlib.encoding.addr_bech32_to_pubkeyhash` to get the hash and `bitcoinlib.scripts.Script` to build the script.
4. **Sign & Broadcast**: Once the output script is updated, we sign and broadcast the transaction normally.

### Result
- The transaction sends funds to the recipient.
- The "change" (leftover funds) is sent back to the wallet's **Index 0 address**.
- This effectively consolidates funds and prevents the wallet from spreading UTXOs across many new addresses.
