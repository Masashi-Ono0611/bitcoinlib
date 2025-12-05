# Bitcoin Signet Wallet Notes

This file summarizes what was learned while testing `simple_signet_transaction.py` and related
manual transaction scripts in `my_implementation/` on Bitcoin Signet.
The main wallet example uses native SegWit (P2WPKH) bech32 addresses.

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
  python my_implementation/simple_signet_transaction.py
  ```

- **How to deactivate the venv**
  ```bash
  deactivate
  ```

- Keep all development and tests for this project inside the activated venv to make the environment reproducible.

## 5. Fixed Change Address Implementation (Address Reuse)

We implemented `p2wpkh_change_output_fixed_example.py` to demonstrate how to force transaction change to return to a specific address (Index 0) instead of generating new change addresses.

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

## 6. P2WPKH ScriptPubKey & Manual Signing Examples

Two scripts in `my_implementation/` focus on understanding native SegWit (P2WPKH) locking scripts and the
difference between "wallet does the signing" vs "you do everything by hand":

- `p2wpkh_scriptpubkey_wallet_sign.py`
  - Manually constructs a **P2WPKH scriptPubKey** but still lets bitcoinlib / the wallet handle signing.
  - Useful to see how a bech32 address maps to `OP_0 <20-byte-pubkey-hash>` and how the wallet fills in the
    witness and other transaction details.

- `p2wpkh_scriptpubkey_manual_sign.py`
  - Goes further and **manually signs** a P2WPKH transaction:
    - Constructs the scriptPubKey by hand.
    - Builds the transaction inputs/outputs explicitly.
    - Computes the signature hash (`SIGHASH_ALL`).
    - Creates the DER-encoded signature and assembles the **witness stack** manually.
  - Prints detailed logging (tx hash, pubkey, signature, witness contents) so you can see the exact
    bytes that go on-chain.

These scripts are intended as learning tools: start from the wallet-driven version, then compare it to the
fully manual version to understand what the library usually does under the hood.

## 7. Legacy P2SH 1-of-2 Multisig (Manual Signing)

There are two scripts dedicated to a simple **legacy P2SH 1-of-2 multisig** flow on Signet.

### 7.1 Address creation: `p2sh_1of2_create_address.py`

- Reads **two WIF private keys** from the CLI (no wallet DB access).
- Derives the corresponding compressed public keys and builds the standard 1-of-2 multisig redeemScript:

  ```text
  OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
  ```

- Computes `hash160(redeemScript)` and then the **legacy P2SH scriptPubKey**:

  ```text
  OP_HASH160 <20-byte-redeem-hash> OP_EQUAL
  ```

- Derives and prints the **Signet P2SH address** for funding.
- This script is "policy only": it does **not** sign or send any transaction, it just tells you
  "If you lock coins to this P2SH address, they will be spendable by 1-of-2 signatures from these keys".

### 7.2 Spending from P2SH 1-of-2: `p2sh_1of2_spend_manual_sign.py`

This script demonstrates **manual construction of the unlocking script (scriptSig)** for the P2SH UTXO.

- CLI inputs (signer perspective):
  - Two WIF keys (same pair used to create the address).
  - The **P2SH funding address** which currently holds the UTXO.
  - UTXO info: `prev_txid` (big-endian hex), `vout`, and `value` (satoshis).
  - Destination address (e.g. P2WPKH bech32).

- Safety check:
  - Rebuilds the 1-of-2 redeemScript from the two WIF keys.
  - Derives the corresponding P2SH address.
  - If the derived P2SH **does not match** the user-supplied funding address, the script raises an error
    and aborts. This ensures you only spend if your keys actually control the specified P2SH address.

- Fee and amount handling:
  - Fee is fixed inside the script to **1000 satoshis** for simplicity.
  - The send amount is computed automatically as `send_value = utxo_value - fee`.

- Transaction construction and manual signing:
  - Builds a 1-input / 1-output **legacy P2SH** transaction (`witness_type='legacy'`).
  - Uses only **Key 1** for the actual signature (1-of-2), while Key 2 is only part of the redeemScript.
  - Computes the legacy `SIGHASH_ALL` signature hash for the input.
  - Creates a DER-encoded signature and builds the **scriptSig** manually as:

    ```text
    scriptSig = OP_0 <sig1> <redeemScript>
    ```

  - Attaches this unlocking script to the input and verifies the transaction using bitcoinlib's
    `tx.verify()`.

- Logging and broadcast:
  - Prints:
    - txid
    - raw transaction hex
    - scriptSig hex
    - signature hash and signature
  - Attempts to broadcast the transaction to Signet via `Service(network="signet").sendrawtransaction(raw_hex)`.
    - If your local `providers.json` has working Signet providers, the script will print the broadcast
      result and a mempool.space URL.
    - Even if providers are not configured, you can always copy the printed **raw hex** and push it
      manually via a Signet block explorer.

### 7.3 Funding the P2SH address on Signet

To get a spendable P2SH UTXO for the above demo:

1. Use `simple_signet_transaction.py` (or another Signet wallet) to obtain some Signet coins.
2. Run `p2sh_1of2_create_address.py` with two WIF keys to generate a P2SH address.
3. From your funded wallet, send some coins to that P2SH address and wait until the transaction is
   visible/confirmed on Signet (check with a block explorer).
4. Take the **funding txid**, output index (`vout`), and value (satoshis) from the explorer and feed them
   into `p2sh_1of2_spend_manual_sign.py` along with the two WIFs and your desired destination address.

This creates a full educational cycle: **create P2SH address → fund it → manually construct and sign a
spend transaction → broadcast on Signet**.

## 8. Legacy P2SH vs Native P2WSH 1-of-2 (Quick Comparison)

The scripts `p2sh_1of2_*` and `p2wsh_1of2_*` use **exactly the same multisig policy**:

- Policy (both):
  - `OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG` (1-of-2)
  - In P2SH this lives as a **redeemScript**, in P2WSH as a **witnessScript**.

The differences are only *where* this policy is hashed and *where* the unlocking data is placed:

- **Locking script / address**
  - Legacy P2SH (`p2sh_1of2_*`):
    - `hash160(redeemScript)` → `OP_HASH160 <20-byte-hash> OP_EQUAL`
    - Address is base58 (`2...` on Signet).
  - Native P2WSH (`p2wsh_1of2_*`):
    - `sha256(witnessScript)` → `OP_0 <32-byte-hash>`
    - Address is bech32 (`tb1q...`).

- **Unlocking data**
  - Legacy P2SH:
    - `scriptSig = OP_0 <sig1> <redeemScript>`
    - Witness is empty.
  - Native P2WSH:
    - `scriptSig` is empty.
    - Witness stack: `[OP_0, <sig1>, <witnessScript>]`.

- **TxID and malleability**
  - P2SH: txid is computed over the entire transaction **including scriptSig**.
    - Changing the signature or redeemScript changes the txid → malleable.
  - P2WSH: txid is computed **without** the witness; signatures only affect `wtxid`.
    - This reduces malleability and is one of the main reasons SegWit was introduced.

By running both flows end-to-end (P2SH and P2WSH) with the same keys and 1-of-2 policy, you can see how
only the *placement* of the policy and signatures changes between the legacy and SegWit worlds.
