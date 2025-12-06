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

## 8. Legacy P2SH, Nested P2SH-P2WSH, and Native P2WSH 1-of-2 (Quick Comparison)

The scripts `p2sh_1of2_*`, `p2sh_p2wsh_1of2_*`, and `p2wsh_1of2_*` use **exactly the same multisig policy**:

- Policy (both):
  - `OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG` (1-of-2)
  - In P2SH this lives as a **redeemScript**, in P2WSH as a **witnessScript**.

The differences are only *where* this policy is hashed and *where* the unlocking data is placed:

- **Locking script / address**
  - Legacy P2SH (`p2sh_1of2_*`):
    - `hash160(redeemScript)` → `OP_HASH160 <20-byte-hash> OP_EQUAL`
    - Address is base58 (`2...` on Signet).
  - Nested P2SH-P2WSH (`p2sh_p2wsh_1of2_*`):
    - `witnessScript` is hashed with SHA256 and wrapped in a P2WSH **redeemScript**:
      - `redeemScript = OP_0 <32-byte-SHA256(witnessScript)>`.
    - The outer P2SH script then uses `hash160(redeemScript)`:
      - `OP_HASH160 <20-byte-hash160(redeemScript)> OP_EQUAL`.
    - Address is also base58 (`2...`), but the inner program is SegWit.
  - Native P2WSH (`p2wsh_1of2_*`):
    - `sha256(witnessScript)` → `OP_0 <32-byte-hash>`
    - Address is bech32 (`tb1q...`).

- **Unlocking data**
  - Legacy P2SH:
    - `scriptSig = OP_0 <sig1> <redeemScript>`
    - Witness is empty.
  - Nested P2SH-P2WSH:
    - `scriptSig` only pushes the P2WSH redeemScript:
      - `scriptSig = <redeemScript = OP_0 <SHA256(witnessScript)>>`.
    - Witness stack is the same as native P2WSH: `[OP_0, <sig1>, <witnessScript>]`.
  - Native P2WSH:
    - `scriptSig` is empty.
    - Witness stack: `[OP_0, <sig1>, <witnessScript>]`.

- **TxID and malleability**
  - P2SH: txid is computed over the entire transaction **including scriptSig**.
    - Changing the signature or redeemScript changes the txid → malleable.
  - P2SH-P2WSH: txid is still computed without the witness; the scriptSig only contains
    the redeemScript (no signatures), so modifying signatures in the witness does *not*
    change the txid. In practice this behaves like P2WSH for malleability.
  - P2WSH: txid is computed **without** the witness; signatures only affect `wtxid`.
    - This reduces malleability and is one of the main reasons SegWit was introduced.

By running all three flows end-to-end (P2SH, P2SH-P2WSH, and P2WSH) with the same keys and 1-of-2 policy,
you can see how only the *placement* and *wrapping* of the policy and signatures changes between the
legacy and SegWit worlds.

## 9. nLockTime vs CLTV / CSV vs Coinbase Maturity (High-level Overview)

The script `p2wpkh_scriptpubkey_manual_sign_nlocktime.py` adds an **absolute block-height lock** using
the transaction's `nLockTime` field. This is different from script-level timelocks such as
`OP_CHECKLOCKTIMEVERIFY` (CLTV) and `OP_CHECKSEQUENCEVERIFY` (CSV), and from the special **coinbase
100-block maturity** rule.

- **nLockTime (transaction-level non-finality)**
  - `nLockTime` lives in the transaction header (not in the script).
  - If `nLockTime > 0` and at least one input has `sequence < 0xffffffff`, then:
    - The transaction is **non-final** until `current_height_or_time >= nLockTime`.
    - Non-final transactions **cannot enter the mempool or be mined**.
  - This is what you see in the nLockTime demo: using a future block height causes
    `non-final` errors on broadcast; using a height at or below the current height succeeds.

- **CLTV / CSV (script-level timelocks)**
  - `OP_CHECKLOCKTIMEVERIFY` (CLTV) and `OP_CHECKSEQUENCEVERIFY` (CSV) live inside the locking
    script (e.g. a P2WSH witnessScript).
  - The *funding* transaction that creates the UTXO can be mined immediately.
  - The **spend** transaction must satisfy the script condition:
    - CLTV: absolute height/time ("not before block X/UNIX-time T").
    - CSV: relative to the age of the UTXO ("not before N blocks after this UTXO was created").
  - Intuitively: the UTXO **exists on-chain**, but its spending path is locked by the script
    until the time/height condition is met.

- **Coinbase 100-block maturity (special consensus rule)**
  - Coinbase outputs have an extra rule baked into consensus:
    - They cannot be spent until **100 blocks** have passed (on mainnet; different on some networks).
  - This is *not* implemented via `nLockTime` or CLTV/CSV.
  - Validation code treats coinbase-derived UTXOs specially and rejects any spend that occurs
    before the required number of confirmations.

In short:

- `nLockTime` → "Is this **transaction as a whole** allowed into mempool/blocks yet?"
- CLTV / CSV → "Is this **UTXO's spending script** satisfied yet?"
- Coinbase maturity → "Is this **coinbase UTXO** old enough to be spent?" (hard-coded consensus rule).

### 9.1 P2WSH CLTV (single-key) demo scripts

Two additional scripts show how to build and spend a **single-key P2WSH timelock** using
`OP_CHECKLOCKTIMEVERIFY` (CLTV):

- `p2wsh_cltv_single_create_address.py`
  - Takes one Signet WIF and an absolute block-height `CLTV locktime`.
  - Builds a P2WSH witnessScript:
    - `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG`
  - Derives the P2WSH address and scriptPubKey from this witnessScript.
  - The funding transaction to this address can be mined immediately, but the UTXO
    can only be spent by transactions that satisfy the CLTV condition.

- `p2wsh_cltv_single_spend_manual_sign.py`
  - Reconstructs the same witnessScript from WIF + CLTV locktime.
  - Verifies that the reconstructed script matches the provided funding P2WSH address.
  - Reads UTXO info (prev txid, vout, value) and a destination address.
  - Lets you specify **two different lock values**:
    - CLTV locktime (script-level, must equal the funding script's locktime).
    - Transaction `nLockTime` (tx-level). For CLTV to pass, `nLockTime >= CLTV locktime`.
  - Manually signs the input and builds the P2WSH witness stack `[<sig>, <witnessScript>]`.
  - Shows how:
    - Wrong `nLockTime` (e.g. lower than CLTV) leads to
      `mandatory-script-verify-flag-failed (Locktime requirement not satisfied)`.
    - Correct `nLockTime` (>= CLTV and <= current height) lets the tx be accepted.

This pair makes the separation very concrete:

- CLTV locktime (in the script) is the **contract written on the UTXO**.
- `nLockTime` is the **claim made by this specific transaction**.
- The node enforces both the **contract** (CLTV) and the **finality rules**
  (`nLockTime` vs current height and `sequence`).

### 9.2 Bitcoin vs Ethereum (failed timelocks)

It is also useful to contrast how Bitcoin and Ethereum handle failed time-lock
conditions:

- **Bitcoin**
  - Scripts (including CLTV/CSV) are used to decide whether a transaction is
    **valid to be in the mempool or a block**.
  - If script evaluation fails (e.g. CLTV requirement not satisfied), the
    transaction is simply **rejected** and never becomes part of the blockchain.
  - There is no concept of "a transaction that got mined but then reverted due to
    a script error".

- **Ethereum**
  - Smart contracts execute **inside** a transaction that is already included in
    a block.
  - If a condition fails (`require`, `revert`, etc.), the contract can roll back
    its state changes, but the **transaction itself remains on-chain** as a
    failed transaction.

In short:

- Bitcoin: failed script/timelock → transaction is not accepted into the block
  at all.
- Ethereum: failed contract condition → transaction is included, but the
  contract logic reverts its effects.

### 9.3 P2WSH CSV (single-key) demo scripts

The CSV (relative lock) demos mirror the CLTV ones, but use
`OP_CHECKSEQUENCEVERIFY` (CSV) instead of `OP_CHECKLOCKTIMEVERIFY`.

- `p2wsh_csv_single_create_address.py`
  - Takes one Signet WIF and a **relative lock** in blocks (e.g. `1`, `5`).
  - Builds a P2WSH witnessScript:
    - `<sequence> OP_CHECKSEQUENCEVERIFY OP_DROP <pubkey> OP_CHECKSIG`
  - Derives the P2WSH address and scriptPubKey from this witnessScript.
  - The funding transaction to this address can be mined immediately, but the
    UTXO can only be spent by transactions that satisfy the CSV condition.

- `p2wsh_csv_single_spend_manual_sign.py`
  - Reconstructs the same witnessScript from WIF + CSV relative lock (blocks).
  - Verifies that the reconstructed script matches the provided funding
    P2WSH address.
  - Reads UTXO info (prev txid, vout, value) and a destination address.
  - Sets the input **sequence** to the same CSV relative lock value.
  - Manually signs the input and builds the P2WSH witness stack
    `[<sig>, <witnessScript>]`.
  - Demonstrates that:
    - If the UTXO does **not yet have enough confirmations** relative to the
      CSV value, script evaluation fails with a locktime-related error and the
      node rejects the transaction.
    - Once enough blocks have passed (UTXO age >= CSV blocks), the same spend
      transaction pattern is accepted.

Together with the CLTV demos, the CSV scripts highlight the difference between
**absolute time locks** (CLTV + nLockTime) and **relative time locks** (CSV
based on sequence and UTXO age) in Bitcoin.

## 10. Future learning topics

Based on the current understanding (P2WPKH, P2WSH, P2SH-P2WSH, nLockTime, CLTV,
and CSV), the next topics to explore are:

- **Fee, mempool, RBF/CPFP**
  - How fee rate (sats/vB) and transaction size interact
  - Replace-By-Fee (RBF) and Child-Pays-For-Parent (CPFP) behavior
- **PSBT flow**
  - Partially Signed Bitcoin Transactions for multi-step / hardware wallet flows
- **Miniscript-style policy thinking**
  - Expressing conditions as policies (and/or/after/before) rather than raw opcodes
- **Taproot (P2TR) overview**
  - Key-path vs script-path spends and script trees
- **Coin selection policies**
  - Simple strategies for picking UTXOs and the trade-offs between fee, privacy, and UX

### 10.3 PSBT and SIGHASH modes (high-level)

The PSBT-style demos (`p2wpkh_psbt_sighash_all_demo.py` and
`p2wpkh_psbt_sighash_single_anyonecanpay_demo.py`) helped clarify how different
SIGHASH modes change **what a signature commits to** inside a transaction.

- **SIGHASH_ALL**
  - "Normal" wallet behavior.
  - A signature on input *i* commits to:
    - **All inputs** `[in0, in1, ..., inN]` and
    - **All outputs** `[out0, out1, ..., outM]`.
  - Any later change to inputs or outputs invalidates the signature.
  - Intuitively: "Sign the **entire transaction** as it is".

- **SIGHASH_SINGLE (without ANYONECANPAY)**
  - For a signature on input *i*:
    - **Inputs**: still commits to **all inputs** (like SIGHASH_ALL).
    - **Outputs**: commits only to **output *i*** (same index as the input).
  - Example mental model:
    - `input[0] = 10k sats`, `input[1] = 5k sats` (total 15k).
    - `output[0] = 8k sats → Address B` is **locked by the signature**.
    - The remaining `7k sats` can later be split into fees and/or other
      outputs (e.g. `output[1] = 7k → Address C`) **without breaking this
      particular signature**, as long as the full input set is unchanged.
  - Intuitively: "Lock my input *i* to a specific output *i*, but leave
    other outputs flexible".

- **SIGHASH_SINGLE | ANYONECANPAY**
  - For a signature on input *i*:
    - **Inputs**: commits only to **input *i*** (due to ANYONECANPAY).
      Other inputs are *not* part of the signed hash and can be added or
      changed later.
    - **Outputs**: commits only to **output *i*** (due to SINGLE).
      Other outputs are not part of the signed hash and can be added or
      changed later.
  - Example mental model:
    - `input[0] = 10k sats` (my input).
    - `output[0] = 8k sats → Address B` is **locked by my signature**.
    - The remaining `2k sats` (fee or change to C, etc.) **and** any
      additional `input[1], input[2], ...` and `output[1], output[2], ...`
      are free to be added/changed later by others without invalidating
      my signature on `input[0]`.
  - Intuitively: "I only commit to **my own input and its corresponding
    output**. The rest of the transaction can be assembled later".

#### 10.3.1 Notes about the SINGLE|ANYONECANPAY demo

- The script `p2wpkh_psbt_sighash_single_anyonecanpay_demo.py` is intentionally
  written as a **didactic PSBT / SIGHASH demo**, not as production-ready code.
- It successfully shows, at the library level:
  - How to construct a custom SIGHASH type (`SIGHASH_SINGLE|ANYONECANPAY`).
  - That the resulting `tx_hash` differs from the SIGHASH_ALL case.
  - How a signature can conceptually commit only to a single
    input/output pair.
- However, when broadcasting to Signet, the node rejects the transaction with:

  > `mandatory-script-verify-flag-failed (Script evaluated without error but
  > finished with a false/empty top stack element)`

  meaning that the node's view of the SIGHASH_SINGLE|ANYONECANPAY rules does
  **not match** the way the library computed the hash/signature in this demo.

- In practice, for **real transactions** I should stick to **SIGHASH_ALL**
  with bitcoinlib. The SINGLE|ANYONECANPAY demo is kept as an educational
  reference to understand the theory of partial commitments in SIGHASH, but
  is not intended for real-world broadcasting.

### 10.4 Taproot (P2TR) experiments and limitations

Taproot (P2TR) support in this repository's version of bitcoinlib is
**partial**:

- The library understands script types such as `p2tr` / `p2tr_unlock` and
  stores them in the DB schema (witness type `p2tr`).
- The `Address` class can construct P2TR-style addresses when called with
  `script_type='p2tr', encoding='bech32', witver=1`, and correctly uses
  witness version 1 (bech32m).
- However, `transactions.py` explicitly logs that Taproot unlocking scripts
  are **not supported yet**:

  > "Taproot is not supported at the moment" (when parsing `p2tr_unlock`)

#### 10.4.1 What was actually tested

Using external Taproot-capable wallet software (e.g. Unisat), the following
experiments were performed on Signet:

- **P2WPKH → P2TR**
  - Spend a native SegWit v0 P2WPKH UTXO at address like
    `tb1qy7wesaxe39pra...` into:
    - `10,000 sats` to a Taproot P2TR address such as
      `tb1ptphs3ts86vmx2yxva3y62ttq8smx75a04e08qaxqxale7xkt5pcqyjvvtt`.
    - The remainder back to the same P2WPKH address as change.
  - Resulting outputs:
    - One **V1_P2TR** output (`OP_1 <32-byte key>`) with 10k sats.
    - One **V0_P2WPKH** change output.

- **P2TR → P2WPKH + P2TR change**
  - Spend the 10k-sat Taproot UTXO via a key-path Taproot spend
    (single Schnorr-style witness element) into:
    - `5,000 sats` to the P2WPKH address `tb1qy7wesaxe39pra...`.
    - `4,858 sats` back to the same P2TR address as change.
    - ~`142 sats` as fee.
  - Resulting outputs:
    - One **V0_P2WPKH** output (5k sats).
    - One **V1_P2TR** change output (4,858 sats).

These on-chain experiments confirm that:

- Funds can move freely between **v0 (P2WPKH)** and **v1 (P2TR)** outputs.
- The Taproot scriptPubKey format is correctly represented as
  `OP_1 <32-byte output key>`.

#### 10.4.2 Why P2TR spend demos are not implemented in this repo

Even though bitcoinlib can:

- Parse Taproot-related script types (`p2tr`, `p2tr_unlock`).
- Build P2TR-style addresses via `Address(script_type='p2tr', ...)`.

the crucial missing pieces for **fully local Taproot spend construction** are:

- A stable, exposed API for **Taproot key-path/script-path signing** (Schnorr
  signatures and correct Taproot SIGHASH behavior).
- A mature implementation of Taproot witness construction that matches
  full-node consensus behavior.

The library itself emits warnings like:

> "Taproot is not supported at the moment, rest of parsing input transaction
>  skipped"

Therefore, in this repository I currently treat Taproot as:

- **Address generation and transaction analysis only**:
  - Generate P2TR addresses for experimentation.
  - Inspect existing P2TR transactions and UTXOs on Signet.
- **Actual P2TR spending (signing and broadcasting)**:
  - Performed via external, Taproot-aware wallet software (e.g. Unisat
    or Bitcoin Core), not via the custom scripts here.

End-to-end manual spend demos (`P2TR → ...`) are intentionally **not
implemented** with bitcoinlib in this repo, because doing so reliably would
require extending or replacing its partial Taproot implementation, which is
out of scope for these learning notes.

### 10.1 RBF (Replace-By-Fee) basics

Key points learned from the RBF demos:

- **What "opt-in RBF" means**
  - Inputs have a 4-byte `nSequence` field.
  - Under BIP125, if **any input** has `nSequence < 0xfffffffe`, the transaction is
    considered to have **opted in to RBF**.
  - In the demos, the low-fee tx used `sequence = 0xfffffffd`, and the higher-fee
    replacement used `sequence = 0xfffffffe`.

- **Mempool-level replacement, not consensus**
  - RBF is a **mempool policy**, not a consensus rule.
  - A higher-fee transaction B can replace a lower-fee transaction A in a node's
    mempool **only while A is unconfirmed** and has opted-in to RBF.
  - Once a transaction that spends a UTXO is **confirmed in a block**, that UTXO is
    consumed and cannot be spent again by another transaction (double-spend rules),
    regardless of RBF.

- **Fee and feerate conditions**
  - The replacement transaction must pay a **higher absolute fee / feerate** than the
    transaction it replaces.
  - In the demos:
    - Low-fee tx: `~0.5–0.6 sats/byte`
    - High-fee tx: a few sats/byte higher, using the same single P2WPKH input.

- **Relationship with sequence, nLockTime, CSV**
  - `nSequence` is multiplexed across several concepts:
    - Legacy "final" vs non-final semantics
    - CLTV / `nLockTime` finality rules
    - CSV (`OP_CHECKSEQUENCEVERIFY`) relative locks
    - RBF opt-in (`sequence < 0xfffffffe`)
  - The RBF demos focused purely on the **"opt-in" side**: using a non-final
    sequence together with higher-fee replacements to observe mempool behavior.

### 10.2 CPFP (Child-Pays-For-Parent) basics

Key points learned from the CPFP demos:

- **Who can perform CPFP? (UTXO ownership)**
  - A child transaction can only spend UTXOs whose **private keys you control**.
  - Therefore, **you can perform CPFP if and only if at least one output of the parent
    transaction pays to an address you control** (you have the WIF / key).
  - It does not matter whether that output is a "payment" output or a "change" output;
    what matters is **ownership of the UTXO**.

- **No-change scenario (cannot CPFP by yourself)**
  - If the parent transaction has a single output which goes entirely to someone else,
    and you do **not** control that address's private key:
    - You cannot build a child transaction spending that UTXO.
    - Only the **receiver** can do CPFP by spending that UTXO with a high-fee child.

- **Change output scenario (sender-side CPFP)**
  - If the parent transaction has at least one **change output** back to an address you
    control (your own wallet):
    - You can construct a child transaction that spends your change UTXO.
    - By paying a high fee in the child, you effectively increase the **combined fee
      per vbyte** of the parent+child package.
  - In practice, this is how a sender can rescue a stuck low-fee parent transaction
    without the cooperation of the receiver.

- **Receiver-side CPFP**
  - If you receive a UTXO from a low-fee parent transaction (the output is to your
    address), you can also perform CPFP:
    - Construct a child transaction that spends your received UTXO.
    - Pay a high fee in the child to pull both parent and child into a block.
  - This is often used by wallets that want to accelerate incoming payments.

- **Parent vs child destinations**
  - CPFP does **not** require a special pattern of destinations; the only requirement
    is that the child spends at least one output of the parent.
  - Common patterns:
    - Parent: pay to receiver + change back to sender; child: spend sender's change.
    - Parent: pay to receiver; child: receiver spends that UTXO to another self-controlled
      address or onward payment.

- **Concrete example from the demo (Signet)**
  - Parent (low-fee) transaction:
    - 1 P2WPKH input, 1 P2WPKH output to the sender's own address (no explicit change).
    - Fee ≈ **110 sats**, virtual size ≈ **110 vB** → ≈ **1 sat/vB**.
  - Child (high-fee) transaction:
    - Spends the parent output (same P2WPKH key) to the same destination address.
    - Fee ≈ **1100 sats**, virtual size ≈ **109 vB** → ≈ **10 sat/vB**.
  - Combined parent+child package (as seen by the mempool):
    - Total fee ≈ **1210 sats**, total vsize ≈ **219 vB**.
    - Effective feerate ≈ **1210 / 219 ≈ 5.5 sats/vB**.
  - On mempool.space this showed up as:
    - Parent: feerate ≈ **1 sat/vB**.
    - Descendant child: feerate ≈ **10 sat/vB**.
    - **Effective fee rate ≈ 5.5 sat/vB** for the package.

In short:

- RBF: you (re)create the **same spend** with a higher-fee replacement transaction,
  typically keeping the same recipient and only adjusting the fee via the change.
- CPFP: you create a **new child transaction** that spends the parent UTXO(s) with a
  high fee, so that miners are incentivized to include both parent and child together.
