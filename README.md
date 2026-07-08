# Base Approval Checker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Built for Base](https://img.shields.io/badge/Built%20for-Base-0052FF)](https://base.org)

A public GitHub Actions template that daily scans a wallet's **active
token approvals** on Base — one of the most common and most overlooked
attack vectors in crypto.

## Why this matters

When you interact with a dApp, you often grant it an "approval" — a
standing permission to move a specific token (or, for NFTs, your whole
collection) on your behalf. Most people forget these exist. If the
approved contract is later exploited or turns out malicious, everything
covered by that old, forgotten approval can be drained — sometimes
years after you granted it.

## What it does

1. Scans historical `Approval` (ERC-20) and `ApprovalForAll`
   (ERC-721/1155) events on Base for your wallet.
2. For every unique token/collection ↔ spender/operator pair found,
   checks the **current** on-chain state directly — not just the old
   event — since the approval may have already been reduced or revoked.
3. Reports every still-active approval, flagging unlimited (or
   effectively unlimited) amounts as high-risk.

## ⚠️ This tool is read-only

It never asks for your private key and cannot revoke anything by
itself — it only reads public blockchain data. To actually revoke an
approval, use a trusted tool:

- https://revoke.cash
- Basescan or Blockscout's "Token Approvals" page for your address

Always double-check what you're signing in your wallet before
confirming a revoke transaction.

## Quick start

### 1. Get a free Blockscout Pro API key

1. https://dev.blockscout.com/ → Login
2. Create an API key (the free tier covers Base)

### 2. Add the secret to your repository

**Settings → Secrets and variables → Actions → New repository secret**
- Name: `BLOCKSCOUT_API_KEY`
- Value: your key

### 3. Add your wallet(s) to `wallets.json`

```json
[
  "0xYourAddress1",
  "0xYourAddress2"
]
```

### 4. Run it manually

**Actions → Base Approval Checker → Run workflow**

After that it runs automatically once a day at 10:00 UTC (change the
`cron` line in `.github/workflows/check.yml` to adjust).

## Example output

```
🔍 Checking 1 wallet(s) on Base (chainId=8453)
⚠️  Read-only tool — it never asks for your private key and cannot revoke anything.
⚠️  To actually revoke an approval, use https://revoke.cash or Basescan/Blockscout's Token Approvals page.

=== 0xYourAddress ===
🔴 UNLIMITED approval | token 0xabc...123 → spender 0xdef...456
🟡 Limited approval (5000000000000000000) | token 0xabc...789 → spender 0x111...222
📊 Total active approvals: 2 (1 high-risk / unlimited)
```

## Structure

```
.
├── wallets.json                  # your wallets (replace the example)
├── approval_checker.py            # main script
├── requirements.txt
└── .github/workflows/check.yml    # daily run + manual trigger
```

## Limitations

- Event scanning is paginated up to 10,000 events per wallet per event
  type — more than enough for the vast majority of wallets, but a
  template default you can raise in `approval_checker.py` if needed.
- This does not check whether a spender contract itself is verified or
  reputable — pair it with [Base Rug Pull Early
  Warning](https://github.com/khlndaaa/base-rugpull-warning) to also
  screen the contracts your approvals point to.
- Heuristic tool, not a substitute for using a well-audited revoke
  interface when actually taking action.

## License

MIT — use it, modify it, fork it freely.
