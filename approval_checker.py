#!/usr/bin/env python3
"""
Base Approval Checker (public template).

Forgotten token approvals are one of the most common attack vectors in
crypto: a wallet grants a contract permission to spend its tokens (an
"approval"), and if that contract later turns out malicious or gets
exploited, everything covered by the approval can be drained — even
years after the original transaction.

For every wallet in wallets.json, this script:

1. Scans historical ERC-20 `Approval` and ERC-721/1155 `ApprovalForAll`
   events on Base where the wallet is the owner.
2. For each unique (token, spender) / (collection, operator) pair found,
   checks the CURRENT on-chain state directly via `allowance()` /
   `isApprovedForAll()` — not just the historical event, since an
   approval may have already been reduced or revoked since.
3. Reports every still-active approval, flagging unlimited (or
   effectively unlimited) amounts as higher risk.

IMPORTANT: this tool is READ-ONLY. It does not revoke anything and
never needs your private key. If you want to actually revoke an
approval, use a trusted tool such as https://revoke.cash or the
"Token Approvals" feature on Basescan/Blockscout, and always verify
the transaction in your wallet before signing.
"""

import os
import json
import requests

CHAIN_ID = 8453  # Base mainnet
BLOCKSCOUT_URL = "https://api.blockscout.com/v2/api"
BASE_RPC_URL = "https://mainnet.base.org"

PLACEHOLDER_ADDRESS = "0x0000000000000000000000000000000000000000"

# Anything at or above this is treated as an effectively unlimited
# approval (the classic "max uint256" pattern wallets/dApps use).
UNLIMITED_THRESHOLD = 2**255

# keccak256("Approval(address,address,uint256)")
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
# keccak256("ApprovalForAll(address,address,bool)")
APPROVAL_FOR_ALL_TOPIC = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"

ALLOWANCE_SELECTOR = "0xdd62ed3e"            # allowance(address,address)
IS_APPROVED_FOR_ALL_SELECTOR = "0xe985e9c5"  # isApprovedForAll(address,address)

API_KEY = os.environ.get("BLOCKSCOUT_API_KEY")
WALLETS_FILE = os.environ.get("WALLETS_FILE", "wallets.json")

if not API_KEY:
    raise SystemExit("❌ BLOCKSCOUT_API_KEY secret is not set")


def load_json(path, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default


def pad_address(address):
    return "0x" + address.lower().replace("0x", "").zfill(64)


def fetch_logs(topic0, owner):
    """Fetch all logs matching topic0 with the wallet as topic1 (owner), paginated."""
    all_logs = []
    page = 1
    offset = 1000
    while page <= 10:  # safety cap: up to 10,000 events per wallet/topic
        params = {
            "chainid": CHAIN_ID,
            "apikey": API_KEY,
            "module": "logs",
            "action": "getLogs",
            "fromBlock": 0,
            "toBlock": "latest",
            "topic0": topic0,
            "topic1": pad_address(owner),
            "topic0_1_opr": "and",
            "page": page,
            "offset": offset,
        }
        try:
            resp = requests.get(BLOCKSCOUT_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as e:
            print(f"⚠️  Failed to fetch logs (page {page}): {e}")
            break

        result = data.get("result")
        if not isinstance(result, list) or not result:
            break

        all_logs.extend(result)
        if len(result) < offset:
            break
        page += 1

    return all_logs


def rpc_call(to, data):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
    }
    try:
        resp = requests.post(BASE_RPC_URL, json=payload, timeout=30)
        resp.raise_for_status()
        result = resp.json()
    except (requests.exceptions.RequestException, ValueError):
        return None
    if "error" in result:
        return None
    return result.get("result")


def get_current_allowance(token, owner, spender):
    data = ALLOWANCE_SELECTOR + pad_address(owner)[2:] + pad_address(spender)[2:]
    raw = rpc_call(token, data)
    if not raw or raw in ("0x", "0x0"):
        return None
    try:
        return int(raw, 16)
    except ValueError:
        return None


def get_is_approved_for_all(collection, owner, operator):
    data = IS_APPROVED_FOR_ALL_SELECTOR + pad_address(owner)[2:] + pad_address(operator)[2:]
    raw = rpc_call(collection, data)
    if raw is None:
        return None
    try:
        return int(raw, 16) != 0
    except ValueError:
        return None


def extract_pairs(logs):
    pairs = set()
    for log in logs:
        contract = log.get("address", "").lower()
        topics = log.get("topics", [])
        if not contract or len(topics) < 3:
            continue
        counterparty = ("0x" + topics[2][-40:]).lower()
        pairs.add((contract, counterparty))
    return pairs


def check_wallet(address):
    print(f"=== {address} ===")

    approval_logs = fetch_logs(APPROVAL_TOPIC, address)
    approval_for_all_logs = fetch_logs(APPROVAL_FOR_ALL_TOPIC, address)

    erc20_pairs = extract_pairs(approval_logs)
    nft_pairs = extract_pairs(approval_for_all_logs)

    active_count = 0
    high_risk_count = 0

    for token, spender in sorted(erc20_pairs):
        allowance = get_current_allowance(token, address, spender)
        if not allowance:
            continue  # None (call failed) or 0 (already revoked/never active)
        active_count += 1
        if allowance >= UNLIMITED_THRESHOLD:
            high_risk_count += 1
            print(f"🔴 UNLIMITED approval | token {token} → spender {spender}")
        else:
            print(f"🟡 Limited approval ({allowance}) | token {token} → spender {spender}")

    for collection, operator in sorted(nft_pairs):
        is_approved = get_is_approved_for_all(collection, address, operator)
        if not is_approved:
            continue
        active_count += 1
        high_risk_count += 1
        print(f"🔴 Full collection approval | {collection} → operator {operator}")

    if active_count == 0:
        print("🟢 No active approvals found")
    else:
        print(f"📊 Total active approvals: {active_count} ({high_risk_count} high-risk / unlimited)")


def main():
    wallets = load_json(WALLETS_FILE, [])
    wallets = [w for w in wallets if w.lower() != PLACEHOLDER_ADDRESS]

    if not wallets:
        print(
            f"⚠️  {WALLETS_FILE} has no real addresses (only the example placeholder). "
            f"Add your own wallets to get a result."
        )
        return

    print(f"🔍 Checking {len(wallets)} wallet(s) on Base (chainId={CHAIN_ID})")
    print("⚠️  Read-only tool — it never asks for your private key and cannot revoke anything.")
    print("⚠️  To actually revoke an approval, use https://revoke.cash or Basescan/Blockscout's Token Approvals page.")

    for address in wallets:
        print("")
        check_wallet(address)


if __name__ == "__main__":
    main()
