# x0 Quick Start Guide

Get your AI agents making payments in 15 minutes.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Deploy x0](#deploy-x0)
3. [Create Your Platform](#create-your-platform)
4. [Choose Your Integration Pattern](#choose-your-integration-pattern)
5. [Pattern A: Session Keys](#pattern-a-session-keys-pre-funded)
6. [Pattern B: Agent Custody](#pattern-b-agent-custody-oauth-for-wallets)
7. [Testing](#testing)
8. [Going to Production](#going-to-production)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Docker and Docker Compose
- A Solana wallet with devnet SOL (for testing)
- Node.js 18+ or Python 3.10+ (for SDK)

---

## Deploy x0

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/x0-project/x0.git
cd x0

# Copy and configure environment
cp .env.example .env
```

Edit `.env` with minimum required settings:

```bash
# Database
DATABASE_URL=postgres://x0:x0password@postgres:5432/x0

# Redis
REDIS_URL=redis://redis:6379

# Security (REQUIRED - generate a secure 32+ char secret)
ADMIN_JWT_SECRET=your-super-secure-secret-at-least-32-chars

# Solana RPC (devnet for testing)
SOLANA_RPC_URL=https://api.devnet.solana.com

# Fee payer for gasless transactions (optional but recommended)
# Generate with: solana-keygen new --no-bip39-passphrase -o fee-payer.json
# Then paste the JSON array here:
DEVNET_FEE_PAYER_KEYPAIR=[1,2,3,4,...]
```

Start the server:

```bash
docker compose up -d

# Check logs
docker compose logs -f x0

# Verify it's running
curl http://localhost:3000/health
# {"status":"healthy","version":"0.1.0"}
```

### Option 2: Build from Source

```bash
cd packages/core

# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build and run
cargo build --release
./target/release/x0
```

---

## Create Your Platform

### Step 1: First Admin Login

On first run, create an admin account:

```bash
# The first admin login creates the account
curl -X POST http://localhost:3000/admin/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourplatform.com",
    "password": "your-secure-password"
  }'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 86400
}
```

### Step 2: Create Platform API Keys

```bash
export ADMIN_TOKEN="eyJhbGciOiJIUzI1NiIs..."

curl -X POST http://localhost:3000/admin/api-keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My AI Platform",
    "wallet_address": "YOUR_SOLANA_WALLET_ADDRESS"
  }'
```

Response:
```json
{
  "platform_id": "550e8400-e29b-41d4-a716-446655440000",
  "test_key": "x0_test_abc123def456...",
  "live_key": "x0_live_xyz789ghi012...",
  "created_at": "2025-01-24T12:00:00Z"
}
```

**Important:** Save both keys securely. The `live_key` won't be shown again.

---

## Choose Your Integration Pattern

| Pattern | Best For | User Experience |
|---------|----------|-----------------|
| **Session Keys** | Fixed budgets, one-time tasks | User deposits upfront |
| **Agent Custody** | Long-running agents, ongoing access | User grants wallet access |

---

## Pattern A: Session Keys (Pre-Funded)

Best for: AI assistants with fixed session budgets (e.g., "Give my agent $50 to spend today")

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. User creates session key with spending limits                │
│ 2. User deposits SOL/USDC to session key address               │
│ 3. Agent spends autonomously within limits                      │
│ 4. Unused funds can be withdrawn by user                        │
└─────────────────────────────────────────────────────────────────┘
```

### TypeScript Integration

```typescript
import { X0Client } from '@x0/sdk';

const x0 = new X0Client({
  apiKey: 'x0_test_abc123...',
  baseUrl: 'http://localhost:3000'
});

// Step 1: Create session key for user
const sessionKey = await x0.sessionKeys.create({
  ownerWallet: 'USER_WALLET_PUBKEY',      // User's main wallet
  spendingLimitSol: 1.0,                   // Max 1 SOL total
  spendingLimitUsdc: 100.0,                // Max 100 USDC total
  dailyLimitSol: 0.5,                      // Max 0.5 SOL per day
  expiresInHours: 24                       // Expires in 24 hours
});

console.log('Session key created:', sessionKey);
// {
//   id: "sk_...",
//   publicKey: "SessionKeyPubkey...",
//   depositAddress: "DepositAddress...",
//   status: "pending_deposit",
//   instructions: {
//     deposit_sol: "solana transfer DepositAddress 1.0",
//     deposit_usdc: "spl-token transfer ... DepositAddress 100"
//   }
// }

// Step 2: User deposits funds (frontend/wallet interaction)
// ... user signs and sends deposit transaction ...

// Step 3: Verify deposit was received
const status = await x0.sessionKeys.getStatus(sessionKey.id);
console.log('Status:', status.status); // "active"
console.log('Balance:', status.balance); // { sol: 1.0, usdc: 0 }

// Step 4: Agent makes payments
const payment = await x0.payments.create({
  sessionKeyId: sessionKey.id,
  amount: 0.1,
  token: 'SOL',
  recipient: 'MERCHANT_WALLET',
  memo: 'Coffee purchase'
});

console.log('Payment:', payment.status); // "confirmed"
console.log('Tx:', payment.transactionSignature);

// Step 5: Check remaining balance
const updated = await x0.sessionKeys.getStatus(sessionKey.id);
console.log('Remaining:', updated.balance); // { sol: 0.9, usdc: 0 }
```

### cURL Example

```bash
# Create session key
curl -X POST http://localhost:3000/api/v1/session-keys/create \
  -H "Authorization: Bearer x0_test_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "owner_wallet": "USER_WALLET_PUBKEY",
    "spending_limit_sol": 1.0,
    "expires_in_hours": 24
  }'

# Make payment
curl -X POST http://localhost:3000/api/v1/payments \
  -H "Authorization: Bearer x0_test_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "session_key_id": "sk_...",
    "amount": 0.1,
    "token": "SOL",
    "recipient": "MERCHANT_WALLET"
  }'
```

---

## Pattern B: Agent Custody (OAuth for Wallets)

Best for: Long-running AI agents that need ongoing wallet access with granular controls.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. User encrypts their keypair client-side                      │
│ 2. User grants custody with spending rules                      │
│ 3. Agent stores access_secret securely                          │
│ 4. Agent signs transactions within rules                        │
│ 5. User can revoke anytime                                      │
└─────────────────────────────────────────────────────────────────┘
```

### TypeScript Integration

```typescript
import { X0Client, encryptKeypair } from '@x0/sdk';
import { Keypair } from '@solana/web3.js';

const x0 = new X0Client({
  apiKey: 'x0_test_abc123...',
  baseUrl: 'http://localhost:3000'
});

// Step 1: User encrypts their keypair (client-side)
// IMPORTANT: This happens in the user's browser/device
const userKeypair = Keypair.generate(); // or loaded from wallet
const { encryptedKeypair, clientNonce } = await encryptKeypair(userKeypair);

// Step 2: Grant custody to agent with spending rules
const custody = await x0.custody.grant({
  agentId: 'shopping-agent-001',
  userWallet: userKeypair.publicKey.toBase58(),
  encryptedKeypair: encryptedKeypair,
  clientNonce: clientNonce,
  expiresInDays: 30,
  spendingRules: {
    maxTransactionAmountSol: 0.5,      // Max 0.5 SOL per transaction
    maxTransactionAmountUsdc: 50,      // Max 50 USDC per transaction
    dailyLimitSol: 2.0,                // Max 2 SOL per day
    dailyLimitUsdc: 200,               // Max 200 USDC per day
    allowedRecipients: [               // Whitelist (empty = allow all)
      'MERCHANT_A_WALLET',
      'MERCHANT_B_WALLET'
    ],
    allowedPrograms: [                 // Program whitelist
      '11111111111111111111111111111111',  // System Program
      'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'  // Token Program
    ],
    requireApprovalAboveSol: 1.0       // Need user approval above 1 SOL
  }
});

console.log('Custody granted:', custody);
// {
//   custody_id: "cust_...",
//   access_secret: "sec_abc123...",  // ⚠️ SHOWN ONCE - STORE SECURELY
//   user_wallet: "UserWalletPubkey",
//   expires_at: "2025-02-24T12:00:00Z",
//   warning: "Store access_secret securely. It will not be shown again."
// }

// Step 3: Agent stores access_secret securely
// (in encrypted storage, secret manager, etc.)

// Step 4: Agent signs transactions
import { Transaction, SystemProgram, LAMPORTS_PER_SOL } from '@solana/web3.js';

// Build unsigned transaction
const transaction = new Transaction().add(
  SystemProgram.transfer({
    fromPubkey: userKeypair.publicKey,
    toPubkey: new PublicKey('MERCHANT_WALLET'),
    lamports: 0.1 * LAMPORTS_PER_SOL
  })
);

// Sign with custody
const signed = await x0.custody.sign(custody.custody_id, {
  accessSecret: custody.access_secret,
  transactionBase64: transaction.serializeMessage().toString('base64')
});

// Submit to Solana
const connection = new Connection('https://api.devnet.solana.com');
const txSignature = await connection.sendRawTransaction(
  Buffer.from(signed.signedTransaction, 'base64')
);

console.log('Transaction:', txSignature);

// Step 5: Revoke custody when done
await x0.custody.revoke(custody.custody_id, {
  accessSecret: custody.access_secret
});
```

### cURL Example

```bash
# Grant custody
curl -X POST http://localhost:3000/api/v1/custody/grant \
  -H "Authorization: Bearer x0_test_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "shopping-agent-001",
    "user_wallet": "USER_WALLET_PUBKEY",
    "encrypted_keypair": "BASE64_ENCRYPTED_DATA",
    "client_nonce": "BASE64_NONCE",
    "expires_in_days": 30,
    "spending_rules": {
      "max_transaction_amount_sol": 0.5,
      "daily_limit_sol": 2.0,
      "allowed_recipients": ["MERCHANT_WALLET"]
    }
  }'

# Sign transaction
curl -X POST http://localhost:3000/api/v1/custody/CUSTODY_ID/sign \
  -H "Authorization: Bearer x0_test_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "access_secret": "sec_abc123...",
    "transaction_base64": "BASE64_UNSIGNED_TX"
  }'
```

---

## Setting Up Webhooks

```bash
# Configure webhook URL for your platform
curl -X PATCH http://localhost:3000/admin/platforms/YOUR_PLATFORM_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "webhook_url": "https://your-app.com/webhooks/x0",
    "webhook_secret": "whsec_your-webhook-secret"
  }'
```

Webhook events:
- `session.created` / `session.revoked`
- `session_key.created` / `session_key.revoked`
- `payment.created` / `payment.confirmed` / `payment.failed`

---

## Testing

### Test Mode vs Live Mode

| Mode | API Key Prefix | Network | Real Money? |
|------|---------------|---------|-------------|
| Test | `x0_test_` | Devnet | No |
| Live | `x0_live_` | Mainnet | Yes |

### Get Devnet SOL

```bash
# Using Solana CLI
solana airdrop 2 YOUR_WALLET_ADDRESS --url devnet

# Or use the faucet
# https://faucet.solana.com/
```

### Test Payment Flow

```bash
# 1. Create a test session key
curl -X POST http://localhost:3000/api/v1/session-keys/create \
  -H "Authorization: Bearer x0_test_..." \
  -d '{"owner_wallet": "...", "spending_limit_sol": 1.0}'

# 2. Deposit devnet SOL to the session key address
solana transfer SESSION_KEY_ADDRESS 1.0 --url devnet

# 3. Make a test payment
curl -X POST http://localhost:3000/api/v1/payments \
  -H "Authorization: Bearer x0_test_..." \
  -d '{"session_key_id": "...", "amount": 0.1, "token": "SOL", "recipient": "..."}'

# 4. Verify on explorer
# https://explorer.solana.com/tx/TX_SIGNATURE?cluster=devnet
```

---

## Going to Production

### 1. Environment Changes

```bash
# Switch to mainnet RPC (use a paid provider for reliability)
SOLANA_RPC_URL=https://your-helius-or-quicknode-url.com

# Add mainnet fee payer
MAINNET_FEE_PAYER_KEYPAIR=[...]

# Configure Lit Protocol for production
LIT_NETWORK=datil
LIT_CAPACITY_CREDIT_TOKEN_ID=your-production-token

# Use strong secrets
ADMIN_JWT_SECRET=super-long-random-secure-production-secret
```

### 2. Use Live API Keys

```typescript
const x0 = new X0Client({
  apiKey: 'x0_live_xyz789...',  // Live key for mainnet
  baseUrl: 'https://your-x0-instance.com'
});
```

### 3. Production Checklist

- [ ] Mainnet RPC URL configured
- [ ] Fee payer wallet funded with SOL
- [ ] Lit Protocol production credentials
- [ ] HTTPS/TLS enabled
- [ ] Database backups configured
- [ ] Monitoring/alerting set up
- [ ] Webhook endpoints secured (verify signatures)
- [ ] Rate limiting configured
- [ ] Spending limits tested thoroughly

---

## Troubleshooting

### Common Issues

#### "Invalid API key"
```bash
# Check your API key format
echo $API_KEY | head -c 8
# Should show: x0_test_ or x0_live_
```

#### "Session key not found"
```bash
# Verify the session key exists
curl http://localhost:3000/api/v1/session-keys/list \
  -H "Authorization: Bearer x0_test_..."
```

#### "Spending limit exceeded"
```bash
# Check current spending
curl http://localhost:3000/api/v1/spending/check \
  -H "Authorization: Bearer x0_test_..." \
  -d '{"session_key_id": "...", "amount": 0.1, "token": "SOL"}'
```

#### "Transaction failed"
- Check the Solana explorer for detailed error
- Ensure sufficient balance (SOL for fees + transfer amount)
- Verify recipient address is valid

### Health Check

```bash
# Basic health
curl http://localhost:3000/health

# Detailed health (shows component status)
curl http://localhost:3000/health/detailed
```

### Logs

```bash
# Docker logs
docker compose logs -f x0

# Filter for errors
docker compose logs x0 2>&1 | grep -i error
```

---

## Next Steps

- [Full API Reference](docs/api-reference.md)
- [TypeScript SDK Documentation](packages/sdk-typescript/README.md)
- [Python SDK Documentation](packages/sdk-python/README.md)
- [Enterprise Features](docs/enterprise.md)
- [Community Discord](https://discord.gg/x0)

