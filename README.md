# x0

**Payment infrastructure for AI agents.** Non-custodial, programmable spending limits, OAuth-style wallet delegation.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Solana](https://img.shields.io/badge/solana-2.0-purple.svg)](https://solana.com/)

![x0 Architecture](imgs/34kgyvbqg5rmr0cvxvrs2dtwjc_result_.gif)

## What is x0?

x0 is a self-hosted payment infrastructure that enables AI agents to spend crypto autonomously within user-defined limits. Think of it as **"Stripe for AI Agents"** or **"OAuth for Wallets"**.

**Key principles:**
- **Non-custodial** — x0 never has access to user funds
- **Agent-first** — Built for autonomous AI spending
- **Self-hosted** — Run on your own infrastructure
- **Solana-native** — Fast, cheap transactions

## Features

### Core (Open Source)

| Feature | Description |
|---------|-------------|
| **Agent Sessions** | Time-limited authorization for AI agents to make payments |
| **Session Keys** | Delegated signing keys with spending constraints |
| **Agent Custody** | OAuth-style wallet delegation with spending rules |
| **Spending Limits** | Per-transaction, daily limits, recipient/program whitelists |
| **Gasless Payments** | Users don't need SOL for transaction fees |
| **Webhooks** | Real-time payment status notifications |
| **WebAuthn/Passkeys** | Passwordless authentication |
| **Multi-Network** | Test (devnet) and Live (mainnet) modes |

### Enterprise (Licensed)

| Feature | Description |
|---------|-------------|
| **Advanced Analytics** | Usage tracking, cost analysis, optimization insights |
| **Compliance** | SOC2 audit logs, GDPR tools, data export |
| **SSO** | SAML/OIDC enterprise authentication |
| **White-label** | Custom branding and domains |

## Quick Start

### 1. Deploy x0 (Docker)

```bash
git clone https://github.com/x0-project/x0.git
cd x0

# Configure environment
cp .env.example .env
# Edit .env with your DATABASE_URL, REDIS_URL, Solana RPC, etc.

# Start the server
docker compose up -d
```

### 2. Get API Keys

```bash
# Create admin account and get API keys
curl -X POST http://localhost:3000/admin/api-keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"name": "My AI Platform", "wallet_address": "YOUR_WALLET"}'

# Response: { "test_key": "x0_test_...", "live_key": "x0_live_..." }
```

### 3. Integrate with Your AI Agent

**TypeScript:**

```typescript
import { X0Client } from '@x0/sdk';

const x0 = new X0Client({
  apiKey: 'x0_test_...',
  baseUrl: 'http://localhost:3000'
});

// Create session key for user
const sessionKey = await x0.sessionKeys.create({
  ownerWallet: 'USER_WALLET',
  spendingLimitSol: 1.0,
  expiresInHours: 24
});

// AI agent makes autonomous payment
const payment = await x0.payments.create({
  sessionKeyId: sessionKey.id,
  amount: 0.1,
  token: 'SOL',
  recipient: 'MERCHANT_WALLET'
});
```

**Python (LangChain):**

```python
from langchain_zendfi import ZendFiToolkit

toolkit = ZendFiToolkit(api_key="x0_test_...")
agent = create_react_agent(llm, toolkit.get_tools())

# Agent can now make payments autonomously
agent.invoke("Buy me a coffee for 0.1 SOL")
```

**See [QUICKSTART.md](QUICKSTART.md) for the complete integration guide.**

## Integration Patterns

### Pattern A: Session Keys (Pre-Funded)
User creates a session key with SOL/USDC pre-deposited. Agent spends within limits.

```
User → [Creates Session Key + Deposits 1 SOL] → Agent → [Spends up to 1 SOL]
```

### Pattern B: Agent Custody (OAuth-Style)
User grants scoped wallet access to agent. Agent signs transactions within spending rules.

```
User → [Grants Custody with Rules] → Agent → [Signs within limits]
         │
         └── max_per_tx: 0.5 SOL
             daily_limit: 2 SOL
             allowed_recipients: [...]
```

## API Reference

### Sessions
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/sessions` | POST | Create agent session |
| `/api/v1/sessions` | GET | List sessions |
| `/api/v1/sessions/:id/revoke` | POST | Revoke session |

### Session Keys
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/session-keys/create` | POST | Create session key |
| `/api/v1/session-keys/status` | POST | Check key status |
| `/api/v1/session-keys/revoke` | POST | Revoke key |
| `/api/v1/session-keys/:id/top-up` | POST | Top up balance |

### Payments
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/payments` | POST | Execute payment |

### Agent Custody
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/custody/grant` | POST | Grant wallet custody |
| `/api/v1/custody/:id/sign` | POST | Sign transaction |
| `/api/v1/custody/:id/revoke` | POST | Revoke custody |

### Admin
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/login` | POST | Admin authentication |
| `/admin/api-keys` | POST | Create platform API key |
| `/admin/platforms/:id/usage` | GET | Platform usage stats |

## SDKs

| Language | Package | Status |
|----------|---------|--------|
| TypeScript | `@x0/sdk` | In active development |
| Python | `langchain-zendfi` | In active development |
| Rust | `x0-core` (native) | Available |

## Self-Hosting Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| PostgreSQL | 14+ | 15+ |
| Redis | 6+ | 7+ |
| Solana RPC | Public | Helius/QuickNode |
| RAM | 512MB | 2GB |
| CPU | 1 core | 2+ cores |

## Environment Variables

```bash
# Required
DATABASE_URL=postgres://user:pass@localhost/x0
REDIS_URL=redis://localhost:6379
ADMIN_JWT_SECRET=your-32-char-secret-minimum

# Solana (at least one RPC)
SOLANA_RPC_URL=https://api.devnet.solana.com

# Fee payers (for gasless transactions)
DEVNET_FEE_PAYER_KEYPAIR=[1,2,3,...]  # JSON array or base58
MAINNET_FEE_PAYER_KEYPAIR=[1,2,3,...]

# Lit Protocol (production)
LIT_NETWORK=datil-dev
LIT_CAPACITY_CREDIT_TOKEN_ID=your-token-id

# WebAuthn
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_ORIGIN=http://localhost:3000
```

## Project Structure

```
x0/
├── packages/
│   ├── core/            # Rust API server
│   ├── sdk-typescript/  # TypeScript SDK
│   └── sdk-python/      # Python SDK
├── apps/                # Example applications
├── deploy/              # Deployment configs
├── docs/                # Documentation
└── examples/            # Integration examples
```

## License

| Component | License |
|-----------|---------|
| x0 Core | Apache-2.0 |
| SDKs | MIT |
| Enterprise Features | Commercial (contact sales) |

## Community

- **GitHub Issues**: [Report bugs](https://github.com/x0-project/x0/issues)
- **Discussions**: [Ask questions](https://github.com/x0-project/x0/discussions)
- **Twitter**: [@x0_payments](https://twitter.com/x0_payments)


## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
cd packages/core
cargo build
cargo test

# Run locally
cargo run
```