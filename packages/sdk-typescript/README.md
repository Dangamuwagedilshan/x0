# @x0/sdk

TypeScript SDK for x0 - Payment Infrastructure for AI Agents.

## Installation

```bash
npm install @x0/sdk
# or
pnpm add @x0/sdk
# or
yarn add @x0/sdk
```

## Quick Start

```typescript
import { createClient } from '@x0/sdk';

const client = createClient({
  apiKey: 'your-api-key',
  baseUrl: 'https://api.x0.dev', // optional, defaults to production
});

// Create an agent session
const session = await client.createSession({
  agentId: 'shopping-agent-v1',
  agentName: 'Shopping Assistant',
  userWallet: 'user-solana-wallet-address',
  maxPerTransaction: 50,
  maxPerDay: 200,
  requireApprovalAbove: 100,
  expiresIn: 3600, // 1 hour
});

// Make a payment
const payment = await client.makePayment({
  sessionToken: session.sessionToken,
  amount: 25.00,
  recipient: 'merchant-wallet-address',
  memo: 'Purchase: Widget Pro',
});

console.log(`Payment ${payment.status}: ${payment.transactionSignature}`);
```

## Session Keys (Auto-Signing)

For autonomous AI agents that need to sign transactions without user intervention:

```typescript
// Create a session key with spending limits
const sessionKey = await client.createSessionKey({
  limitUsdc: 100,
  dailyLimitUsdc: 50,
  expiresIn: 86400, // 24 hours
});

// Check spending limits before payment
const check = await client.checkSpendingLimit(session.sessionToken, 25);
if (check.allowed) {
  await client.makePayment({
    sessionToken: session.sessionToken,
    amount: 25,
    recipient: 'merchant-wallet',
  });
}
```

## PPP Pricing

Adjust prices based on purchasing power parity:

```typescript
const pricing = await client.getPricingSuggestion(99, 'BR');
// { suggestedPrice: 49, pppFactor: 0.49, country: 'BR', ... }
```

## Error Handling

```typescript
import { X0Error } from '@x0/sdk';

try {
  await client.makePayment({ ... });
} catch (error) {
  if (error instanceof X0Error) {
    console.error(`Error ${error.code}: ${error.message}`);
    if (error.code === 'SPENDING_LIMIT_EXCEEDED') {
      // Handle limit exceeded
    }
  }
}
```

## License

MIT
