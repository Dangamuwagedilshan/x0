# x0-sdk

Python SDK for x0 - Payment Infrastructure for AI Agents.

## Installation

```bash
pip install x0-sdk
# or
uv add x0-sdk
```

## Quick Start

```python
from x0 import X0Client, SessionConfig, PaymentConfig

client = X0Client(
    api_key="your-api-key",
    base_url="https://api.x0.dev",  # optional
)

# Create an agent session
session = client.create_session(SessionConfig(
    agent_id="shopping-agent-v1",
    agent_name="Shopping Assistant",
    user_wallet="user-solana-wallet-address",
    max_per_transaction=50,
    max_per_day=200,
    require_approval_above=100,
    expires_in=3600,  # 1 hour
))

# Make a payment
payment = client.make_payment(PaymentConfig(
    session_token=session.session_token,
    amount=25.00,
    recipient="merchant-wallet-address",
    memo="Purchase: Widget Pro",
))

print(f"Payment {payment.status}: {payment.transaction_signature}")
```

## Async Support

```python
import asyncio
from x0 import X0AsyncClient, SessionConfig

async def main():
    async with X0AsyncClient(api_key="your-api-key") as client:
        session = await client.create_session(SessionConfig(
            agent_id="my-agent",
            user_wallet="wallet-address",
        ))
        print(f"Session created: {session.id}")

asyncio.run(main())
```

## Session Keys

For autonomous AI agents:

```python
from x0 import SessionKeyConfig

# Create a session key with spending limits
session_key = client.create_session_key(SessionKeyConfig(
    limit_usdc=100,
    daily_limit_usdc=50,
    expires_in=86400,  # 24 hours
))

# Check spending limits before payment
check = client.check_spending_limit(session.session_token, 25)
if check.allowed:
    client.make_payment(PaymentConfig(
        session_token=session.session_token,
        amount=25,
        recipient="merchant-wallet",
    ))
```

## PPP Pricing

```python
pricing = client.get_pricing_suggestion(base_price=99, target_country="BR")
# PricingSuggestion(suggested_price=49, ppp_factor=0.49, ...)
```

## Error Handling

```python
from x0 import X0APIError

try:
    client.make_payment(config)
except X0APIError as e:
    print(f"Error {e.code}: {e.message}")
    if e.code == "SPENDING_LIMIT_EXCEEDED":
        # Handle limit exceeded
        pass
```

## License

MIT
