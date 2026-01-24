"""Data models for x0 SDK."""

from datetime import datetime
from decimal import Decimal
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class SessionConfig(BaseModel):
    """Configuration for creating an agent session."""

    agent_id: str = Field(..., description="Unique identifier for the agent")
    agent_name: Optional[str] = Field(None, description="Human-readable agent name")
    user_wallet: str = Field(..., description="User's Solana wallet address")
    max_per_transaction: Optional[Decimal] = Field(None, ge=0)
    max_per_day: Optional[Decimal] = Field(None, ge=0)
    max_per_week: Optional[Decimal] = Field(None, ge=0)
    max_per_month: Optional[Decimal] = Field(None, ge=0)
    require_approval_above: Optional[Decimal] = Field(None, ge=0)
    expires_in: Optional[int] = Field(None, ge=60, description="Expiry in seconds")
    metadata: Optional[dict[str, Any]] = None


class Session(BaseModel):
    """AI agent session."""

    id: str
    session_token: str
    agent_id: str
    agent_name: Optional[str] = None
    user_wallet: str
    max_per_transaction: Optional[Decimal] = None
    max_per_day: Optional[Decimal] = None
    max_per_week: Optional[Decimal] = None
    max_per_month: Optional[Decimal] = None
    require_approval_above: Optional[Decimal] = None
    spent_today: Decimal = Decimal(0)
    spent_this_week: Decimal = Decimal(0)
    spent_this_month: Decimal = Decimal(0)
    is_active: bool = True
    created_at: datetime
    expires_at: datetime


class SessionKeyConfig(BaseModel):
    """Configuration for creating a session key."""

    limit_usdc: Decimal = Field(..., gt=0)
    expires_in: Optional[int] = Field(None, ge=60)
    daily_limit_usdc: Optional[Decimal] = Field(None, ge=0)
    weekly_limit_usdc: Optional[Decimal] = Field(None, ge=0)
    monthly_limit_usdc: Optional[Decimal] = Field(None, ge=0)
    device_fingerprint: Optional[str] = None


class SessionKey(BaseModel):
    """Device-bound session key for auto-signing."""

    id: str
    public_key: str
    limit_usdc: Decimal
    used_amount_usdc: Decimal = Decimal(0)
    daily_limit_usdc: Optional[Decimal] = None
    weekly_limit_usdc: Optional[Decimal] = None
    monthly_limit_usdc: Optional[Decimal] = None
    is_active: bool = True
    expires_at: datetime
    created_at: datetime


class PaymentConfig(BaseModel):
    """Configuration for making a payment."""

    session_token: str
    amount: Decimal = Field(..., gt=0)
    recipient: str = Field(..., description="Recipient wallet address")
    currency: Literal["USDC", "USDT"] = "USDC"
    memo: Optional[str] = None
    idempotency_key: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class Payment(BaseModel):
    """Payment transaction."""

    id: str
    status: Literal["pending", "confirmed", "failed", "expired"]
    amount: Decimal
    currency: str
    transaction_signature: Optional[str] = None
    from_wallet: str
    to_wallet: str
    created_at: datetime


class SpendingCheck(BaseModel):
    """Result of spending limit check."""

    allowed: bool
    reason: Optional[str] = None
    limit: Optional[Decimal] = None
    spent: Optional[Decimal] = None
    remaining: Optional[Decimal] = None
    requires_approval: Optional[bool] = None


class PricingSuggestion(BaseModel):
    """PPP-adjusted pricing suggestion."""

    suggested_price: Decimal
    ppp_factor: Decimal
    country: str
    currency: str
    reasoning: str
