"""HTTP client for x0 API."""

from decimal import Decimal
from typing import Any, Optional

import httpx

from x0.exceptions import X0APIError, X0ConnectionError, X0TimeoutError
from x0.models import (
    Payment,
    PaymentConfig,
    PricingSuggestion,
    Session,
    SessionConfig,
    SessionKey,
    SessionKeyConfig,
    SpendingCheck,
)


class X0Client:
    """Synchronous client for x0 API."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.x0.dev",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )

    def __enter__(self) -> "X0Client":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        json: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        try:
            response = self._client.request(method, path, json=json)
            data = response.json()

            if not response.is_success:
                error = data.get("error", {})
                raise X0APIError(
                    message=error.get("message", "Request failed"),
                    code=error.get("code", "UNKNOWN_ERROR"),
                    status_code=response.status_code,
                    details=error.get("details"),
                )

            return data
        except httpx.ConnectError as e:
            raise X0ConnectionError(f"Connection failed: {e}") from e
        except httpx.TimeoutException as e:
            raise X0TimeoutError(f"Request timed out: {e}") from e

    def create_session(self, config: SessionConfig) -> Session:
        data = self._request("POST", "/api/v1/sessions", json=config.model_dump(exclude_none=True))
        return Session.model_validate(data)

    def get_session(self, session_id: str) -> Session:
        data = self._request("GET", f"/api/v1/sessions/{session_id}")
        return Session.model_validate(data)

    def list_sessions(self) -> list[Session]:
        data = self._request("GET", "/api/v1/sessions")
        return [Session.model_validate(s) for s in data.get("sessions", [])]

    def revoke_session(self, session_id: str) -> None:
        self._request("POST", f"/api/v1/sessions/{session_id}/revoke")

    def create_session_key(self, config: SessionKeyConfig) -> SessionKey:
        data = self._request(
            "POST",
            "/api/v1/session-keys/create",
            json=config.model_dump(exclude_none=True),
        )
        return SessionKey.model_validate(data)

    def get_session_key_status(self, session_key_id: str) -> SessionKey:
        data = self._request(
            "POST",
            "/api/v1/session-keys/status",
            json={"session_key_id": session_key_id},
        )
        return SessionKey.model_validate(data)

    def revoke_session_key(self, session_key_id: str) -> None:
        self._request("POST", "/api/v1/session-keys/revoke", json={"session_key_id": session_key_id})

    def list_session_keys(self) -> list[SessionKey]:
        data = self._request("GET", "/api/v1/session-keys/list")
        return [SessionKey.model_validate(sk) for sk in data.get("session_keys", [])]

    def make_payment(self, config: PaymentConfig) -> Payment:
        data = self._request("POST", "/api/v1/payments", json=config.model_dump(exclude_none=True))
        return Payment.model_validate(data)

    def check_spending_limit(self, session_token: str, amount: Decimal) -> SpendingCheck:
        data = self._request(
            "POST",
            "/api/v1/spending/check",
            json={"session_token": session_token, "amount": float(amount)},
        )
        return SpendingCheck.model_validate(data)

    def get_pricing_suggestion(
        self,
        base_price: Decimal,
        target_country: str,
    ) -> PricingSuggestion:
        data = self._request(
            "POST",
            "/api/v1/pricing/suggest",
            json={"base_price": float(base_price), "target_country": target_country},
        )
        return PricingSuggestion.model_validate(data)

    def get_ppp_factor(self, country: str) -> dict[str, Any]:
        return self._request("POST", "/api/v1/pricing/ppp-factor", json={"country": country})


class X0AsyncClient:
    """Asynchronous client for x0 API."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.x0.dev",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )

    async def __aenter__(self) -> "X0AsyncClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        json: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        try:
            response = await self._client.request(method, path, json=json)
            data = response.json()

            if not response.is_success:
                error = data.get("error", {})
                raise X0APIError(
                    message=error.get("message", "Request failed"),
                    code=error.get("code", "UNKNOWN_ERROR"),
                    status_code=response.status_code,
                    details=error.get("details"),
                )

            return data
        except httpx.ConnectError as e:
            raise X0ConnectionError(f"Connection failed: {e}") from e
        except httpx.TimeoutException as e:
            raise X0TimeoutError(f"Request timed out: {e}") from e

    async def create_session(self, config: SessionConfig) -> Session:
        data = await self._request(
            "POST",
            "/api/v1/sessions",
            json=config.model_dump(exclude_none=True),
        )
        return Session.model_validate(data)

    async def get_session(self, session_id: str) -> Session:
        data = await self._request("GET", f"/api/v1/sessions/{session_id}")
        return Session.model_validate(data)

    async def list_sessions(self) -> list[Session]:
        data = await self._request("GET", "/api/v1/sessions")
        return [Session.model_validate(s) for s in data.get("sessions", [])]

    async def revoke_session(self, session_id: str) -> None:
        await self._request("POST", f"/api/v1/sessions/{session_id}/revoke")

    async def create_session_key(self, config: SessionKeyConfig) -> SessionKey:
        data = await self._request(
            "POST",
            "/api/v1/session-keys/create",
            json=config.model_dump(exclude_none=True),
        )
        return SessionKey.model_validate(data)

    async def get_session_key_status(self, session_key_id: str) -> SessionKey:
        data = await self._request(
            "POST",
            "/api/v1/session-keys/status",
            json={"session_key_id": session_key_id},
        )
        return SessionKey.model_validate(data)

    async def revoke_session_key(self, session_key_id: str) -> None:
        await self._request(
            "POST",
            "/api/v1/session-keys/revoke",
            json={"session_key_id": session_key_id},
        )

    async def list_session_keys(self) -> list[SessionKey]:
        data = await self._request("GET", "/api/v1/session-keys/list")
        return [SessionKey.model_validate(sk) for sk in data.get("session_keys", [])]

    async def make_payment(self, config: PaymentConfig) -> Payment:
        data = await self._request(
            "POST",
            "/api/v1/payments",
            json=config.model_dump(exclude_none=True),
        )
        return Payment.model_validate(data)

    async def check_spending_limit(self, session_token: str, amount: Decimal) -> SpendingCheck:
        data = await self._request(
            "POST",
            "/api/v1/spending/check",
            json={"session_token": session_token, "amount": float(amount)},
        )
        return SpendingCheck.model_validate(data)

    async def get_pricing_suggestion(
        self,
        base_price: Decimal,
        target_country: str,
    ) -> PricingSuggestion:
        data = await self._request(
            "POST",
            "/api/v1/pricing/suggest",
            json={"base_price": float(base_price), "target_country": target_country},
        )
        return PricingSuggestion.model_validate(data)

    async def get_ppp_factor(self, country: str) -> dict[str, Any]:
        return await self._request("POST", "/api/v1/pricing/ppp-factor", json={"country": country})
