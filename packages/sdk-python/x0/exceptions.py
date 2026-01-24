"""Exception classes for x0 SDK."""

from typing import Any, Optional


class X0Error(Exception):
    """Base exception for x0 SDK errors."""

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


class X0APIError(X0Error):
    """Error from x0 API response."""

    def __init__(
        self,
        message: str,
        code: str,
        status_code: int,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code, details)
        self.status_code = status_code


class X0ValidationError(X0Error):
    """Validation error for request parameters."""

    pass


class X0ConnectionError(X0Error):
    """Network connection error."""

    pass


class X0TimeoutError(X0Error):
    """Request timeout error."""

    pass
