"""
AIPT Authenticated Scanning Support

Provides authentication mechanisms for scanning protected resources.
Supports multiple authentication methods:
- Session cookies
- Bearer tokens (JWT, OAuth)
- Basic authentication
- API keys
- Custom headers
- Form-based login automation

This enables testing authenticated portions of applications
(with proper authorization from the client).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable
from urllib.parse import urlencode

import httpx


logger = logging.getLogger(__name__)


class AuthMethod(Enum):
    """Authentication methods supported"""
    NONE = "none"
    COOKIE = "cookie"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    API_KEY = "api_key"
    CUSTOM_HEADER = "custom_header"
    FORM_LOGIN = "form_login"
    OAUTH2 = "oauth2"
    AWS_SIGV4 = "aws_sigv4"


@dataclass
class AuthCredentials:
    """Authentication credentials"""
    method: AuthMethod = AuthMethod.NONE

    # For COOKIE method
    cookies: dict[str, str] = field(default_factory=dict)

    # For BEARER_TOKEN method
    token: str = ""
    token_prefix: str = "Bearer"

    # For BASIC_AUTH method
    username: str = ""
    password: str = ""

    # For API_KEY method
    api_key: str = ""
    api_key_header: str = "X-API-Key"
    api_key_in_query: bool = False
    api_key_query_param: str = "api_key"

    # For CUSTOM_HEADER method
    custom_headers: dict[str, str] = field(default_factory=dict)

    # For FORM_LOGIN method
    login_url: str = ""
    login_data: dict[str, str] = field(default_factory=dict)
    csrf_field: str = ""  # If CSRF token needed
    success_indicator: str = ""  # Text/pattern indicating successful login

    # For OAUTH2 method
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_token_url: str = ""
    oauth_scope: str = ""

    # Token management
    token_expires_at: datetime | None = None
    refresh_token: str = ""
    auto_refresh: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.value,
            "has_cookies": bool(self.cookies),
            "has_token": bool(self.token),
            "has_basic_auth": bool(self.username),
            "has_api_key": bool(self.api_key),
            "has_custom_headers": bool(self.custom_headers),
            "login_url": self.login_url if self.login_url else None,
        }


@dataclass
class AuthSession:
    """An authenticated session"""
    credentials: AuthCredentials
    session_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_used: datetime = field(default_factory=datetime.utcnow)
    is_valid: bool = True
    validation_url: str = ""
    validation_indicator: str = ""

    # Session state
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    # Statistics
    requests_made: int = 0
    auth_failures: int = 0


class AuthenticationManager:
    """
    Manages authentication for scanning sessions.

    Handles:
    - Multiple authentication methods
    - Token refresh
    - Session validation
    - Header/cookie injection

    Example:
        creds = AuthCredentials(
            method=AuthMethod.BEARER_TOKEN,
            token="eyJhbGciOi...",
        )
        auth_mgr = AuthenticationManager(creds)
        headers = await auth_mgr.get_auth_headers()
        # Use headers in your requests
    """

    def __init__(self, credentials: AuthCredentials):
        self.credentials = credentials
        self._session: AuthSession | None = None
        self._http_client: httpx.AsyncClient | None = None
        self._token_lock = asyncio.Lock()

    async def initialize(self) -> AuthSession:
        """
        Initialize authentication session.

        For form-based login, this will perform the login.
        For OAuth, this will obtain tokens.
        """
        session_id = hashlib.md5(
            f"{self.credentials.method.value}-{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:12]

        self._session = AuthSession(
            credentials=self.credentials,
            session_id=session_id,
        )

        # Perform initial authentication based on method
        if self.credentials.method == AuthMethod.FORM_LOGIN:
            await self._perform_form_login()
        elif self.credentials.method == AuthMethod.OAUTH2:
            await self._obtain_oauth_token()

        # Build initial headers
        self._session.headers = await self._build_auth_headers()
        self._session.cookies = self.credentials.cookies.copy()

        logger.info(f"Auth session initialized: {session_id} ({self.credentials.method.value})")
        return self._session

    async def get_auth_headers(self) -> dict[str, str]:
        """
        Get authentication headers for a request.

        Automatically refreshes tokens if needed.
        """
        if not self._session:
            await self.initialize()

        # Check if token needs refresh
        if self.credentials.auto_refresh and self._token_expired():
            async with self._token_lock:
                if self._token_expired():  # Double-check after acquiring lock
                    await self._refresh_token()

        self._session.last_used = datetime.utcnow()
        self._session.requests_made += 1

        return self._session.headers.copy()

    async def get_auth_cookies(self) -> dict[str, str]:
        """Get authentication cookies"""
        if not self._session:
            await self.initialize()

        return self._session.cookies.copy()

    async def _build_auth_headers(self) -> dict[str, str]:
        """Build authentication headers based on method"""
        headers = {}

        if self.credentials.method == AuthMethod.BEARER_TOKEN:
            headers["Authorization"] = f"{self.credentials.token_prefix} {self.credentials.token}"

        elif self.credentials.method == AuthMethod.BASIC_AUTH:
            credentials = f"{self.credentials.username}:{self.credentials.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        elif self.credentials.method == AuthMethod.API_KEY:
            if not self.credentials.api_key_in_query:
                headers[self.credentials.api_key_header] = self.credentials.api_key

        elif self.credentials.method == AuthMethod.CUSTOM_HEADER:
            headers.update(self.credentials.custom_headers)

        elif self.credentials.method == AuthMethod.OAUTH2:
            if self.credentials.token:
                headers["Authorization"] = f"Bearer {self.credentials.token}"

        return headers

    async def _perform_form_login(self) -> None:
        """Perform form-based login"""
        if not self.credentials.login_url:
            raise ValueError("login_url required for FORM_LOGIN")

        client = await self._get_http_client()

        # Get login page (for CSRF token if needed)
        login_data = self.credentials.login_data.copy()

        if self.credentials.csrf_field:
            # Fetch login page to get CSRF token
            response = await client.get(self.credentials.login_url)
            csrf_token = self._extract_csrf_token(response.text, self.credentials.csrf_field)
            if csrf_token:
                login_data[self.credentials.csrf_field] = csrf_token

        # Perform login
        response = await client.post(
            self.credentials.login_url,
            data=login_data,
            follow_redirects=True,
        )

        # Check for success
        if self.credentials.success_indicator:
            if self.credentials.success_indicator not in response.text:
                raise AuthenticationError(
                    f"Login failed - success indicator not found: {self.credentials.success_indicator}"
                )

        # Extract session cookies
        for cookie in client.cookies.jar:
            self._session.cookies[cookie.name] = cookie.value

        logger.info("Form login successful")

    def _extract_csrf_token(self, html: str, field_name: str) -> str | None:
        """Extract CSRF token from HTML"""
        # Try common patterns
        patterns = [
            rf'name="{field_name}"[^>]*value="([^"]+)"',
            rf'name=\'{field_name}\'[^>]*value=\'([^\']+)\'',
            rf'value="([^"]+)"[^>]*name="{field_name}"',
            rf'data-csrf="([^"]+)"',
            rf'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    async def _obtain_oauth_token(self) -> None:
        """Obtain OAuth2 token"""
        if not self.credentials.oauth_token_url:
            raise ValueError("oauth_token_url required for OAUTH2")

        client = await self._get_http_client()

        token_data = {
            "grant_type": "client_credentials",
            "client_id": self.credentials.oauth_client_id,
            "client_secret": self.credentials.oauth_client_secret,
        }

        if self.credentials.oauth_scope:
            token_data["scope"] = self.credentials.oauth_scope

        response = await client.post(
            self.credentials.oauth_token_url,
            data=token_data,
        )

        if response.status_code != 200:
            raise AuthenticationError(f"OAuth token request failed: {response.status_code}")

        data = response.json()
        self.credentials.token = data.get("access_token", "")
        self.credentials.refresh_token = data.get("refresh_token", "")

        expires_in = data.get("expires_in", 3600)
        self.credentials.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in - 60)

        logger.info(f"OAuth token obtained, expires in {expires_in}s")

    def _token_expired(self) -> bool:
        """Check if current token is expired"""
        if not self.credentials.token_expires_at:
            return False
        return datetime.utcnow() >= self.credentials.token_expires_at

    async def _refresh_token(self) -> None:
        """Refresh OAuth token"""
        if self.credentials.method == AuthMethod.OAUTH2 and self.credentials.refresh_token:
            client = await self._get_http_client()

            token_data = {
                "grant_type": "refresh_token",
                "refresh_token": self.credentials.refresh_token,
                "client_id": self.credentials.oauth_client_id,
                "client_secret": self.credentials.oauth_client_secret,
            }

            response = await client.post(
                self.credentials.oauth_token_url,
                data=token_data,
            )

            if response.status_code == 200:
                data = response.json()
                self.credentials.token = data.get("access_token", "")

                new_refresh = data.get("refresh_token")
                if new_refresh:
                    self.credentials.refresh_token = new_refresh

                expires_in = data.get("expires_in", 3600)
                self.credentials.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in - 60)

                # Update session headers
                self._session.headers = await self._build_auth_headers()
                logger.info("OAuth token refreshed")
            else:
                logger.warning(f"Token refresh failed: {response.status_code}")
                self._session.auth_failures += 1
        else:
            # For other methods, re-authenticate
            await self.initialize()

    async def validate_session(self, validation_url: str = "", expected_status: int = 200) -> bool:
        """
        Validate that the authentication session is still valid.

        Args:
            validation_url: URL to check (should require auth)
            expected_status: Expected HTTP status for valid session

        Returns:
            True if session is valid
        """
        url = validation_url or self._session.validation_url
        if not url:
            return True  # Can't validate without URL

        try:
            client = await self._get_http_client()
            headers = await self.get_auth_headers()

            response = await client.get(url, headers=headers)

            is_valid = response.status_code == expected_status
            self._session.is_valid = is_valid

            if not is_valid:
                logger.warning(f"Session validation failed: {response.status_code}")
                self._session.auth_failures += 1

            return is_valid

        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get HTTP client for auth requests"""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
            )
        return self._http_client

    async def close(self) -> None:
        """Close HTTP client"""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    def get_session_stats(self) -> dict[str, Any]:
        """Get session statistics"""
        if not self._session:
            return {"status": "not_initialized"}

        return {
            "session_id": self._session.session_id,
            "method": self.credentials.method.value,
            "created_at": self._session.created_at.isoformat(),
            "last_used": self._session.last_used.isoformat(),
            "is_valid": self._session.is_valid,
            "requests_made": self._session.requests_made,
            "auth_failures": self._session.auth_failures,
            "token_expires_at": (
                self.credentials.token_expires_at.isoformat()
                if self.credentials.token_expires_at
                else None
            ),
        }


class AuthenticationError(Exception):
    """Authentication failed"""
    pass


# ============================================================================
# Convenience Functions
# ============================================================================

def create_bearer_auth(token: str, prefix: str = "Bearer") -> AuthCredentials:
    """Create bearer token authentication"""
    return AuthCredentials(
        method=AuthMethod.BEARER_TOKEN,
        token=token,
        token_prefix=prefix,
    )


def create_basic_auth(username: str, password: str) -> AuthCredentials:
    """Create basic authentication"""
    return AuthCredentials(
        method=AuthMethod.BASIC_AUTH,
        username=username,
        password=password,
    )


def create_api_key_auth(
    api_key: str,
    header: str = "X-API-Key",
    in_query: bool = False,
    query_param: str = "api_key",
) -> AuthCredentials:
    """Create API key authentication"""
    return AuthCredentials(
        method=AuthMethod.API_KEY,
        api_key=api_key,
        api_key_header=header,
        api_key_in_query=in_query,
        api_key_query_param=query_param,
    )


def create_cookie_auth(cookies: dict[str, str]) -> AuthCredentials:
    """Create cookie-based authentication"""
    return AuthCredentials(
        method=AuthMethod.COOKIE,
        cookies=cookies,
    )


def create_form_login_auth(
    login_url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",
    csrf_field: str = "",
    success_indicator: str = "",
) -> AuthCredentials:
    """Create form-based login authentication"""
    return AuthCredentials(
        method=AuthMethod.FORM_LOGIN,
        login_url=login_url,
        login_data={
            username_field: username,
            password_field: password,
        },
        csrf_field=csrf_field,
        success_indicator=success_indicator,
    )


def create_oauth2_auth(
    client_id: str,
    client_secret: str,
    token_url: str,
    scope: str = "",
) -> AuthCredentials:
    """Create OAuth2 client credentials authentication"""
    return AuthCredentials(
        method=AuthMethod.OAUTH2,
        oauth_client_id=client_id,
        oauth_client_secret=client_secret,
        oauth_token_url=token_url,
        oauth_scope=scope,
    )
