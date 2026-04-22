from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request


class OktaConfigurationError(RuntimeError):
    """Raised when the Okta connector isn't configured correctly."""


class OktaApiError(RuntimeError):
    """Raised when the Okta Management API returns an error."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(message)


@dataclass(frozen=True)
class OktaSettings:
    okta_domain: str
    timeout_seconds: int = 10
    access_token: str | None = None
    access_token_env: str | None = None
    api_token: str | None = None
    api_token_env: str | None = None

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> "OktaSettings":
        okta_domain = str(params.get("okta_domain", "")).rstrip("/")
        if not okta_domain.startswith("https://"):
            raise OktaConfigurationError("okta_domain must start with https://")
        timeout_seconds = int(params.get("timeout_seconds", 10))
        if timeout_seconds <= 0:
            raise OktaConfigurationError("timeout_seconds must be greater than zero.")
        return cls(
            okta_domain=okta_domain,
            timeout_seconds=timeout_seconds,
            access_token=_clean_optional(params.get("access_token")),
            access_token_env=_clean_optional(params.get("access_token_env")),
            api_token=_clean_optional(params.get("api_token")),
            api_token_env=_clean_optional(params.get("api_token_env")),
        )

    def resolve_auth_header(self, env: Mapping[str, str] | None = None) -> tuple[str, str]:
        environment = env or os.environ
        access_token = self.access_token or _read_env(environment, self.access_token_env)
        if access_token:
            return f"Bearer {access_token}", "oauth_access_token"
        api_token = self.api_token or _read_env(environment, self.api_token_env)
        if api_token:
            return f"SSWS {api_token}", "api_token"
        raise OktaConfigurationError(
            "Okta connector is missing credentials. Provide access_token/access_token_env or api_token/api_token_env."
        )


class OktaClient:
    def __init__(self, settings: OktaSettings) -> None:
        self.settings = settings

    def list_admin_users(self) -> tuple[list[dict[str, Any]], str]:
        auth_header, auth_mode = self.settings.resolve_auth_header()
        next_url: str | None = f"{self.settings.okta_domain}/api/v1/iam/assignees/users?limit=200"
        users: list[dict[str, Any]] = []
        while next_url:
            payload, response_headers = _request_json(
                method="GET",
                url=next_url,
                authorization=auth_header,
                timeout_seconds=self.settings.timeout_seconds,
            )
            users.extend(payload.get("value", []))
            next_url = _extract_next_link(payload, response_headers)
        return users, auth_mode

    def list_user_factors(self, user_id: str) -> list[dict[str, Any]]:
        auth_header, _ = self.settings.resolve_auth_header()
        payload, _ = _request_json(
            method="GET",
            url=f"{self.settings.okta_domain}/api/v1/users/{parse.quote(user_id, safe='')}/factors",
            authorization=auth_header,
            timeout_seconds=self.settings.timeout_seconds,
        )
        if isinstance(payload, list):
            return payload
        return payload.get("value", [])


def _request_json(
    method: str,
    url: str,
    authorization: str,
    timeout_seconds: int,
) -> tuple[Any, dict[str, str]]:
    headers = {
        "Accept": "application/json",
        "Authorization": authorization,
    }
    req = request.Request(url, method=method, headers=headers)
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            payload = response.read().decode("utf-8")
            parsed = json.loads(payload) if payload else {}
            return parsed, dict(response.headers.items())
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise OktaApiError(exc.code, body or exc.reason or "Okta API request failed") from exc
    except error.URLError as exc:
        raise OktaApiError(0, f"Network error while calling Okta: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise OktaApiError(500, f"Received invalid JSON from {url}") from exc


def _extract_next_link(payload: Any, headers: dict[str, str]) -> str | None:
    if isinstance(payload, dict):
        links = payload.get("_links", {})
        next_link = links.get("next", {})
        href = next_link.get("href")
        if href:
            return str(href)

    link_header = headers.get("Link") or headers.get("link")
    if not link_header:
        return None
    for segment in link_header.split(","):
        parts = segment.split(";")
        if len(parts) < 2:
            continue
        if 'rel="next"' in parts[1]:
            return parts[0].strip().lstrip("<").rstrip(">")
    return None


def _clean_optional(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _read_env(environment: Mapping[str, str], env_name: str | None) -> str | None:
    if not env_name:
        return None
    return _clean_optional(environment.get(env_name))
