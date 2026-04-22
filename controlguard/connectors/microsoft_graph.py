from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any
from urllib import error, parse, request


class MicrosoftGraphConfigurationError(RuntimeError):
    """Raised when the Microsoft Graph connector isn't configured correctly."""


class MicrosoftGraphApiError(RuntimeError):
    """Raised when Microsoft Graph or the token endpoint returns an error."""

    def __init__(self, status_code: int, message: str, code: str | None = None) -> None:
        self.status_code = status_code
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class MicrosoftGraphSettings:
    graph_base_url: str = "https://graph.microsoft.com/v1.0"
    authority_host: str = "https://login.microsoftonline.com"
    timeout_seconds: int = 10
    access_token: str | None = None
    access_token_env: str | None = None
    tenant: str | None = None
    tenant_env: str | None = None
    client_id: str | None = None
    client_id_env: str | None = None
    client_secret: str | None = None
    client_secret_env: str | None = None

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> "MicrosoftGraphSettings":
        timeout_seconds = int(params.get("timeout_seconds", 10))
        if timeout_seconds <= 0:
            raise MicrosoftGraphConfigurationError("timeout_seconds must be greater than zero.")

        return cls(
            graph_base_url=str(params.get("graph_base_url", "https://graph.microsoft.com/v1.0")).rstrip("/"),
            authority_host=str(params.get("authority_host", "https://login.microsoftonline.com")).rstrip("/"),
            timeout_seconds=timeout_seconds,
            access_token=_clean_optional(params.get("access_token")),
            access_token_env=_clean_optional(params.get("access_token_env")),
            tenant=_clean_optional(params.get("tenant")),
            tenant_env=_clean_optional(params.get("tenant_env")),
            client_id=_clean_optional(params.get("client_id")),
            client_id_env=_clean_optional(params.get("client_id_env")),
            client_secret=_clean_optional(params.get("client_secret")),
            client_secret_env=_clean_optional(params.get("client_secret_env")),
        )

    def resolve_access_token(self, env: dict[str, str] | None = None) -> tuple[str, str]:
        environment = env or os.environ
        explicit_token = self.access_token or _read_env(environment, self.access_token_env)
        if explicit_token:
            return explicit_token, "access_token"

        tenant = self.tenant or _read_env(environment, self.tenant_env)
        client_id = self.client_id or _read_env(environment, self.client_id_env)
        client_secret = self.client_secret or _read_env(environment, self.client_secret_env)
        missing = []
        if not tenant:
            missing.append(self.tenant_env or "tenant")
        if not client_id:
            missing.append(self.client_id_env or "client_id")
        if not client_secret:
            missing.append(self.client_secret_env or "client_secret")
        if missing:
            raise MicrosoftGraphConfigurationError(
                "Microsoft Graph connector is missing credentials. "
                f"Set {', '.join(missing)} or provide a pre-acquired access token."
            )

        token = _request_client_credentials_token(
            authority_host=self.authority_host,
            tenant=tenant,
            client_id=client_id,
            client_secret=client_secret,
            timeout_seconds=self.timeout_seconds,
        )
        return token, "client_credentials"


class MicrosoftGraphClient:
    def __init__(self, settings: MicrosoftGraphSettings) -> None:
        self.settings = settings

    def list_user_registration_details(self) -> tuple[list[dict[str, Any]], str]:
        access_token, auth_mode = self.settings.resolve_access_token()
        results: list[dict[str, Any]] = []
        next_url = f"{self.settings.graph_base_url}/reports/authenticationMethods/userRegistrationDetails"
        while next_url:
            page = _request_json(
                method="GET",
                url=next_url,
                access_token=access_token,
                timeout_seconds=self.settings.timeout_seconds,
            )
            results.extend(_as_list(page.get("value")))
            next_url = page.get("@odata.nextLink")
        return results, auth_mode


def _request_client_credentials_token(
    authority_host: str,
    tenant: str,
    client_id: str,
    client_secret: str,
    timeout_seconds: int,
) -> str:
    token_url = f"{authority_host}/{tenant}/oauth2/v2.0/token"
    body = parse.urlencode(
        {
            "client_id": client_id,
            "scope": "https://graph.microsoft.com/.default",
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        }
    ).encode("utf-8")
    payload = _request_json(
        method="POST",
        url=token_url,
        timeout_seconds=timeout_seconds,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    access_token = payload.get("access_token")
    if not access_token:
        raise MicrosoftGraphApiError(500, "Token endpoint did not return an access_token.")
    return str(access_token)


def _request_json(
    method: str,
    url: str,
    timeout_seconds: int,
    access_token: str | None = None,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    if access_token:
        request_headers["Authorization"] = f"Bearer {access_token}"

    req = request.Request(url, method=method, data=data, headers=request_headers)
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload) if payload else {}
    except error.HTTPError as exc:
        raise _build_api_error(exc) from exc
    except error.URLError as exc:
        raise MicrosoftGraphApiError(0, f"Network error while calling Microsoft Graph: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise MicrosoftGraphApiError(500, f"Received invalid JSON from {url}") from exc


def _build_api_error(exc: error.HTTPError) -> MicrosoftGraphApiError:
    body = exc.read().decode("utf-8", errors="replace")
    message = body or exc.reason or "HTTP error"
    code: str | None = None
    try:
        payload = json.loads(body)
        graph_error = payload.get("error", {})
        code = graph_error.get("code")
        message = graph_error.get("message") or message
    except json.JSONDecodeError:
        pass
    return MicrosoftGraphApiError(exc.code, f"HTTP {exc.code}: {message}", code=code)


def _clean_optional(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _read_env(environment: dict[str, str], env_name: str | None) -> str | None:
    if not env_name:
        return None
    return _clean_optional(environment.get(env_name))


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
