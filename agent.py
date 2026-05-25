from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import math
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx
from cryptography.fernet import Fernet


@dataclass(slots=True)
class ProvisionResult:
    username: str
    config_link: str
    config_copy_text: str | None = None
    used_traffic_gb: int = 0


class RelayError(ValueError):
    pass


def traffic_bytes_to_gb_value(traffic_limit_bytes: int) -> float:
    return int(traffic_limit_bytes) / 1024**3


def encrypt_payload(payload: dict[str, Any], secret: str) -> str:
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _build_fernet(secret).encrypt(data).decode("utf-8")


def decrypt_payload(token: str, secret: str) -> dict[str, Any]:
    raw = _build_fernet(secret).decrypt(token.encode("utf-8"))
    decoded = json.loads(raw.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise RelayError("relay payload must be a JSON object")
    return decoded


def _build_fernet(secret: str) -> Fernet:
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


class BaseVPNClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        extra_config: dict[str, Any] | None = None,
        *,
        connect_timeout: float = 4.0,
        request_timeout: float = 15.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.extra_config = extra_config or {}
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout

    def _client_timeout(self) -> httpx.Timeout:
        return httpx.Timeout(timeout=self.request_timeout, connect=self.connect_timeout)

    def _normalize_config_link(self, raw_link: object) -> str:
        if raw_link is None:
            return ""
        link = str(raw_link).strip()
        if not link:
            return ""
        if "://" in link or link.startswith(("ss://", "vmess://", "vless://", "trojan://")):
            return link
        if link.startswith(("/", "./", "../", "?")) or "/" in link:
            return urljoin(f"{self.base_url}/", link)
        return link

    def _extract_response_username(self, response: object, fallback: str) -> str:
        if not isinstance(response, Mapping):
            return fallback
        direct_username = str(response.get("username") or response.get("email") or "").strip()
        if direct_username:
            return direct_username
        nested = response.get("obj")
        if isinstance(nested, Mapping):
            nested_username = str(nested.get("username") or nested.get("email") or "").strip()
            if nested_username:
                return nested_username
        return fallback

    def _extract_raw_config_links(self, response: object) -> list[str]:
        if not isinstance(response, Mapping):
            return []
        raw_links = response.get("links")
        if not isinstance(raw_links, list):
            nested = response.get("obj")
            raw_links = nested.get("links") if isinstance(nested, Mapping) else None
        if not isinstance(raw_links, list):
            return []
        normalized_links: list[str] = []
        seen: set[str] = set()
        for raw_link in raw_links:
            normalized = self._normalize_config_link(raw_link)
            if not normalized or normalized in seen:
                continue
            normalized_links.append(normalized)
            seen.add(normalized)
        return normalized_links

    def extract_config_copy_text(self, response: object) -> str | None:
        links = self._extract_raw_config_links(response)
        return "\n".join(links) if links else None

    def _build_request_error_message(self, exc: httpx.RequestError) -> str:
        detail = str(exc).strip()
        normalized_detail = detail.lower()
        if "tlsv1_alert_no_application_protocol" in normalized_detail or "no application protocol" in normalized_detail:
            return "اتصال امن به پنل VPN برقرار نشد. تنظیمات SSL پنل یا reverse proxy آن ناسازگار است."
        if isinstance(exc, httpx.ConnectTimeout):
            return "مهلت اتصال به پنل VPN تمام شد."
        if isinstance(exc, httpx.ReadTimeout):
            return "پنل VPN در زمان مناسب پاسخ نداد."
        if isinstance(exc, httpx.ConnectError):
            return "اتصال به پنل VPN برقرار نشد."
        return f"ارتباط با پنل VPN با خطا مواجه شد: {detail}" if detail else "ارتباط با پنل VPN با خطا مواجه شد."

    async def _build_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = await self._build_headers()
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self._client_timeout(),
                headers=headers,
                trust_env=False,
            ) as client:
                response = await client.request(method, path, json=payload)
        except httpx.RequestError as exc:
            raise RelayError(self._build_request_error_message(exc)) from exc
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            response_text = response.text.strip()
            detail = f" | response: {response_text[:500]}" if response_text else ""
            raise httpx.HTTPStatusError(f"{exc}{detail}", request=exc.request, response=exc.response) from exc
        if response.content:
            return response.json()
        return {}


class MarzbanClient(BaseVPNClient):
    def __init__(self, base_url: str, api_key: str, extra_config: dict[str, Any] | None = None, **kwargs: Any) -> None:
        super().__init__(self._normalize_base_url(base_url), api_key, extra_config, **kwargs)
        self._access_token: str | None = None
        self._available_inbounds: dict[str, list[str]] | None = None

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        parsed = urlsplit(base_url.strip())
        path = parsed.path.rstrip("/")
        for suffix in ("/dashboard", "/api/user", "/api"):
            if path.endswith(suffix):
                path = path[: -len(suffix)]
                break
        normalized = parsed._replace(path=path, query="", fragment="")
        return urlunsplit(normalized).rstrip("/")

    def _load_credentials(self) -> dict[str, str] | None:
        try:
            payload = json.loads(self.api_key)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "").strip()
        return {"username": username, "password": password} if username and password else None

    async def _login(self, *, force_refresh: bool = False) -> str:
        credentials = self._load_credentials()
        if credentials is None:
            return self.api_key
        if self._access_token and not force_refresh:
            return self._access_token
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=self._client_timeout(), trust_env=False) as client:
                response = await client.post(
                    "/api/admin/token",
                    data={"username": credentials["username"], "password": credentials["password"]},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
        except httpx.RequestError as exc:
            raise RelayError(self._build_request_error_message(exc)) from exc
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise RelayError(f"ورود به پنل Marzban ناموفق بود: {exc.response.status_code}") from exc
        payload = response.json()
        access_token = str(payload.get("access_token") or "").strip()
        if not access_token:
            raise RelayError("Marzban login did not return an access token")
        self._access_token = access_token
        return access_token

    async def _build_headers(self) -> dict[str, str]:
        access_token = await self._login()
        return {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    async def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            return await super()._request(method, path, payload)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 401 or self._load_credentials() is None:
                raise
            self._access_token = None
            self._available_inbounds = None
            await self._login(force_refresh=True)
            return await super()._request(method, path, payload)

    @staticmethod
    def _normalize_protocol_inbounds(raw_inbounds: object) -> dict[str, list[str]]:
        if not isinstance(raw_inbounds, Mapping):
            return {}
        normalized: dict[str, list[str]] = {}
        for protocol, entries in raw_inbounds.items():
            protocol_name = str(protocol or "").strip().lower()
            if not protocol_name or not isinstance(entries, list):
                continue
            tags = [str(entry.get("tag") or "").strip() for entry in entries if isinstance(entry, Mapping)]
            tags = [tag for tag in tags if tag]
            if tags:
                normalized[protocol_name] = tags
        return normalized

    @staticmethod
    def _normalize_proxies(raw_proxies: object) -> dict[str, dict[str, Any]]:
        if not isinstance(raw_proxies, Mapping):
            return {}
        normalized: dict[str, dict[str, Any]] = {}
        for protocol, settings in raw_proxies.items():
            protocol_name = str(protocol or "").strip().lower()
            if protocol_name:
                normalized[protocol_name] = dict(settings) if isinstance(settings, Mapping) else {}
        return normalized

    async def _get_available_inbounds(self) -> dict[str, list[str]]:
        if self._available_inbounds is not None:
            return self._available_inbounds
        response = await self._request("GET", "/api/inbounds")
        self._available_inbounds = self._normalize_protocol_inbounds(response)
        return self._available_inbounds

    async def _resolve_user_access_config(self) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
        configured_proxies = self._normalize_proxies(self.extra_config.get("proxies"))
        configured_inbounds = self.extra_config.get("inbounds")
        normalized_inbounds: dict[str, list[str]] = {}
        if isinstance(configured_inbounds, Mapping):
            for protocol, tags in configured_inbounds.items():
                protocol_name = str(protocol or "").strip().lower()
                if protocol_name and isinstance(tags, list):
                    normalized_tags = [str(tag or "").strip() for tag in tags if str(tag or "").strip()]
                    if normalized_tags:
                        normalized_inbounds[protocol_name] = normalized_tags
        if not normalized_inbounds:
            normalized_inbounds = await self._get_available_inbounds()
        protocols = list(normalized_inbounds.keys()) or list(configured_proxies.keys())
        proxies = configured_proxies or {protocol: {} for protocol in protocols}
        inbounds = normalized_inbounds or {protocol: [] for protocol in proxies if protocol}
        if not proxies:
            raise RelayError("Marzban panel has no enabled protocols or inbounds configured")
        return proxies, inbounds

    async def test_connection(self) -> None:
        await self._login()

    async def create_account(self, username: str, traffic_limit_bytes: int, expire_timestamp: int | None) -> ProvisionResult:
        proxies, inbounds = await self._resolve_user_access_config()
        response = await self._request(
            "POST",
            "/api/user",
            {
                "username": username,
                "status": self.extra_config.get("status", "active"),
                "data_limit": int(traffic_limit_bytes),
                "data_limit_reset_strategy": self.extra_config.get("data_limit_reset_strategy", "no_reset"),
                "expire": int(expire_timestamp or 0),
                "proxies": proxies,
                "inbounds": inbounds,
            },
        )
        links = response.get("subscription_url") or response.get("links", [])
        config_link = links[0] if isinstance(links, list) and links else links
        return ProvisionResult(
            username=self._extract_response_username(response, username),
            config_link=self._normalize_config_link(config_link),
            config_copy_text=self.extract_config_copy_text(response),
        )

    async def get_usage(self, username: str) -> dict[str, Any]:
        return await self._request("GET", f"/api/user/{username}")

    async def renew_account(self, username: str, traffic_limit_bytes: int, expire_timestamp: int | None) -> ProvisionResult:
        response = await self._request(
            "PUT",
            f"/api/user/{username}",
            {"data_limit": int(traffic_limit_bytes), "expire": int(expire_timestamp or 0)},
        )
        links = response.get("subscription_url") or response.get("links", [])
        config_link = links[0] if isinstance(links, list) and links else links
        return ProvisionResult(
            username=self._extract_response_username(response, username),
            config_link=self._normalize_config_link(config_link),
            config_copy_text=self.extract_config_copy_text(response),
        )


class HiddifyClient(BaseVPNClient):
    def __init__(self, base_url: str, api_key: str, extra_config: dict[str, Any] | None = None, **kwargs: Any) -> None:
        super().__init__(self._normalize_base_url(base_url), api_key, extra_config, **kwargs)

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        parsed = urlsplit(base_url.strip())
        path = parsed.path.rstrip("/")
        for suffix in ("/api/docs", "/api/redoc", "/docs", "/redoc", "/quick-setup", "/admin/quick-setup", "/admin/login", "/admin"):
            if path.endswith(suffix):
                path = path[: -len(suffix)]
                break
        if path.endswith("/api"):
            path = path[: -len("/api")]
        normalized = parsed._replace(path=path, query="", fragment="")
        return urlunsplit(normalized).rstrip("/")

    async def _build_headers(self) -> dict[str, str]:
        return {
            "Hiddify-API-Key": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _extract_user_name(user: object, fallback: str = "") -> str:
        if not isinstance(user, Mapping):
            return fallback
        name = str(user.get("name") or user.get("username") or "").strip()
        return name or fallback

    @staticmethod
    def _extract_user_uuid(user: object) -> str:
        if not isinstance(user, Mapping):
            return ""
        return str(user.get("uuid") or "").strip()

    @staticmethod
    def _usage_gb_to_bytes(usage_gb: object) -> int:
        try:
            value = float(usage_gb or 0)
        except (TypeError, ValueError):
            return 0
        return int(max(value, 0) * 1024**3)

    @staticmethod
    def _usage_gb_to_int(usage_gb: object) -> int:
        try:
            value = float(usage_gb or 0)
        except (TypeError, ValueError):
            return 0
        return max(int(value), 0)

    @staticmethod
    def _package_days_from_expire_timestamp(expire_timestamp: int) -> int:
        expire_at = datetime.fromtimestamp(expire_timestamp, UTC)
        now = datetime.now(UTC)
        remaining_seconds = max((expire_at - now).total_seconds(), 0)
        return max(1, math.ceil(remaining_seconds / 86400))

    def _package_days_for_payload(self, expire_timestamp: int | None) -> int:
        if expire_timestamp is None:
            raw_days = self.extra_config.get("no_expiry_package_days", 36500)
            try:
                configured_days = int(raw_days)
            except (TypeError, ValueError):
                configured_days = 36500
            return max(configured_days, 1)
        return self._package_days_from_expire_timestamp(expire_timestamp)

    def _build_user_payload(self, username: str, traffic_limit_bytes: int, expire_timestamp: int | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": username,
            "usage_limit_GB": traffic_bytes_to_gb_value(traffic_limit_bytes),
            "package_days": self._package_days_for_payload(expire_timestamp),
            "comment": self.extra_config.get("comment", "telegram-vpn-shop"),
            "enable": bool(self.extra_config.get("enable", True)),
            "is_active": bool(self.extra_config.get("is_active", True)),
            "start_date": datetime.now(UTC).date().isoformat(),
        }
        for key in ("mode", "lang", "telegram_id"):
            value = self.extra_config.get(key)
            if value is not None:
                payload[key] = value
        return payload

    async def _list_users(self) -> list[dict[str, Any]]:
        response = await self._request("GET", "/api/v2/admin/user/")
        candidates: object = response
        if isinstance(response, Mapping):
            for key in ("users", "items", "obj", "results"):
                nested = response.get(key)
                if isinstance(nested, list):
                    candidates = nested
                    break
        if not isinstance(candidates, list):
            raise RelayError("Hiddify list users response is invalid")
        return [dict(item) for item in candidates if isinstance(item, Mapping)]

    async def _get_user_by_name(self, username: str) -> dict[str, Any]:
        normalized_target = username.strip().lower()
        for user in await self._list_users():
            if self._extract_user_name(user).lower() == normalized_target:
                return user
        raise RelayError(f"User {username} not found in Hiddify")

    async def _get_user_details(self, username: str) -> dict[str, Any]:
        user = await self._get_user_by_name(username)
        user_uuid = self._extract_user_uuid(user)
        if not user_uuid:
            raise RelayError(f"Hiddify user {username} does not include uuid")
        response = await self._request("GET", f"/api/v2/admin/user/{user_uuid}/")
        if not isinstance(response, Mapping):
            raise RelayError("Hiddify user details response is invalid")
        return dict(response)

    async def _get_admin_all_configs(self) -> dict[str, Any]:
        response = await self._request("GET", "/api/v2/admin/all-configs/")
        if not isinstance(response, Mapping):
            raise RelayError("Hiddify admin all-configs response is invalid")
        return dict(response)

    def _extract_config_links_from_payload(self, payload: object) -> list[str]:
        seen: set[str] = set()
        links: list[str] = []

        def add_link(raw_link: object) -> None:
            normalized = self._normalize_config_link(raw_link)
            if normalized and normalized not in seen:
                seen.add(normalized)
                links.append(normalized)

        if isinstance(payload, Mapping):
            add_link(payload.get("link"))
            add_link(payload.get("subscription_url"))
            add_link(payload.get("sub_link"))
            raw_links = payload.get("links")
            if isinstance(raw_links, list):
                for raw_link in raw_links:
                    add_link(raw_link)
            for key in ("obj", "items", "results", "configs"):
                nested = payload.get(key)
                if isinstance(nested, list):
                    for item in nested:
                        add_link(item.get("link") if isinstance(item, Mapping) else item)
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, Mapping):
                    add_link(item.get("link"))
                    add_link(item.get("subscription_url"))
                    add_link(item.get("sub_link"))
                else:
                    add_link(item)
        return links

    def _build_subscription_links_from_admin_config(self, user_uuid: str, admin_config: Mapping[str, Any]) -> list[str]:
        chconfigs = admin_config.get("chconfigs")
        if not isinstance(chconfigs, Mapping):
            return []
        root_config = chconfigs.get("0")
        if not isinstance(root_config, Mapping):
            return []
        proxy_path_client = str(root_config.get("proxy_path_client") or "").strip("/")
        if not proxy_path_client or not user_uuid:
            return []
        parsed = urlsplit(self.base_url)
        base_parts = parsed._replace(path="", query="", fragment="")
        links: list[str] = []
        for path in (f"/{proxy_path_client}/{user_uuid}/", f"/{proxy_path_client}/{user_uuid}/singbox/"):
            link = urlunsplit(base_parts._replace(path=path))
            normalized = self._normalize_config_link(link)
            if normalized and normalized not in links:
                links.append(normalized)
        return links

    async def _resolve_config_material(self, user: Mapping[str, Any]) -> tuple[str, str | None]:
        user_uuid = self._extract_user_uuid(user)
        config_links = self._extract_config_links_from_payload(user)
        admin_config = await self._get_admin_all_configs()
        config_links.extend(self._build_subscription_links_from_admin_config(user_uuid, admin_config))
        deduplicated_links: list[str] = []
        seen: set[str] = set()
        for link in config_links:
            if link and link not in seen:
                seen.add(link)
                deduplicated_links.append(link)
        primary_link = deduplicated_links[0] if deduplicated_links else ""
        config_copy_text = "\n".join(deduplicated_links) if deduplicated_links else None
        return primary_link, config_copy_text

    async def test_connection(self) -> None:
        await self._request("GET", "/api/v2/admin/me/")

    async def create_account(self, username: str, traffic_limit_bytes: int, expire_timestamp: int | None) -> ProvisionResult:
        response = await self._request("POST", "/api/v2/admin/user/", self._build_user_payload(username, traffic_limit_bytes, expire_timestamp))
        created_user = dict(response) if isinstance(response, Mapping) else await self._get_user_details(username)
        config_link, config_copy_text = await self._resolve_config_material(created_user)
        if not config_link:
            raise RelayError("Hiddify user created but no config link was returned")
        return ProvisionResult(
            username=self._extract_user_name(created_user, username),
            config_link=config_link,
            config_copy_text=config_copy_text,
            used_traffic_gb=self._usage_gb_to_int(created_user.get("current_usage_GB")),
        )

    async def get_usage(self, username: str) -> dict[str, Any]:
        user = await self._get_user_details(username)
        config_link, config_copy_text = await self._resolve_config_material(user)
        payload = dict(user)
        payload["used_traffic"] = self._usage_gb_to_bytes(payload.get("current_usage_GB"))
        if config_link:
            payload["subscription_url"] = config_link
        if config_copy_text:
            payload["links"] = [link for link in config_copy_text.splitlines() if link.strip()]
        return payload

    async def renew_account(self, username: str, traffic_limit_bytes: int, expire_timestamp: int | None) -> ProvisionResult:
        current_user = await self._get_user_by_name(username)
        user_uuid = self._extract_user_uuid(current_user)
        if not user_uuid:
            raise RelayError(f"Hiddify user {username} does not include uuid")
        response = await self._request("PATCH", f"/api/v2/admin/user/{user_uuid}/", self._build_user_payload(username, traffic_limit_bytes, expire_timestamp))
        updated_user = dict(response) if isinstance(response, Mapping) else await self._get_user_details(username)
        config_link, config_copy_text = await self._resolve_config_material(updated_user)
        if not config_link:
            raise RelayError("Hiddify user updated but no config link was returned")
        return ProvisionResult(
            username=self._extract_user_name(updated_user, username),
            config_link=config_link,
            config_copy_text=config_copy_text,
            used_traffic_gb=self._usage_gb_to_int(updated_user.get("current_usage_GB")),
        )


class XUIClient(BaseVPNClient):
    def __init__(self, base_url: str, api_key: str, extra_config: dict[str, Any] | None = None, **kwargs: Any) -> None:
        super().__init__(self._normalize_base_url(base_url), api_key, extra_config, **kwargs)
        self._api_prefix: str | None = None
        self._session_cookie: str | None = None
        self._csrf_token: str | None = None
        self._subscription_settings: Mapping[str, Any] | None = None

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        parsed = urlsplit(base_url.strip())
        path = parsed.path.rstrip("/")
        for marker in ("/panel/", "/xui/"):
            if marker in path:
                path = path.split(marker, 1)[0]
                break
        for suffix in ("/panel/api/inbounds", "/panel/api", "/panel", "/xui/inbound", "/xui"):
            if path.endswith(suffix):
                path = path[: -len(suffix)]
                break
        normalized = parsed._replace(path=path, query="", fragment="")
        return urlunsplit(normalized).rstrip("/")

    def _candidate_prefixes(self) -> list[str]:
        prefixes: list[str] = []
        parsed_base_url = urlsplit(self.base_url)
        base_path = parsed_base_url.path.rstrip("/")
        if base_path and base_path not in prefixes:
            prefixes.append(base_path)
        for key in ("api_prefix", "panel_base_path", "web_base_path", "webBasePath"):
            raw_value = self.extra_config.get(key)
            if raw_value:
                prefix = str(raw_value).strip()
                if prefix and not prefix.startswith("/"):
                    prefix = f"/{prefix}"
                prefix = prefix.rstrip("/")
                if prefix and prefix not in prefixes:
                    prefixes.append(prefix)
        if "" not in prefixes:
            prefixes.append("")
        return prefixes

    def _request_base_url(self) -> str:
        parsed = urlsplit(self.base_url)
        return urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")

    @staticmethod
    def _merge_cookie_headers(current_cookie: str | None, new_cookie: str | None) -> str | None:
        merged: dict[str, str] = {}
        for raw_cookie in (current_cookie, new_cookie):
            if raw_cookie:
                for part in str(raw_cookie).split(";"):
                    item = part.strip()
                    if item and "=" in item:
                        name, value = item.split("=", 1)
                        merged[name.strip()] = value.strip()
        return "; ".join(f"{name}={value}" for name, value in merged.items()) if merged else None

    @staticmethod
    def _extract_response_json(response: httpx.Response) -> Mapping[str, Any] | None:
        if not response.content:
            return None
        try:
            payload = response.json()
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, Mapping) else None

    @staticmethod
    def _csrf_path(prefix: str, *, authenticated: bool) -> str:
        return f"{prefix}/panel/csrf-token" if authenticated and prefix else "/panel/csrf-token" if authenticated else f"{prefix}/csrf-token" if prefix else "/csrf-token"

    def _load_credentials(self) -> dict[str, str] | None:
        try:
            payload = json.loads(self.api_key)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "").strip()
        return {"username": username, "password": password} if username and password else None

    @staticmethod
    def _session_cookie_from_response(response: httpx.Response) -> str | None:
        cookies = [f"{cookie.name}={cookie.value}" for cookie in response.cookies.jar]
        return "; ".join(cookies) if cookies else None

    @staticmethod
    def _is_auth_failure_message(message: str) -> bool:
        normalized = message.strip().lower()
        return any(token in normalized for token in ("login", "auth", "unauthor", "session", "expired"))

    @staticmethod
    def _response_requires_login(response: httpx.Response) -> bool:
        if response.is_redirect and "/login" in str(response.headers.get("location") or "").lower():
            return True
        content_type = str(response.headers.get("content-type") or "").lower()
        if "text/html" not in content_type:
            return False
        body = response.text[:1000].lower()
        return "login" in body and "form" in body

    async def _fetch_csrf_token(self, client: httpx.AsyncClient, prefix: str, *, authenticated: bool, cookie_header: str | None = None) -> tuple[str | None, str | None]:
        headers: dict[str, str] = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
        if cookie_header:
            headers["Cookie"] = cookie_header
        try:
            response = await client.get(self._csrf_path(prefix, authenticated=authenticated), headers=headers)
        except httpx.RequestError as exc:
            raise RelayError(self._build_request_error_message(exc)) from exc
        response.raise_for_status()
        payload = self._extract_response_json(response) or {}
        token = str(payload.get("obj") or "").strip() or None
        response_cookie = self._session_cookie_from_response(response)
        return token, self._merge_cookie_headers(cookie_header, response_cookie)

    async def _login_with_form(self, prefix: str, credentials: dict[str, str]) -> str | None:
        login_path = f"{prefix}/login" if prefix else "/login"
        async with httpx.AsyncClient(base_url=self._request_base_url(), timeout=self._client_timeout(), follow_redirects=False, trust_env=False) as client:
            csrf_token: str | None = None
            cookie_header: str | None = None
            try:
                csrf_token, cookie_header = await self._fetch_csrf_token(client, prefix, authenticated=False)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 404:
                    raise
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
            }
            if csrf_token:
                headers["X-CSRF-Token"] = csrf_token
            if cookie_header:
                headers["Cookie"] = cookie_header
            try:
                response = await client.post(login_path, data={"username": credentials["username"], "password": credentials["password"]}, headers=headers)
            except httpx.RequestError as exc:
                raise RelayError(self._build_request_error_message(exc)) from exc
            if response.status_code in {403, 404}:
                response.raise_for_status()
            session_cookie = self._merge_cookie_headers(cookie_header, self._session_cookie_from_response(response))
            if response.is_redirect and session_cookie and "/login" not in str(response.headers.get("location") or "").lower():
                self._csrf_token = csrf_token
                try:
                    panel_csrf, _ = await self._fetch_csrf_token(client, prefix, authenticated=True, cookie_header=session_cookie)
                except httpx.HTTPStatusError:
                    panel_csrf = None
                self._csrf_token = panel_csrf or csrf_token
                return session_cookie
            response.raise_for_status()
            payload = self._extract_response_json(response) or {}
            if payload.get("success") is False:
                raise RelayError(str(payload.get("msg") or "ورود به پنل 3X-UI ناموفق بود"))
            if not session_cookie:
                raise RelayError("ورود به پنل 3X-UI انجام شد ولی کوکی نشست دریافت نشد")
            try:
                panel_csrf, _ = await self._fetch_csrf_token(client, prefix, authenticated=True, cookie_header=session_cookie)
            except httpx.HTTPStatusError:
                panel_csrf = None
            self._csrf_token = panel_csrf or csrf_token
            return session_cookie

    async def _login_with_api(self, prefix: str, credentials: dict[str, str]) -> str | None:
        api_login_path = f"{prefix}/api/login" if prefix else "/api/login"
        for payload in ({"username": credentials["username"], "password": credentials["password"]}, {"user": credentials["username"], "pass": credentials["password"]}):
            try:
                async with httpx.AsyncClient(base_url=self._request_base_url(), timeout=self._client_timeout(), trust_env=False) as client:
                    response = await client.post(api_login_path, json=payload, headers={"Accept": "application/json", "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"})
            except httpx.RequestError as exc:
                raise RelayError(self._build_request_error_message(exc)) from exc
            if response.status_code == 404:
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError:
                    continue
            response.raise_for_status()
            response_payload = self._extract_response_json(response) or {}
            if response_payload.get("success") is False:
                raise RelayError(str(response_payload.get("msg") or "ورود به پنل S-UI ناموفق بود"))
            session_cookie = self._session_cookie_from_response(response)
            if session_cookie:
                return session_cookie
        return None

    async def _login(self, *, force_refresh: bool = False) -> str | None:
        credentials = self._load_credentials()
        if credentials is None:
            return None
        if self._session_cookie and not force_refresh:
            return self._session_cookie
        last_not_found: httpx.HTTPStatusError | None = None
        for prefix in self._candidate_prefixes():
            self._csrf_token = None
            try:
                session_cookie = await self._login_with_form(prefix, credentials)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    last_not_found = exc
                    try:
                        session_cookie = await self._login_with_api(prefix, credentials)
                    except httpx.HTTPStatusError as api_exc:
                        if api_exc.response.status_code == 404:
                            last_not_found = api_exc
                            continue
                        raise
                else:
                    raise
            if session_cookie:
                self._session_cookie = session_cookie
                return session_cookie
        if last_not_found is not None:
            raise RelayError("ورود به پنل 3X-UI ممکن نشد. آدرس پنل، WebBasePath و نام کاربری/رمز ادمین را بررسی کنید.") from last_not_found
        raise RelayError("ورود به پنل 3X-UI ممکن نشد. آدرس پنل، WebBasePath و نام کاربری/رمز ادمین را بررسی کنید.")

    async def _build_headers_for_method(self, method: str) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}
        session_cookie = await self._login()
        if session_cookie:
            headers["Cookie"] = session_cookie
            if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and self._csrf_token:
                headers["X-CSRF-Token"] = self._csrf_token
        elif self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _unwrap_response(self, response: object) -> Any:
        if not isinstance(response, Mapping):
            return response
        if response.get("success") is False:
            raise RelayError(str(response.get("msg") or "XUI request failed"))
        return response.get("obj") if "obj" in response else response

    async def _request_with_retry(self, method: str, path: str, payload: dict[str, Any] | None, *, allow_refresh: bool) -> dict[str, Any]:
        headers = await self._build_headers_for_method(method)
        try:
            async with httpx.AsyncClient(base_url=self._request_base_url(), timeout=self._client_timeout(), headers=headers, trust_env=False) as client:
                response = await client.request(method, path, json=payload)
        except httpx.RequestError as exc:
            raise RelayError(self._build_request_error_message(exc)) from exc
        if allow_refresh and self._load_credentials() is not None and (response.status_code in {401, 403} or self._response_requires_login(response)):
            self._session_cookie = None
            self._csrf_token = None
            self._api_prefix = None
            await self._login(force_refresh=True)
            return await self._request_with_retry(method, path, payload, allow_refresh=False)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            response_text = response.text.strip()
            detail = f" | response: {response_text[:500]}" if response_text else ""
            raise httpx.HTTPStatusError(f"{exc}{detail}", request=exc.request, response=exc.response) from exc
        if response.content:
            try:
                return response.json()
            except json.JSONDecodeError as exc:
                raise RelayError("پاسخ پنل 3X-UI معتبر نیست و JSON برنگرداند") from exc
        return {}

    async def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._request_with_retry(method, path, payload, allow_refresh=True)

    async def _resolve_api_prefix(self) -> str:
        if self._api_prefix is not None:
            return self._api_prefix
        for prefix in self._candidate_prefixes():
            try:
                response = await self._request("GET", f"{prefix}/panel/api/inbounds/list")
                self._unwrap_response(response)
                self._api_prefix = prefix
                return prefix
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 404:
                    raise
        raise RelayError("مسیر API پنل 3X-UI پیدا نشد")

    async def _api_request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        prefix = await self._resolve_api_prefix()
        response = await self._request(method, f"{prefix}{path}", payload)
        try:
            return self._unwrap_response(response)
        except RelayError as exc:
            if self._load_credentials() is None or not self._is_auth_failure_message(str(exc)):
                raise
            self._session_cookie = None
            await self._login(force_refresh=True)
            response = await self._request(method, f"{prefix}{path}", payload)
            return self._unwrap_response(response)

    async def _list_inbounds(self) -> list[dict[str, Any]]:
        payload = await self._api_request("GET", "/panel/api/inbounds/list")
        if not isinstance(payload, list):
            raise RelayError("XUI inbounds response is invalid")
        return [item for item in payload if isinstance(item, dict)]

    async def _get_inbound(self, inbound_id: int | None = None) -> dict[str, Any]:
        inbounds = await self._list_inbounds()
        if not inbounds:
            raise RelayError("هیچ inbound فعالی در پنل 3X-UI پیدا نشد")
        configured_inbound_id = self.extra_config.get("inbound_id")
        target_id = inbound_id or (int(configured_inbound_id) if configured_inbound_id is not None else None)
        if target_id is None:
            return inbounds[0]
        for inbound in inbounds:
            if int(inbound.get("id") or 0) == target_id:
                return inbound
        raise RelayError(f"Inbound با شناسه {target_id} در پنل XUI پیدا نشد")

    @staticmethod
    def _load_clients(inbound: Mapping[str, Any]) -> list[dict[str, Any]]:
        raw_settings = inbound.get("settings")
        if not raw_settings:
            return []
        try:
            settings = json.loads(str(raw_settings))
        except json.JSONDecodeError as exc:
            raise RelayError("XUI inbound settings JSON is invalid") from exc
        clients = settings.get("clients") if isinstance(settings, Mapping) else None
        return [client for client in clients if isinstance(client, dict)] if isinstance(clients, list) else []

    @staticmethod
    def _find_client(inbound: Mapping[str, Any], username: str) -> dict[str, Any] | None:
        for client in XUIClient._load_clients(inbound):
            if str(client.get("email") or "").strip() == username:
                return client
        return None

    @staticmethod
    def _client_primary_key(protocol: str, client: Mapping[str, Any]) -> str:
        normalized_protocol = protocol.lower()
        if normalized_protocol == "trojan":
            return str(client.get("password") or "").strip()
        if normalized_protocol == "shadowsocks":
            return str(client.get("email") or "").strip()
        if normalized_protocol in {"hysteria", "hysteria2"}:
            return str(client.get("auth") or "").strip()
        return str(client.get("id") or "").strip()

    @staticmethod
    def _random_token(length: int = 16) -> str:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _build_client_payload(self, protocol: str, username: str, traffic_limit_bytes: int, expire_timestamp: int | None, existing_client: Mapping[str, Any] | None = None, inbound: Mapping[str, Any] | None = None) -> dict[str, Any]:
        client: dict[str, Any] = dict(existing_client or {})
        client.update({
            "email": username,
            "limitIp": int(client.get("limitIp") or 0),
            "totalGB": int(traffic_limit_bytes),
            "expiryTime": int(expire_timestamp * 1000) if expire_timestamp is not None else 0,
            "enable": bool(client.get("enable", True)),
            "tgId": int(client.get("tgId") or 0),
            "subId": str(client.get("subId") or self._random_token(16)),
            "comment": str(client.get("comment") or "telegram-vpn-shop"),
            "reset": int(client.get("reset") or 0),
        })
        normalized_protocol = protocol.lower()
        if normalized_protocol == "vmess":
            client.setdefault("id", str(uuid4()))
            client.setdefault("security", str(self.extra_config.get("security") or client.get("security") or "auto"))
        elif normalized_protocol == "vless":
            client.setdefault("id", str(uuid4()))
            client.setdefault("flow", str(self.extra_config.get("flow") or client.get("flow") or ""))
        elif normalized_protocol == "trojan":
            client.setdefault("password", self._random_token(10))
        elif normalized_protocol == "shadowsocks":
            inbound_method = ""
            if inbound is not None:
                try:
                    inbound_settings = json.loads(str(inbound.get("settings") or "{}"))
                except json.JSONDecodeError:
                    inbound_settings = {}
                inbound_method = str(inbound_settings.get("method") or "") if isinstance(inbound_settings, Mapping) else ""
            client.setdefault("method", str(self.extra_config.get("method") or client.get("method") or inbound_method))
            client.setdefault("password", self._random_token(16))
        elif normalized_protocol in {"hysteria", "hysteria2"}:
            client.setdefault("auth", self._random_token(16))
        else:
            raise RelayError(f"پروتکل {protocol} در XUI برای ساخت اکانت پشتیبانی نمی‌شود")
        return client

    async def _get_client_record(self, username: str) -> tuple[dict[str, Any], list[int]]:
        payload = await self._api_request("GET", f"/panel/api/clients/get/{quote(username, safe='')}")
        if not isinstance(payload, Mapping):
            raise RelayError("پاسخ پنل 3X-UI برای اطلاعات کلاینت معتبر نیست")
        client = payload.get("client") if isinstance(payload.get("client"), Mapping) else None
        if client is None:
            raise RelayError(f"کاربر {username} در پنل 3X-UI پیدا نشد")
        inbound_ids = payload.get("inboundIds")
        normalized_inbound_ids = [int(item) for item in inbound_ids if str(item).strip().isdigit()] if isinstance(inbound_ids, list) else []
        normalized_client = dict(client)
        if not normalized_client.get("id") and normalized_client.get("uuid"):
            normalized_client["id"] = normalized_client.get("uuid")
        return normalized_client, normalized_inbound_ids

    async def _get_sub_links(self, sub_id: str) -> list[str]:
        if not sub_id:
            return []
        try:
            payload = await self._api_request("GET", f"/panel/api/clients/subLinks/{quote(sub_id, safe='')}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
            try:
                payload = await self._api_request("GET", f"/panel/api/inbounds/getSubLinks/{quote(sub_id, safe='')}")
            except httpx.HTTPStatusError as legacy_exc:
                if legacy_exc.response.status_code == 404:
                    return []
                raise
        if not isinstance(payload, list):
            return []
        links: list[str] = []
        seen: set[str] = set()
        for raw_link in payload:
            normalized = self._normalize_config_link(raw_link)
            if normalized and normalized not in seen:
                seen.add(normalized)
                links.append(normalized)
        return links

    async def _get_client_links(self, username: str, *, sub_id: str | None = None) -> list[str]:
        try:
            payload = await self._api_request("GET", f"/panel/api/clients/links/{quote(username, safe='')}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
            return await self._get_sub_links(sub_id or "")
        if not isinstance(payload, list):
            return []
        links: list[str] = []
        seen: set[str] = set()
        for raw_link in payload:
            normalized = self._normalize_config_link(raw_link)
            if normalized and normalized not in seen:
                seen.add(normalized)
                links.append(normalized)
        return links

    async def _get_subscription_settings(self) -> Mapping[str, Any]:
        if self._subscription_settings is not None:
            return self._subscription_settings
        try:
            payload = await self._api_request("POST", "/panel/setting/defaultSettings", {})
        except (httpx.HTTPStatusError, RelayError):
            self._subscription_settings = {}
            return self._subscription_settings
        self._subscription_settings = payload if isinstance(payload, Mapping) else {}
        return self._subscription_settings

    def _build_subscription_link(self, sub_id: str) -> str:
        if not sub_id:
            return ""
        subscription_base_url = str(self.extra_config.get("subscription_base_url") or self.base_url).strip().rstrip("/")
        subscription_path = str(self.extra_config.get("subscription_path") or self.extra_config.get("sub_path") or "/sub/").strip() or "/sub/"
        if not subscription_path.startswith("/"):
            subscription_path = f"/{subscription_path}"
        if not subscription_path.endswith("/"):
            subscription_path = f"{subscription_path}/"
        return self._normalize_config_link(f"{subscription_base_url}{subscription_path}{sub_id}")

    async def _resolve_subscription_link(self, sub_id: str) -> str:
        if not sub_id:
            return ""
        explicit_sub_uri = str(self.extra_config.get("sub_uri") or self.extra_config.get("subscription_uri") or "").strip()
        if explicit_sub_uri:
            base_uri = explicit_sub_uri if explicit_sub_uri.endswith("/") else f"{explicit_sub_uri}/"
            return self._normalize_config_link(f"{base_uri}{sub_id}")
        settings = await self._get_subscription_settings()
        settings_sub_uri = str(settings.get("subURI") or "").strip()
        if settings_sub_uri:
            base_uri = settings_sub_uri if settings_sub_uri.endswith("/") else f"{settings_sub_uri}/"
            return self._normalize_config_link(f"{base_uri}{sub_id}")
        return self._build_subscription_link(sub_id)

    async def _resolve_config_material(self, config_links: list[str], sub_id: str) -> tuple[str, str | None]:
        subscription_link = await self._resolve_subscription_link(sub_id)
        primary_link = subscription_link or (config_links[0] if config_links else "")
        config_copy_text = "\n".join(config_links) if config_links else None
        return primary_link, config_copy_text

    async def test_connection(self) -> None:
        await self._resolve_api_prefix()
        await self._get_inbound()

    async def create_account(self, username: str, traffic_limit_bytes: int, expire_timestamp: int | None) -> ProvisionResult:
        inbound = await self._get_inbound()
        protocol = str(inbound.get("protocol") or "").strip().lower()
        client = self._build_client_payload(protocol, username, traffic_limit_bytes, expire_timestamp, inbound=inbound)
        inbound_id = int(inbound.get("id") or 0)
        if inbound_id <= 0:
            raise RelayError("شناسه inbound برای ساخت کاربر در 3X-UI معتبر نیست")
        await self._api_request("POST", "/panel/api/clients/add", {"client": client, "inboundIds": [inbound_id]})
        created_client, _ = await self._get_client_record(username)
        sub_id = str(created_client.get("subId") or client.get("subId") or "").strip()
        config_links = await self._get_client_links(username, sub_id=sub_id)
        primary_link, config_copy_text = await self._resolve_config_material(config_links, sub_id)
        if not primary_link:
            raise RelayError("لینک اشتراک برای کاربر ساخته شد اما از پنل 3X-UI قابل دریافت نبود")
        return ProvisionResult(username=username, config_link=primary_link, config_copy_text=config_copy_text)

    async def get_usage(self, username: str) -> dict[str, Any]:
        try:
            payload = await self._api_request("GET", f"/panel/api/clients/traffic/{quote(username, safe='')}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
            payload = await self._api_request("GET", f"/panel/api/inbounds/getClientTraffics/{quote(username, safe='')}")
        return payload if isinstance(payload, dict) else {}

    async def renew_account(self, username: str, traffic_limit_bytes: int, expire_timestamp: int | None) -> ProvisionResult:
        existing_client, inbound_ids = await self._get_client_record(username)
        preferred_inbound_id = self.extra_config.get("inbound_id")
        target_inbound_id = int(preferred_inbound_id) if preferred_inbound_id is not None else (inbound_ids[0] if inbound_ids else 0)
        inbound = await self._get_inbound(target_inbound_id or None)
        protocol = str(inbound.get("protocol") or "").strip().lower()
        updated_client = self._build_client_payload(protocol, username, traffic_limit_bytes, expire_timestamp, existing_client=existing_client, inbound=inbound)
        await self._api_request("POST", f"/panel/api/clients/update/{quote(username, safe='')}", updated_client)
        refreshed_client, _ = await self._get_client_record(username)
        sub_id = str(refreshed_client.get("subId") or updated_client.get("subId") or "").strip()
        config_links = await self._get_client_links(username, sub_id=sub_id)
        primary_link, config_copy_text = await self._resolve_config_material(config_links, sub_id)
        if not primary_link:
            raise RelayError("لینک اشتراک کاربر پس از تمدید از پنل 3X-UI قابل دریافت نبود")
        return ProvisionResult(username=username, config_link=primary_link, config_copy_text=config_copy_text)


def build_client(panel: dict[str, Any], *, connect_timeout: float, request_timeout: float) -> BaseVPNClient:
    panel_type = str(panel["type"]).strip().lower()
    base_url = str(panel["base_url"])
    api_key = str(panel["api_key"])
    extra_config = panel.get("extra_config") or {}
    kwargs = {"connect_timeout": connect_timeout, "request_timeout": request_timeout}
    if panel_type == "xui":
        return XUIClient(base_url, api_key, extra_config, **kwargs)
    if panel_type == "marzban":
        return MarzbanClient(base_url, api_key, extra_config, **kwargs)
    if panel_type == "hiddify":
        return HiddifyClient(base_url, api_key, extra_config, **kwargs)
    raise RelayError("unsupported VPN panel type")


def is_retryable_error(message: str) -> bool:
    normalized = message.lower()
    tokens = ("timeout", "timed out", "connect", "network", "tempor", "rate limit", "connection reset", "unreachable", "مهلت", "اتصال", "شبکه")
    return any(token in normalized for token in tokens)


def is_duplicate_account_error(message: str) -> bool:
    normalized = message.lower()
    tokens = ("already exists", "already exist", "duplicate", "conflict", "exist", "409", "exists", "تکراری", "وجود دارد", "قبلا")
    return any(token in normalized for token in tokens)


async def execute_job(job: dict[str, Any], *, connect_timeout: float, request_timeout: float) -> dict[str, Any]:
    operation = str(job["operation"]).strip().lower()
    panel = job["panel"]
    payload = job["request_payload"]
    client = build_client(panel, connect_timeout=connect_timeout, request_timeout=request_timeout)
    if operation == "test_connection":
        await client.test_connection()
        return {"ok": True}
    if operation == "create_account":
        username = str(payload["username"])
        traffic_limit_bytes = int(payload["traffic_limit_bytes"])
        expire_timestamp = int(payload["expire_timestamp"]) if payload.get("expire_timestamp") is not None else None
        try:
            result = await client.create_account(username=username, traffic_limit_bytes=traffic_limit_bytes, expire_timestamp=expire_timestamp)
        except Exception as exc:  # noqa: BLE001
            if not is_duplicate_account_error(str(exc)):
                raise
            result = await client.renew_account(username=username, traffic_limit_bytes=traffic_limit_bytes, expire_timestamp=expire_timestamp)
        return {
            "username": result.username,
            "config_link": result.config_link,
            "config_copy_text": result.config_copy_text,
            "used_traffic_gb": result.used_traffic_gb,
        }
    if operation == "renew_account":
        result = await client.renew_account(
            username=str(payload["username"]),
            traffic_limit_bytes=int(payload["traffic_limit_bytes"]),
            expire_timestamp=int(payload["expire_timestamp"]) if payload.get("expire_timestamp") is not None else None,
        )
        return {
            "username": result.username,
            "config_link": result.config_link,
            "config_copy_text": result.config_copy_text,
            "used_traffic_gb": result.used_traffic_gb,
        }
    if operation == "get_usage":
        usage = await client.get_usage(str(payload["username"]))
        return usage if isinstance(usage, dict) else {"value": usage}
    raise RelayError(f"unsupported relay operation: {operation}")


async def relay_request(client: httpx.AsyncClient, method: str, path: str, *, secret: str, agent_name: str, json_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    response = await client.request(method, path, json=json_payload, headers={"X-Relay-Secret": secret, "X-Relay-Agent": agent_name})
    response.raise_for_status()
    return response.json() if response.content else {}


async def run_agent(base_url: str, secret: str, agent_name: str, poll_seconds: float, connect_timeout: float, request_timeout: float) -> None:
    async with httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=30.0, trust_env=False) as client:
        while True:
            try:
                await relay_request(client, "POST", "/api/v1/vpn-relay/agent/heartbeat", secret=secret, agent_name=agent_name, json_payload={"lease_seconds": 60, "metadata": {"runtime": "termux-standalone", "version": 1}})
                payload = await relay_request(client, "POST", "/api/v1/vpn-relay/agent/pull", secret=secret, agent_name=agent_name, json_payload={"max_jobs": 1})
                jobs = [decrypt_payload(token, secret) for token in (payload.get("encrypted_jobs") or [])]
                if not jobs:
                    await asyncio.sleep(poll_seconds)
                    continue
                for job in jobs:
                    job_id = str(job["id"])
                    try:
                        result = await execute_job(job, connect_timeout=connect_timeout, request_timeout=request_timeout)
                    except Exception as exc:  # noqa: BLE001
                        await relay_request(
                            client,
                            "POST",
                            f"/api/v1/vpn-relay/agent/jobs/{job_id}/fail",
                            secret=secret,
                            agent_name=agent_name,
                            json_payload={"encrypted_payload": encrypt_payload({"error_message": str(exc)[:2000], "retryable": is_retryable_error(str(exc)), "retry_delay_seconds": 15}, secret)},
                        )
                        continue
                    await relay_request(
                        client,
                        "POST",
                        f"/api/v1/vpn-relay/agent/jobs/{job_id}/complete",
                        secret=secret,
                        agent_name=agent_name,
                        json_payload={"encrypted_payload": encrypt_payload(result, secret)},
                    )
            except Exception as exc:  # noqa: BLE001
                print(f"[vpn-relay-agent] loop error: {exc}")
                await asyncio.sleep(max(poll_seconds, 3.0))


def main() -> None:
    parser = argparse.ArgumentParser(description="Standalone VPN relay agent for Termux")
    parser.add_argument("--server", required=True, help="Public base URL of the foreign server, e.g. https://example.com")
    parser.add_argument("--secret", required=True, help="Shared relay secret configured on the foreign server")
    parser.add_argument("--agent-name", default="termux-agent-1", help="Stable name of this relay agent")
    parser.add_argument("--poll-seconds", type=float, default=2.0, help="Polling interval when queue is empty")
    parser.add_argument("--connect-timeout", type=float, default=4.0, help="Panel connect timeout in seconds")
    parser.add_argument("--request-timeout", type=float, default=15.0, help="Panel request timeout in seconds")
    args = parser.parse_args()
    asyncio.run(run_agent(args.server, args.secret, args.agent_name, args.poll_seconds, args.connect_timeout, args.request_timeout))


if __name__ == "__main__":
    main()