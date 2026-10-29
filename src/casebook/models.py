"""Schemas for alerts and the offline enrichment context."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# RFC 5737 documentation ranges. Every IP in this repo must come from one of these,
# so nothing here can ever point at a real host.
DOC_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)

ORG_DOMAIN = "harborline.example"


def _check_doc_ip(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if not any(ip in net for net in DOC_NETWORKS):
        raise ValueError(f"{value} is outside the RFC 5737 documentation ranges")
    return value


def _check_org_upn(value: str) -> str:
    if not value.endswith("@" + ORG_DOMAIN):
        raise ValueError(f"{value} is not a {ORG_DOMAIN} account")
    return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- Alerts -------------------------------------------------------------------


class Detection(_Strict):
    name: str
    rule_id: str
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    tactic: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    source_table: str


class Entities(_Strict):
    users: list[str] = []
    ips: list[str] = []
    apps: list[str] = []

    @field_validator("users")
    @classmethod
    def _users(cls, v: list[str]) -> list[str]:
        return [_check_org_upn(u) for u in v]

    @field_validator("ips")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        return [_check_doc_ip(i) for i in v]


class Alert(_Strict):
    id: str = Field(pattern=r"^[a-z0-9-]+$")
    title: str
    fired_at: datetime
    detection: Detection
    entities: Entities
    detection_output: dict[str, Any]
    evidence: list[dict[str, Any]] = Field(min_length=1)


def load_alert(path: Path) -> Alert:
    return Alert.model_validate(json.loads(path.read_text(encoding="utf-8")))


# --- Context ------------------------------------------------------------------


class DirectoryUser(_Strict):
    upn: str
    display_name: str
    title: str
    department: str
    is_admin: bool
    admin_roles: list[str] = []
    mfa_methods: list[str]
    usual_countries: list[str]
    known_ips: list[str] = []
    notes: str = ""

    @field_validator("upn")
    @classmethod
    def _upn(cls, v: str) -> str:
        return _check_org_upn(v)

    @field_validator("known_ips")
    @classmethod
    def _known_ips(cls, v: list[str]) -> list[str]:
        return [_check_doc_ip(i) for i in v]


class Directory(_Strict):
    organization: str
    domain: Literal["harborline.example"]
    users: list[DirectoryUser]


class IpRecord(_Strict):
    ip: str
    country: str = Field(min_length=2, max_length=2)
    asn: str
    owner: str
    reputation: Literal["benign", "unknown", "suspicious", "malicious"]
    notes: str = ""

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        return _check_doc_ip(v)


class IpReputation(_Strict):
    records: list[IpRecord]


class AppRecord(_Strict):
    app_id: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    display_name: str
    publisher: str
    verified_publisher: bool
    sanctioned: bool
    approved_permissions: list[str] = []
    notes: str = ""


class AppCatalog(_Strict):
    apps: list[AppRecord]


def load_directory(path: Path) -> Directory:
    return Directory.model_validate(json.loads(path.read_text(encoding="utf-8")))


def load_ip_reputation(path: Path) -> IpReputation:
    return IpReputation.model_validate(json.loads(path.read_text(encoding="utf-8")))


def load_app_catalog(path: Path) -> AppCatalog:
    return AppCatalog.model_validate(json.loads(path.read_text(encoding="utf-8")))
