"""Offline, deterministic enrichment: directory, IP reputation, and app catalog lookups.

Same alert and same context files in, same enrichment out. No network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from casebook import paths
from casebook.models import (
    Alert,
    AppCatalog,
    Directory,
    IpReputation,
    load_app_catalog,
    load_directory,
    load_ip_reputation,
)


class Context:
    def __init__(self, directory: Directory, reputation: IpReputation, apps: AppCatalog):
        self.users = {u.upn: u for u in directory.users}
        self.ips = {r.ip: r for r in reputation.records}
        self.apps = {a.app_id: a for a in apps.apps}

    @classmethod
    def load(cls, context_dir: Path = paths.CONTEXT) -> Context:
        return cls(
            load_directory(context_dir / "directory.json"),
            load_ip_reputation(context_dir / "ip-reputation.json"),
            load_app_catalog(context_dir / "apps.json"),
        )


def enrich(alert: Alert, ctx: Context) -> dict[str, Any]:
    users = []
    for upn in alert.entities.users:
        record = ctx.users.get(upn)
        if record is None:
            users.append({"upn": upn, "found": False})
            continue
        entry: dict[str, Any] = {"upn": upn, "found": True, **record.model_dump(exclude={"upn"})}
        # Which alert IPs this user has never been seen on: the question an analyst asks first.
        entry["alert_ips_not_known_for_user"] = [
            ip for ip in alert.entities.ips if ip not in record.known_ips
        ]
        entry["alert_countries_outside_usual"] = sorted(
            {
                ctx.ips[ip].country
                for ip in alert.entities.ips
                if ip in ctx.ips and ctx.ips[ip].country not in record.usual_countries
            }
        )
        users.append(entry)

    ips = []
    for ip in alert.entities.ips:
        record = ctx.ips.get(ip)
        if record is None:
            ips.append({"ip": ip, "found": False})
        else:
            ips.append({"ip": ip, "found": True, **record.model_dump(exclude={"ip"})})

    apps = []
    for app_id in alert.entities.apps:
        record = ctx.apps.get(app_id)
        if record is None:
            apps.append({"app_id": app_id, "found": False})
        else:
            apps.append({"app_id": app_id, "found": True, **record.model_dump(exclude={"app_id"})})

    return {
        "sources": ["context/directory.json", "context/ip-reputation.json", "context/apps.json"],
        "users": users,
        "ips": ips,
        "apps": apps,
    }
