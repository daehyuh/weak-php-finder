"""Offline PHP2Shell inventory review. No network traffic or exploit requests."""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
FIELDS = ("host", "php_state", "php_version", "evidence", "vendor_patch_id")
OUT_FIELDS = ("host", "status", "reason", "php_state", "php_version", "evidence", "vendor_patch_id")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.ASCII)
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
POLICY_DATE = "2026-10-21"
SOURCES = (
    "https://www.php.net/archive/2026.php#2026-10-21-5",
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
)


def clean_host(value: str) -> str:
    host = value.strip().lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253 or not all(LABEL_RE.fullmatch(label) for label in host.split(".")):
        raise ValueError(f"Invalid host: {value!r}")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError("IP literals are not accepted; use inventory hostnames")


def classify(row: dict[str, str]) -> tuple[str, str]:
    state = row["php_state"].strip().lower()
    version = row["php_version"].strip()
    evidence = row["evidence"].strip()
    vendor = row["vendor_patch_id"].strip()
    if state not in {"yes", "no", "unknown"}:
        return "REVIEW", "php_state must be yes, no, or unknown"
    if state == "no":
        if version or vendor:
            return "REVIEW", "Conflicting inventory: no PHP but a version or PHP patch is recorded"
        return ("NOT_APPLICABLE", "Owner inventory confirms no PHP; retain evidence") if evidence else ("REVIEW", "No-PHP assertion has no evidence")
    if state == "unknown":
        return "REVIEW", "PHP usage not established"
    if not evidence:
        return "REVIEW", "PHP version or patch assertion has no evidence"
    match = VERSION_RE.fullmatch(version)
    if not match:
        return "REVIEW", "Exact runtime version missing or malformed"
    major, minor, patch = map(int, match.groups())
    if vendor:
        return "VENDOR_REVIEW", "Vendor backport claimed; confirm package advisory and deployed build"
    floor = FIXED.get((major, minor))
    if floor is not None:
        if patch >= floor:
            return "PATCHED_VERSION", f"PHP {major}.{minor}.{patch} meets official fixed floor {major}.{minor}.{floor}; confirm deployed build"
        return "ACTION", f"PHP {major}.{minor}.{patch} is below official fixed floor {major}.{minor}.{floor}"
    if (major, minor) < (8, 2):
        return "ACTION", "Unsupported upstream branch; upgrade or verify vendor backport"
    return "REVIEW", "Branch is not in the 2026-10-21 stable-release matrix"


def run(hosts_path: Path, inventory_path: Path, output_path: Path) -> list[dict[str, str]]:
    if output_path.resolve() in {hosts_path.resolve(), inventory_path.resolve()}:
        raise ValueError("Output must not overwrite an input file")
    hosts = sorted({clean_host(line) for line in hosts_path.read_text(encoding="utf-8-sig").splitlines() if line.strip() and not line.lstrip().startswith("#")})
    if not hosts:
        raise ValueError("No hostnames were provided")
    inventory: dict[str, dict[str, str]] = {}
    with inventory_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or not set(FIELDS).issubset(reader.fieldnames):
            raise ValueError(f"Inventory requires columns: {', '.join(FIELDS)}")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("Inventory has duplicate column names")
        for row in reader:
            host = clean_host(row["host"])
            if host in inventory:
                raise ValueError(f"Duplicate inventory host: {host}")
            inventory[host] = {key: (row.get(key) or "") for key in FIELDS}
    results = []
    for host in hosts:
        row = inventory.get(host, {key: "" for key in FIELDS})
        if host not in inventory:
            row["php_state"] = "unknown"
        status, reason = classify(row)
        results.append({"host": host, "status": status, "reason": reason, **{k: row[k] for k in FIELDS if k != "host"}})
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=OUT_FIELDS)
        writer.writeheader()
        writer.writerows({key: spreadsheet_safe(value) for key, value in row.items()} for row in results)
    return results


def spreadsheet_safe(value: str) -> str:
    """Keep untrusted evidence strings from becoming Excel formulas."""
    if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def write_json(path: Path, results: list[dict[str, str]], hosts: Path, inventory: Path) -> None:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "offline_inventory_review",
        "policy_date": POLICY_DATE,
        "network_requests": 0,
        "sources": list(SOURCES),
        "input_sha256": {
            "hosts": hashlib.sha256(hosts.read_bytes()).hexdigest(),
            "inventory": hashlib.sha256(inventory.read_bytes()).hexdigest(),
        },
        "summary": dict(sorted(Counter(row["status"] for row in results).items())),
        "results": results,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosts", required=True, type=Path, help="One hostname per line")
    parser.add_argument("--inventory", required=True, type=Path, help="Owner-provided runtime inventory CSV")
    parser.add_argument("--out", required=True, type=Path, help="Output review CSV")
    parser.add_argument("--json-out", type=Path, help="Optional JSON with policy sources, counts and input hashes")
    args = parser.parse_args()
    try:
        if args.json_out and args.json_out.resolve() in {args.hosts.resolve(), args.inventory.resolve(), args.out.resolve()}:
            raise ValueError("JSON output must be different from all input and CSV output paths")
        results = run(args.hosts, args.inventory, args.out)
        if args.json_out:
            write_json(args.json_out, results, args.hosts, args.inventory)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    counts = {status: sum(r["status"] == status for r in results) for status in sorted({r["status"] for r in results})}
    print(f"Reviewed {len(results)} hostnames: {counts}")
    print("Offline classification only; no host was contacted or exploit tested.")


if __name__ == "__main__":
    main()
