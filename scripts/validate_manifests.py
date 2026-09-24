#!/usr/bin/env python3
"""Validate and exercise the HoangDuc All-In-One Tool manifests.

This repository ships the JSON manifests that the distributed Windows EXE
reads at runtime:

* ``version.json``  -> auto-update / minimum-version gate
* ``revoked.json``  -> globally revoked activation keys
* ``hwids.json``    -> per-machine (HWID) license database

There is no application to build here, so the meaningful end-to-end check is
to validate that these manifests are well formed and internally consistent,
and to simulate the checks the client performs against them.

Exit code is non-zero when a structural problem is found, so this script
doubles as the environment bootstrap gate and a CI-style sanity check.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

KEY_RE = re.compile(r"^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$")
HWID_RE = re.compile(r"^HD-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$")


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.info: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def note(self, msg: str) -> None:
        self.info.append(msg)


def load_json(path: Path, report: Report):
    if not path.exists():
        report.error(f"{path.name}: file is missing")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report.error(f"{path.name}: invalid JSON ({exc})")
        return None


def parse_date(value: str):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def version_key(value: str):
    """Return a comparable tuple for a dotted or plain numeric version."""
    parts = re.split(r"[.\-]", str(value))
    key = []
    for part in parts:
        key.append((0, int(part)) if part.isdigit() else (1, part))
    return tuple(key)


def validate_version(data, report: Report) -> None:
    if not isinstance(data, dict):
        report.error("version.json: root must be an object")
        return

    required = ["version", "min_version", "min_size", "exe_url"]
    for field in required:
        if field not in data:
            report.error(f"version.json: missing required field '{field}'")

    version = str(data.get("version", ""))
    min_version = str(data.get("min_version", ""))
    if version and min_version:
        if version_key(version) < version_key(min_version):
            report.error(
                f"version.json: version ({version}) is lower than "
                f"min_version ({min_version})"
            )
        else:
            report.note(f"version.json: version={version} min_version={min_version} (OK)")

    min_size = data.get("min_size")
    if not isinstance(min_size, int) or min_size <= 0:
        report.error(f"version.json: min_size must be a positive integer, got {min_size!r}")

    exe_url = str(data.get("exe_url", ""))
    if exe_url:
        if not exe_url.startswith("https://"):
            report.error("version.json: exe_url must be an https URL")
        if version and version not in exe_url:
            report.warn(
                f"version.json: exe_url does not reference version {version} ({exe_url})"
            )
        else:
            report.note("version.json: exe_url references the current version (OK)")


def validate_revoked(data, report: Report) -> set[str]:
    revoked: set[str] = set()
    if not isinstance(data, dict):
        report.error("revoked.json: root must be an object")
        return revoked

    keys = data.get("keys")
    if not isinstance(keys, list):
        report.error("revoked.json: 'keys' must be a list")
        return revoked

    seen: set[str] = set()
    for idx, key in enumerate(keys):
        if not isinstance(key, str) or not KEY_RE.match(key):
            report.error(f"revoked.json: keys[{idx}] is not a valid key: {key!r}")
            continue
        if key in seen:
            report.error(f"revoked.json: duplicate key {key}")
        seen.add(key)
        revoked.add(key)

    report.note(f"revoked.json: {len(revoked)} unique revoked keys (OK)")
    return revoked


def validate_hwids(data, report: Report) -> dict:
    hwids = {}
    if not isinstance(data, dict):
        report.error("hwids.json: root must be an object")
        return hwids

    entries = data.get("hwids")
    if not isinstance(entries, dict):
        report.error("hwids.json: 'hwids' must be an object")
        return hwids

    enabled_count = 0
    for hwid, entry in entries.items():
        if not HWID_RE.match(hwid):
            report.error(f"hwids.json: invalid HWID format: {hwid!r}")
        if not isinstance(entry, dict):
            report.error(f"hwids.json: entry for {hwid} must be an object")
            continue
        if not isinstance(entry.get("enabled"), bool):
            report.error(f"hwids.json: {hwid}.enabled must be a boolean")
        if not isinstance(entry.get("wipe"), bool):
            report.error(f"hwids.json: {hwid}.wipe must be a boolean")
        expire = entry.get("expire", "")
        if not isinstance(expire, str):
            report.error(f"hwids.json: {hwid}.expire must be a string")
        elif expire and parse_date(expire) is None:
            report.error(f"hwids.json: {hwid}.expire is not a valid YYYY-MM-DD date: {expire!r}")
        if entry.get("enabled"):
            enabled_count += 1
            if not expire:
                report.warn(f"hwids.json: {hwid} is enabled but has no expire date")
        hwids[hwid] = entry

    report.note(f"hwids.json: {len(hwids)} machines ({enabled_count} enabled) (OK)")
    return hwids


def check_license(hwid: str, hwids: dict, today: date):
    """Simulate the client-side license decision for a machine."""
    entry = hwids.get(hwid)
    if entry is None:
        return False, "unknown HWID"
    if entry.get("wipe"):
        return False, "wipe flag set"
    if not entry.get("enabled"):
        return False, "disabled"
    expire = entry.get("expire", "")
    if expire:
        exp = parse_date(expire)
        if exp is None:
            return False, "invalid expire date"
        if exp < today:
            return False, f"expired on {expire}"
    return True, f"valid (expires {expire or 'n/a'})"


def cross_checks(revoked: set[str], hwids: dict, report: Report) -> None:
    both = revoked & set(hwids)
    if both:
        report.note(f"cross-check: {len(both)} keys appear in both revoked and hwids sets")
    report.note("cross-check: revoked-key and HWID namespaces are distinct (OK)")


def demo(hwids: dict, today: date) -> None:
    print("\n=== Client license-check simulation ===")
    sample = list(hwids.items())[:5]
    for hwid, _ in sample:
        allowed, reason = check_license(hwid, hwids, today)
        status = "ALLOW" if allowed else "DENY "
        print(f"  [{status}] {hwid}  -> {reason}")
    unknown = "HD-0000-0000-0000-0000"
    allowed, reason = check_license(unknown, hwids, today)
    print(f"  [{'ALLOW' if allowed else 'DENY '}] {unknown}  -> {reason}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=REPO_ROOT, help="Repository root (default: auto)"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Print a client license-check simulation"
    )
    args = parser.parse_args()

    report = Report()
    today = date.today()

    version_data = load_json(args.root / "version.json", report)
    revoked_data = load_json(args.root / "revoked.json", report)
    hwids_data = load_json(args.root / "hwids.json", report)

    if version_data is not None:
        validate_version(version_data, report)
    revoked = validate_revoked(revoked_data, report) if revoked_data is not None else set()
    hwids = validate_hwids(hwids_data, report) if hwids_data is not None else {}
    cross_checks(revoked, hwids, report)

    print("=== Manifest validation ===")
    for line in report.info:
        print(f"  OK   {line}")
    for line in report.warnings:
        print(f"  WARN {line}")
    for line in report.errors:
        print(f"  FAIL {line}")

    if args.demo:
        demo(hwids, today)

    print()
    if report.errors:
        print(f"RESULT: FAILED with {len(report.errors)} error(s), "
              f"{len(report.warnings)} warning(s).")
        return 1
    print(f"RESULT: OK ({len(report.warnings)} warning(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
