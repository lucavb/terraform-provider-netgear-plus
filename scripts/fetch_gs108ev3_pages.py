#!/usr/bin/env python3
"""Capture GS108Ev3 management pages without exposing the switch password.

Usage:
  export NETGEAR_PLUS_PASSWORD='...'
  python3 scripts/fetch_gs108ev3_pages.py --host 10.0.2.2

The script writes both raw and sanitized HTML responses under:
  captures/gs108ev3/raw
  captures/gs108ev3/sanitized
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from http.cookiejar import CookieJar
from pathlib import Path
import os


DEFAULT_HOST = "10.0.2.2"
DEFAULT_PASSWORD_ENV = "NETGEAR_PLUS_PASSWORD"


@dataclass
class CaptureResult:
    name: str
    method: str
    path: str
    status: int
    bytes: int


def merge(left: str, right: str) -> str:
    result: list[str] = []
    max_len = max(len(left), len(right))
    for idx in range(max_len):
        if idx < len(left):
            result.append(left[idx])
        if idx < len(right):
            result.append(right[idx])
    return "".join(result)


def password_kdf(password: str, rand: str) -> str:
    return hashlib.md5(merge(password, rand).encode("utf-8")).hexdigest()


def fetch(opener: urllib.request.OpenerDirector, base_url: str, method: str, path: str, data: dict[str, str] | None = None) -> tuple[int, str]:
    url = urllib.parse.urljoin(base_url, path)
    encoded = None
    if data is not None:
        encoded = urllib.parse.urlencode(data).encode("utf-8")

    request = urllib.request.Request(url, method=method.upper(), data=encoded)
    with opener.open(request, timeout=15) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, body


def parse_login_rand(body: str) -> str:
    match = re.search(r'id="rand"[^>]*value=[\'"]([^\'"]+)[\'"]', body)
    if not match:
        raise RuntimeError("could not find login rand in login page")
    return match.group(1)


def parse_session_hash(body: str) -> str:
    patterns = (
        r'\bname=["\']hash["\'][^>]*\bvalue=["\']([^"\']+)["\']',
        r'\bid=["\']hash["\'][^>]*\bvalue=["\']([^"\']+)["\']',
        r'\bvalue=["\']([^"\']+)["\'][^>]*\bname=["\']hash["\']',
        r'\bvalue=["\']([^"\']+)["\'][^>]*\bid=["\']hash["\']',
    )
    for pattern in patterns:
        match = re.search(pattern, body, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    raise RuntimeError("could not find session hash in switch info page")


def parse_vlan_ids(body: str) -> list[int]:
    ids = sorted({int(match) for match in re.findall(r'<option[^>]*value=[\'"](\d+)[\'"]', body)})
    if not ids:
        raise RuntimeError("could not find vlan ids in VLAN membership page")
    return ids


def sanitize_body(body: str, host: str) -> str:
    sanitized = body

    sanitized = sanitized.replace(host, DEFAULT_HOST)
    sanitized = re.sub(r'(id="rand"[^>]*value=[\'"])\d+([\'"])', r"\g<1>12345678\2", sanitized)
    sanitized = re.sub(r"(name=['\"]hash['\"][^>]*value=['\"])[^'\"]+(['\"])", r"\g<1>deadbeefcafebabe\2", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"(id=['\"]hash['\"][^>]*value=['\"])[^'\"]+(['\"])", r"\g<1>deadbeefcafebabe\2", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"(value=['\"])[^'\"]+(['\"][^>]*name=['\"]hash['\"])", r"\g<1>deadbeefcafebabe\2", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"(value=['\"])[^'\"]+(['\"][^>]*id=['\"]hash['\"])", r"\g<1>deadbeefcafebabe\2", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"(id=['\"]err_msg['\"][^>]*value=['\"])([^'\"]*)(['\"])", lambda m: m.group(1) + html.escape(m.group(2), quote=True) + m.group(3), sanitized)
    sanitized = re.sub(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "00:11:22:33:44:55", sanitized)

    serial_labels = ("Serial Number", "Seriennummer")
    for label in serial_labels:
        sanitized = re.sub(
            rf"({re.escape(label)}</td>\s*<td[^>]*>)([^<]+)(</td>)",
            r"\g<1>4AB123456789\3",
            sanitized,
            flags=re.IGNORECASE,
        )

    sanitized = re.sub(
        r'(<input[^>]*id=["\']switch_name["\'][^>]*value=["\'])([^"\']+)(["\'])',
        r"\g<1>lab-switch\3",
        sanitized,
        flags=re.IGNORECASE,
    )

    return sanitized


def write_capture(raw_dir: Path, sanitized_dir: Path, host: str, filename: str, body: str) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    sanitized_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / filename
    sanitized_path = sanitized_dir / filename
    raw_path.write_text(body, encoding="utf-8")
    sanitized_path.write_text(sanitize_body(body, host), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch GS108Ev3 management pages using a password from an environment variable.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Switch hostname or IPv4 address.")
    parser.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV, help="Environment variable containing the switch password.")
    parser.add_argument("--output-dir", default="captures/gs108ev3", help="Directory where captures will be stored.")
    args = parser.parse_args()

    password = os.environ.get(args.password_env, "")
    if not password:
        print(f"error: environment variable {args.password_env} is not set", file=sys.stderr)
        return 1

    base_url = f"http://{args.host}/"
    cookie_jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

    output_dir = Path(args.output_dir)
    raw_dir = output_dir / "raw"
    sanitized_dir = output_dir / "sanitized"

    captures: list[CaptureResult] = []

    def capture(name: str, method: str, path: str, data: dict[str, str] | None = None, filename: str | None = None) -> str:
        status, body = fetch(opener, base_url, method, path, data)
        target_name = filename or name
        write_capture(raw_dir, sanitized_dir, args.host, f"{target_name}.html", body)
        captures.append(CaptureResult(name=target_name, method=method.upper(), path=path, status=status, bytes=len(body.encode("utf-8"))))
        return body

    login_root = capture("root", "GET", "/")
    login_htm = capture("login", "GET", "/login.htm")
    capture("login_cgi_get", "GET", "/login.cgi")

    rand = parse_login_rand(login_htm or login_root)
    hashed_password = password_kdf(password, rand)

    login_post_body = capture(
        "login_post",
        "POST",
        "/login.cgi",
        data={"password": hashed_password},
    )
    if "top.location.href" not in login_post_body:
        raise RuntimeError("login did not appear to succeed; inspect captures/gs108ev3/raw/login_post.html")

    switch_info_htm = capture("switch_info", "GET", "/switch_info.htm")
    capture("switch_info_cgi", "GET", "/switch_info.cgi")
    session_hash = parse_session_hash(switch_info_htm)

    capture("8021qCf", "GET", "/8021qCf.htm")
    capture("8021qCf_cgi_get", "GET", "/8021qCf.cgi")

    vlan_list_body = capture("8021qMembe", "GET", "/8021qMembe.htm")
    capture("8021qMembe_cgi_get", "GET", "/8021qMembe.cgi")
    vlan_ids = parse_vlan_ids(vlan_list_body)
    for vlan_id in vlan_ids:
        capture(
            f"8021qMembe_vlan_{vlan_id}",
            "POST",
            "/8021qMembe.cgi",
            data={"VLAN_ID": str(vlan_id), "hash": session_hash},
        )

    capture("portPVID", "GET", "/portPVID.htm")
    capture("portPVID_cgi_get", "GET", "/portPVID.cgi")
    capture("logout", "GET", "/logout.cgi")

    metadata = {
        "host": args.host,
        "captured": [asdict(item) for item in captures],
        "vlan_ids": vlan_ids,
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Captured {len(captures)} responses into {output_dir}")
    print(f"Raw pages: {raw_dir}")
    print(f"Sanitized pages: {sanitized_dir}")
    print("Review the sanitized files before using them as committed fixtures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
