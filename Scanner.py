#!/usr/bin/env python3
"""
SiteGuard - quick security pass on a website.

Checks headers, TLS cert, cookie flags, and a few common exposed files
(.env, .git/config, that kind of thing). Everything here is a normal
GET/HEAD request, same as a browser makes just loading the page - no
exploits, no bypassing auth, no brute force.

Only point this at sites you own or have permission to test.
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces browsers to use HTTPS (HSTS)",
    "Content-Security-Policy": "Restricts where scripts/content can load from",
    "X-Content-Type-Options": "Blocks MIME-type sniffing",
    "X-Frame-Options": "Mitigates clickjacking",
    "Referrer-Policy": "Controls how much referrer info leaks to other sites",
    "Permissions-Policy": "Restricts access to browser features (camera, mic, etc.)",
}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/.DS_Store",
    "/backup.zip",
    "/.aws/credentials",
    "/.htpasswd",
]

TIMEOUT = 8


def normalize_url(raw: str) -> str:
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw.rstrip("/")


def check_headers(resp: requests.Response) -> dict:
    present, missing = {}, {}
    for header, purpose in SECURITY_HEADERS.items():
        if header in resp.headers:
            present[header] = resp.headers[header]
        else:
            missing[header] = purpose
    return {"present": present, "missing": missing}


def check_cookies(resp: requests.Response) -> list:
    results = []
    try:
        raw_cookies = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        raw_cookies = [resp.headers["Set-Cookie"]] if "Set-Cookie" in resp.headers else []

    for cookie in raw_cookies:
        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        results.append({
            "name": name,
            "secure": "secure" in lower,
            "httponly": "httponly" in lower,
            "samesite": "samesite" in lower,
        })
    return results


def check_tls(hostname: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "valid": True,
                    "protocol": ssock.version(),
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "expires": cert["notAfter"],
                    "days_until_expiry": days_left,
                }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


def check_sensitive_paths(base_url: str) -> list:
    exposed = []
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            r = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200:
                exposed.append({"path": path, "status": r.status_code})
        except requests.RequestException:
            continue
    return exposed


def check_robots_sitemap(base_url: str) -> dict:
    result = {}
    for name in ("robots.txt", "sitemap.xml"):
        try:
            r = requests.get(f"{base_url}/{name}", timeout=TIMEOUT)
            result[name] = r.status_code == 200
        except requests.RequestException:
            result[name] = False
    return result


def score(report: dict) -> tuple:
    points = 100
    points -= 10 * len(report["headers"]["missing"])
    if not report["tls"].get("valid"):
        points -= 25
    elif report["tls"].get("days_until_expiry", 999) < 14:
        points -= 10
    insecure_cookies = [c for c in report["cookies"] if not c["secure"] or not c["httponly"]]
    points -= 5 * len(insecure_cookies)
    points -= 15 * len(report["exposed_paths"])
    points = max(0, points)

    if points >= 90:
        grade = "A"
    elif points >= 75:
        grade = "B"
    elif points >= 60:
        grade = "C"
    elif points >= 40:
        grade = "D"
    else:
        grade = "F"
    return points, grade


def scan(url: str) -> dict:
    base_url = normalize_url(url)
    hostname = urlparse(base_url).hostname

    resp = requests.get(base_url, timeout=TIMEOUT, allow_redirects=True)

    report = {
        "target": base_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "final_url": resp.url,
        "status_code": resp.status_code,
        "headers": check_headers(resp),
        "cookies": check_cookies(resp),
        "tls": check_tls(hostname) if base_url.startswith("https://") else {"valid": False, "error": "Not HTTPS"},
        "exposed_paths": check_sensitive_paths(base_url),
        "robots_sitemap": check_robots_sitemap(base_url),
    }
    report["score"], report["grade"] = score(report)
    return report


def print_report(report: dict) -> None:
    print(f"\nSiteGuard report for {report['target']}")
    print(f"Scanned: {report['scanned_at']}")
    print(f"Overall grade: {report['grade']}  ({report['score']}/100)\n")

    print("Security headers:")
    for h in report["headers"]["present"]:
        print(f"  [x] {h}")
    for h, purpose in report["headers"]["missing"].items():
        print(f"  [ ] {h} - missing ({purpose})")

    print("\nTLS certificate:")
    tls = report["tls"]
    if tls.get("valid"):
        print(f"  [x] Valid - {tls['protocol']}, issued by {tls['issuer']}, expires {tls['expires']} ({tls['days_until_expiry']} days)")
    else:
        print(f"  [ ] Invalid or unreachable: {tls.get('error')}")

    print("\nCookies:")
    if not report["cookies"]:
        print("  No cookies set on initial response.")
    for c in report["cookies"]:
        flags = []
        if not c["secure"]:
            flags.append("missing Secure")
        if not c["httponly"]:
            flags.append("missing HttpOnly")
        if not c["samesite"]:
            flags.append("missing SameSite")
        status = "OK" if not flags else ", ".join(flags)
        print(f"  {c['name']}: {status}")

    print("\nExposed sensitive paths:")
    if not report["exposed_paths"]:
        print("  None found.")
    else:
        for e in report["exposed_paths"]:
            print(f"  [!] {e['path']} returned HTTP {e['status']}")

    print("\nrobots.txt / sitemap.xml:")
    for name, present in report["robots_sitemap"].items():
        print(f"  {'[x]' if present else '[ ]'} {name}")
    print()


def to_markdown(report: dict) -> str:
    lines = [
        f"# SiteGuard Report - {report['target']}",
        f"*Scanned {report['scanned_at']}*",
        "",
        f"**Overall grade: {report['grade']} ({report['score']}/100)**",
        "",
        "## Security Headers",
    ]
    for h in report["headers"]["present"]:
        lines.append(f"- [x] `{h}`")
    for h, purpose in report["headers"]["missing"].items():
        lines.append(f"- [ ] `{h}` - {purpose}")

    lines += ["", "## TLS Certificate"]
    tls = report["tls"]
    if tls.get("valid"):
        lines.append(f"- [x] Valid - {tls['protocol']}, issued by {tls['issuer']}, expires {tls['expires']} ({tls['days_until_expiry']} days left)")
    else:
        lines.append(f"- [ ] {tls.get('error')}")

    lines += ["", "## Cookies"]
    if not report["cookies"]:
        lines.append("No cookies set on initial response.")
    for c in report["cookies"]:
        flags = [f for f, ok in (("Secure", c["secure"]), ("HttpOnly", c["httponly"]), ("SameSite", c["samesite"])) if not ok]
        lines.append(f"- `{c['name']}`: {'OK' if not flags else 'missing ' + ', '.join(flags)}")

    lines += ["", "## Exposed Paths"]
    if not report["exposed_paths"]:
        lines.append("None found.")
    for e in report["exposed_paths"]:
        lines.append(f"- WARNING `{e['path']}` returned HTTP {e['status']}")

    lines += ["", "## robots.txt / sitemap.xml"]
    for name, present in report["robots_sitemap"].items():
        lines.append(f"- {'[x]' if present else '[ ]'} {name}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="SiteGuard - passive website security posture scanner.")
    parser.add_argument("url", help="Target site, e.g. example.com or https://example.com")
    parser.add_argument("--json", metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("--md", metavar="FILE", help="Write Markdown report to FILE")
    args = parser.parse_args()

    try:
        report = scan(args.url)
    except requests.RequestException as exc:
        print(f"Error reaching {args.url}: {exc}", file=sys.stderr)
        sys.exit(1)

    print_report(report)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"JSON report written to {args.json}")

    if args.md:
        with open(args.md, "w") as f:
            f.write(to_markdown(report))
        print(f"Markdown report written to {args.md}")


if __name__ == "__main__":
    main()