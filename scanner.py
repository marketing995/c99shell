#!/usr/bin/env python3
import ipaddress
import json
import re
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse
from urllib.request import Request, urlopen

# ------------------------- Signatures -------------------------
# Heuristic patterns often seen in c99-like and wso-like shells.
SIGNATURE_PATTERNS = [
    re.compile(r"c99\s*shell", re.I),
    re.compile(r"c999?shell", re.I),
    re.compile(r"wso\s*shell", re.I),
    re.compile(r"Web\s*Shell\s*by\s*C99", re.I),
    re.compile(r"safe\s*mode\s*bypass", re.I),
    re.compile(r"disable_functions\s*:\s*", re.I),
    re.compile(r"Server\s*IP\s*:\s*", re.I),
    re.compile(r"cmd\s*:\s*<input", re.I),
    re.compile(r"\$_(GET|POST)\[\s*['\"]cmd['\"]\s*\]", re.I),
    re.compile(r"\$_FILES\[", re.I),
    re.compile(r"eval\s*\(\s*base64_decode\s*\(", re.I),
    re.compile(r"preg_replace\s*\(\s*['\"]/e['\"]", re.I),
]

DEFAULT_PATHS = [
    "/c99.php",
    "/c99shell.php",
    "/wso.php",
    "/shell.php",
    "/sh.php",
    "/cmd.php",
    "/adminer.php",
    "/wp-content/uploads/c99.php",
    "/wp-content/uploads/shell.php",
    "/upload/cmd.php",
    "/.well-known/c99.php",
    "/.well-known/shell.php",
]

COMMON_PORTS = [80, 443, 8080, 8000, 8443]
MAX_READ_BYTES = 300_000

@dataclass
class Args:
    targets_file: Optional[Path]
    cidr: Optional[str]
    ports: List[int]
    paths: List[str]
    only_http: bool
    insecure: bool
    timeout: float
    concurrency: int
    output: Optional[Path]
    verbose: bool
    i_understand: bool


def parse_args(argv: List[str]) -> Args:
    import argparse

    parser = argparse.ArgumentParser(
        description="Defensive c99-style PHP web shell scanner (authorized use only)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--targets", type=Path, help="File with one host or IP per line", default=None)
    parser.add_argument("--cidr", type=str, help="CIDR range to enumerate (authorized lab only)", default=None)
    parser.add_argument("--ports", type=str, help="Comma-separated ports to scan", default=",".join(str(p) for p in COMMON_PORTS))
    parser.add_argument("--paths", type=str, help="Comma-separated paths or 'common' to use built-ins", default="common")
    parser.add_argument("--only-http", action="store_true", help="Skip HTTPS attempts")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    parser.add_argument("--timeout", type=float, default=6.0, help="Per-request timeout seconds")
    parser.add_argument("--concurrency", type=int, default=200, help="Max concurrent requests")
    parser.add_argument("--output", type=Path, default=None, help="Write JSONL findings to this file")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging to stderr")
    parser.add_argument("--i-understand", dest="i_understand", action="store_true", help="Confirm authorized scanning when using --cidr")

    ns = parser.parse_args(argv)

    ports = [int(p.strip()) for p in str(ns.ports).split(",") if p.strip()]
    if ns.paths == "common":
        paths = list(DEFAULT_PATHS)
    else:
        raw_paths = [p.strip() for p in str(ns.paths).split(",") if p.strip()]
        paths = [(p if p.startswith("/") else f"/{p}") for p in raw_paths]

    return Args(
        targets_file=ns.targets,
        cidr=ns.cidr,
        ports=ports,
        paths=paths,
        only_http=ns.only_http,
        insecure=ns.insecure,
        timeout=ns.timeout,
        concurrency=ns.concurrency,
        output=ns.output,
        verbose=ns.verbose,
        i_understand=ns.i_understand,
    )


def iter_targets_from_file(path: Path) -> Iterable[str]:
    for line in path.read_text().splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        yield value


def iter_targets_from_cidr(cidr: str) -> Iterable[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    for ip in net.hosts():
        yield str(ip)


def build_urls(hosts: Iterable[str], ports: Iterable[int], paths: Iterable[str], only_http: bool) -> Iterable[str]:
    for host in hosts:
        for port in ports:
            schemes = ["http"] if only_http or port in {80, 8000, 8080} else ["https", "http"]
            for scheme in schemes:
                for path in paths:
                    yield f"{scheme}://{host}:{port}{path}"


def extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        if title:
            return title
    return None


def detect_signatures(text: str) -> List[str]:
    hits = []
    for pattern in SIGNATURE_PATTERNS:
        if pattern.search(text):
            hits.append(pattern.pattern)
    return hits


def create_ssl_context(insecure: bool) -> ssl.SSLContext:
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


def fetch(url: str, timeout_s: float, ssl_ctx: ssl.SSLContext, verbose: bool) -> Tuple[str, Optional[int], Optional[str], Optional[str]]:
    try:
        req = Request(url, headers={"User-Agent": "c99-defensive-scanner/1.0"})
        parsed = urlparse(url)
        context = ssl_ctx if parsed.scheme == "https" else None
        with urlopen(req, timeout=timeout_s, context=context) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            raw = resp.read(MAX_READ_BYTES)
            text = raw.decode("utf-8", "ignore")
            title = extract_title(text)
            return url, int(status), title, text
    except Exception as exc:
        if verbose:
            sys.stderr.write(f"[debug] {url} -> {exc}\n")
        return url, None, None, None


def run(args: Args) -> int:
    if not args.targets_file and not args.cidr:
        sys.stderr.write("Provide --targets or --cidr. See --help.\n")
        return 2

    hosts: List[str] = []
    if args.targets_file:
        if not args.targets_file.exists():
            sys.stderr.write(f"Targets file not found: {args.targets_file}\n")
            return 2
        hosts.extend(list(iter_targets_from_file(args.targets_file)))

    if args.cidr:
        if not args.i_understand:
            sys.stderr.write("--cidr requires --i-understand confirming authorized scope.\n")
            return 2
        hosts.extend(list(iter_targets_from_cidr(args.cidr)))

    if not hosts:
        sys.stderr.write("No targets resolved.\n")
        return 2

    # Deduplicate while preserving order
    seen: Set[str] = set()
    unique_hosts: List[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            unique_hosts.append(h)

    urls = list(build_urls(unique_hosts, args.ports, args.paths, args.only_http))

    if args.verbose:
        sys.stderr.write(f"[info] Total URLs to probe: {len(urls)}\n")

    ssl_ctx = create_ssl_context(args.insecure)

    output_file = None
    if args.output:
        output_file = args.output.open("a", encoding="utf-8")

    def emit(finding: dict) -> None:
        line = json.dumps(finding, ensure_ascii=False)
        if output_file:
            output_file.write(line + "\n")
            output_file.flush()
        else:
            print(line)

    # Threaded concurrency
    max_workers = max(1, min(args.concurrency, 500))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(fetch, u, args.timeout, ssl_ctx, args.verbose): u for u in urls}
        for future in as_completed(future_to_url):
            u, status, title, text = future.result()
            if status is None or text is None:
                continue
            matches = detect_signatures(text)
            if matches:
                emit({
                    "target": u,
                    "status": status,
                    "reason": "signature",
                    "matches": matches,
                    "title": title,
                })
            elif status == 200 and re.search(r"name=['\"]cmd['\"]", text, re.I):
                emit({
                    "target": u,
                    "status": status,
                    "reason": "heuristic_cmd_input",
                    "matches": ["name=cmd"],
                    "title": title,
                })

    if output_file:
        output_file.close()
    return 0


def main() -> int:
    args = parse_args(sys.argv[1:])
    # Safety banner
    sys.stderr.write(
        "This scanner is for authorized defensive use in lab or permitted environments only. "
        "You are responsible for complying with laws and policies.\n"
    )
    try:
        return run(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())