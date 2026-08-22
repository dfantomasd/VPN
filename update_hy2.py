#!/usr/bin/env python3
"""Add runtime-verified Hysteria2 nodes to the Happ subscription.

The VLESS builder runs on TCP.  Some Russian mobile networks currently allow
the handshake and then freeze a long downstream TCP flow.  Hysteria2 uses
QUIC/UDP, so it provides a genuinely different fallback instead of another
TCP disguise.
"""

import base64
import json
import math
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlsplit

import update_vless


SOURCES = (
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy2.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
)
HYSTERIA_BIN = os.getenv("HYSTERIA_BIN", "hysteria")
HY2_LIMIT = int(os.getenv("HY2_LIMIT", "8"))
HY2_TEST_LIMIT = int(os.getenv("HY2_TEST_LIMIT", "40"))
HY2_WORKERS = int(os.getenv("HY2_WORKERS", "5"))
HY2_TIMEOUT = float(os.getenv("HY2_TIMEOUT", "12"))
HY2_MIN_MBPS = float(os.getenv("HY2_MIN_MBPS", "1.0"))
HY2_TEST_BYTES = int(os.getenv("HY2_TEST_BYTES", "262144"))
HY2_SOURCE_LIMIT = int(os.getenv("HY2_SOURCE_LIMIT", "300"))
ALLOW_PUBLIC_INSECURE = os.getenv("HY2_ALLOW_PUBLIC_INSECURE", "1").lower() not in {"0", "false", "no"}


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Fast-VPN-HY2-checker/1.0"})
    with urllib.request.urlopen(request, timeout=45) as response:
        return response.read().decode("utf-8-sig", errors="replace")


def decode_subscription(text):
    if "hysteria2://" in text.lower() or "hy2://" in text.lower():
        return text
    compact = "".join(text.split())
    try:
        decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
        return decoded.decode("utf-8", errors="replace")
    except (ValueError, UnicodeError):
        return ""


def parse_hy2_uri(value):
    value = value.strip().strip('"\'')
    if not value.lower().startswith(("hysteria2://", "hy2://")):
        return None
    clean, _, _ = value.partition("#")
    try:
        parsed = urlsplit(clean)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not parsed.hostname or not parsed.username:
            return None
        # Port hopping is useful but cannot be represented by urllib's port
        # parser or tested deterministically here.  Keep the feed conservative.
        port = parsed.port or 443
    except (TypeError, ValueError):
        return None
    insecure = str(params.get("insecure") or "0").lower() in {"1", "true", "yes"}
    pinned = bool(params.get("pinSHA256") or params.get("pinsha256"))
    # Most free HY2 relays use self-signed certificates. They are still
    # useful as a QUIC fallback, but must remain explicitly identifiable as
    # public/unverified rather than being presented as equivalent to a relay
    # with authenticated TLS.
    if insecure and not pinned and not ALLOW_PUBLIC_INSECURE:
        return None
    sni = params.get("sni") or (parsed.hostname if not _is_ip(parsed.hostname) else "")
    if not sni:
        return None
    return {
        "uri": clean,
        "address": parsed.hostname,
        "port": port,
        "auth": unquote(parsed.username),
        "sni": sni,
        "params": params,
        "authenticated_tls": not insecure or pinned,
    }


def _is_ip(value):
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in value else socket.AF_INET, value)
        return True
    except OSError:
        return False


def extract_candidates(text):
    decoded = decode_subscription(text)
    candidates = {}
    for token in re.split(r"[\s\"']+", decoded):
        item = parse_hy2_uri(token)
        if item:
            candidates[item["uri"]] = item
    return list(candidates.values())


def resolve(item):
    try:
        infos = socket.getaddrinfo(item["address"], item["port"], socket.AF_UNSPEC, socket.SOCK_DGRAM)
    except OSError:
        return None
    ips = [info[4][0] for info in infos]
    ipv4 = next((ip for ip in ips if ":" not in ip), None)
    item["resolved_ip"] = ipv4 or ips[0]
    return item


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_port(port, process):
    deadline = time.monotonic() + HY2_TIMEOUT
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def curl_via(port, url, timeout, output=os.devnull):
    return subprocess.run(
        ["curl", "--silent", "--show-error", "--location", "--output", output,
         "--write-out", "%{http_code} %{time_total} %{size_download}",
         "--max-time", str(timeout), "--proxy", f"socks5h://127.0.0.1:{port}", url],
        capture_output=True, text=True, check=False, timeout=timeout + 3,
    )


def probe(item):
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="hy2-check-") as directory:
        config = Path(directory) / "config.json"
        config.write_text(json.dumps({
            "server": item["uri"], "lazy": False,
            "socks5": {"listen": f"127.0.0.1:{port}", "disableUDP": False},
        }), encoding="utf-8")
        process = subprocess.Popen(
            [HYSTERIA_BIN, "-c", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            if not wait_for_port(port, process):
                return None
            telegram = curl_via(port, "https://api.telegram.org/botINVALID/getMe", HY2_TIMEOUT)
            if telegram.returncode != 0:
                return None
            started = time.monotonic()
            speed = curl_via(
                port, f"https://speed.cloudflare.com/__down?bytes={HY2_TEST_BYTES}", HY2_TIMEOUT,
            )
            elapsed = max(time.monotonic() - started, 0.001)
            if speed.returncode != 0:
                return None
            fields = speed.stdout.strip().split()
            downloaded = int(float(fields[2])) if len(fields) >= 3 else 0
            if downloaded < HY2_TEST_BYTES * 0.9:
                return None
            mbps = downloaded * 8 / elapsed / 1_000_000
            if mbps < HY2_MIN_MBPS:
                return None
            return {"mbps": mbps, "latency_ms": elapsed * 1000}
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return None
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def label(item, geo, result):
    country = geo.get("country") or "Unknown"
    city = geo.get("city") or ""
    location = country + (f" · {city}" if city else "")
    distance = round(update_vless.distance_from_moscow_km(geo))
    suffix = str(item["resolved_ip"]).split(":")[-1].split(".")[-1]
    trust = "HY2/QUIC" if item["authenticated_tls"] else "HY2/QUIC PUBLIC"
    title = f"{geo.get('flag') or '🌐'} {location} · {distance} km · {result['mbps']:.1f} Mbps · {trust} · {suffix}"
    return f"{item['uri']}#{quote(title, safe='')}"


def update_files(selected):
    path = Path("vless.txt")
    lines = path.read_text(encoding="utf-8").splitlines()
    lines = [line for line in lines if not line.lower().startswith(("hysteria2://", "hy2://"))]
    insert_at = next((index for index, line in enumerate(lines) if line.lower().startswith("vless://")), len(lines))
    hy2_lines = [label(item, geo, result) for item, geo, result in selected]
    lines[insert_at:insert_at] = hy2_lines
    plain = "\n".join(lines) + "\n"
    path.write_text(plain, encoding="utf-8")
    Path("vless_base64.txt").write_text(base64.b64encode(plain.encode()).decode() + "\n", encoding="utf-8")
    status_path = Path(update_vless.STATUS_FILE)
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        status = {}
    status["hy2_selected_count"] = len(selected)
    status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    if not shutil.which(HYSTERIA_BIN):
        raise SystemExit(f"Hysteria binary not found: {HYSTERIA_BIN}")
    candidates = {}
    for source in SOURCES:
        try:
            found = extract_candidates(fetch(source))
            authenticated = sum(item["authenticated_tls"] for item in found)
            print(
                f"HY2 source {source}: {len(found)} candidates "
                f"({authenticated} authenticated TLS)"
            )
            for item in found[:HY2_SOURCE_LIMIT]:
                candidates.setdefault((item["address"], item["port"]), item)
        except Exception as exc:
            print(f"HY2 source {source}: FAILED: {exc}")
    resolved = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(resolve, item) for item in candidates.values()]
        for future in as_completed(futures):
            item = future.result()
            if item:
                resolved.append(item)
    geo_by_ip = update_vless.geolocate_ips(item["resolved_ip"] for item in resolved)
    located = []
    for item in resolved:
        geo = geo_by_ip.get(item["resolved_ip"])
        if geo and geo.get("code") != "RU" and math.isfinite(update_vless.distance_from_moscow_km(geo)):
            located.append((item, geo))
    located.sort(key=lambda row: update_vless.distance_from_moscow_km(row[1]))
    results = []
    with ThreadPoolExecutor(max_workers=HY2_WORKERS) as pool:
        futures = {pool.submit(probe, item): (item, geo) for item, geo in located[:HY2_TEST_LIMIT]}
        for future in as_completed(futures):
            result = future.result()
            if result:
                item, geo = futures[future]
                results.append((item, geo, result))
    # Different collectors often publish the same relay once by IP and once
    # by hostname.  Keep one tested credential per real UDP endpoint and
    # prefer authenticated TLS when both variants work.
    unique = {}
    for row in results:
        key = (row[0]["resolved_ip"], row[0]["port"])
        current = unique.get(key)
        if current is None or (
            row[0]["authenticated_tls"], row[2]["mbps"]
        ) > (
            current[0]["authenticated_tls"], current[2]["mbps"]
        ):
            unique[key] = row
    results = list(unique.values())
    results.sort(key=lambda row: (
        not row[0]["authenticated_tls"],
        update_vless.distance_from_moscow_km(row[1]),
        -row[2]["mbps"],
    ))
    selected = results[:HY2_LIMIT]
    update_files(selected)
    if selected:
        print(f"Selected {len(selected)} runtime-verified HY2/QUIC nodes")
    else:
        print("::warning title=No mobile QUIC fallback::No Hysteria2 node passed the full runtime probe")


if __name__ == "__main__":
    main()
