#!/usr/bin/env python3
import base64
import json
import os
import socket
import statistics
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

SOURCE_URL = "https://raw.githubusercontent.com/kenkaral45/happ-subscription/main/whitelist_configs_combined.json"
LIMIT = int(os.getenv("VLESS_LIMIT", "10"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "1.8"))
PING_ATTEMPTS = int(os.getenv("PING_ATTEMPTS", "2"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "24"))


def fetch_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "happ-subscription-builder/3.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def country_flag(code):
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(127397 + ord(ch)) for ch in code)


def geo_for_ip(ip):
    try:
        data = fetch_json(f"https://ipwho.is/{ip}", timeout=8)
        if data.get("success") is False:
            raise ValueError("lookup failed")
        code = (data.get("country_code") or "").upper()
        country = data.get("country") or "Unknown"
        city = data.get("city") or ""
        return {
            "code": code,
            "country": country,
            "city": city,
            "flag": country_flag(code),
        }
    except Exception:
        return {"code": "", "country": "Unknown", "city": "", "flag": "🌐"}


def parse_vless(outbound):
    if outbound.get("protocol") != "vless":
        return None
    settings = outbound.get("settings") or {}
    vnext = settings.get("vnext") or []
    if not vnext:
        return None
    server = vnext[0]
    users = server.get("users") or []
    if not users:
        return None
    user = users[0]
    address = server.get("address")
    port = server.get("port")
    uid = user.get("id")
    if not all([address, port, uid]):
        return None

    stream = outbound.get("streamSettings") or {}
    reality = stream.get("realitySettings") or {}
    network = stream.get("network") or "tcp"
    security = stream.get("security") or "none"

    params = [
        ("encryption", user.get("encryption") or "none"),
        ("type", network),
        ("security", security),
    ]
    flow = user.get("flow")
    if flow:
        params.append(("flow", flow))
    sni = reality.get("serverName")
    pbk = reality.get("publicKey")
    sid = reality.get("shortId")
    fp = reality.get("fingerprint")
    if sni:
        params.append(("sni", sni))
    if fp:
        params.append(("fp", fp))
    if pbk:
        params.append(("pbk", pbk))
    if sid is not None:
        params.append(("sid", sid))

    query = "&".join(
        f"{quote(str(k), safe='')}={quote(str(v), safe='-_~.')}" for k, v in params
    )
    base = f"vless://{uid}@{address}:{port}?{query}"
    return {"address": address, "port": int(port), "base": base}


def tcp_latency_ms(address, port):
    samples = []
    for _ in range(PING_ATTEMPTS):
        started = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=PING_TIMEOUT):
                samples.append((time.perf_counter() - started) * 1000)
        except OSError:
            pass
    if not samples:
        return None
    return statistics.median(samples)


def main():
    data = fetch_json(SOURCE_URL)
    if isinstance(data, dict):
        data = [data]

    candidates = []
    seen = set()
    for cfg in data:
        for outbound in (cfg.get("outbounds") or []):
            item = parse_vless(outbound)
            if not item:
                continue
            key = (item["address"], item["port"], item["base"])
            if key in seen:
                continue
            seen.add(key)
            candidates.append(item)

    if not candidates:
        raise SystemExit("No VLESS links found in source JSON")

    tested = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(tcp_latency_ms, item["address"], item["port"]): item
            for item in candidates
        }
        for future in as_completed(futures):
            item = futures[future]
            latency = future.result()
            if latency is not None:
                tested.append((latency, item))

    if not tested:
        raise SystemExit("No reachable VLESS endpoints found")

    tested.sort(key=lambda x: x[0])
    selected = tested[:LIMIT]

    lines = ["#subscriptions-sort-type: ping", "#profile-title: Fast VPN"]
    for index, (latency, item) in enumerate(selected, start=1):
        geo = geo_for_ip(item["address"])
        location = geo["country"]
        if geo["city"]:
            location = f"{location} · {geo['city']}"
        title = f"{geo['flag']} {location} · #{index}"
        link = f"{item['base']}#{quote(title, safe='')}"
        lines.append(link)
        print(f"{latency:7.1f} ms  {geo['flag']} {geo['country']}  {item['address']}:{item['port']}")

    plain = "\n".join(lines) + "\n"
    with open("vless.txt", "w", encoding="utf-8") as f:
        f.write(plain)

    encoded = base64.b64encode(plain.encode()).decode()
    with open("vless_base64.txt", "w", encoding="utf-8") as f:
        f.write(encoded + "\n")

    print(f"Selected {len(selected)} fastest reachable servers from {len(candidates)} candidates")


if __name__ == "__main__":
    main()
