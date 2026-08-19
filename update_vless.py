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
ROUTING_TEMPLATE_FILE = "vless_test_ru_gemini.txt"
LIMIT = int(os.getenv("VLESS_LIMIT", "10"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "1.8"))
PING_ATTEMPTS = int(os.getenv("PING_ATTEMPTS", "2"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "24"))


def fetch_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "happ-subscription-builder/10.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def tested_routing_link():
    """Reuse the exact routing profile already tested successfully on iPhone."""
    with open(ROUTING_TEMPLATE_FILE, "r", encoding="utf-8") as source:
        first = source.readline().strip()
    if not first.startswith("happ://routing/onadd/"):
        raise SystemExit("Tested routing template is missing or invalid")
    return first


def country_flag(code):
    code = (code or "").upper()
    return "".join(chr(127397 + ord(ch)) for ch in code) if len(code) == 2 and code.isalpha() else "🌐"


def geo_for_ip(ip):
    try:
        d = fetch_json(f"https://ipwho.is/{ip}", 8)
        if d.get("success") is False:
            raise ValueError
        code = (d.get("country_code") or "").upper()
        return {
            "code": code,
            "country": d.get("country") or "Unknown",
            "city": d.get("city") or "",
            "flag": country_flag(code),
        }
    except Exception:
        return {"code": "", "country": "Unknown", "city": "", "flag": "🌐"}


def parse_vless(o):
    if o.get("protocol") != "vless":
        return None
    v = (o.get("settings") or {}).get("vnext") or []
    if not v or not (v[0].get("users") or []):
        return None
    s = v[0]
    u = s["users"][0]
    a = s.get("address")
    p = s.get("port")
    uid = u.get("id")
    if not all([a, p, uid]):
        return None
    st = o.get("streamSettings") or {}
    r = st.get("realitySettings") or {}
    if st.get("security") != "reality" or not r.get("publicKey"):
        return None
    params = [
        ("encryption", u.get("encryption") or "none"),
        ("type", st.get("network") or "tcp"),
        ("security", "reality"),
    ]
    for k, val in [
        ("flow", u.get("flow")),
        ("sni", r.get("serverName")),
        ("fp", r.get("fingerprint")),
        ("pbk", r.get("publicKey")),
        ("sid", r.get("shortId")),
    ]:
        if val is not None and val != "":
            params.append((k, val))
    q = "&".join(f"{quote(str(k))}={quote(str(v), safe='-_~.')}" for k, v in params)
    return {"address": a, "port": int(p), "base": f"vless://{uid}@{a}:{p}?{q}"}


def tcp_latency_ms(a, p):
    samples = []
    for _ in range(PING_ATTEMPTS):
        started = time.perf_counter()
        try:
            with socket.create_connection((a, p), timeout=PING_TIMEOUT):
                samples.append((time.perf_counter() - started) * 1000)
        except OSError:
            pass
    return statistics.median(samples) if samples else None


def main():
    data = fetch_json(SOURCE_URL)
    data = [data] if isinstance(data, dict) else data
    candidates = []
    seen = set()
    for cfg in data:
        for o in (cfg.get("outbounds") or []):
            item = parse_vless(o)
            if item and item["base"] not in seen:
                seen.add(item["base"])
                candidates.append(item)
    if not candidates:
        raise SystemExit("No VLESS Reality candidates")

    reachable = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(tcp_latency_ms, i["address"], i["port"]): i for i in candidates}
        for future in as_completed(futures):
            try:
                latency = future.result()
            except Exception:
                continue
            if latency is not None:
                reachable.append((latency, futures[future]))
    reachable.sort(key=lambda x: x[0])

    selected = []
    for latency, item in reachable[:80]:
        geo = geo_for_ip(item["address"])
        if geo.get("code") == "RU":
            continue
        selected.append((latency, item, geo))
        if len(selected) >= LIMIT:
            break
    if not selected:
        raise SystemExit("No suitable reachable VLESS Reality endpoints")

    # Routing is intentionally frozen to the profile that was verified on-device.
    # Scheduled runs only refresh the VLESS nodes and their labels.
    lines = [
        tested_routing_link(),
        "#routing-enable: 1",
        "#profile-update-interval: 2",
        "#subscription-auto-update-open-enable: 1",
        "#subscription-ping-onopen-enabled: 1",
        "#subscriptions-sort-type: ping",
        "#profile-title: Fast VPN",
    ]
    for latency, item, geo in selected:
        location = geo["country"] + (f" · {geo['city']}" if geo["city"] else "")
        label = f"{geo['flag']} {location}"
        lines.append(f"{item['base']}#{quote(label, safe='')}")
        print(f"{latency:7.1f} ms runner  {label}  {item['address']}:{item['port']}")

    plain = "\n".join(lines) + "\n"
    with open("vless.txt", "w", encoding="utf-8") as output:
        output.write(plain)
    with open("vless_base64.txt", "w", encoding="utf-8") as output:
        output.write(base64.b64encode(plain.encode()).decode() + "\n")
    print(f"Selected {len(selected)} Reality servers; tested RU+Gemini routing preserved")


if __name__ == "__main__":
    main()
