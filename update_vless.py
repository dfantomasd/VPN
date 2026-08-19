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

# RU sites/IPs go directly. Everything unmatched is proxied because GlobalProxy=true.
ROUTING_PROFILE = {
    "Name": "Dmitry RU Direct",
    "GlobalProxy": "true",
    "UseChunkFiles": "true",
    "RemoteDNSType": "DoH",
    "RemoteDNSDomain": "https://8.8.8.8/dns-query",
    "RemoteDNSIP": "8.8.8.8",
    "DomesticDNSType": "DoH",
    "DomesticDNSDomain": "https://77.88.8.8/dns-query",
    "DomesticDNSIP": "77.88.8.8",
    "Geositeurl": "https://cdn.jsdelivr.net/gh/b-n-m-n/happ-routing@main/release/geosite.dat",
    "Geoipurl": "https://cdn.jsdelivr.net/gh/b-n-m-n/happ-routing@main/release/geoip.dat",
    "LastUpdated": "",
    "DnsHosts": {
        "lkfl2.nalog.ru": "213.24.64.175",
        "lknpd.nalog.ru": "213.24.64.181",
    },
    "RouteOrder": "block-proxy-direct",
    "DirectSites": [
        "geosite:private",
        "geosite:russia-inside",
        "geosite:category-ru",
        "geosite:whitelist",
    ],
    "DirectIp": [
        "geoip:private",
        "geoip:russia-inside",
    ],
    "ProxySites": [
        "geosite:google-play",
        "geosite:github",
        "geosite:youtube",
        "geosite:telegram",
        "geosite:twitch",
        "geosite:pinterest",
    ],
    "ProxyIp": [],
    "BlockSites": [],
    "BlockIp": [],
    "DomainStrategy": "IPIfNonMatch",
    "FakeDNS": "false",
}


def fetch_json(url, timeout=30):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "happ-subscription-builder/5.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)


def country_flag(code):
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(127397 + ord(ch)) for ch in code)


def geo_for_ip(ip):
    try:
        data = fetch_json(f"https://ipwho.is/{ip}", timeout=8)
        if data.get("success") is False:
            raise ValueError("IP geolocation lookup failed")
        code = (data.get("country_code") or "").upper()
        continent = (data.get("continent_code") or "").upper()
        return {
            "code": code,
            "continent": continent,
            "country": data.get("country") or "Unknown",
            "city": data.get("city") or "",
            "flag": country_flag(code),
        }
    except Exception:
        return {
            "code": "",
            "continent": "",
            "country": "Unknown",
            "city": "",
            "flag": "🌐",
        }


def parse_vless(outbound):
    if outbound.get("protocol") != "vless":
        return None

    vnext = (outbound.get("settings") or {}).get("vnext") or []
    if not vnext or not (vnext[0].get("users") or []):
        return None

    server = vnext[0]
    user = server["users"][0]
    address = server.get("address")
    port = server.get("port")
    uid = user.get("id")
    if not all([address, port, uid]):
        return None

    stream = outbound.get("streamSettings") or {}
    reality = stream.get("realitySettings") or {}
    params = [
        ("encryption", user.get("encryption") or "none"),
        ("type", stream.get("network") or "tcp"),
        ("security", stream.get("security") or "none"),
    ]
    for key, value in [
        ("flow", user.get("flow")),
        ("sni", reality.get("serverName")),
        ("fp", reality.get("fingerprint")),
        ("pbk", reality.get("publicKey")),
        ("sid", reality.get("shortId")),
    ]:
        if value is not None and value != "":
            params.append((key, value))

    query = "&".join(
        f"{quote(str(key))}={quote(str(value), safe='-_~.')}"
        for key, value in params
    )
    return {
        "address": address,
        "port": int(port),
        "base": f"vless://{uid}@{address}:{port}?{query}",
    }


def tcp_latency_ms(address, port):
    samples = []
    for _ in range(PING_ATTEMPTS):
        started = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=PING_TIMEOUT):
                samples.append((time.perf_counter() - started) * 1000)
        except OSError:
            pass
    return statistics.median(samples) if samples else None


def routing_link():
    raw = json.dumps(
        ROUTING_PROFILE,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return "happ://routing/onadd/" + base64.b64encode(raw).decode("ascii")


def location_priority(geo):
    # GitHub's runner can be in the US, so raw runner latency alone strongly biases
    # North American nodes. Prefer Europe, then Asia; Happ performs the final ping
    # and sorting from the iPhone itself.
    continent = geo.get("continent")
    if continent == "EU":
        return 0
    if continent == "AS":
        return 1
    if continent in {"AF", "OC", "SA"}:
        return 2
    if continent == "NA":
        return 3
    return 2


def main():
    data = fetch_json(SOURCE_URL)
    if isinstance(data, dict):
        data = [data]

    candidates = []
    seen = set()
    for config in data:
        for outbound in (config.get("outbounds") or []):
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

    reachable = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(tcp_latency_ms, item["address"], item["port"]): item
            for item in candidates
        }
        for future in as_completed(futures):
            item = futures[future]
            try:
                latency = future.result()
            except Exception:
                continue
            if latency is not None:
                reachable.append((latency, item))

    if not reachable:
        raise SystemExit("No reachable VLESS endpoints found")

    enriched = []
    for latency, item in reachable:
        geo = geo_for_ip(item["address"])
        # A Russian exit node can still be subject to Russian blocking, so it should
        # not be offered as a VPN exit for this subscription.
        if geo.get("code") == "RU":
            continue
        enriched.append((location_priority(geo), latency, item, geo))

    if not enriched:
        raise SystemExit("No suitable non-RU VLESS endpoints found")

    enriched.sort(key=lambda row: (row[0], row[1]))
    selected = enriched[:LIMIT]

    lines = [
        routing_link(),
        "#routing-enable: 1",
        "#profile-update-interval: 6",
        "#subscription-auto-update-open-enable: 1",
        "#subscription-ping-onopen-enabled: 1",
        "#subscriptions-sort-type: ping",
        "#profile-title: Fast VPN",
    ]

    for _, latency, item, geo in selected:
        location = geo["country"]
        if geo["city"]:
            location += f" · {geo['city']}"
        label = f"{geo['flag']} {location}"
        lines.append(f"{item['base']}#{quote(label, safe='')}")
        print(
            f"{latency:7.1f} ms (runner)  {geo['flag']} "
            f"{geo['country']}  {item['address']}:{item['port']}"
        )

    plain = "\n".join(lines) + "\n"
    with open("vless.txt", "w", encoding="utf-8") as output:
        output.write(plain)

    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    with open("vless_base64.txt", "w", encoding="utf-8") as output:
        output.write(encoded + "\n")

    print(
        f"Selected {len(selected)} non-RU servers from {len(candidates)} candidates; "
        "Happ will ping and sort them on device"
    )


if __name__ == "__main__":
    main()
