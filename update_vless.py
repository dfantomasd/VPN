#!/usr/bin/env python3
import base64
import ipaddress
import json
import os
import socket
import statistics
import time
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlsplit

SOURCES = [
    {
        "name": "kenkaral45",
        "kind": "json",
        "url": "https://raw.githubusercontent.com/kenkaral45/happ-subscription/main/whitelist_configs_combined.json",
    },
    {
        "name": "Freedom-V2Ray",
        "kind": "text",
        "url": "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless.txt",
    },
    {
        "name": "Matin-VLESS",
        "kind": "text",
        "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    },
    {
        "name": "Matin-Super",
        "kind": "text",
        "url": "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    },
]

LIMIT = int(os.getenv("VLESS_LIMIT", "15"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "1.8"))
PING_ATTEMPTS = int(os.getenv("PING_ATTEMPTS", "2"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "32"))
MAX_PER_SOURCE = int(os.getenv("MAX_PER_SOURCE", "800"))
MAX_COUNTRY = int(os.getenv("MAX_COUNTRY", "3"))
MAX_GEO_LOOKUPS = int(os.getenv("MAX_GEO_LOOKUPS", "120"))

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
    "DirectIp": ["geoip:private", "geoip:russia-inside"],
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


def fetch_bytes(url, timeout=40):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "happ-subscription-builder/6.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def fetch_json(url, timeout=40):
    return json.loads(fetch_bytes(url, timeout=timeout).decode("utf-8"))


def fetch_text(url, timeout=40):
    return fetch_bytes(url, timeout=timeout).decode("utf-8", errors="ignore")


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
        return {
            "code": code,
            "continent": (data.get("continent_code") or "").upper(),
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


def parse_json_vless(outbound):
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
    base = f"vless://{uid}@{address}:{port}?{query}"
    return normalize_text_vless(base)


def normalize_text_vless(link):
    link = link.strip()
    if not link.lower().startswith("vless://"):
        return None
    link = link.split("#", 1)[0]
    try:
        parsed = urlsplit(link)
        if not parsed.hostname or not parsed.port or not parsed.username:
            return None
        address = parsed.hostname
        port = int(parsed.port)
    except Exception:
        return None
    return {
        "address": address,
        "port": port,
        "base": link,
    }


def extract_source(source):
    items = []
    try:
        if source["kind"] == "json":
            data = fetch_json(source["url"])
            if isinstance(data, dict):
                data = [data]
            for config in data:
                for outbound in (config.get("outbounds") or []):
                    item = parse_json_vless(outbound)
                    if item:
                        items.append(item)
                        if len(items) >= MAX_PER_SOURCE:
                            break
                if len(items) >= MAX_PER_SOURCE:
                    break
        else:
            text = fetch_text(source["url"])
            for token in text.replace("\r", "\n").split():
                item = normalize_text_vless(token)
                if item:
                    items.append(item)
                    if len(items) >= MAX_PER_SOURCE:
                        break
    except Exception as exc:
        print(f"WARN source failed: {source['name']}: {exc}")
    print(f"Source {source['name']}: {len(items)} VLESS candidates")
    return items


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


def subnet_key(address):
    try:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv4Address):
            return str(ipaddress.ip_network(f"{address}/24", strict=False))
        return str(ipaddress.ip_network(f"{address}/48", strict=False))
    except ValueError:
        return address.lower()


def region_penalty(geo):
    # Small preference for Europe, but North America is deliberately kept as reserve.
    continent = geo.get("continent")
    return {
        "EU": 0,
        "AS": 80,
        "NA": 120,
        "AF": 160,
        "SA": 180,
        "OC": 200,
    }.get(continent, 120)


def main():
    appearances = defaultdict(set)
    by_key = {}

    for source in SOURCES:
        for item in extract_source(source):
            key = item["base"]
            appearances[key].add(source["name"])
            by_key.setdefault(key, item)

    candidates = list(by_key.values())
    if not candidates:
        raise SystemExit("No VLESS candidates found from any source")

    print(f"Unique candidates: {len(candidates)}")

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

    # Geolocate only the most promising endpoints to avoid unnecessary API load.
    reachable.sort(key=lambda row: row[0])
    pool_for_geo = reachable[:MAX_GEO_LOOKUPS]

    enriched = []
    for latency, item in pool_for_geo:
        geo = geo_for_ip(item["address"])
        if geo.get("code") == "RU":
            continue
        popularity = len(appearances[item["base"]])
        # A repeated public config is more likely to be crowded. This is a heuristic,
        # not a direct load measurement, so the penalty is intentionally moderate.
        popularity_penalty = max(0, popularity - 1) * 90
        score = latency + region_penalty(geo) + popularity_penalty
        enriched.append((score, latency, popularity, item, geo))

    if not enriched:
        raise SystemExit("No suitable non-RU VLESS endpoints found")

    enriched.sort(key=lambda row: row[0])

    selected = []
    country_counts = Counter()
    used_subnets = set()

    for row in enriched:
        _, _, _, item, geo = row
        code = geo.get("code") or "XX"
        subnet = subnet_key(item["address"])
        if country_counts[code] >= MAX_COUNTRY:
            continue
        if subnet in used_subnets:
            continue
        selected.append(row)
        country_counts[code] += 1
        used_subnets.add(subnet)
        if len(selected) >= LIMIT:
            break

    # If diversity constraints leave too few nodes, relax only the country cap,
    # while still avoiding duplicate subnets.
    if len(selected) < LIMIT:
        selected_bases = {row[3]["base"] for row in selected}
        for row in enriched:
            item = row[3]
            subnet = subnet_key(item["address"])
            if item["base"] in selected_bases or subnet in used_subnets:
                continue
            selected.append(row)
            selected_bases.add(item["base"])
            used_subnets.add(subnet)
            if len(selected) >= LIMIT:
                break

    lines = [
        routing_link(),
        "#routing-enable: 1",
        "#profile-update-interval: 6",
        "#subscription-auto-update-open-enable: 1",
        "#subscription-ping-onopen-enabled: 1",
        "#subscriptions-sort-type: ping",
        "#profile-title: Fast VPN",
    ]

    for score, latency, popularity, item, geo in selected:
        location = geo["country"]
        if geo["city"]:
            location += f" · {geo['city']}"
        label = f"{geo['flag']} {location}"
        lines.append(f"{item['base']}#{quote(label, safe='')}")
        print(
            f"score={score:7.1f} runner={latency:7.1f}ms sources={popularity} "
            f"{geo['flag']} {geo['country']} {item['address']}:{item['port']}"
        )

    plain = "\n".join(lines) + "\n"
    with open("vless.txt", "w", encoding="utf-8") as output:
        output.write(plain)

    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    with open("vless_base64.txt", "w", encoding="utf-8") as output:
        output.write(encoded + "\n")

    print(
        f"Selected {len(selected)} diverse non-RU servers from {len(candidates)} unique candidates; "
        "Happ will do final ping sorting on the iPhone"
    )


if __name__ == "__main__":
    main()
