#!/usr/bin/env python3
import base64
import hashlib
import html
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import statistics
import struct
import subprocess
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, unquote, urlsplit


DEFAULT_SOURCES = [
    ("connliberty", "https://connliberty.com/connection/subs/d950be8a-ab95-4618-bf67-21b76c969342?r=1"),
    ("vpn-free-russia", "https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/verified_configs.txt"),
    ("proxy-collector", "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt"),
    ("barry-far", "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/vless.txt"),
    ("radikal", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt"),
]
ROUTING_PROFILE_FILE = "routing_profile.json"
LIMIT = int(os.getenv("VLESS_LIMIT", "20"))
MIN_SERVERS = int(os.getenv("VLESS_MIN_SERVERS", "3"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "1.8"))
PING_ATTEMPTS = int(os.getenv("PING_ATTEMPTS", "2"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "24"))
MAX_CANDIDATES_PER_SOURCE = int(os.getenv("MAX_CANDIDATES_PER_SOURCE", "300"))
SOURCE_ROTATION_SECONDS = int(os.getenv("SOURCE_ROTATION_SECONDS", "3600"))
REALITY_TEST_WORKERS = int(os.getenv("REALITY_TEST_WORKERS", "4"))
REALITY_TEST_LIMIT = int(os.getenv("REALITY_TEST_LIMIT", "100"))
REALITY_TEST_TIMEOUT = float(os.getenv("REALITY_TEST_TIMEOUT", "8"))
MAX_REALITY_LATENCY_MS = float(os.getenv("MAX_REALITY_LATENCY_MS", "3500"))
REALITY_TEST_URL = os.getenv("REALITY_TEST_URL", "https://www.gstatic.com/generate_204")
NEAREST_POOL_LIMIT = int(os.getenv("NEAREST_POOL_LIMIT", "60"))
FASTEST_POOL_LIMIT = int(os.getenv("FASTEST_POOL_LIMIT", "40"))
GEO_WORKERS = int(os.getenv("GEO_WORKERS", "8"))
GEO_CACHE_FILE = os.getenv("GEO_CACHE_FILE", ".cache/geo.json")
GEO_CACHE_TTL = int(os.getenv("GEO_CACHE_TTL", "86400"))
FINALIST_LIMIT = int(os.getenv("FINALIST_LIMIT", "30"))
ADVANCED_TEST_WORKERS = int(os.getenv("ADVANCED_TEST_WORKERS", "6"))
THROUGHPUT_BYTES = int(os.getenv("THROUGHPUT_BYTES", "1048576"))
THROUGHPUT_TEST_URL = os.getenv(
    "THROUGHPUT_TEST_URL", f"https://speed.cloudflare.com/__down?bytes={THROUGHPUT_BYTES}"
)
THROUGHPUT_TEST_TIMEOUT = float(os.getenv("THROUGHPUT_TEST_TIMEOUT", "10"))
MIN_THROUGHPUT_MBPS = float(os.getenv("MIN_THROUGHPUT_MBPS", "3.0"))
UDP_TEST_TIMEOUT = float(os.getenv("UDP_TEST_TIMEOUT", "4"))
SERVICE_TEST_TIMEOUT = float(os.getenv("SERVICE_TEST_TIMEOUT", "7"))
SERVICE_TESTS = (
    ("telegram", os.getenv("TELEGRAM_TEST_URL", "https://api.telegram.org/botINVALID/getMe"), False),
    ("gemini", os.getenv("GEMINI_TEST_URL", "https://gemini.google.com/"), True),
)
TELEGRAM_DC_ENDPOINTS = tuple(
    (host, int(port))
    for host, port in (
        value.rsplit(":", 1)
        for value in os.getenv(
            "TELEGRAM_DC_ENDPOINTS",
            "149.154.167.50:443,149.154.175.100:443,91.108.56.100:443",
        ).split(",")
        if ":" in value
    )
)
TELEGRAM_DC_MIN_SUCCESS = int(os.getenv("TELEGRAM_DC_MIN_SUCCESS", "2"))
HISTORY_FILE = os.getenv("VLESS_HISTORY_FILE", "server_history.json")
HISTORY_SAMPLES = int(os.getenv("VLESS_HISTORY_SAMPLES", "12"))
STABILITY_MIN_STRICT_PASSES = int(os.getenv("STABILITY_MIN_STRICT_PASSES", "2"))
STABILITY_WINDOW = int(os.getenv("STABILITY_WINDOW", "8"))
RU_PROBE_ENABLED = os.getenv("RU_PROBE_ENABLED", "1").strip().lower() not in {"0", "false", "no"}
RU_PROBE_API = os.getenv("RU_PROBE_API", "https://api.globalping.io/v1/measurements")
RU_PROBE_ASNS = tuple(
    int(value) for value in os.getenv("RU_PROBE_ASNS", "8359,12389").split(",") if value.strip().isdigit()
)
RU_PROBE_PER_ASN = int(os.getenv("RU_PROBE_PER_ASN", "1"))
RU_PROBE_MIN_SUCCESS = int(os.getenv("RU_PROBE_MIN_SUCCESS", "2"))
RU_PROBE_TIMEOUT = float(os.getenv("RU_PROBE_TIMEOUT", "30"))
RU_PROBE_CACHE_TTL = int(os.getenv("RU_PROBE_CACHE_TTL", "21600"))
RU_PROBE_WORKERS = int(os.getenv("RU_PROBE_WORKERS", "4"))
STATUS_FILE = os.getenv("VLESS_STATUS_FILE", "generation_status.json")
ROUTING_STATUS_FILE = os.getenv("ROUTING_STATUS_FILE", "routing_data_status.json")
STALE_WARNING_HOURS = float(os.getenv("STALE_WARNING_HOURS", "6"))
XRAY_BIN = os.getenv("XRAY_BIN", "xray")
CURL_BIN = os.getenv("CURL_BIN", "curl")
MOSCOW_LATITUDE = 55.7558
MOSCOW_LONGITUDE = 37.6173


def configured_sources():
    raw = os.getenv("VLESS_SOURCES", "").strip()
    if not raw:
        return DEFAULT_SOURCES
    sources = []
    for index, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            name, url = line.split("=", 1)
        else:
            name, url = f"source-{index}", line
        sources.append((name.strip(), url.strip()))
    if not sources:
        raise SystemExit("VLESS_SOURCES does not contain any source URLs")
    return sources


def fetch_text(url, timeout=60):
    error = None
    for attempt in range(3):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; happ-subscription-builder/11.0)",
                "Accept": "application/json,text/plain,*/*",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read().decode("utf-8-sig", errors="replace")
        except OSError as exc:
            error = exc
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
    raise error


def fetch_json(url, timeout=30):
    return json.loads(fetch_text(url, timeout))


def request_json(url, payload=None, timeout=30):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": "happ-subscription-builder/12.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def routing_profile():
    with open(ROUTING_PROFILE_FILE, "r", encoding="utf-8") as source:
        profile = json.load(source)
    required = {
        "DirectSites": {
            "domain:ru", "domain:xn--p1ai", "domain:su", "domain:xn--p1acf",
            "domain:moscow", "domain:xn--80adxhks",
            "geosite:russia-inside", "geosite:category-ru",
            "geosite:category-bank-ru", "geosite:sber", "geosite:tbank-ru",
            "domain:sberbank.com", "domain:tbank-online.com", "domain:tinkoff-group.com",
        },
        "DirectIp": {"geoip:private", "geoip:ru", "geoip:by", "geoip:russia-inside"},
        "ProxySites": {
            "domain:gemini.google.com", "domain:generativelanguage.googleapis.com",
            "domain:accounts.google.com", "domain:ai.google.dev",
            "geosite:telegram", "geosite:youtube", "geosite:google",
            "geosite:ru-blocked", "geosite:ru-geoblock",
        },
        "ProxyIp": {"149.154.160.0/20"},
    }
    if profile.get("Name") != "SIMUTIN":
        raise SystemExit("Routing profile must keep the stable name 'SIMUTIN'")
    if profile.get("GlobalProxy") != "false" or profile.get("DomainStrategy") != "IPIfNonMatch":
        raise SystemExit("Routing profile must send unmatched traffic directly and resolve IP rules")
    if profile.get("RouteOrder") != "block-direct-proxy":
        raise SystemExit("Routing profile must prioritize direct Russian traffic")
    for field, expected in required.items():
        if not expected.issubset(set(profile.get(field) or [])):
            raise SystemExit(f"Routing profile is missing required {field} rules")
    if not profile.get("ProxyIp"):
        raise SystemExit("Routing profile must proxy Telegram IP ranges")
    return profile


def parse_cidr_lines(text):
    networks = []
    for raw in text.splitlines():
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            networks.append(str(ipaddress.ip_network(value, strict=False)))
        except ValueError:
            continue
    return list(dict.fromkeys(networks))


def routing_revision():
    override = os.getenv("ROUTING_REVISION", "").strip()
    if re.fullmatch(r"\d{9,11}", override):
        return override
    try:
        with open(ROUTING_STATUS_FILE, encoding="utf-8") as source:
            status = json.load(source)
        version = str(status.get("version") or "")
        if re.fullmatch(r"\d{9,11}", version):
            return version
        if re.fullmatch(r"\d{12}", version):
            legacy = datetime.strptime(version, "%Y%m%d%H%M").replace(tzinfo=timezone.utc)
            return str(int(legacy.timestamp()))
    except (OSError, ValueError):
        pass
    return str(int(datetime.now(timezone.utc).timestamp()))


def versioned_url(url, version):
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}v={version}"


def tested_routing_link(telegram_cidrs=None):
    profile = routing_profile()
    static_proxy_ip = [rule for rule in profile["ProxyIp"] if rule.startswith("geoip:")]
    fallback_cidrs = parse_cidr_lines("\n".join(profile["ProxyIp"]))
    supplied_cidrs = parse_cidr_lines("\n".join(telegram_cidrs or []))
    # Keep this profile byte-stable between GeoData releases. Happ imports the
    # line on every subscription refresh; changing a live CIDR feed here used
    # to cause needless in-place routing updates on iOS.
    profile["ProxyIp"] = static_proxy_ip + (supplied_cidrs or fallback_cidrs)
    version = routing_revision()
    profile["LastUpdated"] = version
    profile["Geositeurl"] = versioned_url(profile["Geositeurl"], version)
    profile["Geoipurl"] = versioned_url(profile["Geoipurl"], version)
    payload = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return "happ://routing/onadd/" + encoded


def country_flag(code):
    code = (code or "").upper()
    return "".join(chr(127397 + ord(ch)) for ch in code) if len(code) == 2 and code.isalpha() else "🌐"


def geo_for_ip(ip):
    try:
        data = fetch_json(f"https://ipwho.is/{ip}", 8)
        if data.get("success") is False:
            raise ValueError
        code = (data.get("country_code") or "").upper()
        connection = data.get("connection") or {}
        return {
            "code": code,
            "country": data.get("country") or "Unknown",
            "city": data.get("city") or "",
            "flag": country_flag(code),
            "asn": str(connection.get("asn") or ""),
            "isp": connection.get("isp") or "",
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
        }
    except Exception:
        return {
            "code": "", "country": "Unknown", "city": "", "flag": "🌐", "asn": "", "isp": "",
            "latitude": None, "longitude": None,
        }


def load_json_file(path, default):
    try:
        with open(path, "r", encoding="utf-8") as source:
            value = json.load(source)
        return value
    except (OSError, ValueError, TypeError):
        return default


def save_json_file(path, value):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as output:
        json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True)
        output.write("\n")
    os.replace(temporary, path)


def geolocate_ips(ips):
    now = int(time.time())
    cache = load_json_file(GEO_CACHE_FILE, {"entries": {}})
    entries = cache.get("entries") if isinstance(cache, dict) else {}
    if not isinstance(entries, dict):
        entries = {}
    result, missing = {}, []
    for ip in dict.fromkeys(ips):
        cached = entries.get(ip) or {}
        if cached.get("geo") and now - int(cached.get("updated_at") or 0) <= GEO_CACHE_TTL:
            result[ip] = cached["geo"]
        else:
            missing.append(ip)
    with ThreadPoolExecutor(max_workers=GEO_WORKERS) as pool:
        futures = {pool.submit(geo_for_ip, ip): ip for ip in missing}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                geo = future.result()
            except Exception:
                geo = None
            if geo and geo.get("code"):
                result[ip] = geo
                entries[ip] = {"updated_at": now, "geo": geo}
            elif (entries.get(ip) or {}).get("geo"):
                result[ip] = entries[ip]["geo"]
    cutoff = now - 30 * 86400
    entries = {ip: value for ip, value in entries.items() if int(value.get("updated_at") or 0) >= cutoff}
    save_json_file(GEO_CACHE_FILE, {"entries": entries})
    return result


def history_key(item):
    identity = f"{item.get('resolved_ip') or item['address']}:{item['port']}|{item['uuid']}"
    return hashlib.sha256(identity.encode()).hexdigest()[:24]


def load_history():
    value = load_json_file(HISTORY_FILE, {"version": 1, "servers": {}})
    if not isinstance(value, dict) or not isinstance(value.get("servers"), dict):
        return {"version": 1, "servers": {}}
    return value


def history_stats(item, history):
    samples = (history.get("servers", {}).get(history_key(item)) or {}).get("samples") or []
    successes = [sample for sample in samples if sample.get("success")]
    if not samples:
        return {"success_rate": 0.5, "latency": None, "throughput": None, "jitter": 0.0, "samples": 0}
    latencies = [float(sample["latency_ms"]) for sample in successes if sample.get("latency_ms") is not None]
    throughputs = [float(sample["throughput_mbps"]) for sample in successes if sample.get("throughput_mbps")]
    return {
        "success_rate": len(successes) / len(samples),
        "latency": statistics.median(latencies) if latencies else None,
        "throughput": statistics.median(throughputs) if throughputs else None,
        "jitter": statistics.pstdev(latencies) if len(latencies) > 1 else 0.0,
        "samples": len(samples),
    }


def strict_pass_count(item, history, window=STABILITY_WINDOW):
    samples = (history.get("servers", {}).get(history_key(item)) or {}).get("samples") or []
    strict = [
        sample for sample in samples
        if "quality_ok" in sample or "telegram_dc" in sample
    ][-window:]
    return sum(
        bool(sample.get("quality_ok")) or (
            sample.get("success")
            and sample.get("udp")
            and sample.get("telegram_dc")
            and all((sample.get("services") or {}).get(name) for name, _, _ in SERVICE_TESTS)
            and float(sample.get("throughput_mbps") or 0) >= MIN_THROUGHPUT_MBPS
        )
        for sample in strict
    )


def cached_ru_probe(item, history, now=None):
    now = int(time.time()) if now is None else int(now)
    endpoint = f"{item.get('resolved_ip') or item['address']}:{item['port']}"
    newest = None
    for record in history.get("servers", {}).values():
        probe = record.get("ru_probe") or {}
        if record.get("endpoint") != endpoint or not probe.get("checked_at"):
            continue
        if newest is None or int(probe["checked_at"]) > int(newest["checked_at"]):
            newest = probe
    if newest and now - int(newest["checked_at"]) <= RU_PROBE_CACHE_TTL:
        return dict(newest, cached=True)
    return None


def russian_network_probe(item, history):
    cached = cached_ru_probe(item, history)
    if cached is not None:
        return cached
    previous = None
    endpoint = f"{item.get('resolved_ip') or item['address']}:{item['port']}"
    for record in history.get("servers", {}).values():
        probe = record.get("ru_probe") or {}
        if record.get("endpoint") == endpoint and probe.get("checked_at"):
            if previous is None or int(probe["checked_at"]) > int(previous["checked_at"]):
                previous = probe
    target = item.get("resolved_ip") or item["address"]
    locations = [{"country": "RU", "asn": asn} for asn in RU_PROBE_ASNS]
    payload = {
        "type": "traceroute",
        "target": target,
        "locations": locations,
        "limit": max(1, len(locations) * RU_PROBE_PER_ASN),
        "measurementOptions": {"protocol": "TCP", "port": item["port"]},
    }
    try:
        created = request_json(RU_PROBE_API, payload, timeout=10)
        measurement_id = created["id"]
        deadline = time.monotonic() + RU_PROBE_TIMEOUT
        result = None
        while time.monotonic() < deadline:
            result = request_json(f"{RU_PROBE_API}/{measurement_id}", timeout=10)
            if result.get("status") == "finished":
                break
            time.sleep(1)
        if not result or result.get("status") != "finished":
            raise TimeoutError("Russian reachability measurement did not finish")
        successes = 0
        probes = []
        for entry in result.get("results") or []:
            probe = entry.get("probe") or {}
            hops = (entry.get("result") or {}).get("hops") or []
            reached = any(hop.get("resolvedAddress") == target for hop in hops)
            successes += int(reached)
            probes.append({
                "asn": probe.get("asn"), "city": probe.get("city"),
                "network": probe.get("network"), "reached": reached,
            })
        return {
            "checked_at": int(time.time()), "ok": successes >= RU_PROBE_MIN_SUCCESS,
            "success_count": successes, "probe_count": len(probes),
            "measurement_id": measurement_id, "probes": probes, "cached": False,
        }
    except (KeyError, OSError, TimeoutError, ValueError) as exc:
        if previous and previous.get("ok"):
            return dict(previous, cached=True, stale=True, error=str(exc))
        return {
            "checked_at": int(time.time()), "ok": False, "success_count": 0,
            "probe_count": 0, "error": str(exc), "cached": False,
        }


def update_history(history, items_by_key, results):
    now = datetime.now(timezone.utc).isoformat()
    servers = history.setdefault("servers", {})
    for key, sample in results.items():
        item = items_by_key[key]
        record = servers.setdefault(key, {})
        record["endpoint"] = f"{item.get('resolved_ip') or item['address']}:{item['port']}"
        record["last_seen"] = now
        samples = list(record.get("samples") or [])
        samples.append(sample)
        record["samples"] = samples[-HISTORY_SAMPLES:]
    if len(servers) > 1000:
        newest = sorted(servers.items(), key=lambda pair: pair[1].get("last_seen", ""), reverse=True)[:1000]
        history["servers"] = dict(newest)
    save_json_file(HISTORY_FILE, history)


def distance_from_moscow_km(geo):
    try:
        latitude, longitude = float(geo["latitude"]), float(geo["longitude"])
    except (KeyError, TypeError, ValueError):
        return math.inf
    lat1, lat2 = math.radians(MOSCOW_LATITUDE), math.radians(latitude)
    delta_lat = math.radians(latitude - MOSCOW_LATITUDE)
    delta_lon = math.radians(longitude - MOSCOW_LONGITUDE)
    value = math.sin(delta_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    return 6371.0088 * 2 * math.atan2(math.sqrt(value), math.sqrt(1 - value))


def moscow_rank_key(row):
    latency, item, geo = row
    return distance_from_moscow_km(geo), latency, len(item.get("endpoint_sources") or ())


def quality_score(row, history, throughput_mbps=None):
    latency, item, geo = row
    stats = history_stats(item, history)
    throughput = throughput_mbps or stats["throughput"] or MIN_THROUGHPUT_MBPS
    reliability_penalty = (1.0 - stats["success_rate"]) * 2500
    jitter_penalty = min(stats["jitter"], 1500) * 0.20
    shared_penalty = max(0, len(item.get("endpoint_sources") or ()) - 1) * 250
    latency_penalty = min(float(latency), MAX_REALITY_LATENCY_MS) * 0.35
    throughput_penalty = 1800 / math.sqrt(max(float(throughput), 0.1))
    distance_penalty = min(distance_from_moscow_km(geo), 10_000) * 0.15
    return (
        distance_penalty + reliability_penalty + jitter_penalty
        + shared_penalty + latency_penalty + throughput_penalty
    )


def canonical_item(address, port, uid, params):
    if not address or not port or not uid:
        return None
    network = (params.get("type") or params.get("network") or "tcp").lower()
    if params.get("security") != "reality" or not params.get("pbk") or not params.get("sni"):
        return None
    if network not in {"tcp", "raw"}:
        return None
    normalized = {
        "encryption": params.get("encryption") or "none", "type": network,
        "security": "reality", "fp": params.get("fp") or "chrome",
    }
    for key in ("flow", "sni", "pbk", "sid", "spx"):
        value = params.get(key)
        if value not in (None, ""):
            normalized[key] = str(value)
    query = "&".join(f"{quote(str(key))}={quote(str(value), safe='-_~./')}" for key, value in normalized.items())
    uri_address = f"[{address}]" if ":" in address and not address.startswith("[") else address
    base = f"vless://{quote(str(uid), safe='-')}@{uri_address}:{int(port)}?{query}"
    return {
        "address": address, "port": int(port), "uuid": str(uid), "network": network,
        "encryption": normalized["encryption"], "flow": normalized.get("flow", ""),
        "sni": normalized.get("sni", ""), "fingerprint": normalized.get("fp", "chrome"),
        "public_key": normalized["pbk"], "short_id": normalized.get("sid", ""),
        "spider_x": normalized.get("spx", ""), "base": base, "sources": set(),
    }


def parse_vless_uri(uri):
    try:
        parsed = urlsplit(html.unescape(uri.strip()))
        if parsed.scheme.lower() != "vless" or not parsed.hostname or not parsed.port:
            return None
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        return canonical_item(parsed.hostname, parsed.port, unquote(parsed.username or ""), params)
    except (TypeError, ValueError):
        return None


def parse_vless_outbound(outbound):
    if outbound.get("protocol") != "vless":
        return None
    vnext = (outbound.get("settings") or {}).get("vnext") or []
    if not vnext or not (vnext[0].get("users") or []):
        return None
    server, user = vnext[0], vnext[0]["users"][0]
    stream = outbound.get("streamSettings") or {}
    reality = stream.get("realitySettings") or {}
    address, port, uid = server.get("address"), server.get("port"), user.get("id")
    if not all((address, port, uid)):
        return None
    return canonical_item(address, port, uid, {
        "encryption": user.get("encryption") or "none", "type": stream.get("network") or "tcp",
        "security": stream.get("security"), "flow": user.get("flow"),
        "sni": reality.get("serverName"), "fp": reality.get("fingerprint"),
        "pbk": reality.get("publicKey"), "sid": reality.get("shortId"), "spx": reality.get("spiderX"),
    })


def looks_like_config(value):
    return isinstance(value, dict) and isinstance(value.get("outbounds"), list)


def extract_json_configs(text):
    text = html.unescape(text)
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = None
    if looks_like_config(value):
        return [value]
    if isinstance(value, list):
        return [item for item in value if looks_like_config(item)]
    decoder, configs = json.JSONDecoder(), []
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            continue
        if looks_like_config(value):
            configs.append(value)
    return configs


def maybe_decode_base64(text):
    compact = "".join(text.split())
    if len(compact) < 16:
        return None
    try:
        decoded = base64.b64decode(compact, validate=True).decode("utf-8", errors="replace")
    except (ValueError, UnicodeError):
        return None
    return decoded if "vless://" in decoded or '"outbounds"' in decoded else None


def parse_source(text):
    text, items = html.unescape(text), []
    for token in text.replace('"', "\n").replace("'", "\n").split():
        if token.lower().startswith("vless://"):
            item = parse_vless_uri(token)
            if item:
                items.append(item)
    for config in extract_json_configs(text):
        for outbound in config.get("outbounds") or []:
            item = parse_vless_outbound(outbound)
            if item:
                items.append(item)
    if not items:
        decoded = maybe_decode_base64(text)
        if decoded:
            return parse_source(decoded)
    return items


def rotating_source_sample(name, items, limit, bucket=None):
    unique = list(dict.fromkeys(item["base"] for item in items))
    by_base = {item["base"]: item for item in items}
    if len(unique) <= limit:
        return [by_base[base] for base in unique]
    bucket = int(time.time() // SOURCE_ROTATION_SECONDS) if bucket is None else int(bucket)
    seed = int(hashlib.sha256(f"{name}:{bucket}".encode()).hexdigest()[:12], 16)
    offset = seed % len(unique)
    rotated = unique[offset:] + unique[:offset]
    indexes = [index * len(rotated) // limit for index in range(limit)]
    return [by_base[rotated[index]] for index in indexes]


def collect_candidates(sources):
    merged, failures = {}, []
    with ThreadPoolExecutor(max_workers=min(len(sources), 6)) as pool:
        futures = {pool.submit(fetch_text, url): (name, url) for name, url in sources}
        for future in as_completed(futures):
            name, _ = futures[future]
            try:
                items = parse_source(future.result())
                if not items:
                    raise ValueError("no supported VLESS Reality TCP nodes")
                sampled = rotating_source_sample(name, items, MAX_CANDIDATES_PER_SOURCE)
                source_keys = set()
                for item in sampled:
                    source_keys.add(item["base"])
                    if item["base"] not in merged:
                        merged[item["base"]] = item
                    merged[item["base"]]["sources"].add(name)
                print(
                    f"source {name}: sampled {len(source_keys)} of "
                    f"{len(set(item['base'] for item in items))} unique supported candidates"
                )
            except Exception as exc:
                failures.append(f"{name}: {exc}")
                print(f"source {name}: FAILED: {exc}")
    if not merged:
        raise SystemExit("All VLESS sources failed: " + "; ".join(failures))
    endpoint_sources = {}
    for item in merged.values():
        endpoint = (item["address"], item["port"])
        endpoint_sources.setdefault(endpoint, set()).update(item["sources"])
    for item in merged.values():
        item["endpoint_sources"] = endpoint_sources[(item["address"], item["port"])]
    return list(merged.values())


def tcp_latency_ms(address, port):
    samples = []
    for _ in range(PING_ATTEMPTS):
        started = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=PING_TIMEOUT) as connection:
                samples.append(((time.perf_counter() - started) * 1000, connection.getpeername()[0]))
        except OSError:
            pass
    if not samples:
        return None
    return statistics.median(value[0] for value in samples), samples[0][1]


def xray_outbound(item):
    user = {"id": item["uuid"], "encryption": item["encryption"]}
    if item["flow"]:
        user["flow"] = item["flow"]
    return {
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": item.get("resolved_ip") or item["address"],
            "port": item["port"], "users": [user],
        }]},
        "streamSettings": {
            "network": "raw" if item["network"] == "raw" else "tcp", "security": "reality",
            "realitySettings": {
                "show": False, "fingerprint": item["fingerprint"], "serverName": item["sni"],
                "publicKey": item["public_key"], "shortId": item["short_id"], "spiderX": item["spider_x"],
            },
        },
        "tag": "proxy",
    }


def rendered_vless_uri(item):
    address = item.get("resolved_ip") or item["address"]
    uri_address = f"[{address}]" if ":" in address and not address.startswith("[") else address
    query = item["base"].split("?", 1)[1]
    return f"vless://{quote(str(item['uuid']), safe='-')}@{uri_address}:{item['port']}?{query}"


def free_local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_port(port, process, timeout=2.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def reality_latency_ms(item):
    port = free_local_port()
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [xray_outbound(item)],
    }
    with tempfile.TemporaryDirectory(prefix="vless-check-") as directory:
        config_path = os.path.join(directory, "config.json")
        with open(config_path, "w", encoding="utf-8") as output:
            json.dump(config, output)
        process = subprocess.Popen([XRAY_BIN, "run", "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not wait_for_port(port, process):
                return None
            result = subprocess.run([
                CURL_BIN, "--silent", "--show-error", "--output", os.devnull, "--write-out", "%{time_total}",
                "--max-time", str(REALITY_TEST_TIMEOUT), "--proxy", f"socks5h://127.0.0.1:{port}", REALITY_TEST_URL,
            ], capture_output=True, text=True, timeout=REALITY_TEST_TIMEOUT + 2, check=False)
            return float(result.stdout.strip()) * 1000 if result.returncode == 0 else None
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return None
        finally:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)


def recv_exact(connection, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise OSError("unexpected end of SOCKS response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def socks5_tcp_connect_check(port, host, target_port, timeout=SERVICE_TEST_TIMEOUT):
    try:
        address = ipaddress.ip_address(host)
        atyp = b"\x01" if address.version == 4 else b"\x04"
        encoded_host = address.packed
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            return False
        atyp, encoded_host = b"\x03", bytes([len(encoded)]) + encoded
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(b"\x05\x01\x00")
            if recv_exact(connection, 2) != b"\x05\x00":
                return False
            request = b"\x05\x01\x00" + atyp + encoded_host + struct.pack("!H", target_port)
            connection.sendall(request)
            header = recv_exact(connection, 4)
            if header[:2] != b"\x05\x00":
                return False
            if header[3] == 1:
                recv_exact(connection, 4)
            elif header[3] == 3:
                recv_exact(connection, recv_exact(connection, 1)[0])
            elif header[3] == 4:
                recv_exact(connection, 16)
            else:
                return False
            recv_exact(connection, 2)
            return True
    except OSError:
        return False


def telegram_dc_check(port):
    if not TELEGRAM_DC_ENDPOINTS:
        return False
    successes = sum(
        socks5_tcp_connect_check(port, host, target_port)
        for host, target_port in TELEGRAM_DC_ENDPOINTS
    )
    return successes >= min(TELEGRAM_DC_MIN_SUCCESS, len(TELEGRAM_DC_ENDPOINTS))


def socks5_udp_dns_check(port, timeout=UDP_TEST_TIMEOUT):
    transaction_id = os.urandom(2)
    labels = b"".join(bytes([len(part)]) + part.encode() for part in "cloudflare.com".split(".")) + b"\x00"
    query = transaction_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as control:
        control.settimeout(timeout)
        control.sendall(b"\x05\x01\x00")
        if recv_exact(control, 2) != b"\x05\x00":
            return False
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        header = recv_exact(control, 4)
        if header[:2] != b"\x05\x00":
            return False
        atyp = header[3]
        if atyp == 1:
            relay_host = socket.inet_ntoa(recv_exact(control, 4))
        elif atyp == 3:
            relay_host = recv_exact(control, recv_exact(control, 1)[0]).decode()
        elif atyp == 4:
            relay_host = socket.inet_ntop(socket.AF_INET6, recv_exact(control, 16))
        else:
            return False
        relay_port = struct.unpack("!H", recv_exact(control, 2))[0]
        if relay_host in {"0.0.0.0", "::"}:
            relay_host = "127.0.0.1"
        packet = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53) + query
        family = socket.AF_INET6 if ":" in relay_host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(timeout)
            udp.sendto(packet, (relay_host, relay_port))
            response = udp.recv(4096)
    if len(response) < 10 or response[:3] != b"\x00\x00\x00":
        return False
    atyp, offset = response[3], 4
    if atyp == 1:
        offset += 4
    elif atyp == 3:
        offset += 1 + response[offset]
    elif atyp == 4:
        offset += 16
    else:
        return False
    dns = response[offset + 2:]
    return len(dns) >= 12 and dns[:2] == transaction_id and bool(dns[2] & 0x80)


def http_service_check(port, url, require_success, timeout=SERVICE_TEST_TIMEOUT):
    try:
        result = subprocess.run([
            CURL_BIN, "--silent", "--show-error", "--location", "--max-redirs", "3",
            "--output", os.devnull, "--write-out", "%{http_code}", "--max-time", str(timeout),
            "--proxy", f"socks5h://127.0.0.1:{port}", url,
        ], capture_output=True, text=True, timeout=timeout + 2, check=False)
        status = int(result.stdout.strip()) if result.returncode == 0 else 0
        if require_success:
            return 200 <= status < 400
        return 200 <= status < 500 and status != 451
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def advanced_probe(item):
    port = free_local_port()
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [xray_outbound(item)],
    }
    with tempfile.TemporaryDirectory(prefix="vless-advanced-") as directory:
        config_path = os.path.join(directory, "config.json")
        with open(config_path, "w", encoding="utf-8") as output:
            json.dump(config, output)
        process = subprocess.Popen([XRAY_BIN, "run", "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not wait_for_port(port, process):
                return {
                    "throughput_mbps": 0.0, "udp": False, "telegram_dc": False,
                    "services": {name: False for name, _, _ in SERVICE_TESTS},
                }
            result = subprocess.run([
                CURL_BIN, "--silent", "--show-error", "--output", os.devnull,
                "--write-out", "%{size_download} %{speed_download}",
                "--max-time", str(THROUGHPUT_TEST_TIMEOUT),
                "--proxy", f"socks5h://127.0.0.1:{port}", THROUGHPUT_TEST_URL,
            ], capture_output=True, text=True, timeout=THROUGHPUT_TEST_TIMEOUT + 2, check=False)
            size, speed = (float(value) for value in result.stdout.strip().split()) if result.returncode == 0 else (0.0, 0.0)
            throughput = speed * 8 / 1_000_000 if size >= THROUGHPUT_BYTES * 0.8 else 0.0
            with ThreadPoolExecutor(max_workers=len(SERVICE_TESTS) + 2) as checks:
                service_futures = {
                    name: checks.submit(http_service_check, port, url, require_success)
                    for name, url, require_success in SERVICE_TESTS
                }
                udp_future = checks.submit(socks5_udp_dns_check, port)
                telegram_dc_future = checks.submit(telegram_dc_check, port)
                services = {name: future.result() for name, future in service_futures.items()}
                try:
                    udp_ok = udp_future.result()
                except OSError:
                    udp_ok = False
                try:
                    telegram_dc_ok = telegram_dc_future.result()
                except OSError:
                    telegram_dc_ok = False
            return {
                "throughput_mbps": throughput, "udp": udp_ok,
                "telegram_dc": telegram_dc_ok, "services": services,
            }
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return {
                "throughput_mbps": 0.0, "udp": False, "telegram_dc": False,
                "services": {name: False for name, _, _ in SERVICE_TESTS},
            }
        finally:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)


def network_key(ip):
    try:
        address = ipaddress.ip_address(ip)
        return str(ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 48}", strict=False))
    except ValueError:
        return ip


def node_suffix(item):
    ip = item.get("resolved_ip") or item["address"]
    try:
        address = ipaddress.ip_address(ip)
        return ".".join(str(address).split(".")[-2:]) if address.version == 4 else address.compressed.rsplit(":", 1)[-1]
    except ValueError:
        return item["address"].split(".")[0][-10:]


def select_diverse(tested, limit):
    selected = []
    used_endpoints, used_networks, used_uuids, used_asns, used_countries = set(), set(), set(), set(), set()
    uuid_counts = {}

    def add_pass(unique_country):
        for latency, item, geo in tested:
            endpoint, subnet = (item["resolved_ip"], item["port"]), network_key(item["resolved_ip"])
            if endpoint in used_endpoints or subnet in used_networks or item["uuid"] in used_uuids:
                continue
            if geo["asn"] and geo["asn"] in used_asns:
                continue
            if unique_country and geo["code"] and geo["code"] in used_countries:
                continue
            selected.append((latency, item, geo))
            used_endpoints.add(endpoint); used_networks.add(subnet); used_uuids.add(item["uuid"])
            uuid_counts[item["uuid"]] = uuid_counts.get(item["uuid"], 0) + 1
            if geo["asn"]: used_asns.add(geo["asn"])
            if geo["code"]: used_countries.add(geo["code"])
            if len(selected) >= limit:
                return True
        return False

    if add_pass(True):
        return selected
    add_pass(False)
    for latency, item, geo in tested:
        endpoint, subnet = (item["resolved_ip"], item["port"]), network_key(item["resolved_ip"])
        if endpoint in used_endpoints or subnet in used_networks or uuid_counts.get(item["uuid"], 0) >= 2:
            continue
        selected.append((latency, item, geo))
        used_endpoints.add(endpoint); used_networks.add(subnet); used_uuids.add(item["uuid"])
        uuid_counts[item["uuid"]] = uuid_counts.get(item["uuid"], 0) + 1
        if len(selected) >= limit:
            break
    return selected


def take_unique(rows, limit):
    selected, identities = [], set()
    for row in rows:
        identity = history_key(row[1])
        if identity in identities:
            continue
        identities.add(identity)
        selected.append(row)
        if len(selected) >= limit:
            break
    return selected


def write_generation_status(
    success, selected_count, candidates, reality_ok, eligible, message="",
    stable=None, russia_reachable=None,
):
    now = datetime.now(timezone.utc)
    previous = load_json_file(STATUS_FILE, {})
    last_success = now.isoformat() if success else previous.get("last_success_at")
    stale_hours = None
    if last_success:
        try:
            stale_hours = max(0.0, (now - datetime.fromisoformat(last_success)).total_seconds() / 3600)
        except ValueError:
            stale_hours = None
    status = {
        "version": 1,
        "status": "healthy" if success else "degraded",
        "last_attempt_at": now.isoformat(),
        "last_success_at": last_success,
        "stale_hours": round(stale_hours, 2) if stale_hours is not None else None,
        "selected_count": selected_count,
        "candidate_count": candidates,
        "reality_passed_count": reality_ok,
        "quality_passed_count": eligible,
        "stability_passed_count": stable,
        "russia_reachable_count": russia_reachable,
        "minimum_required": MIN_SERVERS,
        "message": message,
    }
    save_json_file(STATUS_FILE, status)
    if not success or (stale_hours is not None and stale_hours >= STALE_WARNING_HOURS):
        warning = message or f"Subscription has not refreshed for {stale_hours:.1f} hours"
        print(f"::warning title=VPN subscription is stale::{warning}")


def main():
    if not shutil.which(XRAY_BIN):
        raise SystemExit(f"Xray binary not found: {XRAY_BIN}")
    if not shutil.which(CURL_BIN):
        raise SystemExit(f"curl binary not found: {CURL_BIN}")
    history = load_history()
    candidates = collect_candidates(configured_sources())
    reachable = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(tcp_latency_ms, item["address"], item["port"]): item for item in candidates}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception:
                continue
            if result is not None:
                latency, resolved_ip = result
                item = futures[future]; item["resolved_ip"] = resolved_ip
                reachable.append((latency, item))
    reachable.sort(key=lambda value: (value[0], len(value[1]["endpoint_sources"])))
    geo_by_ip = geolocate_ips(item["resolved_ip"] for _, item in reachable)
    located = []
    for tcp_latency, item in reachable:
        geo = geo_by_ip.get(item["resolved_ip"])
        if geo and geo.get("code") != "RU" and math.isfinite(distance_from_moscow_km(geo)):
            located.append((tcp_latency, item, geo))
    nearest = take_unique(sorted(located, key=moscow_rank_key), NEAREST_POOL_LIMIT)
    fastest = take_unique(
        sorted(located, key=lambda row: (row[0], len(row[1]["endpoint_sources"]))),
        FASTEST_POOL_LIMIT,
    )
    test_pool, pooled_keys = [], set()
    for row in nearest + fastest:
        key = history_key(row[1])
        if key not in pooled_keys:
            pooled_keys.add(key)
            test_pool.append(row)
        if len(test_pool) >= REALITY_TEST_LIMIT:
            break
    print(f"Reality pool: {len(nearest)} nearest to Moscow + {len(fastest)} fastest from runner = {len(test_pool)} unique")

    reality_ok, current_results, items_by_key = [], {}, {}
    with ThreadPoolExecutor(max_workers=REALITY_TEST_WORKERS) as pool:
        futures = {pool.submit(reality_latency_ms, item): (item, geo) for _, item, geo in test_pool}
        for future in as_completed(futures):
            item, geo = futures[future]
            key = history_key(item)
            items_by_key[key] = item
            try:
                real_latency = future.result()
            except Exception:
                real_latency = None
            success = real_latency is not None and real_latency <= MAX_REALITY_LATENCY_MS
            current_results[key] = {"success": success, "latency_ms": real_latency}
            if success:
                reality_ok.append((real_latency, item, geo))

    ranked = sorted(reality_ok, key=lambda row: quality_score(row, history))
    finalists = select_diverse(ranked, FINALIST_LIMIT)
    advanced = {}
    with ThreadPoolExecutor(max_workers=ADVANCED_TEST_WORKERS) as pool:
        futures = {pool.submit(advanced_probe, item): (latency, item, geo) for latency, item, geo in finalists}
        for future in as_completed(futures):
            row = futures[future]
            try:
                result = future.result()
            except Exception:
                result = {
                    "throughput_mbps": 0.0, "udp": False, "telegram_dc": False,
                    "services": {name: False for name, _, _ in SERVICE_TESTS},
                }
            key = history_key(row[1])
            advanced[key] = result
            current_results[key].update(result)

    eligible = []
    for row in finalists:
        result = advanced.get(history_key(row[1])) or {}
        services = result.get("services") or {}
        result["quality_ok"] = bool(
            result.get("udp")
            and result.get("telegram_dc")
            and all(services.get(name) for name, _, _ in SERVICE_TESTS)
            and float(result.get("throughput_mbps") or 0) >= MIN_THROUGHPUT_MBPS
        )
        if result["quality_ok"]:
            eligible.append(row)
    update_history(history, items_by_key, current_results)
    eligible.sort(key=lambda row: quality_score(row, history, advanced[history_key(row[1])]["throughput_mbps"]))
    stable = [row for row in eligible if strict_pass_count(row[1], history) >= STABILITY_MIN_STRICT_PASSES]
    russian_reachable = stable
    if RU_PROBE_ENABLED and stable:
        probe_results = {}
        with ThreadPoolExecutor(max_workers=RU_PROBE_WORKERS) as pool:
            futures = {pool.submit(russian_network_probe, row[1], history): row for row in stable}
            for future in as_completed(futures):
                row = futures[future]
                try:
                    probe_results[history_key(row[1])] = future.result()
                except Exception as exc:
                    probe_results[history_key(row[1])] = {
                        "checked_at": int(time.time()), "ok": False,
                        "success_count": 0, "probe_count": 0, "error": str(exc),
                    }
        for row in stable:
            key = history_key(row[1])
            history["servers"][key]["ru_probe"] = probe_results[key]
            probe = probe_results[key]
            print(
                f"RU probe {history['servers'][key]['endpoint']}: "
                f"{probe.get('success_count', 0)}/{probe.get('probe_count', 0)}"
                f"{' cached' if probe.get('cached') else ''}"
            )
        save_json_file(HISTORY_FILE, history)
        russian_reachable = [
            row for row in stable if probe_results[history_key(row[1])].get("ok")
        ]
    selected = russian_reachable[:LIMIT]
    if len(selected) < MIN_SERVERS:
        message = (
            f"Only {len(selected)} endpoints passed quality, stability and Russian-network checks; "
            f"keeping the current subscription below the safe minimum of {MIN_SERVERS}"
        )
        print(message)
        write_generation_status(
            False, len(selected), len(candidates), len(reality_ok), len(eligible), message,
            stable=len(stable), russia_reachable=len(russian_reachable),
        )
        return

    lines = [tested_routing_link(), "#routing-enable: 1", "#profile-update-interval: 1",
             "#subscription-auto-update-open-enable: 1", "#subscription-ping-onopen-enabled: 0",
             "#subscriptions-sort-type: without", "#profile-title: Fast VPN"]
    for latency, item, geo in selected:
        location = geo["country"] + (f" · {geo['city']}" if geo["city"] else "")
        distance = round(distance_from_moscow_km(geo))
        speed = advanced[history_key(item)]["throughput_mbps"]
        label = f"{geo['flag']} {location} · {distance} km · {speed:.1f} Mbps · {node_suffix(item)}"
        lines.append(f"{rendered_vless_uri(item)}#{quote(label, safe='')}")
        services = "+".join(name for name, ok in advanced[history_key(item)]["services"].items() if ok)
        print(
            f"{latency:7.1f} ms  {speed:6.2f} Mbps  UDP ok  {services} ok  "
            f"{label}  [{','.join(sorted(item['sources']))}]"
        )
    plain = "\n".join(lines) + "\n"
    with open("vless.txt", "w", encoding="utf-8") as output:
        output.write(plain)
    with open("vless_base64.txt", "w", encoding="utf-8") as output:
        output.write(base64.b64encode(plain.encode()).decode() + "\n")
    write_generation_status(
        True, len(selected), len(candidates), len(reality_ok), len(eligible),
        stable=len(stable), russia_reachable=len(russian_reachable),
    )
    print(
        f"Selected {len(selected)} diverse Reality servers from {len(candidates)} candidates; "
        f"{len(reality_ok)} passed latency, {len(eligible)} passed quality, "
        f"{len(stable)} passed stability and {len(russian_reachable)} were reachable from Russia"
    )


if __name__ == "__main__":
    main()
