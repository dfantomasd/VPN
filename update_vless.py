#!/usr/bin/env python3
import base64
import html
import ipaddress
import json
import math
import os
import shutil
import socket
import statistics
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
]
ROUTING_PROFILE_FILE = "routing_profile.json"
LIMIT = int(os.getenv("VLESS_LIMIT", "20"))
MIN_SERVERS = int(os.getenv("VLESS_MIN_SERVERS", "10"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "1.8"))
PING_ATTEMPTS = int(os.getenv("PING_ATTEMPTS", "2"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "24"))
REALITY_TEST_WORKERS = int(os.getenv("REALITY_TEST_WORKERS", "4"))
REALITY_TEST_LIMIT = int(os.getenv("REALITY_TEST_LIMIT", "100"))
REALITY_TEST_TIMEOUT = float(os.getenv("REALITY_TEST_TIMEOUT", "8"))
MAX_REALITY_LATENCY_MS = float(os.getenv("MAX_REALITY_LATENCY_MS", "3500"))
REALITY_TEST_URL = os.getenv("REALITY_TEST_URL", "https://www.gstatic.com/generate_204")
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
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; happ-subscription-builder/11.0)",
            "Accept": "application/json,text/plain,*/*",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8-sig", errors="replace")


def fetch_json(url, timeout=30):
    return json.loads(fetch_text(url, timeout))


def routing_profile():
    with open(ROUTING_PROFILE_FILE, "r", encoding="utf-8") as source:
        profile = json.load(source)
    required = {
        "DirectSites": {"domain:ru", "domain:xn--p1ai", "geosite:russia-inside", "geosite:category-ru"},
        "DirectIp": {"geoip:private", "geoip:direct", "geoip:russia-inside"},
        "ProxySites": {
            "domain:gemini.google.com", "domain:generativelanguage.googleapis.com",
            "domain:accounts.google.com", "domain:ai.google.dev",
            "geosite:telegram", "geosite:youtube", "geosite:google",
        },
    }
    if profile.get("Name") != "Dmitry RU Direct":
        raise SystemExit("Routing profile must keep the stable name 'Dmitry RU Direct'")
    if profile.get("GlobalProxy") != "true" or profile.get("DomainStrategy") != "IPIfNonMatch":
        raise SystemExit("Routing profile must proxy unmatched traffic and resolve IP rules")
    for field, expected in required.items():
        if not expected.issubset(set(profile.get(field) or [])):
            raise SystemExit(f"Routing profile is missing required {field} rules")
    if not profile.get("ProxyIp"):
        raise SystemExit("Routing profile must proxy Telegram IP ranges")
    return profile


def tested_routing_link():
    profile = routing_profile()
    # Change once per UTC day so Happ re-imports the profile and refreshes its
    # cached GeoSite/GeoIP files without downloading them every two hours.
    profile["LastUpdated"] = datetime.now(timezone.utc).strftime("%Y%m%d0000")
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


def canonical_item(address, port, uid, params):
    if not address or not port or not uid:
        return None
    network = (params.get("type") or params.get("network") or "tcp").lower()
    if params.get("security") != "reality" or not params.get("pbk"):
        return None
    if network not in {"tcp", "raw"}:
        return None
    normalized = {"encryption": params.get("encryption") or "none", "type": network, "security": "reality"}
    for key in ("flow", "sni", "fp", "pbk", "sid", "spx"):
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
                source_keys = set()
                for item in items:
                    source_keys.add(item["base"])
                    if item["base"] not in merged:
                        merged[item["base"]] = item
                    merged[item["base"]]["sources"].add(name)
                print(f"source {name}: {len(source_keys)} unique supported candidates")
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
        "settings": {"vnext": [{"address": item["address"], "port": item["port"], "users": [user]}]},
        "streamSettings": {
            "network": "raw" if item["network"] == "raw" else "tcp", "security": "reality",
            "realitySettings": {
                "show": False, "fingerprint": item["fingerprint"], "serverName": item["sni"],
                "publicKey": item["public_key"], "shortId": item["short_id"], "spiderX": item["spider_x"],
            },
        },
        "tag": "proxy",
    }


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
        if endpoint in used_endpoints or subnet in used_networks or item["uuid"] in used_uuids:
            continue
        selected.append((latency, item, geo))
        used_endpoints.add(endpoint); used_networks.add(subnet); used_uuids.add(item["uuid"])
        if len(selected) >= limit:
            break
    return selected


def main():
    if not shutil.which(XRAY_BIN):
        raise SystemExit(f"Xray binary not found: {XRAY_BIN}")
    if not shutil.which(CURL_BIN):
        raise SystemExit(f"curl binary not found: {CURL_BIN}")
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

    reality_ok = []
    with ThreadPoolExecutor(max_workers=REALITY_TEST_WORKERS) as pool:
        futures = {pool.submit(reality_latency_ms, item): item for _, item in reachable[:REALITY_TEST_LIMIT]}
        for future in as_completed(futures):
            try:
                real_latency = future.result()
            except Exception:
                continue
            if real_latency is not None:
                reality_ok.append((real_latency, futures[future]))
    reality_ok.sort(key=lambda value: (value[0], len(value[1]["endpoint_sources"])))

    enriched = []
    for latency, item in reality_ok:
        if latency > MAX_REALITY_LATENCY_MS:
            continue
        geo = geo_for_ip(item["resolved_ip"])
        if geo.get("code") and geo["code"] != "RU" and math.isfinite(distance_from_moscow_km(geo)):
            enriched.append((latency, item, geo))
    enriched.sort(key=moscow_rank_key)
    selected = select_diverse(enriched, LIMIT)
    if len(selected) < MIN_SERVERS:
        raise SystemExit(
            f"Only {len(selected)} diverse endpoints passed the real proxy check; "
            f"refusing to replace the subscription below the safe minimum of {MIN_SERVERS}"
        )
    selected.sort(key=moscow_rank_key)

    lines = [tested_routing_link(), "#routing-enable: 1", "#profile-update-interval: 2",
             "#subscription-auto-update-open-enable: 1", "#subscription-ping-onopen-enabled: 1",
             "#subscriptions-sort-type: ping", "#profile-title: Fast VPN"]
    for latency, item, geo in selected:
        location = geo["country"] + (f" · {geo['city']}" if geo["city"] else "")
        distance = round(distance_from_moscow_km(geo))
        label = f"{geo['flag']} {location} · {distance} km · {node_suffix(item)}"
        lines.append(f"{item['base']}#{quote(label, safe='')}")
        print(f"{latency:7.1f} ms real  {label}  {item['address']}:{item['port']}  [{','.join(sorted(item['sources']))}]")
    plain = "\n".join(lines) + "\n"
    with open("vless.txt", "w", encoding="utf-8") as output:
        output.write(plain)
    with open("vless_base64.txt", "w", encoding="utf-8") as output:
        output.write(base64.b64encode(plain.encode()).decode() + "\n")
    print(f"Selected {len(selected)} diverse Reality servers from {len(candidates)} candidates; {len(reality_ok)} passed the real proxy check")


if __name__ == "__main__":
    main()
