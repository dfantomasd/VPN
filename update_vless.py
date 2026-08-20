#!/usr/bin/env python3
import base64
import hashlib
import html
import ipaddress
import json
import math
import os
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
MIN_SERVERS = int(os.getenv("VLESS_MIN_SERVERS", "10"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "1.8"))
PING_ATTEMPTS = int(os.getenv("PING_ATTEMPTS", "2"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "24"))
MAX_CANDIDATES_PER_SOURCE = int(os.getenv("MAX_CANDIDATES_PER_SOURCE", "300"))
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
THROUGHPUT_BYTES = int(os.getenv("THROUGHPUT_BYTES", "262144"))
THROUGHPUT_TEST_URL = os.getenv(
    "THROUGHPUT_TEST_URL", f"https://speed.cloudflare.com/__down?bytes={THROUGHPUT_BYTES}"
)
THROUGHPUT_TEST_TIMEOUT = float(os.getenv("THROUGHPUT_TEST_TIMEOUT", "10"))
MIN_THROUGHPUT_MBPS = float(os.getenv("MIN_THROUGHPUT_MBPS", "0.5"))
UDP_TEST_TIMEOUT = float(os.getenv("UDP_TEST_TIMEOUT", "4"))
HISTORY_FILE = os.getenv("VLESS_HISTORY_FILE", "server_history.json")
HISTORY_SAMPLES = int(os.getenv("VLESS_HISTORY_SAMPLES", "12"))
TELEGRAM_CIDR_URL = os.getenv(
    "TELEGRAM_CIDR_URL", "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/telegram.txt"
)
TELEGRAM_MIN_CIDRS = int(os.getenv("TELEGRAM_MIN_CIDRS", "8"))
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


def current_telegram_cidrs(fallback):
    try:
        networks = parse_cidr_lines(fetch_text(TELEGRAM_CIDR_URL, 12))
        if len(networks) < TELEGRAM_MIN_CIDRS:
            raise ValueError(f"only {len(networks)} valid networks")
        return networks
    except Exception as exc:
        print(f"Telegram CIDR refresh failed, using validated fallback: {exc}")
        return list(fallback)


def tested_routing_link(telegram_cidrs=None):
    profile = routing_profile()
    profile["ProxyIp"] = list(telegram_cidrs or current_telegram_cidrs(profile["ProxyIp"]))
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
    reliability_penalty = (1.0 - stats["success_rate"]) * 1500
    jitter_penalty = min(stats["jitter"], 1500) * 0.15
    shared_penalty = max(0, len(item.get("endpoint_sources") or ()) - 1) * 200
    latency_penalty = min(float(latency), MAX_REALITY_LATENCY_MS) * 0.15
    throughput_penalty = 1200 / math.sqrt(max(float(throughput), 0.1))
    return (
        distance_from_moscow_km(geo) + reliability_penalty + jitter_penalty
        + shared_penalty + latency_penalty + throughput_penalty
    )


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
                    if item["base"] in source_keys:
                        continue
                    if len(source_keys) >= MAX_CANDIDATES_PER_SOURCE:
                        break
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
                return {"throughput_mbps": 0.0, "udp": False}
            result = subprocess.run([
                CURL_BIN, "--silent", "--show-error", "--output", os.devnull,
                "--write-out", "%{size_download} %{speed_download}",
                "--max-time", str(THROUGHPUT_TEST_TIMEOUT),
                "--proxy", f"socks5h://127.0.0.1:{port}", THROUGHPUT_TEST_URL,
            ], capture_output=True, text=True, timeout=THROUGHPUT_TEST_TIMEOUT + 2, check=False)
            size, speed = (float(value) for value in result.stdout.strip().split()) if result.returncode == 0 else (0.0, 0.0)
            throughput = speed * 8 / 1_000_000 if size >= THROUGHPUT_BYTES * 0.8 else 0.0
            try:
                udp_ok = socks5_udp_dns_check(port)
            except OSError:
                udp_ok = False
            return {"throughput_mbps": throughput, "udp": udp_ok}
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return {"throughput_mbps": 0.0, "udp": False}
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
        if endpoint in used_endpoints or subnet in used_networks:
            continue
        selected.append((latency, item, geo))
        used_endpoints.add(endpoint); used_networks.add(subnet); used_uuids.add(item["uuid"])
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
                result = {"throughput_mbps": 0.0, "udp": False}
            key = history_key(row[1])
            advanced[key] = result
            current_results[key].update(result)

    update_history(history, items_by_key, current_results)
    eligible = []
    for row in finalists:
        result = advanced.get(history_key(row[1])) or {}
        if result.get("udp") and float(result.get("throughput_mbps") or 0) >= MIN_THROUGHPUT_MBPS:
            eligible.append(row)
    eligible.sort(key=lambda row: quality_score(row, history, advanced[history_key(row[1])]["throughput_mbps"]))
    selected = eligible[:LIMIT]
    if len(selected) < MIN_SERVERS:
        print(
            f"Only {len(selected)} diverse endpoints passed latency, throughput and UDP checks; "
            f"keeping the current subscription below the safe minimum of {MIN_SERVERS}"
        )
        return

    lines = [tested_routing_link(), "#routing-enable: 1", "#profile-update-interval: 2",
             "#subscription-auto-update-open-enable: 1", "#subscription-ping-onopen-enabled: 1",
             "#subscriptions-sort-type: ping", "#profile-title: Fast VPN"]
    for latency, item, geo in selected:
        location = geo["country"] + (f" · {geo['city']}" if geo["city"] else "")
        distance = round(distance_from_moscow_km(geo))
        label = f"{geo['flag']} {location} · {distance} km · {node_suffix(item)}"
        lines.append(f"{item['base']}#{quote(label, safe='')}")
        speed = advanced[history_key(item)]["throughput_mbps"]
        print(f"{latency:7.1f} ms  {speed:6.2f} Mbps  UDP ok  {label}  [{','.join(sorted(item['sources']))}]")
    plain = "\n".join(lines) + "\n"
    with open("vless.txt", "w", encoding="utf-8") as output:
        output.write(plain)
    with open("vless_base64.txt", "w", encoding="utf-8") as output:
        output.write(base64.b64encode(plain.encode()).decode() + "\n")
    print(
        f"Selected {len(selected)} diverse Reality servers from {len(candidates)} candidates; "
        f"{len(reality_ok)} passed latency and {len(eligible)} passed throughput+UDP"
    )


if __name__ == "__main__":
    main()
