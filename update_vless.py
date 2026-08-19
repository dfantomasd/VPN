#!/usr/bin/env python3
import base64, json, os, urllib.request
from urllib.parse import quote

SOURCE_URL = "https://raw.githubusercontent.com/kenkaral45/happ-subscription/main/whitelist_configs_combined.json"
LIMIT = int(os.getenv("VLESS_LIMIT", "50"))


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "happ-subscription-builder/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def build_vless(outbound):
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

    query = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='-_~.')}" for k, v in params)
    name = quote(f"{address}:{port}", safe='')
    return f"vless://{uid}@{address}:{port}?{query}#{name}"


def main():
    data = fetch_json(SOURCE_URL)
    if isinstance(data, dict):
        data = [data]

    links, seen = [], set()
    for cfg in data:
        for outbound in (cfg.get("outbounds") or []):
            link = build_vless(outbound)
            if not link or link in seen:
                continue
            seen.add(link)
            links.append(link)
            if len(links) >= LIMIT:
                break
        if len(links) >= LIMIT:
            break

    if not links:
        raise SystemExit("No VLESS links found in source JSON")

    plain = "\n".join(links) + "\n"
    with open("vless.txt", "w", encoding="utf-8") as f:
        f.write(plain)
    encoded = base64.b64encode(plain.encode()).decode()
    with open("vless_base64.txt", "w", encoding="utf-8") as f:
        f.write(encoded + "\n")
    print(f"Generated {len(links)} unique VLESS links")


if __name__ == "__main__":
    main()
