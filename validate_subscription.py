#!/usr/bin/env python3
import argparse
import base64
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

import update_vless


ROUTE_FIELDS = {
    "block": ("BlockSites", "BlockIp"),
    "proxy": ("ProxySites", "ProxyIp"),
    "direct": ("DirectSites", "DirectIp"),
}


def decode_routing_link(line):
    prefix = "happ://routing/onadd/"
    if not line.startswith(prefix):
        raise ValueError("subscription does not start with a Happ routing profile")
    payload = line[len(prefix):]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def xray_routing_rules(profile):
    order = str(profile.get("RouteOrder") or "block-proxy-direct").split("-")
    if sorted(order) != ["block", "direct", "proxy"]:
        raise ValueError(f"unsupported RouteOrder: {profile.get('RouteOrder')}")
    rules = []
    for tag in order:
        domain_field, ip_field = ROUTE_FIELDS[tag]
        domains, ips = profile.get(domain_field) or [], profile.get(ip_field) or []
        if domains:
            rules.append({"type": "field", "outboundTag": tag, "domain": domains})
        if ips:
            rules.append({"type": "field", "outboundTag": tag, "ip": ips})
    return rules


def validate_files(plain_path, base64_path, minimum):
    plain = Path(plain_path).read_bytes()
    encoded = b"".join(Path(base64_path).read_bytes().split())
    if base64.b64decode(encoded, validate=True) != plain:
        raise ValueError("vless_base64.txt does not decode to vless.txt")
    lines = plain.decode("utf-8").splitlines()
    routing_lines = [line for line in lines if line.startswith("happ://routing/")]
    if len(routing_lines) != 1 or lines[0] != routing_lines[0]:
        raise ValueError("subscription must contain one routing profile on its first line")
    profile = decode_routing_link(lines[0])
    nodes = [update_vless.parse_vless_uri(line) for line in lines if line.startswith("vless://")]
    if len(nodes) < minimum or any(node is None for node in nodes):
        raise ValueError(f"subscription contains only {len(nodes)} valid nodes; minimum is {minimum}")
    revision = str(profile.get("LastUpdated") or "")
    if not re.fullmatch(r"\d{9,11}", revision):
        raise ValueError("LastUpdated must be a Unix timestamp")
    for field in ("Geositeurl", "Geoipurl"):
        if not str(profile.get(field) or "").startswith("https://"):
            raise ValueError(f"{field} must use HTTPS")
    return profile, nodes


def validate_with_xray(profile, first_node, xray_bin, asset_dir):
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": 10888, "protocol": "socks",
            "settings": {"udp": True},
        }],
        "outbounds": [
            update_vless.xray_outbound(first_node),
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainStrategy": profile["DomainStrategy"],
            "rules": xray_routing_rules(profile),
        },
    }
    with tempfile.TemporaryDirectory(prefix="subscription-validation-") as directory:
        config_path = Path(directory) / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        environment = os.environ.copy()
        environment["XRAY_LOCATION_ASSET"] = str(Path(asset_dir).resolve())
        result = subprocess.run(
            [xray_bin, "run", "-test", "-format=json", "-c", str(config_path)],
            capture_output=True, text=True, env=environment, check=False,
        )
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plain", default="vless.txt")
    parser.add_argument("--base64", default="vless_base64.txt")
    parser.add_argument("--minimum", type=int, default=update_vless.MIN_SERVERS)
    parser.add_argument("--xray", default=update_vless.XRAY_BIN)
    parser.add_argument("--asset-dir", default="routing-data")
    args = parser.parse_args()
    profile, nodes = validate_files(args.plain, args.base64, args.minimum)
    validate_with_xray(profile, nodes[0], args.xray, args.asset_dir)
    print(f"Subscription OK: {len(nodes)} nodes, routing {profile['Name']}, revision {profile['LastUpdated']}")


if __name__ == "__main__":
    main()
