#!/usr/bin/env python3
import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


OPENCCK_URL = "https://russia.iplist.opencck.org/?format=json"
REFILTER_DOMAINS_URL = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst"
REFILTER_IPS_URL = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst"
COMMUNITY_DOMAINS_URL = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/community.lst"
COMMUNITY_IPS_URL = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/community_ips.lst"
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")
INCLUDE_RE = re.compile(r"^include:([^\s@]+)")
MINIMUMS = {"russia-inside": 1000, "ru-blocked": 50000, "ru-geoblock": 100}
CIDR_MINIMUMS = {"russia-inside": 500, "ru-blocked": 10000, "ru-geoblock": 5}


def fetch_bytes(url, timeout=180):
    request = urllib.request.Request(url, headers={"User-Agent": "dfantomasd-vpn-routing-builder/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def clean_domains(lines):
    domains = set()
    for raw in lines:
        value = raw.split("#", 1)[0].strip().lower().rstrip(".")
        for prefix in ("domain:", "full:", "*."):
            if value.startswith(prefix):
                value = value[len(prefix):]
                break
        if "/" in value or "://" in value:
            continue
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            continue
        if DOMAIN_RE.fullmatch(value):
            domains.add(value)
    return sorted(domains)


def collapse_cidrs(values):
    v4, v6 = [], []
    for value in values:
        value = value.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        (v4 if network.version == 4 else v6).append(network)
    return [str(item) for item in ipaddress.collapse_addresses(v4)] + [
        str(item) for item in ipaddress.collapse_addresses(v6)
    ]


def opencck_entries(data):
    domains, cidrs = set(), set()
    for service in data.values():
        external = service.get("external") or {}
        domains.update(service.get("domains") or [])
        domains.update(external.get("domains") or [])
        for family, suffix in (("4", "/32"), ("6", "/128")):
            current = set(service.get(f"cidr{family}") or [])
            replacements = (service.get("replace") or {}).get(f"cidr{family}") or {}
            for broad, narrow in replacements.items():
                if broad in current:
                    current.remove(broad)
                    current.update(narrow)
            current.update(external.get(f"cidr{family}") or [])
            current.update(f"{value}{suffix}" for value in service.get(f"ip{family}") or [])
            current.update(f"{value}{suffix}" for value in external.get(f"ip{family}") or [])
            cidrs.update(current)
    return clean_domains(domains), collapse_cidrs(cidrs)


def write_lines(target, values):
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(values) + "\n", encoding="utf-8")


def copy_category(name, sources, destination, copied):
    if name in copied or (destination / name).exists():
        return
    source = next((folder / name for folder in sources if (folder / name).is_file()), None)
    if source is None:
        raise RuntimeError(f"GeoSite category is unavailable: {name}")
    text = source.read_text(encoding="utf-8")
    (destination / name).write_text(text, encoding="utf-8")
    copied.add(name)
    for line in text.splitlines():
        match = INCLUDE_RE.match(line.strip())
        if match:
            copy_category(match.group(1), sources, destination, copied)


def prepare(args):
    output = Path(args.outdir)
    geosite = output / "geosite"
    geoip = output / "geoip"
    if output.exists():
        shutil.rmtree(output)
    geosite.mkdir(parents=True)
    geoip.mkdir(parents=True)

    opencck = json.loads(fetch_bytes(OPENCCK_URL).decode("utf-8"))
    inside_domains, inside_cidrs = opencck_entries(opencck)
    blocked_domains = clean_domains(fetch_bytes(REFILTER_DOMAINS_URL).decode("utf-8-sig").splitlines())
    geoblock_domains = clean_domains(fetch_bytes(COMMUNITY_DOMAINS_URL).decode("utf-8-sig").splitlines())
    blocked_cidrs = collapse_cidrs(fetch_bytes(REFILTER_IPS_URL).decode("utf-8-sig").splitlines())
    geoblock_cidrs = collapse_cidrs(fetch_bytes(COMMUNITY_IPS_URL).decode("utf-8-sig").splitlines())

    categories = {
        "russia-inside": inside_domains,
        "ru-blocked": blocked_domains,
        "ru-geoblock": geoblock_domains,
    }
    for name, values in categories.items():
        if len(values) < MINIMUMS[name]:
            raise RuntimeError(f"{name} unexpectedly contains only {len(values)} domains")
        write_lines(geosite / name, values)
    write_lines(geoip / "russia-inside.txt", inside_cidrs)
    write_lines(geoip / "ru-blocked.txt", blocked_cidrs)
    write_lines(geoip / "ru-geoblock.txt", geoblock_cidrs)
    for name, values in {
        "russia-inside": inside_cidrs,
        "ru-blocked": blocked_cidrs,
        "ru-geoblock": geoblock_cidrs,
    }.items():
        if len(values) < CIDR_MINIMUMS[name]:
            raise RuntimeError(f"{name} unexpectedly contains only {len(values)} CIDRs")

    seeds = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    category_names = {
        rule.split(":", 1)[1]
        for field in ("DirectSites", "ProxySites", "BlockSites")
        for rule in seeds.get(field, [])
        if rule.startswith("geosite:")
    }
    category_names -= categories.keys()
    sources = [Path(args.roscom_data), Path(args.dlc_data)]
    copied = set()
    for name in sorted(category_names):
        copy_category(name, sources, geosite, copied)

    metadata = {
        "profile_sha256": hashlib.sha256(Path(args.profile).read_bytes()).hexdigest(),
        "opencck_services": len(opencck),
        "russia_inside_domains": len(inside_domains),
        "russia_inside_cidrs": len(inside_cidrs),
        "blocked_domains": len(blocked_domains),
        "blocked_cidrs": len(blocked_cidrs),
        "geoblock_domains": len(geoblock_domains),
        "geoblock_cidrs": len(geoblock_cidrs),
        "geosite_categories": len(list(geosite.iterdir())),
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2, sort_keys=True))


def needs_update(args):
    built = Path(args.built_dir)
    release = Path(args.release_dir)
    binaries_changed = any(
        not (release / name).is_file() or (built / name).read_bytes() != (release / name).read_bytes()
        for name in ("geosite.dat", "geoip.dat")
    )
    metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    try:
        status = json.loads(Path(args.status).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        status = {}
    profile_changed = metadata.get("profile_sha256") != status.get("profile_sha256")
    print(f"binaries_changed={str(binaries_changed).lower()} profile_changed={str(profile_changed).lower()}")
    return 0 if binaries_changed or profile_changed else 1


def finalize(args):
    built = Path(args.built_dir)
    release = Path(args.release_dir)
    geosite = built / "geosite.dat"
    geoip = built / "geoip.dat"
    if not geosite.is_file() or not geoip.is_file():
        raise RuntimeError("Compiled GeoSite/GeoIP files are missing")
    if not 100_000 <= geosite.stat().st_size <= 20_000_000:
        raise RuntimeError(f"Unexpected GeoSite size: {geosite.stat().st_size}")
    if not 10_000 <= geoip.stat().st_size <= 20_000_000:
        raise RuntimeError(f"Unexpected GeoIP size: {geoip.stat().st_size}")
    release.mkdir(parents=True, exist_ok=True)
    shutil.copy2(geosite, release / "geosite.dat")
    shutil.copy2(geoip, release / "geoip.dat")
    metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    version = args.version or datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
    metadata.update({
        "version": version,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "geosite_bytes": geosite.stat().st_size,
        "geoip_bytes": geoip.stat().st_size,
        "geosite_sha256": hashlib.sha256(geosite.read_bytes()).hexdigest(),
        "geoip_sha256": hashlib.sha256(geoip.read_bytes()).hexdigest(),
    })
    Path(args.status).write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("--dlc-data", required=True)
    prep.add_argument("--roscom-data", required=True)
    prep.add_argument("--profile", default="routing_profile.json")
    prep.add_argument("--outdir", required=True)
    prep.set_defaults(handler=prepare)
    final = commands.add_parser("finalize")
    final.add_argument("--built-dir", required=True)
    final.add_argument("--release-dir", default="routing-data")
    final.add_argument("--metadata", required=True)
    final.add_argument("--status", default="routing_data_status.json")
    final.add_argument("--version")
    final.set_defaults(handler=finalize)
    changed = commands.add_parser("needs-update")
    changed.add_argument("--built-dir", required=True)
    changed.add_argument("--release-dir", default="routing-data")
    changed.add_argument("--metadata", required=True)
    changed.add_argument("--status", default="routing_data_status.json")
    changed.set_defaults(handler=needs_update)
    args = parser.parse_args()
    return args.handler(args) or 0


if __name__ == "__main__":
    sys.exit(main())
