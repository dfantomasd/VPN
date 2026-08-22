import base64
import json
import os
import re
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

import update_vless
import build_routing_data
import validate_subscription


SAMPLE = ("vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443"
          "?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision"
          "&sni=example.com&fp=chrome&pbk=public-key&sid=abcd#Example")


class ParserTests(unittest.TestCase):
    def test_published_subscription_enables_device_health_sorting(self):
        with open("vless.txt", encoding="utf-8") as source:
            payload = source.read()
        self.assertIn("#subscription-ping-onopen-enabled: 1", payload)
        self.assertIn("#subscriptions-sort-type: ping", payload)

    def test_plain_vless(self):
        items = update_vless.parse_source("# comment\n" + SAMPLE + "\n")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["address"], "203.0.113.10")
        self.assertEqual(items[0]["short_id"], "abcd")

    def test_base64_subscription(self):
        items = update_vless.parse_source(base64.b64encode((SAMPLE + "\n").encode()).decode())
        self.assertEqual(len(items), 1)

    def test_rejects_non_reality_and_unsupported_transport(self):
        self.assertIsNone(update_vless.parse_vless_uri("vless://id@203.0.113.1:443?type=tcp&security=tls&pbk=x"))
        self.assertIsNone(update_vless.parse_vless_uri("vless://id@203.0.113.1:443?type=ws&security=reality&pbk=x"))

    def test_json_outbound(self):
        config = {"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "203.0.113.20", "port": 443, "users": [{"id": "22222222-2222-2222-2222-222222222222", "encryption": "none", "flow": "xtls-rprx-vision"}]}]}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "example.com", "fingerprint": "firefox", "publicKey": "key", "shortId": "1234"}}}]}
        items = update_vless.parse_source(json.dumps([config]))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["uuid"], "22222222-2222-2222-2222-222222222222")

    def test_diversity_prefers_distinct_uuid_and_subnet(self):
        def row(ip, uid, asn, country, latency):
            item = update_vless.parse_vless_uri(f"vless://{uid}@{ip}:443?type=tcp&security=reality&pbk=key&sni=x")
            item["resolved_ip"] = ip
            return latency, item, {"asn": asn, "code": country, "country": country, "city": "", "flag": ""}
        rows = [row("203.0.113.1", "u1", "1", "DE", 10), row("203.0.113.2", "u2", "2", "NL", 11), row("198.51.100.1", "u3", "3", "NL", 12)]
        selected = update_vless.select_diverse(rows, 2)
        self.assertEqual([item["resolved_ip"] for _, item, _ in selected], ["203.0.113.1", "198.51.100.1"])

    def test_moscow_ranking_prefers_nearby_location(self):
        def row(city, latitude, longitude, latency):
            item = {"endpoint_sources": {"source"}}
            geo = {"city": city, "latitude": latitude, "longitude": longitude}
            return latency, item, geo
        helsinki = row("Helsinki", 60.1699, 24.9384, 300)
        los_angeles = row("Los Angeles", 34.0522, -118.2437, 50)
        self.assertLess(update_vless.moscow_rank_key(helsinki), update_vless.moscow_rank_key(los_angeles))
        self.assertLess(update_vless.distance_from_moscow_km(helsinki[2]), 1000)
        self.assertGreater(update_vless.distance_from_moscow_km(los_angeles[2]), 9000)

    def test_diversity_caps_uuid_reuse(self):
        def row(ip, uid, latency):
            item = update_vless.parse_vless_uri(f"vless://{uid}@{ip}:443?type=tcp&security=reality&pbk=key&sni=x")
            item["resolved_ip"] = ip
            return latency, item, {"asn": "", "code": "", "country": "", "city": "", "flag": ""}
        rows = [
            row("203.0.113.1", "shared", 10), row("198.51.100.1", "shared", 11),
            row("192.0.2.1", "unique", 12), row("198.18.0.1", "shared", 13),
        ]
        selected = update_vless.select_diverse(rows, 4)
        self.assertEqual([item["uuid"] for _, item, _ in selected], ["shared", "unique", "shared"])

    def test_rendered_uri_uses_tested_ip_to_avoid_client_dns(self):
        item = update_vless.parse_vless_uri(SAMPLE.replace("203.0.113.10", "edge.example.com"))
        item["resolved_ip"] = "203.0.113.20"
        rendered = update_vless.rendered_vless_uri(item)
        self.assertIn("@203.0.113.20:443?", rendered)
        self.assertIn("sni=example.com", rendered)

    def test_published_uri_contains_the_fingerprint_used_by_xray(self):
        item = update_vless.parse_vless_uri(SAMPLE.replace("&fp=chrome", ""))
        self.assertEqual(item["fingerprint"], "chrome")
        self.assertIn("fp=chrome", update_vless.rendered_vless_uri(item))

    def test_xray_uses_the_same_resolved_ip_that_is_published(self):
        item = update_vless.parse_vless_uri(SAMPLE.replace("203.0.113.10", "edge.example.com"))
        item["resolved_ip"] = "203.0.113.20"
        outbound = update_vless.xray_outbound(item)
        self.assertEqual(outbound["settings"]["vnext"][0]["address"], "203.0.113.20")

    def test_validator_rejects_a_published_uri_without_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            plain = os.path.join(directory, "vless.txt")
            encoded = os.path.join(directory, "vless_base64.txt")
            route = update_vless.tested_routing_link()
            broken = SAMPLE.replace("&fp=chrome", "")
            payload = f"{route}\n{broken}\n"
            with open(plain, "w", encoding="utf-8") as output:
                output.write(payload)
            with open(encoded, "w", encoding="utf-8") as output:
                output.write(base64.b64encode(payload.encode()).decode())
            with self.assertRaisesRegex(ValueError, "missing fp"):
                validate_subscription.validate_files(plain, encoded, 1)

    def test_routing_profile_covers_ru_and_telegram(self):
        profile = update_vless.routing_profile()
        self.assertEqual(profile["Name"], "SIMUTIN")
        self.assertEqual(profile["GlobalProxy"], "false")
        self.assertEqual(profile["RouteOrder"], "block-direct-proxy")
        self.assertIn("domain:ru", profile["DirectSites"])
        self.assertIn("domain:su", profile["DirectSites"])
        self.assertIn("domain:moscow", profile["DirectSites"])
        self.assertIn("geosite:russia-inside", profile["DirectSites"])
        for rule in (
            "geosite:category-bank-ru",
            "geosite:sber",
            "geosite:tbank-ru",
            "domain:sberbank.com",
            "domain:t-bank-app.ru",
            "domain:tbank-online.com",
            "domain:tinkoff-group.com",
        ):
            self.assertIn(rule, profile["DirectSites"])
        self.assertIn("geoip:russia-inside", profile["DirectIp"])
        self.assertIn("geoip:ru", profile["DirectIp"])
        self.assertIn("geoip:by", profile["DirectIp"])
        self.assertIn("geosite:telegram", profile["ProxySites"])
        self.assertIn("domain:t.me", profile["ProxySites"])
        self.assertIn("domain:telegram.org", profile["ProxySites"])
        self.assertIn("geosite:ru-blocked", profile["ProxySites"])
        self.assertIn("geosite:ru-geoblock", profile["ProxySites"])
        self.assertNotIn("geoip:ru-blocked", profile["ProxyIp"])
        self.assertNotIn("geoip:ru-geoblock", profile["ProxyIp"])
        self.assertIn("149.154.160.0/20", profile["ProxyIp"])
        self.assertIn("domain:gemini.google.com", profile["ProxySites"])
        self.assertIn("domain:generativelanguage.googleapis.com", profile["ProxySites"])
        self.assertIn("domain:accounts.google.com", profile["ProxySites"])
        self.assertIn("domain:ai.google.dev", profile["ProxySites"])
        link = update_vless.tested_routing_link(profile["ProxyIp"])
        self.assertTrue(link.startswith("happ://routing/onadd/"))
        payload = link.split("/onadd/", 1)[1]
        imported = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        self.assertEqual(imported["Name"], "SIMUTIN")
        self.assertRegex(imported["LastUpdated"], re.compile(r"^\d{9,11}$"))
        self.assertGreater(int(imported["LastUpdated"]), 1_500_000_000)
        self.assertLess(int(imported["LastUpdated"]), 4_000_000_000)
        self.assertEqual(imported["GlobalProxy"], "false")
        self.assertIn("149.154.160.0/20", imported["ProxyIp"])
        self.assertTrue(imported["Geositeurl"].endswith("?v=" + imported["LastUpdated"]))
        self.assertIn("cdn.jsdelivr.net", imported["Geositeurl"])
        self.assertEqual(imported["DomesticDNSType"], "DoU")
        self.assertEqual(link, update_vless.tested_routing_link(profile["ProxyIp"]))

    def test_legacy_routing_revision_is_converted_to_unix_time(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "status.json")
            with open(path, "w", encoding="utf-8") as output:
                json.dump({"version": "202608220416"}, output)
            with mock.patch.object(update_vless, "ROUTING_STATUS_FILE", path):
                revision = update_vless.routing_revision()
        expected = int(datetime(2026, 8, 22, 4, 16, tzinfo=timezone.utc).timestamp())
        self.assertEqual(int(revision), expected)

    def test_telegram_dc_requires_multiple_reachable_endpoints(self):
        with mock.patch.object(update_vless, "TELEGRAM_DC_ENDPOINTS", (("one", 443), ("two", 443), ("three", 443))):
            with mock.patch.object(update_vless, "TELEGRAM_DC_MIN_SUCCESS", 2):
                with mock.patch.object(update_vless, "socks5_tcp_connect_check", side_effect=[True, False, True]):
                    self.assertTrue(update_vless.telegram_dc_check(1080))
                with mock.patch.object(update_vless, "socks5_tcp_connect_check", side_effect=[True, False, False]):
                    self.assertFalse(update_vless.telegram_dc_check(1080))

    def test_xray_rules_preserve_happ_route_order(self):
        profile = {
            "RouteOrder": "block-direct-proxy",
            "BlockSites": ["domain:ads.example"], "BlockIp": [],
            "ProxySites": ["geosite:telegram"], "ProxyIp": ["149.154.160.0/20"],
            "DirectSites": ["domain:ru"], "DirectIp": ["geoip:ru"],
        }
        rules = validate_subscription.xray_routing_rules(profile)
        self.assertEqual([rule["outboundTag"] for rule in rules], ["block", "direct", "direct", "proxy", "proxy"])

    def test_stability_requires_repeated_strict_passes(self):
        item = update_vless.parse_vless_uri(SAMPLE)
        item["resolved_ip"] = "203.0.113.10"
        strict = {
            "success": True, "quality_ok": True, "telegram_dc": True,
            "udp": True, "throughput_mbps": 8,
            "services": {"telegram": True, "gemini": True},
        }
        history = {"servers": {update_vless.history_key(item): {"samples": [strict, strict]}}}
        self.assertEqual(update_vless.strict_pass_count(item, history), 2)

    def test_fresh_strict_pass_is_currently_eligible_before_stable(self):
        item = update_vless.parse_vless_uri(SAMPLE)
        item["resolved_ip"] = "203.0.113.10"
        current = {
            "success": True, "quality_ok": True, "telegram_dc": True,
            "udp": True, "throughput_mbps": 8,
            "services": {"telegram": True, "gemini": True},
        }
        history = {"servers": {update_vless.history_key(item): {"samples": [current]}}}
        self.assertEqual(update_vless.strict_pass_count(item, history), 1)
        self.assertLess(update_vless.strict_pass_count(item, history), update_vless.STABILITY_MIN_STRICT_PASSES)

    def test_russian_probe_cache_is_shared_by_endpoint(self):
        first = update_vless.parse_vless_uri(SAMPLE)
        second = update_vless.parse_vless_uri(SAMPLE.replace("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"))
        for item in (first, second):
            item["resolved_ip"] = "203.0.113.10"
        history = {"servers": {update_vless.history_key(first): {
            "endpoint": "203.0.113.10:443",
            "ru_probe": {"checked_at": 1000, "ok": True, "success_count": 2, "probe_count": 2},
        }}}
        cached = update_vless.cached_ru_probe(second, history, now=1001)
        self.assertTrue(cached["ok"])
        self.assertTrue(cached["cached"])

    def test_routing_list_cleanup(self):
        domains = build_routing_data.clean_domains([
            "# ignored", "*.Example.COM", "domain:api.example.com", "https://bad.example/path", "пример.рф"
        ])
        self.assertEqual(domains, ["api.example.com", "example.com", "xn--e1afmkfd.xn--p1ai"])
        cidrs = build_routing_data.collapse_cidrs(["192.0.2.1/32", "192.0.2.0/31", "invalid"])
        self.assertEqual(cidrs, ["192.0.2.0/31"])

    def test_protected_domains_detect_proxy_conflicts(self):
        conflicts = build_routing_data.find_domain_overlaps(
            {"sberbank.com", "tbank.ru"},
            {"api.sberbank.com", "tbank.ru", "unrelated.example"},
        )
        self.assertEqual(conflicts, [
            ("sberbank.com", "api.sberbank.com"),
            ("tbank.ru", "tbank.ru"),
        ])

    def test_telegram_cidr_parser_rejects_noise(self):
        parsed = update_vless.parse_cidr_lines("91.108.4.0/22\ninvalid\n2001:b28:f23c::/47 # telegram\n")
        self.assertEqual(parsed, ["91.108.4.0/22", "2001:b28:f23c::/47"])

    def test_quality_score_penalizes_shared_and_unreliable_nodes(self):
        def item(ip, uid, sources):
            value = update_vless.parse_vless_uri(f"vless://{uid}@{ip}:443?type=tcp&security=reality&pbk=key&sni=x")
            value["resolved_ip"] = ip
            value["endpoint_sources"] = set(sources)
            return value
        geo = {"latitude": 59.93, "longitude": 30.31}
        stable = item("203.0.113.1", "stable", {"one"})
        shared = item("198.51.100.1", "shared", {"one", "two", "three"})
        history = {"servers": {
            update_vless.history_key(stable): {"samples": [{"success": True, "latency_ms": 300, "throughput_mbps": 10}]},
            update_vless.history_key(shared): {"samples": [{"success": False, "latency_ms": None}]},
        }}
        self.assertLess(
            update_vless.quality_score((300, stable, geo), history, 10),
            update_vless.quality_score((300, shared, geo), history, 10),
        )

    def test_source_sample_rotates_across_the_whole_feed(self):
        items = [{"base": f"node-{index}"} for index in range(20)]
        first = update_vless.rotating_source_sample("feed", items, 5, bucket=1)
        second = update_vless.rotating_source_sample("feed", items, 5, bucket=2)
        self.assertEqual(len(first), 5)
        self.assertEqual(len({item["base"] for item in first}), 5)
        self.assertNotEqual([item["base"] for item in first], [item["base"] for item in second])
        self.assertGreater(len({item["base"] for item in first + second}), 5)

    @mock.patch("update_vless.subprocess.run")
    def test_service_checks_distinguish_reachable_from_success(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, stdout="404", stderr="")
        self.assertTrue(update_vless.http_service_check(1080, "https://api.telegram.org", False))
        self.assertFalse(update_vless.http_service_check(1080, "https://gemini.google.com", True))
        run.return_value = subprocess.CompletedProcess([], 0, stdout="200", stderr="")
        self.assertTrue(update_vless.http_service_check(1080, "https://gemini.google.com", True))

    def test_generation_status_preserves_last_success_when_degraded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "status.json")
            with mock.patch.object(update_vless, "STATUS_FILE", path):
                update_vless.write_generation_status(True, 20, 500, 30, 20)
                with open(path, encoding="utf-8") as source:
                    healthy = json.load(source)
                with mock.patch("builtins.print"):
                    update_vless.write_generation_status(False, 4, 100, 7, 4, "too few")
                with open(path, encoding="utf-8") as source:
                    degraded = json.load(source)
            self.assertEqual(degraded["status"], "degraded")
            self.assertEqual(degraded["last_success_at"], healthy["last_success_at"])
            self.assertEqual(degraded["selected_count"], 4)


if __name__ == "__main__":
    unittest.main()
