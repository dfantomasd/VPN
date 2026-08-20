import base64
import json
import unittest

import update_vless


SAMPLE = ("vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443"
          "?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision"
          "&sni=example.com&fp=chrome&pbk=public-key&sid=abcd#Example")


class ParserTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
