#!/usr/bin/env python3
import base64
from pathlib import Path

import update_vless


def refresh(plain_path="vless.txt", base64_path="vless_base64.txt"):
    target = Path(plain_path)
    lines = target.read_text(encoding="utf-8").splitlines()
    indexes = [index for index, line in enumerate(lines) if line.startswith("happ://routing/onadd/")]
    if indexes != [0]:
        raise RuntimeError("Subscription must contain exactly one routing header on the first line")
    lines[0] = update_vless.tested_routing_link()
    plain = "\n".join(lines) + "\n"
    target.write_text(plain, encoding="utf-8")
    Path(base64_path).write_text(base64.b64encode(plain.encode()).decode() + "\n", encoding="utf-8")


if __name__ == "__main__":
    refresh()
