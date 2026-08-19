#!/usr/bin/env python3
import base64, json, os, socket, statistics, time, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

SOURCE_URL = "https://raw.githubusercontent.com/kenkaral45/happ-subscription/main/whitelist_configs_combined.json"
LIMIT = int(os.getenv("VLESS_LIMIT", "10"))
PING_TIMEOUT = float(os.getenv("PING_TIMEOUT", "1.8"))
PING_ATTEMPTS = int(os.getenv("PING_ATTEMPTS", "2"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "24"))

ROUTING_PROFILE = {
  "Name": "Dmitry RU Direct",
  "GlobalProxy": "true",
  "UseChunkFiles": "true",
  "RemoteDns": "8.8.8.8",
  "DomesticDns": "77.88.8.8",
  "RemoteDNSType": "DoH",
  "RemoteDNSDomain": "https://8.8.8.8/dns-query",
  "RemoteDNSIP": "8.8.8.8",
  "DomesticDNSType": "DoH",
  "DomesticDNSDomain": "https://77.88.8.8/dns-query",
  "DomesticDNSIP": "77.88.8.8",
  "Geositeurl": "https://cdn.jsdelivr.net/gh/b-n-m-n/happ-routing@main/release/geosite.dat",
  "Geoipurl": "https://cdn.jsdelivr.net/gh/b-n-m-n/happ-routing@main/release/geoip.dat",
  "LastUpdated": "",
  "DnsHosts": {"lkfl2.nalog.ru": "213.24.64.175", "lknpd.nalog.ru": "213.24.64.181"},
  "RouteOrder": "block-proxy-direct",
  "DirectSites": ["geosite:private","geosite:russia-inside","geosite:category-ru","geosite:whitelist","geosite:microsoft","geosite:apple","geosite:epicgames","geosite:riot","geosite:escapefromtarkov","geosite:steam","geosite:twitch","geosite:pinterest","geosite:faceit"],
  "DirectIp": ["geoip:private","geoip:direct","geoip:russia-inside"],
  "ProxySites": ["geosite:google-play","geosite:github","geosite:twitch-ads","geosite:youtube","geosite:telegram"],
  "ProxyIp": [], "BlockSites": [], "BlockIp": [],
  "DomainStrategy": "IPIfNonMatch", "FakeDNS": "false"
}

def fetch_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "happ-subscription-builder/4.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r: return json.load(r)

def country_flag(code):
    code=(code or "").upper()
    return "".join(chr(127397+ord(ch)) for ch in code) if len(code)==2 and code.isalpha() else "🌐"

def geo_for_ip(ip):
    try:
        d=fetch_json(f"https://ipwho.is/{ip}",8); code=(d.get("country_code") or "").upper()
        return {"country":d.get("country") or "Unknown","city":d.get("city") or "","flag":country_flag(code)}
    except Exception: return {"country":"Unknown","city":"","flag":"🌐"}

def parse_vless(o):
    if o.get("protocol")!="vless": return None
    v=(o.get("settings") or {}).get("vnext") or []
    if not v or not (v[0].get("users") or []): return None
    s=v[0]; u=s["users"][0]; a=s.get("address"); p=s.get("port"); uid=u.get("id")
    if not all([a,p,uid]): return None
    st=o.get("streamSettings") or {}; r=st.get("realitySettings") or {}
    params=[("encryption",u.get("encryption") or "none"),("type",st.get("network") or "tcp"),("security",st.get("security") or "none")]
    for k,val in [("flow",u.get("flow")),("sni",r.get("serverName")),("fp",r.get("fingerprint")),("pbk",r.get("publicKey")),("sid",r.get("shortId"))]:
        if val is not None and val!="": params.append((k,val))
    q="&".join(f"{quote(str(k))}={quote(str(v),safe='-_~.')}" for k,v in params)
    return {"address":a,"port":int(p),"base":f"vless://{uid}@{a}:{p}?{q}"}

def tcp_latency_ms(a,p):
    x=[]
    for _ in range(PING_ATTEMPTS):
        t=time.perf_counter()
        try:
            with socket.create_connection((a,p),timeout=PING_TIMEOUT): x.append((time.perf_counter()-t)*1000)
        except OSError: pass
    return statistics.median(x) if x else None

def routing_link():
    raw=json.dumps(ROUTING_PROFILE,ensure_ascii=False,separators=(",",":")).encode()
    return "happ://routing/onadd/"+base64.b64encode(raw).decode()

def main():
    data=fetch_json(SOURCE_URL); data=[data] if isinstance(data,dict) else data
    candidates=[]; seen=set()
    for cfg in data:
        for o in (cfg.get("outbounds") or []):
            item=parse_vless(o)
            if item and (item["address"],item["port"],item["base"]) not in seen:
                seen.add((item["address"],item["port"],item["base"])); candidates.append(item)
    tested=[]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        fs={pool.submit(tcp_latency_ms,i["address"],i["port"]):i for i in candidates}
        for f in as_completed(fs):
            lat=f.result()
            if lat is not None: tested.append((lat,fs[f]))
    tested.sort(key=lambda x:x[0]); selected=tested[:LIMIT]
    if not selected: raise SystemExit("No reachable VLESS endpoints found")
    lines=[
        routing_link(),
        "#profile-update-interval: 1",
        "#subscription-auto-update-open-enable: 1",
        "#subscription-ping-onopen-enabled: 1",
        "#subscriptions-sort-type: ping",
        "#profile-title: Fast VPN",
    ]
    for lat,item in selected:
        g=geo_for_ip(item["address"])
        loc=g["country"]+(f" · {g['city']}" if g["city"] else "")
        label=f"{g['flag']} {loc}"
        lines.append(f"{item['base']}#{quote(label,safe='')}")
    plain="\n".join(lines)+"\n"
    open("vless.txt","w",encoding="utf-8").write(plain)
    open("vless_base64.txt","w",encoding="utf-8").write(base64.b64encode(plain.encode()).decode()+"\n")
    print(f"Selected {len(selected)} servers; Happ will ping and sort them on device")
if __name__=="__main__": main()
