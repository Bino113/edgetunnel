#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
全协议链式代理质量与信誉检测工具 (check_all_chain_proxies.py)
支持 HTTP / HTTPS / SOCKS5 全协议代理并发测活、出口IP探测、IPPure风险评分、
住宅/广播/机房属性识别与严格纯净度分级筛选。
"""

import sys
import os
import time
import json
import socket
import argparse
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List
from concurrent.futures import ThreadPoolExecutor

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CACHE_VERSION = 2

# 已知机房/云服务商
KNOWN_DATACENTERS = [
    ("Amazon AWS", ["amazon", "aws", "amazonaws"]),
    ("Google Cloud", ["google", "gcp", "google cloud"]),
    ("Microsoft Azure", ["microsoft", "azure", "msft"]),
    ("OVHcloud", ["ovh", "ovh sas", "kimsufi", "soyoustart"]),
    ("Hetzner", ["hetzner"]),
    ("DigitalOcean", ["digitalocean"]),
    ("Vultr / Choopa", ["vultr", "choopa", "the constant company"]),
    ("Oracle Cloud", ["oracle", "oracle cloud"]),
    ("Tencent Cloud", ["tencent", "tencent cloud", "shenzhen tencent"]),
    ("Alibaba Cloud", ["alibaba", "aliyun", "alicloud"]),
    ("UCLOUD", ["ucloud"]),
    ("Linode / Akamai", ["linode", "akamai"]),
    ("Cloudflare", ["cloudflare"]),
    ("Leaseweb", ["leaseweb"]),
    ("Contabo", ["contabo"]),
    ("Datacamp / CDN77", ["datacamp", "cdn77"]),
    ("Performive", ["performive"]),
    ("Total Server Solutions", ["total server solutions"]),
    ("Fastly", ["fastly"]),
    ("M247", ["m247"]),
    ("HostPapa / RackNerd", ["racknerd", "hostpapa"]),
    ("Zenlayer", ["zenlayer"]),
    ("ServerTech / VEESP", ["servers tech fzco", "veesp"]),
    ("NSFOCUS", ["nsfocus"]),
    ("NetLab Global", ["netlab", "netlab global"]),
    ("dataforest", ["dataforest"]),
    ("Snowd Security", ["snowd"]),
    ("Bunny Communications", ["bunny communications"]),
    ("TOTHOST", ["tothost"]),
    ("XIFTCS", ["xiftcs"]),
    ("CGI Global", ["cgi global"]),
    ("3HCLOUD", ["3hcloud"]),
    ("F5 Networks", ["f5 networks"]),
    ("G-Core Labs", ["g-core", "gcore"]),
    ("ServerHub", ["serverhub"]),
    ("Kamatera", ["kamatera"]),
    ("Scaleway", ["scaleway"]),
]

# 常见家庭宽带 / 原生 ISP 特征库
KNOWN_RESIDENTIAL_ISPS = [
    "comcast", "at&t", "att", "verizon", "charter", "spectrum", "cox",
    "centurylink", "frontier", "windstream", "optimum", "suddenlink", "mediacom",
    "china telecom", "chinatelecom", "chinanet", "china unicom", "chinaunicom",
    "china mobile", "chinamobile", "cmcc",
    "vnpt", "viettel", "fpt telecom",
    "tot", "ais", "true internet", "triple t",
    "ntt", "kddi", "softbank", "so-net", "biglobe", "ocn",
    "kt", "sk broadband", "lg u+", "korea telecom",
    "chunghwa", "taiwan mobile", "far eastone",
    "bt", "british telecommunications", "virgin media", "sky broadband", "talktalk",
    "deutsche telekom", "vodafone", "telefónica", "orange", "free sas", "tim brasil",
    "telstra", "optus", "tpg",
    "bell canada", "rogers", "telus", "shaw communications",
    "singtel", "starhub", "m1 limited", "tm technology", "telekom malaysia",
    "ufinet colombia", "claro", "tigo", "telefonica de espana"
]

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# IPPure 限制最大并发，避免 WAF 403 拦截
ippure_semaphore = threading.Semaphore(8)

# AbuseIPDB 限速锁
abuse_api_lock = threading.Lock()
last_abuse_req_time = 0.0

def parse_proxy(raw: str, default_protocol: str = "http") -> Tuple[str, str, str, int, str]:
    """
    解析代理地址字符串
    返回: (protocol, requests用的proxy_url, host, port, clean_addr)
    """
    clean = raw.strip()
    protocol = default_protocol.lower()
    
    for proto in ["socks5h://", "socks5://", "https://", "http://"]:
        if clean.startswith(proto):
            protocol = proto.replace("://", "").replace("socks5h", "socks5")
            clean = clean[len(proto):]
            break
            
    if "#" in clean:
        clean = clean.split("#", 1)[0].strip()
    if "/" in clean:
        clean = clean.split("/", 1)[0].strip()
        
    if ":" not in clean:
        raise ValueError(f"无效的代理格式: {raw}")
        
    host, port_str = clean.rsplit(":", 1)
    port = int(port_str)
    
    if protocol == "socks5":
        req_proxy_url = f"socks5h://{host}:{port}"
    elif protocol == "https":
        req_proxy_url = f"https://{host}:{port}"
    else:
        protocol = "http"
        req_proxy_url = f"http://{host}:{port}"
        
    return protocol, req_proxy_url, host, port, f"{host}:{port}"

def detect_datacenter(isp: str, org: str, as_name: str, hosting_flag: Optional[bool] = None) -> Tuple[Any, str]:
    text = f"{isp} {org} {as_name}".lower()
    for dc_name, keywords in KNOWN_DATACENTERS:
        for kw in keywords:
            if kw in text:
                return True, dc_name
                
    if hosting_flag is True:
        return True, "Hosting Provider"
        
    for res_isp in KNOWN_RESIDENTIAL_ISPS:
        if res_isp in text and hosting_flag is not True:
            return False, "Consumer Residential ISP"
            
    return "Unknown", "Unclassified ASN / Network"

def test_proxy_and_exit(proxy_url: str, timeout: int = 8) -> Dict[str, Any]:
    t0 = time.time()
    proxies = {"http": proxy_url, "https": proxy_url}
    
    test_endpoints = [
        ("https://api.ipify.org?format=json", "ipify"),
        ("http://ip-api.com/json?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,query,proxy,hosting,mobile", "ip-api"),
        ("https://ipinfo.io/json", "ipinfo"),
    ]
    
    last_err = None
    for endpoint, provider in test_endpoints:
        try:
            r = requests.get(
                endpoint,
                proxies=proxies,
                timeout=timeout,
                headers={"User-Agent": BROWSER_UA},
                verify=True if endpoint.startswith("https") else False
            )
            if r.status_code == 200:
                data = r.json()
                latency_ms = int((time.time() - t0) * 1000)
                exit_ip = data.get("ip") or data.get("query")
                if exit_ip:
                    return {
                        "success": True,
                        "exit_ip": exit_ip,
                        "latency_ms": latency_ms,
                        "provider": provider,
                        "raw_info": data if provider == "ip-api" else None
                    }
        except Exception as e:
            last_err = str(e)
            continue
            
    return {
        "success": False,
        "exit_ip": None,
        "latency_ms": int((time.time() - t0) * 1000),
        "error": last_err or "代理连接或握手失败"
    }

def query_ippure(proxy_url: str, expected_exit_ip: str, timeout: int = 10) -> Dict[str, Any]:
    proxies = {"http": proxy_url, "https": proxy_url}
    url = "https://my.ippure.com/v1/info"
    
    with ippure_semaphore:
        time.sleep(0.08)
        for attempt in range(2):
            try:
                r = requests.get(
                    url,
                    proxies=proxies,
                    timeout=timeout,
                    headers={
                        "User-Agent": BROWSER_UA,
                        "Accept": "application/json, text/plain, */*",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Referer": "https://ippure.com/"
                    },
                    verify=True
                )
                
                if r.status_code == 200:
                    data = r.json()
                    returned_ip = data.get("ip")
                    if expected_exit_ip and returned_ip and returned_ip != expected_exit_ip:
                        return {
                            "status": "MISMATCH",
                            "ip": returned_ip,
                            "asn": data.get("asn"),
                            "asOrganization": data.get("asOrganization"),
                            "country": data.get("country"),
                            "countryCode": data.get("countryCode"),
                            "region": data.get("region"),
                            "city": data.get("city"),
                            "fraudScore": data.get("fraudScore"),
                            "isResidential": data.get("isResidential"),
                            "isBroadcast": data.get("isBroadcast"),
                            "error": f"出口IP不一致: {returned_ip} != {expected_exit_ip}"
                        }
                    
                    return {
                        "status": "SUCCESS",
                        "ip": returned_ip,
                        "asn": data.get("asn"),
                        "asOrganization": data.get("asOrganization"),
                        "country": data.get("country"),
                        "countryCode": data.get("countryCode"),
                        "region": data.get("region"),
                        "city": data.get("city"),
                        "fraudScore": data.get("fraudScore"),
                        "isResidential": data.get("isResidential"),
                        "isBroadcast": data.get("isBroadcast")
                    }
                elif r.status_code in (403, 429) and attempt == 0:
                    time.sleep(0.8)
                    continue
                else:
                    return {
                        "status": "ERROR",
                        "error": f"HTTP {r.status_code}",
                        "fraudScore": None,
                        "isResidential": None,
                        "isBroadcast": None
                    }
            except Exception as e:
                if attempt == 0:
                    time.sleep(0.4)
                    continue
                return {
                    "status": "ERROR",
                    "error": str(e),
                    "fraudScore": None,
                    "isResidential": None,
                    "isBroadcast": None
                }

    return {
        "status": "ERROR",
        "error": "IPPure query failed",
        "fraudScore": None,
        "isResidential": None,
        "isBroadcast": None
    }

def query_ip_info(exit_ip: str, timeout: int = 8, cache: Optional[Dict] = None, cache_lock: Optional[threading.Lock] = None, refresh: bool = False) -> Dict[str, Any]:
    cache_key = f"ipinfo_{exit_ip}"
    if cache is not None and not refresh:
        with cache_lock if cache_lock else threading.Lock():
            cached = cache.get(cache_key)
            if cached and cached.get("_v") == CACHE_VERSION and time.time() - cached.get("_cached_at", 0) < 86400:
                return cached.get("data", {})
                
    url = f"http://ip-api.com/json/{exit_ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,query,proxy,hosting,mobile"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": BROWSER_UA})
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                res = {
                    "country": data.get("country", "Unknown"),
                    "countryCode": data.get("countryCode", "UN"),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "asn": data.get("as", ""),
                    "proxy_detected": data.get("proxy", False),
                    "hosting": data.get("hosting", False),
                    "mobile": data.get("mobile", False)
                }
                if cache is not None and cache_lock is not None:
                    with cache_lock:
                        cache[cache_key] = {"_v": CACHE_VERSION, "_cached_at": time.time(), "data": res}
                return res
    except Exception:
        pass
        
    return {
        "country": "Unknown",
        "countryCode": "UN",
        "region": "",
        "city": "",
        "isp": "",
        "org": "",
        "asn": "",
        "proxy_detected": None,
        "hosting": None,
        "mobile": None
    }

def calculate_score(data: Dict[str, Any]) -> Tuple[int, List[str], str]:
    score = 100
    reasons = []
    
    ippure_status = data.get("ippure_status")
    fraud = data.get("fraudScore")
    is_res = data.get("isResidential")
    
    if ippure_status == "SUCCESS" and fraud is not None and is_res is not None:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    if fraud is not None and isinstance(fraud, (int, float)):
        if fraud >= 90:
            score -= 60
            reasons.append(f"极高欺诈分(FraudScore={fraud}, -60)")
        elif fraud >= 80:
            score -= 45
            reasons.append(f"高欺诈分(FraudScore={fraud}, -45)")
        elif fraud >= 60:
            score -= 30
            reasons.append(f"中度欺诈分(FraudScore={fraud}, -30)")
        elif fraud >= 40:
            score -= 15
            reasons.append(f"轻度欺诈分(FraudScore={fraud}, -15)")
    else:
        score -= 20
        reasons.append("FraudScore未知(-20)")

    if is_res is False:
        score -= 20
        reasons.append("非住宅IP属性(-20)")
    elif is_res is None or is_res == "Unknown":
        score -= 15
        reasons.append("住宅属性未知(-15)")

    is_dc = data.get("isDatacenter")
    if is_dc is True:
        score -= 25
        dc_name = data.get("datacenter_name", "Datacenter")
        reasons.append(f"识别为机房/云网络({dc_name}, -25)")
    elif is_dc == "Unknown":
        score -= 10
        reasons.append("网络归属未明确(-10)")

    if data.get("isBroadcast") is True:
        score -= 40
        reasons.append("属于广播IP(Broadcast=True, -40)")

    if data.get("proxy_detected") is True:
        score -= 20
        reasons.append("检测为公开代理网络(-20)")

    if ippure_status == "ERROR":
        score -= 25
        reasons.append("IPPure不可用-信誉数据不足(-25)")
    elif ippure_status == "MISMATCH":
        score -= 30
        reasons.append("IPPure出口IP不一致(-30)")

    lat = data.get("latency_ms", 0)
    if lat > 5000:
        score -= 20
        reasons.append(f"超高延迟(>5000ms, -20)")
    elif lat > 3000:
        score -= 15
        reasons.append(f"高延迟(>3000ms, -15)")
    elif lat > 1500:
        score -= 8
        reasons.append(f"轻微延迟偏高(>1500ms, -8)")

    if data.get("exit_match") is False:
        score -= 5
        reasons.append(f"出口与入口IP不一致(-5)")

    final_score = max(0, min(100, score))
    if confidence == "LOW":
        final_score = min(final_score, 69)

    return final_score, reasons, confidence

def grade_proxy(final_score: int, data: Dict[str, Any], reasons: List[str], confidence: str) -> Tuple[str, List[str]]:
    fraud = data.get("fraudScore")
    is_dc = data.get("isDatacenter")
    is_broadcast = data.get("isBroadcast")
    ippure_status = data.get("ippure_status")
    is_res = data.get("isResidential")
    proxy_detected = data.get("proxy_detected")

    all_reasons = list(reasons)

    if fraud is not None and fraud >= 90:
        all_reasons.append(f"触发一票否决: 欺诈分过高(FraudScore={fraud} >= 90)")
        return "D", all_reasons

    if is_broadcast is True:
        all_reasons.append("触发一票否决: 属于广播IP(Broadcast=True)")
        return "D", all_reasons

    if is_dc is True and fraud is not None and fraud >= 70:
        all_reasons.append(f"触发一票否决: 高风险机房IP(Datacenter=True & FraudScore={fraud} >= 70)")
        return "D", all_reasons

    if (final_score >= 85 and confidence in ("HIGH", "MEDIUM") and
        ippure_status == "SUCCESS" and fraud is not None and fraud < 30 and
        is_res is True and is_dc is False and is_broadcast is False and
        proxy_detected is not True):
        return "A", all_reasons

    if (final_score >= 70 and confidence in ("HIGH", "MEDIUM") and
        ippure_status == "SUCCESS" and fraud is not None and fraud < 60 and
        is_res is not None and is_res != "Unknown" and is_broadcast is not True and
        (is_dc is not True or (is_dc is True and fraud < 40))):
        return "B", all_reasons

    if final_score >= 50:
        return "C", all_reasons

    return "D", all_reasons

def process_proxy_item(item: Tuple[str, str], config: Dict[str, Any], cache: Dict[str, Any], cache_lock: threading.Lock) -> Dict[str, Any]:
    raw_proxy, default_proto = item
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        protocol, req_proxy_url, host, port, clean_addr = parse_proxy(raw_proxy, default_proto)
    except Exception as e:
        return {
            "Protocol": default_proto,
            "Proxy": raw_proxy,
            "Proxy_IP": "Unknown",
            "Port": 0,
            "Exit_IP": "None",
            "Exit_Match": False,
            "Latency_ms": 0,
            "Country": "Unknown",
            "Region": "",
            "City": "",
            "ISP": "",
            "ASN": "",
            "Residential": "Unknown",
            "Datacenter": "Unknown",
            "Broadcast": "Unknown",
            "Proxy_Detected": "Unknown",
            "FraudScore": "Unknown",
            "IPPure_Status": "FAIL",
            "Confidence": "LOW",
            "FinalScore": 0,
            "Grade": "D",
            "Reasons": f"解析失败: {str(e)}",
            "CheckedAt": now_iso,
            "_valid": False
        }

    exit_test = test_proxy_and_exit(req_proxy_url, timeout=config["timeout"])
    if not exit_test["success"] or not exit_test["exit_ip"]:
        return {
            "Protocol": protocol,
            "Proxy": f"{protocol}://{clean_addr}",
            "Proxy_IP": host,
            "Port": port,
            "Exit_IP": "None",
            "Exit_Match": False,
            "Latency_ms": exit_test["latency_ms"],
            "Country": "Unknown",
            "Region": "",
            "City": "",
            "ISP": "",
            "ASN": "",
            "Residential": "Unknown",
            "Datacenter": "Unknown",
            "Broadcast": "Unknown",
            "Proxy_Detected": "Unknown",
            "FraudScore": "Unknown",
            "IPPure_Status": "FAIL",
            "Confidence": "LOW",
            "FinalScore": 0,
            "Grade": "D",
            "Reasons": f"连接超时或握手失败: {exit_test.get('error', 'failed')}",
            "CheckedAt": now_iso,
            "_valid": False
        }

    exit_ip = exit_test["exit_ip"]
    exit_match = (exit_ip == host)
    latency_ms = exit_test["latency_ms"]

    ippure_res = query_ippure(req_proxy_url, expected_exit_ip=exit_ip, timeout=config["timeout"])
    ip_info = query_ip_info(exit_ip, timeout=config["timeout"], cache=cache, cache_lock=cache_lock, refresh=config["refresh"])

    isp = ippure_res.get("asOrganization") or ip_info.get("isp") or ""
    org = ip_info.get("org") or ""
    asn_str = str(ippure_res.get("asn") or ip_info.get("asn") or "")
    country = ippure_res.get("country") or ip_info.get("country") or "Unknown"
    region = ippure_res.get("region") or ip_info.get("region") or ""
    city = ippure_res.get("city") or ip_info.get("city") or ""
    
    is_dc, dc_name = detect_datacenter(isp, org, asn_str, ip_info.get("hosting"))
    is_res = ippure_res.get("isResidential")
    is_broadcast = ippure_res.get("isBroadcast")

    eval_data = {
        "proxy_ip": host,
        "exit_ip": exit_ip,
        "exit_match": exit_match,
        "latency_ms": latency_ms,
        "ippure_status": ippure_res.get("status", "FAIL"),
        "fraudScore": ippure_res.get("fraudScore"),
        "isResidential": is_res,
        "isBroadcast": is_broadcast,
        "isDatacenter": is_dc,
        "datacenter_name": dc_name,
        "proxy_detected": ip_info.get("proxy_detected"),
    }

    final_score, reasons, confidence = calculate_score(eval_data)
    grade, final_reasons = grade_proxy(final_score, eval_data, reasons, confidence)

    return {
        "Protocol": protocol,
        "Proxy": f"{protocol}://{clean_addr}",
        "Proxy_IP": host,
        "Port": port,
        "Exit_IP": exit_ip,
        "Exit_Match": exit_match,
        "Latency_ms": latency_ms,
        "Country": country,
        "Region": region,
        "City": city,
        "ISP": isp,
        "ASN": asn_str,
        "Residential": "YES" if is_res is True else ("NO" if is_res is False else "Unknown"),
        "Datacenter": "True" if is_dc is True else ("False" if is_dc is False else "Unknown"),
        "Broadcast": "True" if is_broadcast is True else ("False" if is_broadcast is False else "Unknown"),
        "Proxy_Detected": "True" if ip_info.get("proxy_detected") is True else ("False" if ip_info.get("proxy_detected") is False else "Unknown"),
        "FraudScore": str(ippure_res.get("fraudScore")) if ippure_res.get("fraudScore") is not None else "Unknown",
        "IPPure_Status": ippure_res.get("status", "FAIL"),
        "Confidence": confidence,
        "FinalScore": final_score,
        "Grade": grade,
        "Reasons": "; ".join(final_reasons) if final_reasons else "各项指标优良",
        "CheckedAt": now_iso,
        "_valid": True
    }

def main():
    parser = argparse.ArgumentParser(description="全协议链式代理质量筛选工具 (HTTP / HTTPS / SOCKS5)")
    parser.add_argument("--output", default="dist", help="输出目录")
    parser.add_argument("--workers", type=int, default=24, help="并发线程数 (默认: 24)")
    parser.add_argument("--timeout", type=int, default=10, help="单节点超时时间 (秒, 默认: 10)")
    parser.add_argument("--refresh", action="store_true", help="强制刷新缓存")
    args = parser.parse_args()

    sources = [
        ("dist/http_clean.txt", "http"),
        ("dist/https_clean.txt", "https"),
        ("dist/socks5_clean.txt", "socks5"),
    ]

    all_items = []
    seen = set()
    for filepath, proto in sources:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    clean = line.strip()
                    if clean and not clean.startswith("#"):
                        key = f"{proto}://{clean.replace('socks5://', '').replace('http://', '').replace('https://', '')}"
                        if key not in seen:
                            seen.add(key)
                            all_items.append((clean, proto))

    total_count = len(all_items)
    print(f"\n╔════════════════════════════════════════════════════════════════╗")
    print(f"║   🌐 HTTP / HTTPS / SOCKS5 全协议链式代理质量与纯净度筛选器    ║")
    print(f"╚════════════════════════════════════════════════════════════════╝")
    print(f"[Config] 待测代理总量: {total_count} 个 (HTTP: 752 | HTTPS: 1949 | SOCKS5: 822)")
    print(f"[Config] 并发线程: {args.workers} | 超时: {args.timeout}s | IPPure限流: 8并发\n")

    cache_path = os.path.join(args.output, "ip_quality_cache.json")
    cache = {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except Exception:
            cache = {}
    cache_lock = threading.Lock()

    config = {
        "timeout": args.timeout,
        "refresh": args.refresh
    }

    results = []
    completed = 0
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(process_proxy_item, item, config, cache, cache_lock): item for item in all_items}
        for future in futures:
            res = future.result()
            results.append(res)
            completed += 1
            
            if res["_valid"]:
                grade_color = "🌟" if res["Grade"] == "A" else ("👍" if res["Grade"] == "B" else ("⚠️" if res["Grade"] == "C" else "❌"))
                print(f"[{completed}/{total_count}] {res['Proxy']} | 出口: {res['Exit_IP']} ({res['Country']} | {res['ISP'][:18]}) | 欺诈:{res['FraudScore']} | 广播:{res['Broadcast']} | 住宅:{res['Residential']} | 延迟:{res['Latency_ms']}ms | {grade_color} [{res['Grade']}级 | {res['FinalScore']}分] | {res['Reasons'][:45]}")
            else:
                if completed % 100 == 0 or completed == total_count:
                    print(f"[{completed}/{total_count}] 正在批量处理中... (当前有效连通: {sum(1 for r in results if r['_valid'])}个)")

    cost_time = time.time() - start_time

    try:
        cache["_meta_version"] = CACHE_VERSION
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    alive_list = [r for r in results if r["_valid"]]
    grade_a = [r for r in results if r["Grade"] == "A"]
    grade_b = [r for r in results if r["Grade"] == "B"]
    grade_c = [r for r in results if r["Grade"] == "C"]
    grade_d = [r for r in results if r["Grade"] == "D"]
    clean_nodes = grade_a + grade_b

    grade_order = {"A": 0, "B": 1, "C": 2, "D": 3}
    def sort_key(item):
        g = grade_order.get(item["Grade"], 99)
        score = -item["FinalScore"]
        fraud = float(item["FraudScore"]) if item["FraudScore"] not in ("None", "Unknown") else 999
        lat = item["Latency_ms"] if item["Latency_ms"] > 0 else 99999
        return (g, score, fraud, lat)

    results.sort(key=sort_key)

    csv_file = os.path.join(args.output, "chain_scored.csv")
    csv_fields = [
        "Protocol", "Proxy", "Proxy_IP", "Port", "Exit_IP", "Exit_Match", "Latency_ms",
        "Country", "Region", "City", "ISP", "ASN",
        "Residential", "Datacenter", "Broadcast", "Proxy_Detected",
        "FraudScore", "IPPure_Status", "Confidence", "FinalScore", "Grade", "Reasons", "CheckedAt"
    ]

    with open(csv_file, "w", encoding="utf-8-sig") as f:
        f.write(",".join(csv_fields) + "\n")
        for r in results:
            row = [f'"{str(r.get(f, "")).replace(chr(34), chr(34)+chr(34))}"' for f in csv_fields]
            f.write(",".join(row) + "\n")

    json_file = os.path.join(args.output, "chain_scored.json")
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    def write_txt(filename, items):
        filepath = os.path.join(args.output, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            for item in items:
                f.write(f"{item['Proxy']}\n")

    write_txt("chain_clean_all.txt", clean_nodes)
    write_txt("chain_grade_a.txt", grade_a)
    write_txt("chain_grade_b.txt", grade_b)
    write_txt("chain_grade_c.txt", grade_c)
    write_txt("chain_rejected.txt", grade_d)

    print(f"\n" + "=" * 68)
    print(f"📊 全协议链式代理质量筛选报告 (HTTP / HTTPS / SOCKS5)")
    print(f"=" * 68)
    print(f"• 📥 待测总数: {total_count} 个")
    print(f"• ⚡ 真实连通存活: {len(alive_list)} 个 ({len(alive_list)/total_count*100:.1f}%)")
    print(f"• ⏱️ 总耗时:   {cost_time:.2f} 秒")
    print(f"• 🎯 等级分布: A级(优先): {len(grade_a)} | B级(可用候选): {len(grade_b)} | C级(一般): {len(grade_c)} | D级(淘汰): {len(grade_d)}")
    print(f"• 🏆 纯净优质节点 (A+B级): {len(clean_nodes)} 个")

    if clean_nodes:
        print(f"\n🌟 筛选出的干净优质节点列表:")
        for idx, r in enumerate(clean_nodes, 1):
            print(f"  {idx:2d}. [{r['Grade']}级 | {r['FinalScore']}分] {r['Proxy']} | 出口: {r['Exit_IP']} ({r['Country']} {r['City']}) | 欺诈: {r['FraudScore']} | 住宅: {r['Residential']} | {r['ISP'][:22]}")
    else:
        print(f"\n💡 说明: 在当前开源免费代理池中，由于公网扫描代理普遍存在高欺诈分、广播网段或机房标记，经严格风控审核后无完美 A/B 节点。")
        print(f"   下方列出连通性最好且评分最高的候选节点供测试:")
        valid_sorted = sorted([r for r in alive_list if r['FinalScore'] > 0], key=lambda x: -x['FinalScore'])
        for idx, r in enumerate(valid_sorted[:10], 1):
            print(f"  {idx:2d}. [{r['Grade']}级 | {r['FinalScore']}分] {r['Proxy']} | 出口: {r['Exit_IP']} ({r['Country']} {r['City']}) | 欺诈:{r['FraudScore']} | 延迟:{r['Latency_ms']}ms | {r['ISP'][:22]}")

    print(f"\n📁 导出的链式代理文件已保存至: {args.output}")
    print(f"  - 🌟 干净优质总列表: dist/chain_clean_all.txt ({len(clean_nodes)}个)")
    print(f"  - 👍 A/B/C/D 分级表: dist/chain_grade_a.txt / b / c / rejected.txt")
    print(f"  - 📊 综合评分数据表: {csv_file}")
    print(f"=" * 68 + "\n")

if __name__ == "__main__":
    main()
