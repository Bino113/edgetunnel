#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import requests


def main():
    api_token = os.environ.get("CLOUDFLARE_API_TOKEN")
    account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID")
    namespace_id = os.environ.get("CLOUDFLARE_KV_NAMESPACE_ID")

    if not api_token or not account_id or not namespace_id:
        print("[KV Sync] missing Cloudflare credentials, skip")
        return

    dist = "dist"
    proxy_file = os.path.join(dist, "proxyip_clean.txt")
    chain_file = os.path.join(dist, "chain_clean_all.txt")

    def read_lines(path, limit):
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            return [x.strip() for x in f if x.strip() and not x.startswith("#")][:limit]

    proxyips = read_lines(proxy_file, 100)
    chains = read_lines(chain_file, 50)

    data = [
        {"key": "ADD.txt", "value": "\n".join(proxyips)},
        {"key": "AUTO_PROXYIPS", "value": "\n".join(proxyips)},
        {"key": "AUTO_CHAIN_PROXIES", "value": "\n".join(chains)},
    ]

    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{namespace_id}/bulk"
    r = requests.put(url, headers={"Authorization": f"Bearer {api_token}"}, json=data, timeout=15)
    if not r.ok or not r.json().get("success"):
        raise RuntimeError(r.text)
    print("[KV Sync] OK")


if __name__ == "__main__":
    main()
