# ProxyIP Collector Automation

This fork runs the collector from `.github/workflows/auto_scan_and_update.yml`.

- GitHub Actions schedule: every 4 hours.
- Curated outputs: `dist/proxyip_clean.txt`, `dist/chain_clean_all.txt`, and `dist/summary.json`.
- Cloudflare synchronization: a separate scheduled Worker reads the curated public outputs and updates the existing KV namespace used by the deployed EdgeTunnel Worker.
- Cloudflare API credentials are not stored in this repository.
