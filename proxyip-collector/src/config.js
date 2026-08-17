import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

export const protocolSources = {
  proxyip: {
    name: 'ProxyIP (Cloudflare 反代落地)',
    url: 'https://zip.cm.edu.kg.cmliussss.net/all.json',
    defaultPort: 443,
    checkApi: 'https://api.090227.xyz/check?proxyip='
  },
  socks5: {
    name: 'SOCKS5 代理池',
    url: 'https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/socks5.json',
    defaultPort: 1080,
    checkApi: null
  },
  http: {
    name: 'HTTP 代理池',
    url: 'https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/http.json',
    defaultPort: 80,
    checkApi: null
  },
  https: {
    name: 'HTTPS 代理池',
    url: 'https://raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/https.json',
    defaultPort: 443,
    checkApi: null
  }
};

export const defaultConfig = {
  protocolType: 'all',
  enableCheck: true,
  concurrency: 16,
  timeoutMs: 8000,
  maxLatencyMs: 3000,
  limitTotal: 0,
  limitPerCountry: 0,
  allowedPorts: [],
  outputDir: path.join(projectRoot, 'dist'),
  countriesDir: path.join(projectRoot, 'dist', 'countries')
};

export function parseCliArgs() {
  const args = process.argv.slice(2);
  const config = { ...defaultConfig };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--type' && args[i + 1]) {
      config.protocolType = args[++i].toLowerCase();
    } else if (arg === '--no-check') {
      config.enableCheck = false;
    } else if (arg === '--check') {
      config.enableCheck = true;
    } else if (arg === '--concurrency' && args[i + 1]) {
      config.concurrency = parseInt(args[++i], 10) || config.concurrency;
    } else if (arg === '--timeout' && args[i + 1]) {
      config.timeoutMs = parseInt(args[++i], 10) || config.timeoutMs;
    } else if (arg === '--max-latency' && args[i + 1]) {
      config.maxLatencyMs = parseInt(args[++i], 10) || config.maxLatencyMs;
    } else if (arg === '--limit' && args[i + 1]) {
      config.limitTotal = parseInt(args[++i], 10) || config.limitTotal;
    } else if (arg === '--limit-per-country' && args[i + 1]) {
      config.limitPerCountry = parseInt(args[++i], 10) || config.limitPerCountry;
    } else if (arg === '--output' && args[i + 1]) {
      config.outputDir = path.resolve(process.cwd(), args[++i]);
      config.countriesDir = path.join(config.outputDir, 'countries');
    }
  }

  return config;
}
