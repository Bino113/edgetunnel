/**
 * 远程多协议代理数据拉取模块 (ProxyIP / SOCKS5 / HTTP / HTTPS)
 */

import { protocolSources } from './config.js';

const IPV6_REGEX = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

export async function fetchByType(type, config) {
  const source = protocolSources[type];
  if (!source) return [];

  console.log(`[Fetcher] 正在拉取 ${source.name}: ${source.url} ...`);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(source.url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ProxyIP-Collector/1.0'
      }
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    const json = await response.json();
    const rawData = Array.isArray(json) ? json : json.data || [];
    console.log(`[Fetcher] 成功获取到 ${rawData.length} 条 ${source.name} 记录`);

    const list = [];
    const seen = new Set();

    for (const item of rawData) {
      const rawIp = item.ip || '';
      let ports = [];

      if (Array.isArray(item.port)) {
        ports = item.port;
      } else if (item.port) {
        ports = [parseInt(item.port, 10)];
      } else if (item._port) {
        ports = [parseInt(item._port, 10)];
      } else {
        ports = [source.defaultPort];
      }

      const meta = item.meta || {};
      const country = (meta.country || item.country || 'UNKNOWN').toUpperCase();
      const countryCn = meta.country_cn || item.country_cn || country;
      const countryEmoji = meta.country_emoji || item.country_emoji || '🌐';
      const city = meta.city || item.city || '';
      const asn = meta.asn || item.asn || 0;
      const asOrg = meta.asOrganization || item.asOrganization || '';
      const continent = meta.continent || item.continent || 'UN';
      const lat = meta.latitude ?? meta.colo?.lat ?? item.latitude ?? null;
      const lon = meta.longitude ?? meta.colo?.lon ?? item.longitude ?? null;

      const isIpv6 = IPV6_REGEX.test(rawIp) || rawIp.includes(':');
      const formattedIp = isIpv6 && !rawIp.startsWith('[') ? `[${rawIp}]` : rawIp;

      for (const p of ports) {
        const portNum = Number(p);
        if (isNaN(portNum)) continue;

        if (config.allowedPorts?.length > 0 && !config.allowedPorts.includes(portNum)) {
          continue;
        }

        const address = `${formattedIp}:${portNum}`;
        const key = `${type}:${address}`;
        if (seen.has(key)) continue;
        seen.add(key);

        list.push({
          protocolType: type,
          ip: rawIp,
          formattedIp,
          port: portNum,
          fullAddress: address,
          proxyUrl: type === 'proxyip' ? address : `${type}://${address}`,
          country,
          countryCn,
          countryEmoji,
          city,
          asn,
          asOrganization: asOrg,
          continent,
          latitude: lat ? parseFloat(lat) : null,
          longitude: lon ? parseFloat(lon) : null,
          isIpv6,
          sourceUrl: source.url
        });
      }
    }

    return list;
  } catch (err) {
    console.error(`[Fetcher] 拉取 ${source.name} 失败: ${err.message}`);
    return [];
  }
}

export async function fetchProxyIPList(config) {
  const targetTypes = config.protocolType === 'all'
    ? ['proxyip', 'socks5', 'http', 'https']
    : [config.protocolType];

  let aggregated = [];

  for (const type of targetTypes) {
    const list = await fetchByType(type, config);
    aggregated.push(...list);
  }

  console.log(`[Fetcher] 全部协议标准化清洗完成，共计 ${aggregated.length} 个节点目标`);

  if (config.limitPerCountry > 0) {
    const countryGroups = {};
    for (const item of aggregated) {
      const key = `${item.protocolType}:${item.country}`;
      if (!countryGroups[key]) countryGroups[key] = [];
      if (countryGroups[key].length < config.limitPerCountry) {
        countryGroups[key].push(item);
      }
    }
    aggregated = Object.values(countryGroups).flat();
    console.log(`[Fetcher] 抽样过滤后剩余: ${aggregated.length} 个节点`);
  }

  if (config.limitTotal > 0 && aggregated.length > config.limitTotal) {
    aggregated = aggregated.slice(0, config.limitTotal);
  }

  return aggregated;
}
