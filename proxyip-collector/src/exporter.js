import fs from 'fs/promises';
import path from 'path';

export function formatWithRemark(item) {
  const parts = [];
  parts.push(`${item.countryEmoji || '🌐'} ${item.countryCn || item.country}`);
  if (item.city) parts.push(`[${item.city}]`);
  if (item.responseTime !== undefined && item.responseTime !== null && item.responseTime > 0) {
    parts.push(`(${item.responseTime}ms)`);
  }
  if (item.supportsIpv4 && item.supportsIpv6) {
    parts.push('[双栈]');
  } else if (item.supportsIpv6) {
    parts.push('[IPv6]');
  }
  if (item.asn) parts.push(`AS${item.asn}`);
  if (item.asOrganization) parts.push(item.asOrganization.slice(0, 25).trim());

  const prefix = item.protocolType === 'proxyip' ? item.fullAddress : `${item.protocolType}://${item.fullAddress}`;
  return `${prefix}#${parts.join(' ')}`;
}

export async function exportToTxtFiles(validList, config) {
  const { outputDir, countriesDir } = config;

  await fs.mkdir(outputDir, { recursive: true });
  await fs.mkdir(countriesDir, { recursive: true });

  console.log(`[Exporter] 正在导出文件至目录: ${outputDir} ...`);

  const typeGroups = {
    proxyip: [],
    socks5: [],
    http: [],
    https: []
  };

  for (const item of validList) {
    const t = item.protocolType || 'proxyip';
    if (!typeGroups[t]) typeGroups[t] = [];
    typeGroups[t].push(item);
  }

  for (const [type, items] of Object.entries(typeGroups)) {
    if (items.length === 0) continue;
    const withRemarkContent = items.map(formatWithRemark).join('\n') + '\n';
    await fs.writeFile(path.join(outputDir, `${type}.txt`), withRemarkContent, 'utf-8');
    const cleanContent = items.map(i => type === 'proxyip' ? i.fullAddress : `${type}://${i.fullAddress}`).join('\n') + '\n';
    await fs.writeFile(path.join(outputDir, `${type}_clean.txt`), cleanContent, 'utf-8');
  }

  const allContent = validList.map(formatWithRemark).join('\n') + '\n';
  await fs.writeFile(path.join(outputDir, 'all_proxies.txt'), allContent, 'utf-8');

  const countryMap = {};
  for (const item of validList) {
    const code = (item.country || 'UNKNOWN').toUpperCase();
    if (!countryMap[code]) countryMap[code] = [];
    countryMap[code].push(item);
  }

  for (const [code, items] of Object.entries(countryMap)) {
    const countryContent = items.map(formatWithRemark).join('\n') + '\n';
    await fs.writeFile(path.join(countriesDir, `${code}.txt`), countryContent, 'utf-8');
  }

  const summary = {
    updatedAt: new Date().toISOString(),
    totalValid: validList.length,
    countsByType: {
      proxyip: typeGroups.proxyip.length,
      socks5: typeGroups.socks5.length,
      http: typeGroups.http.length,
      https: typeGroups.https.length
    },
    countryCount: Object.keys(countryMap).length,
    files: {
      proxyip: 'proxyip.txt & proxyip_clean.txt (Cloudflare 反代 IP)',
      socks5: 'socks5.txt & socks5_clean.txt (标准 SOCKS5 代理)',
      http: 'http.txt & http_clean.txt (标准 HTTP 代理)',
      https: 'https.txt & https_clean.txt (标准 HTTPS 代理)',
      countries: `countries/*.txt (${Object.keys(countryMap).length} 个国家/地区)`
    }
  };

  await fs.writeFile(path.join(outputDir, 'summary.json'), JSON.stringify(summary, null, 2), 'utf-8');

  console.log('[Exporter] 导出完成！各协议输出概览：');
  console.log(`  - 🗺️ ProxyIP: ${typeGroups.proxyip.length} 个 (dist/proxyip.txt)`);
  console.log(`  - 🧦 SOCKS5:  ${typeGroups.socks5.length} 个 (dist/socks5.txt)`);
  console.log(`  - 🌐 HTTP:    ${typeGroups.http.length} 个 (dist/http.txt)`);
  console.log(`  - 🔒 HTTPS:   ${typeGroups.https.length} 个 (dist/https.txt)`);
  console.log(`  - 📁 countries/: ${Object.keys(countryMap).length} 个国家`);
}
