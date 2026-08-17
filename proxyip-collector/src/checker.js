/**
 * ProxyIP 批量并发测活与性能验证模块
 */

const DEFAULT_PROXYIP_CHECK_API = 'https://api.090227.xyz/check?proxyip=';

export async function checkSingleProxyIP(item, config) {
  // HTTP / HTTPS / SOCKS5 的真实出口、IPPure 风控由第二阶段 Python 完成。
  // 第一阶段只对 ProxyIP 使用专用检测 API，避免把链式代理误判为失败。
  if (item.protocolType && item.protocolType !== 'proxyip') {
    return {
      ...item,
      valid: true,
      responseTime: 0,
      supportsIpv4: !item.isIpv6,
      supportsIpv6: item.isIpv6
    };
  }

  const checkApi = config.checkApi || DEFAULT_PROXYIP_CHECK_API;
  const checkUrl = `${checkApi}${encodeURIComponent(item.ip)}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.timeoutMs);
  const startTime = Date.now();

  try {
    const response = await fetch(checkUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'ProxyIP-Checker/1.0'
      }
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        ...item,
        valid: false,
        reason: `HTTP ${response.status}`,
        responseTime: null
      };
    }

    const data = await response.json();
    const networkTime = Date.now() - startTime;

    if (data.success) {
      const responseTime = typeof data.responseTime === 'number' ? data.responseTime : networkTime;
      if (responseTime > config.maxLatencyMs) {
        return {
          ...item,
          valid: false,
          reason: `Latency too high (${responseTime}ms > ${config.maxLatencyMs}ms)`,
          responseTime
        };
      }

      return {
        ...item,
        valid: true,
        responseTime,
        supportsIpv4: data.supports_ipv4 === true,
        supportsIpv6: data.supports_ipv6 === true,
        dualStack: data.dual_stack === true,
        colo: data.colo || ''
      };
    }

    return {
      ...item,
      valid: false,
      reason: 'Probe failed',
      responseTime: null
    };
  } catch (err) {
    clearTimeout(timeoutId);
    return {
      ...item,
      valid: false,
      reason: err.name === 'AbortError' ? 'Timeout' : err.message,
      responseTime: null
    };
  }
}

export async function checkProxyIPList(list, config) {
  if (!config.enableCheck) {
    console.log('[Checker] 跳过测活验证（已配置 --no-check），直接采用全部拉取到的 IP');
    return list.map(item => ({
      ...item,
      valid: true,
      responseTime: 0,
      supportsIpv4: !item.isIpv6,
      supportsIpv6: item.isIpv6
    }));
  }

  const total = list.length;
  const concurrency = Math.max(1, config.concurrency || 16);
  console.log(`[Checker] 开始并发检查：ProxyIP 在线测活，链式代理留待第二阶段；总数 ${total}，并发 ${concurrency}`);

  const results = [];
  let completedCount = 0;
  let successCount = 0;
  let currentIndex = 0;

  const printProgress = () => {
    const percent = total ? ((completedCount / total) * 100).toFixed(1) : '100.0';
    process.stdout.write(`\r[Checker] 进度: ${completedCount}/${total} (${percent}%) | 第一阶段保留: ${successCount} 个`);
  };

  async function worker() {
    while (currentIndex < total) {
      const idx = currentIndex++;
      const item = list[idx];
      const result = await checkSingleProxyIP(item, config);

      completedCount++;
      if (result.valid) {
        successCount++;
        results.push(result);
      }
      printProgress();
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, total) }, () => worker());
  await Promise.all(workers);

  process.stdout.write('\n');
  const rate = total ? ((results.length / total) * 100).toFixed(1) : '0.0';
  console.log(`[Checker] 第一阶段完成：总量 ${total}，保留 ${results.length}，保留率 ${rate}%`);

  results.sort((a, b) => (a.responseTime || 9999) - (b.responseTime || 9999));
  return results;
}
