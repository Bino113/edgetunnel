#!/usr/bin/env node

/**
 * ProxyIP Collector 主执行入口
 */

import { parseCliArgs } from './config.js';
import { fetchProxyIPList } from './fetcher.js';
import { checkProxyIPList } from './checker.js';
import { exportToTxtFiles } from './exporter.js';

function printBanner() {
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║                🗺️  ProxyIP Collector v1.0.0                    ║
║      Cloudflare 反代落地 IP 采集、测活与 TXT 多维导出工具      ║
╚════════════════════════════════════════════════════════════════╝
`);
}

async function main() {
  printBanner();
  const startTime = Date.now();
  const config = parseCliArgs();

  console.log(`[Config] 运行配置:
  - 测活开启: ${config.enableCheck ? '✅ 是' : '❌ 否 (直接导出)'}
  - 测活并发: ${config.concurrency} 路
  - 超时时间: ${config.timeoutMs} ms
  - 最大延迟: ${config.maxLatencyMs} ms
  - 端口过滤: [${config.allowedPorts.join(', ')}]
  - 限制抽样: ${config.limitPerCountry > 0 ? `每国 ${config.limitPerCountry} 个` : '全量'}
  - 输出目录: ${config.outputDir}
`);

  try {
    const rawList = await fetchProxyIPList(config);
    if (rawList.length === 0) {
      console.error('[Error] 未获取到有效节点数据，程序终止。');
      process.exit(1);
    }

    const validList = await checkProxyIPList(rawList, config);
    if (validList.length === 0) {
      console.warn('[Warning] 经测活无可用节点符合条件。');
    }

    await exportToTxtFiles(validList, config);

    const costSec = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(`\n🎉 [Success] 全部任务执行完成！耗时: ${costSec} 秒。\n`);
  } catch (err) {
    console.error(`\n❌ [Fatal Error] 执行失败: ${err.message}\n`, err.stack);
    process.exit(1);
  }
}

main();
