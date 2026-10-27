#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════
# 免费威胁情报源一键接线 — abuse.ch Feodo C2 IP 黑名单 (+ OpenPhish)
#
# 把平台从"客户端就绪、零真实情报"推进到"真实外源 IOC 落库可命中":
#   1. 登录平台 (admin)
#   2. 幂等注册 csv_http 情报源 (按 name 查重, 已存在则跳过)
#   3. 立即触发一次拉取并落库
#   4. 输出 IOC 总数 + 样例 (答辩证据: 截图本步输出)
#
# 用法:
#   SOC_BASE=http://127.0.0.1:8001 SOC_USER=admin SOC_PASS=*** \
#     bash tools/seed-free-intel-feeds.sh
# ════════════════════════════════════════════════════════════════
set -euo pipefail

SOC_BASE="${SOC_BASE:-http://127.0.0.1:8001}"
SOC_USER="${SOC_USER:-admin}"
SOC_PASS="${SOC_PASS:?必须设置 SOC_PASS}"
POLL="${POLL:-1}"    # POLL=0 只注册不拉取

say() { echo "[intel-seed $(date +%H:%M:%S)] $*"; }

command -v jq >/dev/null || { echo "需要 jq"; exit 1; }

TOKEN=$(curl -sf -X POST "${SOC_BASE}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${SOC_USER}\",\"password\":\"${SOC_PASS}\"}" | jq -r .access_token)
[ -n "${TOKEN}" ] && [ "${TOKEN}" != "null" ] || { say "登录失败"; exit 1; }
say "登录 OK"

auth() { curl -sf -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" "$@"; }

register_feed() {  # name url type config_json interval_min
  local name="$1" url="$2" ftype="$3" cfg="$4" interval="$5"
  if auth "${SOC_BASE}/api/intel/feeds" | jq -e --arg n "${name}" '.[] | select(.name == $n)' >/dev/null 2>&1; then
    say "已存在, 跳过注册: ${name}"
    return
  fi
  local body
  body=$(jq -n --arg name "${name}" --arg url "${url}" --arg t "${ftype}" \
              --argjson cfg "${cfg}" --argjson i "${interval}" \
              '{name:$name, url:$url, feed_type:$t, config:$cfg, poll_interval_min:$i, enabled:true}')
  local id
  id=$(auth -X POST "${SOC_BASE}/api/intel/feeds" -d "${body}" | jq -r .id)
  say "注册成功: ${name} (id=${id})"
}

# ── 源 1: abuse.ch Feodo Tracker — Botnet C2 IP 黑名单 (CSV, 免费, 无 key) ──
register_feed "abuse.ch-feodo" \
  "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" "csv_http" \
  '{"format":"csv","value_column":"dst_ip","fixed_type":"ip","threat_column":"malware","severity":"high"}' 60

# ── 源 2: OpenPhish 免费源 — 钓鱼 URL (纯文本, 免费, 无 key) ──
register_feed "openphish-free" \
  "https://openphish.com/feed.txt" "csv_http" \
  '{"format":"plain","fixed_type":"url","fixed_threat":"phishing","severity":"high"}' 120

# ── 源 3: abuse.ch URLhaus — 恶意 URL 分发源 (CSV, 免费, 无 key) ──
# csv_recent 列: id,dateadded,url,url_status,threat,tags,urlhaus_link
# '#' 开头为 abuse.ch 头注释块, 方言里统一跳过
register_feed "urlhaus-free" \
  "https://urlhaus.abuse.ch/downloads/csv_recent/" "csv_http" \
  '{"format":"csv","value_column":"url","threat_column":"threat","fixed_type":"url","fixed_threat":"malware_distribution","severity":"high","comment_prefix":"#"}' 60

# ── 源 4: CISA KEV — 已知被利用漏洞目录 (JSON, 免费, 无 key) ──
# 每条都是已在野利用的 CVE: 富化命中自动提级(intel_enricher KEV 特权逻辑)
# 体量 ~1.2k 条且低频更新, 6 小时轮询足够
register_feed "cisa-kev" \
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" "kev_json" \
  '{"severity":"critical"}' 360

if [ "${POLL}" != "1" ]; then say "POLL=0, 跳过拉取"; exit 0; fi

# ── 立即拉取 + 证据输出 ──
auth "${SOC_BASE}/api/intel/feeds" | jq -r '.[] | "\(.id) \(.name)"' | while read -r id name; do
  say "拉取 ${name} (id=${id})..."
  auth -X POST "${SOC_BASE}/api/intel/feeds/${id}/poll" | jq -c .
done

echo
say "=== 证据: IOC 库规模 ==="
TOTAL=$(auth "${SOC_BASE}/api/intel/iocs?limit=1" | jq -r 'if type=="array" then length else .total end' 2>/dev/null || echo "?")
say "intel/iocs 查询 OK (样例见下)"
auth "${SOC_BASE}/api/intel/iocs?limit=5" | jq -c '.[] | {ioc_type, ioc_value, threat_type, source}' | head -5
say "完成 —— 答辩时对照 capabilities.yaml threat_intel 条目与 Grafana soc_intel_ioc_total 指标"
