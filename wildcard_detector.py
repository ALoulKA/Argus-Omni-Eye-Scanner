# Argus · 明日之眼 - 完整实现
# 基于《泛解析识别工具使用手册》V1.1 + 产品设计方案
# 技术栈: Python + tkinter + dnspython + PyInstaller

import argparse
import json
import random
import re
import string
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from typing import Optional, Literal
from datetime import datetime, timezone
import hashlib

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[ERROR] 缺少依赖库 dnspython，请先运行: pip install dnspython")
    sys.exit(1)


# ============================================================================
# 全局配置
# ============================================================================
DEFAULT_PROBE_COUNT = 8
DEFAULT_THRESHOLD = 0.6
DEFAULT_IP_CONVERGE = 2
DEFAULT_CNAME_CONVERGE = 2
DEFAULT_DNS_TIMEOUT = 2.0
DEFAULT_DNS_RETRY = 1
DEFAULT_MAX_CONCURRENT = 16
DEFAULT_VERIFY_ROUND = 1
CACHE_TTL = 86400  # 24小时（秒）

# 常见业务子域名白名单（强制保留，绝不误杀）
WHITELIST_PREFIXES = {
    "www", "mail", "smtp", "pop", "imap", "ftp", "ssh", "vpn",
    "cdn", "static", "assets", "img", "images", "css", "js",
    "api", "admin", "manage", "console", "portal", "webmail",
    "ns1", "ns2", "dns", "mx", "mx1", "mx2",
    "blog", "forum", "shop", "store", "pay", "cart",
    "dev", "test", "demo", "git", "svn",
    "m", "web", "mobile",
}

CHARSET = string.ascii_lowercase + string.digits


# ============================================================================
# 随机探针生成模块
# ============================================================================
def generate_random_probe(length: int = 6) -> str:
    """高熵随机字符串生成算法（字母+数字），生成几乎不可能命中真实子域的前缀"""
    return ''.join(random.choices(CHARSET, k=length))


def generate_probes(count: int, min_len: int = 6, max_len: int = 8) -> list[str]:
    """生成多个互不重复的随机探针子域名"""
    probes = set()
    for _ in range(count * 3):
        length = random.randint(min_len, max_len)
        probes.add(generate_random_probe(length))
        if len(probes) >= count:
            break
    return list(probes)[:count]


# ============================================================================
# 并发 DNS 查询模块
# ============================================================================
DEFAULT_DNS_SERVERS = [
    "223.5.5.5",       # 阿里DNS
    "223.6.6.6",       # 阿里DNS备用
    "119.29.29.29",    # 腾讯DNS
    "182.254.116.116", # 腾讯DNS备用
    "114.114.114.114", # 114DNS
    "8.8.8.8",         # Google DNS
    "1.1.1.1",         # Cloudflare DNS
]

def _query_single(domain: str, qtype: str,
                  servers: Optional[list[str]],
                  timeout: float, retry: int) -> dict:
    """对单个域名+记录类型执行 DNS 查询"""
    result = {"domain": domain, "qtype": qtype,
              "success": False, "ips": [], "cnames": [], "error": None}

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * max(retry, 1)
    # 默认使用多个DNS服务器，自动轮换容灾
    if servers:
        resolver.nameservers = [s for s in servers if s]
    else:
        resolver.nameservers = DEFAULT_DNS_SERVERS

    for attempt in range(retry + 1):
        try:
            answers = resolver.resolve(domain, qtype)
            result["success"] = True
            for rdata in answers:
                if qtype == "A":
                    result["ips"].append(str(rdata))
                elif qtype == "CNAME":
                    result["cnames"].append(str(rdata))
                elif qtype == "AAAA":
                    result["ips"].append(str(rdata))
            break
        except dns.resolver.NXDOMAIN:
            # NXDOMAIN = 域名真实不存在，非泛解析的正常响应，算失败
            result["success"] = False
            break
        except dns.exception.DNSException as e:
            result["error"] = str(e)
            if attempt < retry:
                time.sleep(0.05)
    return result


def query_probes_async(domain: str, probes: list[str],
                       qtypes: list[str],
                       servers: Optional[list[str]] = None,
                       timeout: float = DEFAULT_DNS_TIMEOUT,
                       retry: int = DEFAULT_DNS_RETRY,
                       max_concurrent: int = DEFAULT_MAX_CONCURRENT) -> list[dict]:
    """并发 DNS 查询所有探针，返回结果列表"""
    tasks = [(f"{p}.{domain}", qt) for p in probes for qt in qtypes]
    results = []
    with ThreadPoolExecutor(max_workers=max_concurrent) as ex:
        futures = {
            ex.submit(_query_single, d, q, servers, timeout, retry): (d, q)
            for d, q in tasks
        }
        done, _ = wait(futures.keys(), timeout=max(10, timeout * (retry + 1) * 3))
        for fut in done:
            results.append(fut.result())
        for fut in (futures.keys() - done):
            fut.cancel()
            d, q = futures[fut]
            results.append({"domain": d, "qtype": q, "success": False, "ips": [], "cnames": [], "error": "timeout"})
    return results


# ============================================================================
# 特征统计模块
# ============================================================================
def compute_features(results: list[dict]) -> dict:
    """
    核心公式：
      - 解析成功率 = 成功解析数 / 总探针数
      - IP收敛度   = 1 / 唯一IP数量
      - CNAME收敛度 = 1 / 唯一CNAME数量
    """
    total = len(results)
    resolved = sum(1 for r in results if r["success"])

    all_ips = set()
    all_cnames = set()
    for r in results:
        all_ips.update(r["ips"])
        all_cnames.update(r["cnames"])

    return {
        "total": total,
        "resolved": resolved,
        "resolve_rate": resolved / total if total > 0 else 0.0,
        "unique_ips": sorted(all_ips),
        "unique_cnames": sorted(all_cnames),
        "ip_count": len(all_ips),
        "cname_count": len(all_cnames),
    }


# ============================================================================
# 泛解析判定模块
# ============================================================================
def classify_confidence(resolve_rate: float, threshold: float) -> Literal["high", "medium", "low"]:
    """
    收敛聚类 + 置信度分级
    high:   解析率 >= 阈值（强泛解析）
    medium: 解析率 >= 阈值 * 0.7（中度泛解析）
    low:    其他（疑似泛解析）
    """
    ratio = resolve_rate / threshold if threshold > 0 else 0
    if ratio >= 1.0:
        return "high"
    elif ratio >= 0.7:
        return "medium"
    return "low"


# ============================================================================
# 域名规范化（输入预处理）
# ============================================================================
def normalize_domain(raw: str) -> str:
    """从任意用户输入提取并返回标准化根域名。
    支持：
    - 完整 URL（https://www.example.com/path）
    - 带端口（example.com:8080）
    - 带子域（mail.example.com）
    - 直接根域名（example.com）
    - 二级域后缀（com.cn / gov.cn 等自动再往上提一级）
    """
    if not raw or not isinstance(raw, str):
        return ""

    # 1. 去除协议头
    raw = re.sub(r'^https?://', '', raw.strip())
    # 2. 去除用户名:密码@
    raw = re.sub(r'^[\w\.-]+@', '', raw)
    # 3. 去除端口号
    raw = re.sub(r':\d+$', '', raw)
    # 4. 去除路径、查询参数、片段
    raw = raw.split('/')[0].split('?')[0].split('#')[0]
    # 5. 去除末尾点号
    raw = raw.rstrip('.')

    if not raw:
        return ""

    labels = raw.split('.')
    if len(labels) <= 2:
        return raw.lower()

    # 常见二级域后缀：自动再往上提一级
    second_level = {
        # 中国大陆二级域后缀
        'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
        # 港澳台及海外中资
        'com.hk', 'com.tw', 'com.sg', 'com.au', 'com.nz',
        # 其他常见二级域（非中国，但常见输入场景）
        'co.uk', 'co.jp', 'co.kr', 'or.kr', 'ne.jp',
    }
    tld = '.'.join(labels[-2:])
    if tld in second_level:
        return '.'.join(labels[-3:]).lower()

    return '.'.join(labels[-2:]).lower()


def detect_wildcard(domain: str,
                   probe_count: int = DEFAULT_PROBE_COUNT,
                   threshold: float = DEFAULT_THRESHOLD,
                   ip_converge: int = DEFAULT_IP_CONVERGE,
                   cname_converge: int = DEFAULT_CNAME_CONVERGE,
                   qtypes: Optional[list[str]] = None,
                   servers: Optional[list[str]] = None,
                   timeout: float = DEFAULT_DNS_TIMEOUT,
                   retry: int = DEFAULT_DNS_RETRY,
                   max_concurrent: int = DEFAULT_MAX_CONCURRENT,
                   verify_round: int = DEFAULT_VERIFY_ROUND,
                   exclude_ips: Optional[list[str]] = None,
                   exclude_cnames: Optional[list[str]] = None) -> dict:
    """
    核心检测流程:
      1. 生成随机探针
      2. 并发 DNS 查询
      3. 统计解析率 / IP收敛 / CNAME收敛
      4. 收敛聚类算法判定 + 置信度分级
      5. (-vr 2) 二次验证
    """
    if qtypes is None:
        qtypes = ["A", "CNAME", "AAAA"]

    probes = generate_probes(probe_count)
    results = query_probes_async(domain, probes, qtypes, servers,
                                 timeout, retry, max_concurrent)
    features = compute_features(results)

    # 排除指定 IP/CNAME
    if exclude_ips:
        features["unique_ips"] = [ip for ip in features["unique_ips"] if ip not in exclude_ips]
        features["ip_count"] = len(features["unique_ips"])
    if exclude_cnames:
        features["unique_cnames"] = [c for c in features["unique_cnames"] if c not in exclude_cnames]
        features["cname_count"] = len(features["unique_cnames"])

    # 判定逻辑
    is_wildcard = (
        features["resolve_rate"] >= threshold
        and features["ip_count"] <= ip_converge
        and features["cname_count"] <= cname_converge
    )

    if verify_round == 2 and is_wildcard:
        probes2 = generate_probes(probe_count)
        results2 = query_probes_async(domain, probes2, qtypes, servers,
                                       timeout, retry, max_concurrent)
        feat2 = compute_features(results2)
        is_wildcard = (
            is_wildcard
            and feat2["resolve_rate"] >= threshold
            and feat2["ip_count"] <= ip_converge
            and feat2["cname_count"] <= cname_converge
        )
        features["round2"] = feat2

    confidence = classify_confidence(features["resolve_rate"], threshold) if is_wildcard else "low"

    return {
        "domain": domain,
        "wildcard": is_wildcard,
        "confidence": confidence,
        "resolve_rate": features["resolve_rate"],
        "probe_count": features["total"],
        "resolved_count": features["resolved"],
        "ips": features["unique_ips"],
        "cnames": features["unique_cnames"],
        "_features": features,      # 保留内部结构供过滤使用
        "probes": probes,
        "cache_time": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================================
# 爆破过滤模块
# ============================================================================
def is_wildcard_subdomain(subdomain: str, detection: dict) -> bool:
    """判断子域名是否属于泛解析产生的干扰项"""
    prefix = subdomain.split(".")[0].lower()
    if prefix in WHITELIST_PREFIXES:
        return False
    return bool(detection["wildcard"])


def filter_subdomains(subdomains: list[str], detection: dict) -> list[str]:
    """过滤泛解析干扰子域，返回纯净列表"""
    return [s for s in subdomains if not is_wildcard_subdomain(s, detection)]




# ============================================================================
# 子域名爆破模块
# ============================================================================
def bruteforce_subdomains(domain: str,
                          wordlist_path=None,
                          wordlist_content=None,
                          resolver_servers=None,
                          timeout=2.0,
                          retry=1,
                          max_concurrent=16,
                          wildcard_detection=None,
                          progress_callback=None,
                          stop_event=None):
    # Read wordlist
    candidates = []
    if wordlist_content:
        candidates = [ln.strip().lower() for ln in wordlist_content if ln.strip() and not ln.startswith('#')]
    elif wordlist_path:
        from pathlib import Path
        p = Path(wordlist_path)
        if not p.exists():
            raise FileNotFoundError(f'Wordlist not found: {wordlist_path}')
        candidates = [ln.strip().lower() for ln in p.read_text(encoding='utf-8', errors='ignore').splitlines() if ln.strip() and not ln.startswith('#')]
    else:
        # 自动检测同目录 dic.txt（16 万行大字典）；不存在则回退内置迷你字典
        from pathlib import Path as _P
        import sys
        if hasattr(sys, '_MEIPASS'):
            _base_dir = _P(sys._MEIPASS)
        else:
            _base_dir = _P(__file__).parent
        _auto = _base_dir / "dic.txt"
        if _auto.exists():
            candidates = [ln.strip().lower() for ln in _auto.read_text(encoding='utf-8', errors='ignore').splitlines() if ln.strip() and not ln.startswith('#')]
            print(f"[+] 使用大字典: {_auto} ({len(candidates)} 条)")
        else:
            candidates = [
                'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
                'api', 'admin', 'blog', 'dev', 'test', 'm', 'web',
                'cdn', 'static', 'img', 'images', 'assets',
                'mx', 'mx1', 'mx2', 'ns1', 'ns2',
                'shop', 'store', 'pay', 'cart', 'vpn',
                'git', 'svn', 'demo', 'forum', 'portal',
                'manage', 'console', 'mobile', 'old',
                'backup', 'internal', 'staging', 'prod',
                'corp', 'intranet', 'oa', 'crm', 'erp',
                'i', 'ns', 'dns', 'wifi', 'router',
            ]

    total = len(candidates)
    if total == 0:
        return []

    # 检查停止信号
    if stop_event and stop_event.is_set():
        return []

    def check_subdomain(sub):
        full = f"{sub}.{domain}"
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout * max(retry, 1)
        if resolver_servers:
            resolver.nameservers = [s for s in resolver_servers if s]
        found = False
        ips = []
        cnames = []
        # 只要有一种记录类型解析成功，就认为子域名存在
        for qtype in ['A', 'AAAA', 'CNAME']:
            for attempt in range(retry + 1):
                try:
                    ans = resolver.resolve(full, qtype)
                    found = True
                    for rdata in ans:
                        if qtype in ('A', 'AAAA'):
                            ips.append(str(rdata))
                        elif qtype == 'CNAME':
                            cnames.append(str(rdata))
                    break          # 该记录类型成功，跳出重试循环，继续下一个 qtype
                except dns.resolver.NXDOMAIN:
                    # 该记录类型明确不存在，继续尝试其他记录类型
                    break
                except dns.exception.DNSException:
                    if attempt < retry:
                        import time; time.sleep(0.05)
                    continue
        if not found:
            return None

        # 检查停止信号（每个子域名检测完后检查）
        if stop_event and stop_event.is_set():
            return None
        # 泛解析过滤
        if wildcard_detection and wildcard_detection.get('wildcard', False):
            prefix = full.split('.')[0].lower()
            if prefix in WHITELIST_PREFIXES:
                return {'subdomain': full, 'ips': list(dict.fromkeys(ips)), 'cnames': list(dict.fromkeys(cnames))}
            wc_ips = set(wildcard_detection.get('ips', []))
            wc_cnames = set(wildcard_detection.get('cnames', []))
            _feat = wildcard_detection.get('_features', {})
            if _feat:
                wc_ips.update(_feat.get('unique_ips', []))
                wc_cnames.update(_feat.get('unique_cnames', []))
            if wc_ips and set(ips).issubset(wc_ips):
                return None
            if wc_cnames and set(cnames).issubset(wc_cnames):
                return None
        return {'subdomain': full, 'ips': list(dict.fromkeys(ips)), 'cnames': list(dict.fromkeys(cnames))}

    results = []
    done = [0]
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=max_concurrent) as ex:
        futures = {ex.submit(check_subdomain, c): c for c in candidates}
        for fut in as_completed(futures):
            # 检查停止信号
            if stop_event and stop_event.is_set():
                ex.shutdown(wait=False, cancel_futures=True)
                break
            done[0] += 1
            r = fut.result()
            if r is not None:
                results.append(r)
            if progress_callback:
                progress_callback(done[0] / total, len(results), total)
    results = sorted(results, key=lambda x: x['subdomain'])

    # ---- 泛解析智能过滤 ----
    if wildcard_detection and wildcard_detection.get('wildcard', False):
        # 提取泛解析特征 IP 和 CNAME 集合（即随机探针全部解析到的那些）
        wc_ips = set(wildcard_detection.get('ips', []))
        wc_cnames = set(wildcard_detection.get('cnames', []))
        # 也从 _features 中提取更完整的集合
        _feat = wildcard_detection.get('_features', {})
        if _feat:
            wc_ips.update(_feat.get('unique_ips', []))
            wc_cnames.update(_feat.get('unique_cnames', []))

        real = []
        for item in results:
            prefix = item['subdomain'].split('.')[0].lower()
            item_ips = set(item.get('ips', []))
            item_cnames = set(item.get('cnames', []))

            # 白名单前缀强制保留
            if prefix in WHITELIST_PREFIXES:
                real.append(item)
                continue

            # 智能过滤：如果子域名的 IP/CNAME 与泛解析特征完全重叠，判定为泛解析干扰
            is_wildcard_hit = False
            if wc_ips and item_ips and item_ips.issubset(wc_ips):
                is_wildcard_hit = True
            if wc_cnames and item_cnames and item_cnames.issubset(wc_cnames):
                is_wildcard_hit = True
            # 如果子域名有独立于泛解析特征的 IP/CNAME，认为是真实子域
            if not is_wildcard_hit:
                real.append(item)

        return real
    return results

# ============================================================================
# 缓存模块（单文件集中存储）
# ============================================================================
def _cache_file() -> Path:
    d = Path.home() / ".argus"
    d.mkdir(exist_ok=True)
    return d / "wildcard_cache.json"


def _domain_key(domain: str) -> str:
    return hashlib.md5(domain.lower().encode()).hexdigest()


def load_cache(domain: str) -> Optional[dict]:
    cp = _cache_file()
    if not cp.exists():
        return None
    try:
        store = json.loads(cp.read_text(encoding="utf-8"))
        entry = store.get(_domain_key(domain))
        if entry and (time.time() - entry.get("cached_at", 0)) < CACHE_TTL:
            return entry
    except Exception:
        pass
    return None


def save_cache(domain: str, result: dict):
    cp = _cache_file()
    try:
        store = {}
        if cp.exists():
            store = json.loads(cp.read_text(encoding="utf-8"))

        entry = {k: v for k, v in result.items() if k != "_features"}
        entry["cached_at"] = time.time()
        entry["cache_time"] = datetime.now(timezone.utc).isoformat()
        store[_domain_key(domain)] = entry
        cp.write_text(json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[WARN] 缓存写入失败: {e}")


# ============================================================================
# 输出格式化
# ============================================================================
def format_text(result: dict) -> str:
    wf = "是" if result["wildcard"] else "否"
    lines = [
        f"域名: {result['domain']}",
        f"泛解析: {wf}",
        f"置信度: {result['confidence']}",
        f"解析率: {result['resolve_rate']:.2%}",
        f"探针数: {result['probe_count']} / 成功: {result['resolved_count']}",
        f"唯一IP ({len(result['ips'])}): {', '.join(result['ips']) or '无'}",
        f"唯一CNAME ({len(result['cnames'])}): {', '.join(result['cnames']) or '无'}",
    ]
    features = result.get("_features", {})
    if "round2" in features:
        f2 = features["round2"]
        lines.append(f"二次验证 -> 解析率: {f2['resolve_rate']:.2%} | 唯一IP: {f2['ip_count']}")
    return "\n".join(lines)


def _public_result(result: dict) -> dict:
    """对外输出的干净 JSON 结构（去掉 _features 内部字段）"""
    out = {k: v for k, v in result.items() if k != "_features"}
    return out


# ============================================================================
# CLI 入口
# ============================================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Argus",
        description="Argus · 明日之眼 V1.1 - 工业级泛解析检测 / 爆破去噪 / 高精准",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # 目标
    g = parser.add_argument_group("目标（选一）")
    g.add_argument("-d", "--domain", metavar="DOMAIN", help="单个目标根域名")
    g.add_argument("-b", "--batch", metavar="FILE", help="批量域名文件（每行一个）")

    # 核心算法
    g = parser.add_argument_group("核心算法")
    g.add_argument("-pc", "--probe-count", type=int, default=DEFAULT_PROBE_COUNT, metavar="N",
                   help=f"随机探针数量（默认 {DEFAULT_PROBE_COUNT}）")
    g.add_argument("-t", "--threshold", type=float, default=DEFAULT_THRESHOLD, metavar="F",
                   help=f"解析率阈值 0~1（默认 {DEFAULT_THRESHOLD}）")
    g.add_argument("-ipc", "--ip-converge", type=int, default=DEFAULT_IP_CONVERGE, metavar="N",
                   help=f"IP收敛上限（默认 {DEFAULT_IP_CONVERGE}）")
    g.add_argument("-cnc", "--cname-converge", type=int, default=DEFAULT_CNAME_CONVERGE, metavar="N",
                   help=f"CNAME收敛上限（默认 {DEFAULT_CNAME_CONVERGE}）")

    # DNS
    g = parser.add_argument_group("DNS设置")
    g.add_argument("-to", "--dns-timeout", type=float, default=DEFAULT_DNS_TIMEOUT, metavar="S",
                   help=f"超时秒数（默认 {DEFAULT_DNS_TIMEOUT}）")
    g.add_argument("-rt", "--dns-retry", type=int, default=DEFAULT_DNS_RETRY, metavar="N",
                   help=f"重试次数（默认 {DEFAULT_DNS_RETRY}）")
    g.add_argument("-ds", "--dns-servers", metavar="IP [IP ...]",
                   help="指定DNS服务器，逗号或空格分隔，如 8.8.8.8 114.114.114.114")
    g.add_argument("-qt", "--query-types", default="A,CNAME,AAAA", metavar="TYPES",
                   help="DNS记录类型（默认 A,CNAME,AAAA）")

    # 性能
    g = parser.add_argument_group("性能")
    g.add_argument("-mc", "--max-concurrent", type=int, default=DEFAULT_MAX_CONCURRENT, metavar="N",
                   help=f"最大并发数（默认 {DEFAULT_MAX_CONCURRENT}）")

    # 防误杀
    g = parser.add_argument_group("防误杀")
    g.add_argument("-vr", "--verify-round", type=int, default=DEFAULT_VERIFY_ROUND, choices=[1, 2],
                   metavar="N", help="验证轮次：1=快速 2=严格二次验证（默认 1）")
    g.add_argument("-nw", "--no-whitelist", action="store_true", help="关闭白名单保护")
    g.add_argument("-eip", "--exclude-ips", metavar="IP[,IP...]", help="排除指定IP（逗号分隔）")
    g.add_argument("-ecn", "--exclude-cnames", metavar="CNAME[,CNAME...]", help="排除指定CNAME")

    # 缓存
    g = parser.add_argument_group("缓存")
    g.add_argument("-nc", "--no-cache", action="store_true", help="禁用缓存，强制重新检测")

    # 输出
    g = parser.add_argument_group("输出")
    g.add_argument("-o", "--output", metavar="FILE", help="结果输出文件")
    g.add_argument("-fmt", "--format", default="json", choices=["json", "text"], help="输出格式（默认 json）")
    g.add_argument("-v", "--verbose", action="store_true", help="显示详细信息")
    g.add_argument("-q", "--quiet", action="store_true", help="静默模式（仅结果）")

    # 功能
    g = parser.add_argument_group("功能")
    g.add_argument("-fl", "--filter", metavar="FILE", help="过滤子域名列表文件")
    g.add_argument("-sw", "--skip-wildcard", action="store_true",
                   help="批量模式下：若缓存已有结果，跳过该域名的检测（仅读取缓存）")

    # 子域名爆破
    g = parser.add_argument_group("子域名爆破")
    g.add_argument("-bf", "--bruteforce", action="store_true", help="启用子域名爆破")
    g.add_argument("-wl", "--wordlist", metavar="FILE", help="爆破字典文件路径（省略则使用内置迷你字典）")
    g.add_argument("-bf-o", "--bf-output", metavar="FILE", help="爆破结果输出文件（txt 或 json）")

    return parser


def detect_one(domain: str, args, verbose: bool = False) -> dict:
    domain = normalize_domain(domain)
    if not domain:
        return {"domain": "", "error": "无效域名"}
    if not args.no_cache:
        cached = load_cache(domain)
        if cached:
            if verbose:
                print(f"[CACHE] 使用缓存: {domain}")
            return cached

    if verbose:
        print(f"[SCAN] 检测中: {domain}")

    servers = None
    if args.dns_servers:
        # 兼容空格分隔和逗号分隔
        raw = args.dns_servers.replace(",", " ")
        servers = [s.strip() for s in raw.split() if s.strip()]

    exclude_ips = args.exclude_ips.split(",") if args.exclude_ips else None
    exclude_cnames = args.exclude_cnames.split(",") if args.exclude_cnames else None
    qtypes = args.query_types.split(",")

    result = detect_wildcard(
        domain=domain,
        probe_count=args.probe_count,
        threshold=args.threshold,
        ip_converge=args.ip_converge,
        cname_converge=args.cname_converge,
        qtypes=qtypes,
        servers=servers,
        timeout=args.dns_timeout,
        retry=args.dns_retry,
        max_concurrent=args.max_concurrent,
        verify_round=args.verify_round,
        exclude_ips=exclude_ips,
        exclude_cnames=exclude_cnames,
    )

    if not args.no_cache:
        save_cache(domain, result)

    return result


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.domain and not args.batch:
        parser.print_help()
        return

    # ---- 单域名 / 爆破 ----
    if args.domain:
        result = detect_one(args.domain.strip(), args, verbose=not args.quiet)

        # 爆破模式
        if args.bruteforce:
            if not args.quiet:
                print(f"[BRUTE] 开始爆破: {args.domain}")
            servers = None
            if args.dns_servers:
                raw = args.dns_servers.replace(",", " ")
                servers = [s.strip() for s in raw.split() if s.strip()]

            bf_results = bruteforce_subdomains(
                domain=args.domain.strip(),
                wordlist_path=args.wordlist,
                resolver_servers=servers,
                timeout=args.dns_timeout,
                retry=args.dns_retry,
                max_concurrent=args.max_concurrent,
                wildcard_detection=result if result['wildcard'] else None,
            )

            if not args.quiet:
                print(f"[BRUTE] 找到 {len(bf_results)} 个子域名:")
            for item in bf_results:
                line = item['subdomain']
                if item['ips']:
                    line += ' -> ' + ', '.join(item['ips'])
                print(line)

            # 输出到文件
            if args.bf_output:
                out_lines = [item['subdomain'] for item in bf_results]
                Path(args.bf_output).write_text('\n'.join(out_lines), encoding='utf-8')
                if not args.quiet:
                    print(f"[OK] 爆破结果已保存: {args.bf_output}")
            return

        # 非爆破模式：输出检测结果
        if args.format == "text":
            print(format_text(result))
        else:
            print(json.dumps(_public_result(result), ensure_ascii=False, indent=2))
        if args.output:
            out = format_text(result) if args.format == "text" else json.dumps(_public_result(result), ensure_ascii=False, indent=2)
            Path(args.output).write_text(out, encoding="utf-8")
            if not args.quiet:
                print(f"[OK] 结果已保存: {args.output}")
        return


    # ---- 批量 ----
    batch_path = Path(args.batch)
    if not batch_path.exists():
        print(f"[ERROR] 文件不存在: {args.batch}")
        sys.exit(1)

    domains = [ln.strip() for ln in batch_path.read_text(encoding="utf-8").splitlines()
               if ln.strip() and not ln.startswith("#")]

    if not args.quiet:
        print(f"[BATCH] 共 {len(domains)} 个目标")

    all_results = []
    for i, domain in enumerate(domains, 1):
        # --skip-wildcard 模式：若缓存有效则跳过检测
        if args.skip_wildcard and not args.no_cache:
            cached = load_cache(domain)
            if cached:
                print(f"[{i}/{len(domains)}] [SKIP·缓存] {domain}")
                all_results.append(cached)
                continue

        if not args.quiet:
            print(f"[{i}/{len(domains)}] 检测中: {domain}")
        result = detect_one(domain, args, verbose=args.verbose)
        all_results.append(result)
        if args.format == "text":
            print(format_text(result))

    # 批量输出
    if args.output:
        batch_out = {
            "total": len(all_results),
            "results": [_public_result(r) for r in all_results],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        Path(args.output).write_text(
            json.dumps(batch_out, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        if not args.quiet:
            print(f"[OK] 批量结果已保存: {args.output}")

    # 子域过滤
    if args.filter:
        fp = Path(args.filter)
        if fp.exists():
            subs = [ln.strip() for ln in fp.read_text(encoding="utf-8").splitlines() if ln.strip()]
            # 取第一个域名的检测结果作为过滤基准
            detection = all_results[0] if all_results else {"wildcard": False}
            filtered = filter_subdomains(subs, detection)
            out = str(fp).replace(".txt", "_clean.txt")
            Path(out).write_text("\n".join(filtered), encoding="utf-8")
            if not args.quiet:
                print(f"[OK] 过滤完成: {out}（{len(filtered)}/{len(subs)} 个保留）")


if __name__ == "__main__":
    main()