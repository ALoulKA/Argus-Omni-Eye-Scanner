<div align="center">

# 🛡️ Argus · 明日之眼

**工业级 DNS 泛解析识别工具**

全自动泛解析检测 · 子域名爆破去噪 · 白名单防误杀

[中文](#快速开始) | [English](#quick-start)

</div>
## 🤔 Why Argus?

Because **Layer Subdomain Miner** kept committing suicide whenever I threw a big dictionary at it. 💥

I needed a tool that:
1. Doesn't crash (Priority #1).
2. Actually finishes the scan.
3. Doesn't melt my CPU.

So, I built **Argus**. It's like Layer, but it won't rage-quit on you.

---

## 🤔 为什么要造这个轮子？

因为 **Layer 域名挖掘机** 一吃大字典就当场去世（Core Dump）。💀

作为一个成熟的黑客工具，怎么能动不动就崩？
于是 **Argus（明日之眼）** 诞生了。
它的使命只有一个：**只要你电脑不炸，它就绝不罢工。**
---

## ✨ 特性

- 🔍 **全自动泛解析检测** — 纯 DNS 层探测，无需 HTTP 请求，无人工规则
- 💥 **子域名爆破** — 内置字典 + 自定义字典，自动过滤泛解析干扰
- 🎯 **智能去噪** — 基于 IP/CNAME 收敛聚类，精准区分真实子域与泛解析干扰
- 🛡️ **白名单防误杀** — www / mail / api / admin 等业务子域永不误删
- 🌐 **多 DNS 容灾** — 7 个公共 DNS 服务器自动轮换（阿里/腾讯/114/Google/Cloudflare）
- 🖥️ **GUI + CLI 双模式** — 可视化界面 + 命令行，适配不同场景
- 📦 **单文件 EXE** — PyInstaller 打包，零依赖，双击即用
- 💾 **缓存加速** — 本地 JSON 缓存（TTL 24h），避免重复检测

---

## 🚀 快速开始

### 安装依赖

```bash
pip install dnspython
```

### GUI 模式（推荐）

```bash
python wildcard_gui.py
```

### CLI 模式

```bash
# 单域名泛解析检测
python wildcard_detector.py -d example.com

# 批量检测
python wildcard_detector.py -b domains.txt

# 子域名爆破（自动过滤泛解析）
python wildcard_detector.py -d example.com -bf

# 爆破结果去噪
python wildcard_detector.py -d example.com -fl subdomains.txt
```

### EXE 模式（无需安装 Python）

从 [Releases](../../releases) 下载 `Argus.exe`，双击运行。

---

## 🎯 使用场景

| 场景 | 说明 |
|------|------|
| 渗透测试 | 爆破子域名前自动过滤泛解析干扰，避免浪费精力 |
| 资产测绘 | 批量检测域名泛解析状态，精准识别真实资产 |
| Bug Bounty | 子域名发现后去噪，聚焦高价值目标 |
| 安全审计 | 快速判断域名是否存在泛解析配置风险 |

---

## ⚙️ 参数说明

### 目标类

| 参数 | 缩写 | 默认 | 说明 |
|------|------|------|------|
| `--domain` | `-d` | - | 单个域名 |
| `--batch` | `-b` | - | 批量域名文件 |

### 核心算法类

| 参数 | 缩写 | 默认 | 说明 |
|------|------|------|------|
| `--probe-count` | `-pc` | 8 | 随机探针数量 |
| `--threshold` | `-t` | 0.6 | 泛解析判定阈值（0~1） |
| `--ip-converge` | `-ipc` | 2 | IP 收敛上限 |
| `--cname-converge` | `-cnc` | 2 | CNAME 收敛上限 |

### DNS 设置类

| 参数 | 缩写 | 默认 | 说明 |
|------|------|------|------|
| `--dns-timeout` | `-to` | 2.0 | DNS 超时（秒） |
| `--dns-retry` | `-rt` | 1 | DNS 重试次数 |
| `--dns-server` | `-ds` | 自动 | 指定 DNS 服务器 |

### 输出类

| 参数 | 缩写 | 默认 | 说明 |
|------|------|------|------|
| `--output` | `-o` | - | 输出文件路径 |
| `--quiet` | `-q` | 关闭 | 安静模式 |
| `--verbose` | `-v` | 关闭 | 详细输出 |
| `--verify-round` | `-vr` | 1 | 验证轮次（1=快速 2=深度） |

### 爆破类

| 参数 | 缩写 | 默认 | 说明 |
|------|------|------|------|
| `--bruteforce` | `-bf` | 关闭 | 启用子域名爆破 |
| `--wordlist` | `-wl` | 内置 | 字典文件路径 |
| `--bf-output` | `-bf-o` | - | 爆破结果输出路径 |
| `--max-concurrency` | `-mc` | 16 | 最大并发数 |

### 过滤类

| 参数 | 缩写 | 默认 | 说明 |
|------|------|------|------|
| `--filter` | `-fl` | - | 过滤已有子域名文件 |
| `--whitelist` | - | www,mail,api,... | 白名单子域名（强制保留） |
| `--skip-wildcard` | `-sw` | 关闭 | 跳过泛解析检测（用缓存） |

---

## 🧪 使用示例

```bash
# 快速检测单个域名
python wildcard_detector.py -d example.com

# 深度检测 + 详细输出
python wildcard_detector.py -d example.com -vr 2 -v

# 自定义参数检测
python wildcard_detector.py -d example.com -pc 10 -t 0.7 -vr 2 -o result.json

# 批量检测
python wildcard_detector.py -b domains.txt -o results.json

# 指定 DNS 服务器
python wildcard_detector.py -d example.com -ds 114.114.114.114 8.8.8.8 -mc 32

# 子域名爆破
python wildcard_detector.py -d example.com -bf

# 自定义字典爆破
python wildcard_detector.py -d example.com -bf -wl my_dict.txt -bf-o results.txt

# 过滤已有子域名列表
python wildcard_detector.py -d example.com -fl subdomains.txt -o clean.txt
```

---

## 📊 置信度说明

| 级别 | 条件 | 建议 |
|------|------|------|
| **high** | 解析率 ≥ 阈值，且收敛度强 | 强泛解析，可安全过滤 |
| **medium** | 解析率 ≥ 阈值 × 0.7 | 中度泛解析，建议结合业务判断 |
| **low** | 其他 | 非泛解析或疑似，保留所有子域 |

---

## 🛠️ 打包 EXE

```bash
# 双击 打包脚本.bat，或手动执行：
pip install pyinstaller
pyinstaller --noconsole --onefile --clean --name "Argus · 明日之眼" wildcard_gui.py
```

输出：`dist/Argus · 明日之眼.exe`

---

## 📁 项目结构

```
Argus/
├── wildcard_gui.py          # GUI 主程序
├── wildcard_detector.py     # CLI 核心引擎
├── wordlists/               # 字典文件
│   ├── dic.txt              # 完整字典（16 万条）
│   └── small_dic.txt        # 常用字典（60 条）
├── logo.ico                 # 图标
├── 打包脚本.bat              # 一键打包
├── requirements.txt         # Python 依赖
├── LICENSE                  # MIT 协议
└── README.md
```

---

## ⚠️ 免责声明

本工具仅供安全研究、渗透测试、资产测绘等合法用途。使用者需确保操作已获得授权。未经授权对他人域名进行扫描可能违反相关法律法规，作者不承担任何责任。

---

## 📄 License

[MIT License](LICENSE)
