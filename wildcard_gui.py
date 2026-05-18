# Argus · 明日之眼 - GUI 可视化界面
# 工业级·单文件便携版 V1.1
# 技术栈: Python + tkinter + dnspython + PyInstaller

import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from datetime import datetime, timezone
import json
import hashlib

try:
    import dns.resolver
    import dns.exception
except ImportError:
    tk.messagebox.showerror("依赖缺失", "请先运行: pip install dnspython\n然后重新启动程序")
    sys.exit(1)

from wildcard_detector import (
    detect_wildcard as _detect_core,
    normalize_domain,
    bruteforce_subdomains,
    WHITELIST_PREFIXES,
    DEFAULT_PROBE_COUNT, DEFAULT_THRESHOLD,
    DEFAULT_IP_CONVERGE, DEFAULT_CNAME_CONVERGE,
    DEFAULT_DNS_TIMEOUT, DEFAULT_DNS_RETRY,
    DEFAULT_MAX_CONCURRENT, DEFAULT_VERIFY_ROUND,
    CACHE_TTL,
)

CACHE_FILE = Path.home() / ".argus" / "wildcard_cache.json"
CACHE_FILE.parent.mkdir(exist_ok=True)


# ============================================================================
# 缓存层（与 CLI 共用同一缓存文件）
# ============================================================================
def _domain_key(domain: str) -> str:
    return hashlib.md5(domain.lower().encode()).hexdigest()


def load_cache(domain: str):
    if not CACHE_FILE.exists():
        return None
    try:
        store = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        entry = store.get(_domain_key(domain))
        if entry and (datetime.now().timestamp() - entry.get("cached_at", 0)) < CACHE_TTL:
            return entry
    except Exception:
        pass
    return None


def save_cache(domain: str, result: dict):
    try:
        store = {}
        if CACHE_FILE.exists():
            store = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        entry = {k: v for k, v in result.items() if k != "_features"}
        entry["cached_at"] = datetime.now().timestamp()
        entry["cache_time"] = datetime.now(timezone.utc).isoformat()
        store[_domain_key(domain)] = entry
        CACHE_FILE.write_text(json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


# ============================================================================
# 工具函数
# ============================================================================
def _run(root: tk.Tk, func, *args):
    """在主线程执行 GUI 更新"""
    root.update()


def _public(r: dict) -> dict:
    return {k: v for k, v in r.items() if k != "_features"}


def format_result_gui(result: dict) -> str:
    wf = "✅ 是（泛解析）" if result["wildcard"] else "❌ 否（非泛解析）"
    conf_color = {"high": "🟢", "medium": "🟡", "low": "🔴"}.get(result["confidence"], "")
    ts = datetime.now().strftime("%H:%M:%S")
    feat = result.get("_features", {})
    lines = [
        f"[{ts}] {result['domain']}",
        f"   泛解析判定: {wf}",
        f"   置信度: {conf_color} {result['confidence'].upper()}",
        f"   解析率: {result['resolve_rate']:.2%}  ({result['resolved_count']}/{result['probe_count']} 探针)",
        f"   唯一IP ({len(result['ips'])}): {', '.join(result['ips']) or '无'}",
        f"   唯一CNAME ({len(result['cnames'])}): {', '.join(result['cnames']) or '无'}",
    ]
    if "round2" in feat:
        f2 = feat["round2"]
        lines.append(f"   【二次验证】解析率: {f2['resolve_rate']:.2%} | 唯一IP: {f2['ip_count']} | 唯一CNAME: {f2['cname_count']}")
    return "\n".join(lines)


def filter_subdomains(subs: list[str], detection: dict) -> list[str]:
    return [s for s in subs if not (detection.get("wildcard") and s.split(".")[0].lower() not in WHITELIST_PREFIXES)]


# ============================================================================
# 主界面
# ============================================================================
class WildcardApp:
    VERSION = "V1.1"

    def __init__(self, root: tk.Tk):
        self.root = root
        self._apply_icon()
        self.root.title(f"Argus · 明日之眼 {self.VERSION} - 工业级便携版")
        self.root.geometry("900x720")
        self.root.minsize(800, 600)
        self.root.configure(bg="#f0f0f0")

        self._cache = {}         # session-level fast cache
        self._batch_results = []
        self._filter_subs = []
        self._filter_detection = None

        self._build_title_bar()
        self._build_tabs()

    # ------------------------------------------------------------------
    # 窗口图标
    # ------------------------------------------------------------------
    def _apply_icon(self):
        ico_path = Path(__file__).parent / "logo.ico"
        if ico_path.exists():
            try:
                self.root.iconbitmap(str(ico_path))
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 标题栏
    # ------------------------------------------------------------------
    def _build_title_bar(self):
        bar = tk.Frame(self.root, bg="#1a1a2e", height=52)
        bar.pack(fill="x", padx=0, pady=0)

        tk.Label(bar, text=f"Argus · 明日之眼  {self.VERSION}", fg="white",
                 bg="#1a1a2e").pack(side="left", padx=16, pady=10)

        tk.Label(bar, text="工业级 · 零依赖 · 零安装 · 双模式", fg="#aaaaff",
                 bg="#1a1a2e").pack(side="left", padx=20, pady=0)

        tk.Label(bar, text="by ASUKA", fg="#666688",
                 bg="#1a1a2e").pack(side="right", padx=12, pady=0)

    # ------------------------------------------------------------------
    # 标签页
    # ------------------------------------------------------------------
    def _build_tabs(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=(6, 10))
        nb.add(self._build_single_tab(), text="① 单域名检测")
        nb.add(self._build_batch_tab(), text="② 批量域名检测")
        nb.add(self._build_bruteforce_tab(), text="③ 子域名爆破")
        nb.add(self._build_batch_bf_tab(), text="⑥ 批量子域名爆破")
        nb.add(self._build_filter_tab(), text="④ 爆破结果去噪")
        nb.add(self._build_settings_tab(), text="⚙ 高级设置")

    # ------------------------------------------------------------------
    # Tab1：单域名检测
    # ------------------------------------------------------------------
    def _build_single_tab(self):
        frm = ttk.Frame(padding=10)

        # 操作栏
        ctrl = ttk.Frame(frm)
        ctrl.pack(fill="x", pady=(0, 8))
        ttk.Label(ctrl, text="目标域名").pack(side="left")
        self._s_domain = ttk.Entry(ctrl, width=42)
        self._s_domain.pack(side="left", padx=8, fill="x", expand=True)
        self._s_domain.bind("<Return>", lambda e: self._on_single())
        ttk.Button(ctrl, text="开始检测", command=self._on_single,
                  width=12).pack(side="left", padx=6)
        ttk.Button(ctrl, text="导出JSON", command=self._on_single_export,
                  width=10).pack(side="left")

        # 状态标签
        self._s_status = ttk.Label(frm, text="就绪", foreground="#666666")
        self._s_status.pack(anchor="w", pady=(0, 4))

        # 结果区
        self._s_txt = scrolledtext.ScrolledText(frm, height=22,
                                                state="disabled",
                                                relief="solid", bd=1,
                                                bg="#1e1e2e", fg="#d4d4d4",
                                                insertbackground="white")
        self._s_txt.pack(fill="both", expand=True)
        self._s_txt.tag_config("ok", foreground="#4ec9b0")
        self._s_txt.tag_config("warn", foreground="#ce9178")

        return frm

    def _on_single(self):
        domain = normalize_domain(self._s_domain.get().strip())
        if not domain:
            self._s_status.config(text="⚠ 请输入目标域名", foreground="#e06000")
            return
        self._s_status.config(text="检测中…", foreground="#888888")
        threading.Thread(target=self._do_single, args=(domain,), daemon=True).start()

    def _do_single(self, domain: str):
        # 检测
        cached = None
        if not hasattr(self, '_s_nocache') or not self._s_nocache:
            cached = load_cache(domain)
        if cached:
            result = cached
        else:
            result = _detect_core(domain,
                                  probe_count=self._cfg_probe.get(),
                                  threshold=self._cfg_thresh.get(),
                                  ip_converge=self._cfg_ipc.get(),
                                  cname_converge=self._cfg_cnc.get(),
                                  servers=self._cfg_dns_list(),
                                  timeout=self._cfg_timeout.get(),
                                  retry=self._cfg_retry.get(),
                                  max_concurrent=self._cfg_conc.get(),
                                  verify_round=self._cfg_vr.get())
            save_cache(domain, result)

        # GUI 更新
        def update():
            self._s_txt.config(state="normal")
            # 记录插入前的位置
            start = self._s_txt.index("end-1c")
            self._s_txt.insert("end", "\n" + format_result_gui(result) + "\n")
            self._s_txt.see("end")
            end = self._s_txt.index("end-1c")
            self._s_txt.config(state="disabled")
            tag = "ok" if not result["wildcard"] else "warn"
            self._s_txt.tag_add(tag, start, end)
            src = "【缓存】" if cached else "【新检测】"
            self._s_status.config(text=f"{src} 完成 - {domain}", foreground="#4ec9b0")

        self.root.after(0, update)

    def _on_single_export(self):
        txt = self._s_txt.get("1.0", "end").strip()
        if not txt:
            messagebox.showwarning("无内容", "请先执行检测")
            return
        path = filedialog.asksaveasfilename(title="导出结果",
                                            defaultextension=".json",
                                            filetypes=[("JSON文件", "*.json")])
        if path:
            Path(path).write_text(json.dumps({"raw": txt}, ensure_ascii=False, indent=2), encoding="utf-8")
            messagebox.showinfo("导出成功", f"已保存: {path}")

    # ------------------------------------------------------------------
    # Tab2：批量域名检测
    # ------------------------------------------------------------------
    def _build_batch_tab(self):
        frm = ttk.Frame(padding=10)

        ctrl = ttk.Frame(frm)
        ctrl.pack(fill="x", pady=(0, 6))
        ttk.Label(ctrl, text="域名文件").pack(side="left")
        self._b_file = ttk.Entry(ctrl, width=44)
        self._b_file.pack(side="left", padx=8, fill="x", expand=True)
        ttk.Button(ctrl, text="浏览…", command=self._browse_batch,
                   width=8).pack(side="left")
        ttk.Button(ctrl, text="批量检测", command=self._on_batch,
                   width=10).pack(side="left", padx=6)
        ttk.Button(ctrl, text="导出结果", command=self._on_batch_export,
                   width=10).pack(side="left")

        self._b_count = ttk.Label(frm, text="未导入文件", foreground="#888888")
        self._b_count.pack(anchor="w", pady=(0, 4))

        # 进度条
        self._b_prog = ttk.Progressbar(frm, mode="determinate")
        self._b_prog.pack(fill="x", pady=(0, 6))

        # 表格
        cols = ("域名", "泛解析", "置信度", "解析率", "唯一IP", "唯一CNAME")
        self._b_tree = ttk.Treeview(frm, columns=cols, show="headings", height=20)
        col_widths = (200, 65, 70, 70, 70, 100)
        for col, w in zip(cols, col_widths):
            self._b_tree.heading(col, text=col)
            self._b_tree.column(col, width=w, anchor="center")
        self._b_tree.column("域名", anchor="w")
        sv = ttk.Scrollbar(frm, orient="vertical", command=self._b_tree.yview)
        self._b_tree.configure(yscrollcommand=sv.set)
        self._b_tree.pack(fill="both", expand=True, side="left")
        sv.pack(fill="y", side="right")

        self._batch_domains = []
        self._batch_results = []

        return frm

    def _browse_batch(self):
        path = filedialog.askopenfilename(title="选择域名文件", filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if path:
            self._b_file.delete(0, "end")
            self._b_file.insert(0, path)
            lines = [ln.strip() for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
            self._batch_domains = [ln for ln in lines if not ln.startswith("#")]
            self._b_count.config(text=f"已导入 {len(self._batch_domains)} 个域名")

    def _on_batch(self):
        if not self._batch_domains:
            messagebox.showwarning("未导入", "请先导入域名文件")
            return
        threading.Thread(target=self._do_batch, daemon=True).start()

    def _do_batch(self):
        self._batch_results.clear()
        n = len(self._batch_domains)

        def clear_tree():
            for item in self._b_tree.get_children():
                self._b_tree.delete(item)
        self.root.after(0, clear_tree)
        self.root.after(0, lambda: self._b_prog.config(maximum=n, value=0))

        for i, domain in enumerate(self._batch_domains, 1):
            cached = load_cache(domain)
            if cached:
                result = cached
            else:
                result = _detect_core(domain,
                                      probe_count=self._cfg_probe.get(),
                                      threshold=self._cfg_thresh.get(),
                                      ip_converge=self._cfg_ipc.get(),
                                      cname_converge=self._cfg_cnc.get(),
                                      servers=self._cfg_dns_list(),
                                      timeout=self._cfg_timeout.get(),
                                      retry=self._cfg_retry.get(),
                                      max_concurrent=self._cfg_conc.get(),
                                      verify_round=self._cfg_vr.get())
                save_cache(domain, result)
            self._batch_results.append(result)

            def insert_row():
                r = result
                self._b_tree.insert("", "end", values=(
                    r["domain"],
                    "是" if r["wildcard"] else "否",
                    r["confidence"],
                    f"{r['resolve_rate']:.2%}",
                    r["ip_count"] if "ip_count" in r else len(r["ips"]),
                    r["cname_count"] if "cname_count" in r else len(r["cnames"]),
                ))
                self._b_prog.config(value=i)
                self._b_count.config(text=f"检测中 {i}/{n}：{domain}")

            self.root.after(0, insert_row)

        def done():
            self._b_count.config(text=f"批量检测完成，共 {n} 个域名")
        self.root.after(0, done)

    def _on_batch_export(self):
        if not self._batch_results:
            messagebox.showwarning("无结果", "请先执行批量检测")
            return
        path = filedialog.asksaveasfilename(title="导出批量结果",
                                            defaultextension=".json",
                                            filetypes=[("JSON文件", "*.json"), ("文本文件", "*.txt")])
        if not path:
            return
        if path.endswith(".json"):
            data = {"total": len(self._batch_results),
                    "results": [_public(r) for r in self._batch_results],
                    "generated_at": datetime.now(timezone.utc).isoformat()}
            Path(path).write_text(json.dumps(data, ensure_asascii=False, indent=2), encoding="utf-8")
        else:
            Path(path).write_text("\n---\n".join(format_result_gui(r) for r in self._batch_results), encoding="utf-8")
        messagebox.showinfo("导出成功", f"结果已保存:\n{path}")

    # ------------------------------------------------------------------
    # Tab3：子域爆破去噪
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Tab③：子域名爆破
    # ------------------------------------------------------------------
    def _build_bruteforce_tab(self):
        frm = ttk.Frame(padding=10)
        self._bf_results = []

        # ---- 控制栏 ----
        ctrl = ttk.Frame(frm)
        ctrl.pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="目标域名").pack(side="left")
        self._bf_domain = ttk.Entry(ctrl, width=36)
        self._bf_domain.pack(side="left", padx=6)
        self._bf_domain.insert(0, "example.com")

        ttk.Button(ctrl, text="选择字典…", command=self._on_bf_choose_wordlist,
                   width=12).pack(side="left", padx=(12, 4))
        self._bf_wl_var = tk.StringVar(value="（内置迷你字典）")
        ttk.Label(ctrl, textvariable=self._bf_wl_var, foreground="#444444").pack(side="left", padx=4)

        self._bf_start_btn = ttk.Button(ctrl, text="开始爆破", command=self._on_bf_start,
                   width=12)
        self._bf_start_btn.pack(side="left", padx=(18, 4))
        self._bf_stop_btn = ttk.Button(ctrl, text="终止", command=self._on_bf_stop,
                   width=10, state="disabled")
        self._bf_stop_btn.pack(side="left", padx=6)
        ttk.Button(ctrl, text="导出结果", command=self._on_bf_export,
                   width=10).pack(side="left")

        # ---- 设置行 ----
        settings = ttk.Frame(frm)
        settings.pack(fill="x", pady=(0, 8))

        ttk.Label(settings, text="超时(s)").pack(side="left", padx=(0, 4))
        self._bf_timeout = ttk.Spinbox(settings, from_=1, to=30, width=5)
        self._bf_timeout.set(2)
        self._bf_timeout.pack(side="left", padx=(0, 12))

        ttk.Label(settings, text="重试").pack(side="left", padx=(0, 4))
        self._bf_retry = ttk.Spinbox(settings, from_=0, to=5, width=4)
        self._bf_retry.set(1)
        self._bf_retry.pack(side="left", padx=(0, 12))

        ttk.Label(settings, text="并发数").pack(side="left", padx=(0, 4))
        self._bf_concur = ttk.Spinbox(settings, from_=1, to=200, width=6)
        self._bf_concur.set(50)
        self._bf_concur.pack(side="left", padx=(0, 12))

        ttk.Label(settings, text="DNS服务器（空=系统）").pack(side="left", padx=(0, 4))
        self._bf_dns = ttk.Entry(settings, width=24)
        self._bf_dns.pack(side="left", padx=(0, 4))

        # ---- 状态栏 + 进度条 ----
        status_frm = ttk.Frame(frm)
        status_frm.pack(fill="x", pady=(0, 4))
        
        self._bf_status = ttk.Label(status_frm, text="就绪", foreground="#666666")
        self._bf_status.pack(side="left")
        
        self._bf_progress = ttk.Progressbar(status_frm, mode="determinate", length=300)
        self._bf_progress.pack(side="right", padx=(8, 0))
        self._bf_progress_var = tk.DoubleVar(value=0)

        # ---- 结果表格 ----
        cols = ("#", "子域名", "IP/CNAME")
        self._bf_tree = ttk.Treeview(frm, columns=cols, show="headings", height=22)
        for col, w in zip(cols, (50, 260, 500)):
            self._bf_tree.heading(col, text=col)
            self._bf_tree.column(col, width=w, anchor="w")
        self._bf_tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(frm, orient="vertical", command=self._bf_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self._bf_tree.configure(yscrollcommand=scrollbar.set)

        return frm

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def _on_bf_choose_wordlist(self):
        fp = filedialog.askopenfilename(
            title="选择爆破字典文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if fp:
            self._bf_wl_path = fp
            self._bf_wl_var.set(Path(fp).name)
        else:
            self._bf_wl_path = None
            self._bf_wl_var.set("（内置迷你字典）")

    def _on_bf_start(self):
        domain = normalize_domain(self._bf_domain.get().strip())
        if not domain:
            messagebox.showwarning("提示", "请输入目标域名")
            return

        # 清空旧结果
        for item in self._bf_tree.get_children():
            self._bf_tree.delete(item)
        self._bf_results = []

        self._bf_stop_event = threading.Event()
        self._bf_start_btn.config(state="disabled")
        self._bf_stop_btn.config(state="normal")
        self._bf_status.config(text="检测泛解析 + 爆破中…")
        threading.Thread(target=self._bf_worker, args=(domain,), daemon=True).start()

    def _bf_worker(self, domain):
        import json as _json
        
        # 进度回调（在主线程更新 UI）
        def on_progress(pct, found, total):
            def _update():
                self._bf_progress["value"] = pct * 100
                self._bf_status.config(text=f"爆破中... {found}/{total} ({int(pct*100)}%)")
            self.root.after(0, _update)
        
        # 1) 先检测泛解析
        self.root.after(0, lambda: self._bf_status.config(text="检测泛解析中..."))
        detection = _detect_core(
            domain, probe_count=DEFAULT_PROBE_COUNT, threshold=DEFAULT_THRESHOLD,
            ip_converge=DEFAULT_IP_CONVERGE, cname_converge=DEFAULT_CNAME_CONVERGE,
            timeout=float(self._bf_timeout.get()), retry=int(self._bf_retry.get()),
            max_concurrent=int(self._bf_concur.get()), verify_round=DEFAULT_VERIFY_ROUND,
            exclude_ips=set(), exclude_cnames=set()
        )
        wildcard = detection.get("wildcard", False)
        
        # 2) 爆破（带进度回调）
        wl_path = getattr(self, "_bf_wl_path", None)
        servers = None
        dns_str = self._bf_dns.get().strip()
        if dns_str:
            raw = dns_str.replace(",", " ")
            servers = [s.strip() for s in raw.split() if s.strip()]

        self.root.after(0, lambda: self._bf_status.config(text="开始爆破子域名..."))
        results = bruteforce_subdomains(
            domain=domain,
            wordlist_path=wl_path,
            resolver_servers=servers,
            timeout=float(self._bf_timeout.get()),
            retry=int(self._bf_retry.get()),
            max_concurrent=int(self._bf_concur.get()),
            wildcard_detection=detection if wildcard else None,
            progress_callback=on_progress,
            stop_event=self._bf_stop_event,
        )

        self._bf_results = results
        found = len(results)
        wf = "（泛解析开启，已自动过滤）" if wildcard else "（非泛解析）"

        # 更新 UI（主线程）
        def update():
            try:
                self._bf_progress["value"] = 100
                print(f"[DEBUG] 爆破完成，共 {len(results)} 个结果")
                for i, item in enumerate(results, 1):
                    sub = item["subdomain"]
                    ips = ", ".join(item.get("ips", []))
                    print(f"[DEBUG] 插入: {i} {sub} {ips}")
                    self._bf_tree.insert("", "end", values=(i, sub, ips))
                self._bf_status.config(text=f"完成：找到 {found} 个子域名 {wf}")
                print(f"[DEBUG] 状态栏已更新")
            except Exception as e:
                import traceback
                print(f"[ERROR] update() 异常: {e}")
                traceback.print_exc()
            finally:
                # 恢复按钮状态
                self._bf_start_btn.config(state="normal")
                self._bf_stop_btn.config(state="disabled")
        self.root.after(0, update)

    def _on_bf_stop(self):
        if hasattr(self, '_bf_stop_event'):
            self._bf_stop_event.set()
            self._bf_status.config(text="正在终止...")
            self._bf_stop_btn.config(state="disabled")

    def _on_bf_export(self):
        if not self._bf_results:
            messagebox.showinfo("提示", "暂无爆破结果可导出")
            return
        result_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result")
        os.makedirs(result_dir, exist_ok=True)
        fp = filedialog.asksaveasfilename(
            title="保存爆破结果",
            initialdir=result_dir,
            defaultextension=".txt",
            filetypes=[
                ("文本文件", "*.txt"),
                ("CSV 文件", "*.csv"),
                ("Excel 文件", "*.xlsx"),
                ("JSON 文件", "*.json"),
                ("所有文件", "*.*")
            ]
        )
        if not fp:
            return
        try:
            if fp.endswith(".json"):
                _json.dump(self._bf_results, open(fp, "w", encoding="utf-8"),
                           ensure_ascii=False, indent=2)
            elif fp.endswith(".csv"):
                import csv
                with open(fp, "w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["序号", "子域名", "IP地址"])
                    for i, item in enumerate(self._bf_results, 1):
                        sub = item["subdomain"]
                        ips = ", ".join(item.get("ips", []))
                        writer.writerow([i, sub, ips])
            elif fp.endswith(".xlsx"):
                from openpyxl import Workbook
                wb = Workbook()
                ws = wb.active
                ws.title = "爆破结果"
                ws.append(["序号", "子域名", "IP地址"])
                for i, item in enumerate(self._bf_results, 1):
                    sub = item["subdomain"]
                    ips = ", ".join(item.get("ips", []))
                    ws.append([i, sub, ips])
                wb.save(fp)
            else:  # .txt 或其他格式
                lines_out = [item["subdomain"] for item in self._bf_results]
                open(fp, "w", encoding="utf-8").write("\n".join(lines_out))
            messagebox.showinfo("导出成功", f"结果已保存至：\n{fp}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    # ----------------------------------------------------------------

    # Tab⑥：批量子域名爆破
    # ----------------------------------------------------------------
    def _build_batch_bf_tab(self):
        frm = ttk.Frame(padding=10)
        self._bb_results = []  # list of (domain, results_list)

        # ---- 控制栏 ----
        ctrl = ttk.Frame(frm)
        ctrl.pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="域名文件").pack(side="left")
        self._bb_file = ttk.Entry(ctrl, width=36)
        self._bb_file.pack(side="left", padx=6)
        ttk.Button(ctrl, text="浏览…", command=self._on_bb_choose_file,
                   width=8).pack(side="left", padx=4)

        ttk.Button(ctrl, text="选择字典…", command=self._on_bb_choose_wordlist,
                   width=12).pack(side="left", padx=(14, 4))
        self._bb_wl_var = tk.StringVar(value="（内置迷你字典）")
        ttk.Label(ctrl, textvariable=self._bb_wl_var, foreground="#444444").pack(side="left", padx=4)

        ttk.Button(ctrl, text="开始爆破", command=self._on_bb_start,
                   width=12).pack(side="left", padx=(16, 4))
        ttk.Button(ctrl, text="导出结果", command=self._on_bb_export,
                   width=10).pack(side="left")

        # ---- 设置行 ----
        settings = ttk.Frame(frm)
        settings.pack(fill="x", pady=(0, 8))

        ttk.Label(settings, text="超时(s)").pack(side="left", padx=(0, 4))
        self._bb_timeout = ttk.Spinbox(settings, from_=1, to=30, width=5)
        self._bb_timeout.set(2)
        self._bb_timeout.pack(side="left", padx=(0, 12))

        ttk.Label(settings, text="重试").pack(side="left", padx=(0, 4))
        self._bb_retry = ttk.Spinbox(settings, from_=0, to=5, width=4)
        self._bb_retry.set(1)
        self._bb_retry.pack(side="left", padx=(0, 12))

        ttk.Label(settings, text="并发数").pack(side="left", padx=(0, 4))
        self._bb_concur = ttk.Spinbox(settings, from_=1, to=200, width=6)
        self._bb_concur.set(50)
        self._bb_concur.pack(side="left", padx=(0, 12))

        ttk.Label(settings, text="域名最大并发").pack(side="left", padx=(0, 4))
        self._bb_domain_concur = ttk.Spinbox(settings, from_=1, to=20, width=5)
        self._bb_domain_concur.set(5)
        self._bb_domain_concur.pack(side="left", padx=(0, 12))

        ttk.Label(settings, text="DNS服务器（空=系统）").pack(side="left", padx=(0, 4))
        self._bb_dns = ttk.Entry(settings, width=20)
        self._bb_dns.pack(side="left", padx=(0, 4))

        # ---- 进度条 ----
        progress_frame = ttk.Frame(frm)
        progress_frame.pack(fill="x", pady=(0, 6))
        self._bb_progress = ttk.Progressbar(progress_frame, length=200, mode="determinate")
        self._bb_progress.pack(fill="x", expand=True)

        # ---- 状态栏 ----
        self._bb_status = ttk.Label(frm, text="就绪", foreground="#666666")
        self._bb_status.pack(anchor="w", pady=(0, 4))

        # ---- 结果表格 ----
        cols = ("#", "域名", "子域名数", "泛解析", "状态", "IP/CNAME 样例")
        self._bb_tree = ttk.Treeview(frm, columns=cols, show="headings", height=20)
        widths = (50, 200, 80, 70, 60, 300)
        for col, w in zip(cols, widths):
            self._bb_tree.heading(col, text=col)
            self._bb_tree.column(col, width=w, anchor="w")
        self._bb_tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(frm, orient="vertical", command=self._bb_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self._bb_tree.configure(yscrollcommand=scrollbar.set)

        return frm

    def _on_bb_choose_file(self):
        fp = filedialog.askopenfilename(
            title="选择域名列表文件",
            filetypes=[("文本文件", "*.txt"), ("CSV", "*.csv"), ("所有文件", "*.*")]
        )
        if fp:
            self._bb_domain_file = fp
            self._bb_file.delete(0, "end")
            self._bb_file.insert(0, fp)

    def _on_bb_choose_wordlist(self):
        fp = filedialog.askopenfilename(
            title="选择爆破字典文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if fp:
            self._bb_wl_path = fp
            self._bb_wl_var.set(Path(fp).name)
        else:
            self._bb_wl_path = None
            self._bb_wl_var.set("（内置迷你字典）")

    def _on_bb_start(self):
        file_path = self._bb_file.get().strip()
        if not file_path or not Path(file_path).is_file():
            messagebox.showwarning("提示", "请选择有效的域名列表文件")
            return

        # 清空旧结果
        for item in self._bb_tree.get_children():
            self._bb_tree.delete(item)
        self._bb_results = []

        self._bb_status.config(text="加载域名中…")
        threading.Thread(target=self._bb_worker, daemon=True).start()

    def _bb_worker(self):
        import json as _json
        file_path = self._bb_file.get().strip()

        # 加载域名列表
        try:
            with open(file_path, encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception as e:
            self.root.after(0, lambda: self._bb_status.config(text=f"文件读取失败: {e}"))
            return

        domains = []
        for line in lines:
            domain = normalize_domain(line)
            if domain:
                domains.append(domain)

        if not domains:
            self.root.after(0, lambda: self._bb_status.config(text="文件中未找到有效域名"))
            return

        total = len(domains)
        self.root.after(0, lambda: self._bb_status.config(text=f"共 {total} 个域名，开始爆破…"))

        servers = None
        dns_str = self._bb_dns.get().strip()
        if dns_str:
            raw = dns_str.replace(",", " ")
            servers = [s.strip() for s in raw.split() if s.strip()]

        timeout = float(self._bb_timeout.get())
        retry = int(self._bb_retry.get())
        max_concurrent = int(self._bb_concur.get())
        domain_concur = int(self._bb_domain_concur.get())
        wl_path = getattr(self, "_bb_wl_path", None)

        completed = 0
        results = []
        lock = threading.Lock()

        def process_domain(domain):
            nonlocal completed
            try:
                # 先检测泛解析
                detection = _detect_core(
                    domain, probe_count=DEFAULT_PROBE_COUNT, threshold=DEFAULT_THRESHOLD,
                    ip_converge=DEFAULT_IP_CONVERGE, cname_converge=DEFAULT_CNAME_CONVERGE,
                    timeout=timeout, retry=retry,
                    max_concurrent=max_concurrent, verify_round=DEFAULT_VERIFY_ROUND,
                    exclude_ips=set(), exclude_cnames=set()
                )
                wildcard = detection.get("wildcard", False)

                # 爆破
                sub_results = bruteforce_subdomains(
                    domain=domain,
                    wordlist_path=wl_path,
                    resolver_servers=servers,
                    timeout=timeout, retry=retry,
                    max_concurrent=max_concurrent,
                    wildcard_detection=detection if wildcard else None,
                )

                with lock:
                    results.append({"domain": domain, "wildcard": wildcard, "subs": sub_results})
                    completed += 1
                    pct = int(completed / total * 100)
                    self.root.after(0, lambda p=pct: self._bb_progress.config(value=p))
                    self.root.after(0, lambda c=completed: self._bb_status.config(text=f"进度 {c}/{total} ({pct}%)"))
            except Exception as e:
                with lock:
                    completed += 1
                    results.append({"domain": domain, "wildcard": False, "subs": [], "error": str(e)})
                    pct = int(completed / total * 100)
                    self.root.after(0, lambda p=pct: self._bb_progress.config(value=p))

        threads = []
        for domain in domains:
            t = threading.Thread(target=process_domain, daemon=True)
            t.start()
            threads.append(t)
            # 控制域名级并发
            active = sum(1 for t in threads if t.is_alive())
            if active >= domain_concur:
                # 等待一个完成再继续
                for i, tt in enumerate(threads):
                    tt.join(timeout=30)
                    if not tt.is_alive():
                        threads[i] = None
                threads = [t for t in threads if t is not None]

        for t in threads:
            t.join()

        self._bb_results = results

        def update():
            for i, r in enumerate(results, 1):
                domain = r["domain"]
                subs = r["subs"]
                wf = "是" if r.get("wildcard") else "否"
                sub_count = len(subs)
                sample = ""
                if subs:
                    ips = ", ".join(subs[0].get("ips", []))
                    sample = f"{subs[0]['subdomain']} -> {ips}"
                    if len(sample) > 50:
                        sample = sample[:50] + "…"
                status = "成功" if sub_count > 0 else ("失败" if r.get("error") else "无结果")
                self._bb_tree.insert("", "end", values=(i, domain, sub_count, wf, status, sample))

            total_subs = sum(len(r["subs"]) for r in results)
            total_wf = sum(1 for r in results if r.get("wildcard"))
            self._bb_progress.config(value=100)
            self._bb_status.config(text=f"完成：{total} 个域名，{total_subs} 个子域名，{total_wf} 个泛解析")

        self.root.after(0, update)

    def _on_bb_export(self):
        if not self._bb_results:
            messagebox.showinfo("提示", "暂无爆破结果可导出")
            return
        fp = filedialog.asksaveasfilename(
            title="保存爆破结果",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("CSV", "*.csv"), ("JSON", "*.json")]
        )
        if not fp:
            return
        try:
            if fp.endswith(".csv"):
                import csv
                with open(fp, "w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f)
                    writer.writerow(["域名", "子域名", "IP"])
                    for r in self._bb_results:
                        for sub in r["subs"]:
                            writer.writerow([r["domain"], sub["subdomain"], ", ".join(sub.get("ips", []))])
            elif fp.endswith(".json"):
                import json
                with open(fp, "w", encoding="utf-8") as f:
                    json.dump(self._bb_results, f, ensure_ascii=False, indent=2)
            else:
                with open(fp, "w", encoding="utf-8") as f:
                    for r in self._bb_results:
                        f.write(f"=== {r['domain']} {'[泛解析]' if r.get('wildcard') else ''} ===\n")
                        for sub in r["subs"]:
                            ips = ", ".join(sub.get("ips", []))
                            f.write(f"  {sub['subdomain']} -> {ips}\n")
                        if not r["subs"]:
                            f.write("  (无子域名)\n")
            messagebox.showinfo("完成", f"结果已导出至:\n{fp}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    # ----------------------------------------------------------------

    def _build_filter_tab(self):
        frm = ttk.Frame(padding=10)

        row1 = ttk.Frame(frm)
        row1.pack(fill="x", pady=(0, 6))

        ttk.Label(row1, text="根域名").pack(side="left")
        self._f_root = ttk.Entry(row1, width=24)
        self._f_root.pack(side="left", padx=6)
        ttk.Button(row1, text="① 检测泛解析", command=self._on_filter_detect,
                   width=14).pack(side="left", padx=4)

        ttk.Label(row1, text="子域文件").pack(side="left", padx=(12, 0))
        self._f_file = ttk.Entry(row1, width=24)
        self._f_file.pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(row1, text="浏览…", command=self._browse_filter,
                   width=7).pack(side="left")
        ttk.Button(row1, text="② 执行过滤", command=self._on_filter_apply,
                   width=14).pack(side="left", padx=4)
        ttk.Button(row1, text="导出结果", command=self._on_filter_export,
                   width=10).pack(side="left")

        self._f_info = ttk.Label(frm, text="请先检测根域名泛解析状态，再导入子域文件执行过滤",
                                 foreground="#888888")
        self._f_info.pack(anchor="w", pady=(0, 4))

        self._f_prog = ttk.Progressbar(frm, mode="determinate")
        self._f_prog.pack(fill="x", pady=(0, 6))

        # 结果表格
        cols = ("子域名", "状态", "说明")
        self._f_tree = ttk.Treeview(frm, columns=cols, show="headings", height=20)
        widths = (300, 90, 200)
        for col, w in zip(cols, widths):
            self._f_tree.heading(col, text=col)
            self._f_tree.column(col, width=w)
        sv = ttk.Scrollbar(frm, orient="vertical", command=self._f_tree.yview)
        self._f_tree.configure(yscrollcommand=sv.set)
        self._f_tree.pack(fill="both", expand=True, side="left")
        sv.pack(fill="y", side="right")

        self._filter_subs = []
        self._filter_detection = None

        return frm

    def _on_filter_detect(self):
        domain = normalize_domain(self._f_root.get().strip())
        if not domain:
            messagebox.showwarning("输入为空", "请输入根域名")
            return
        self._f_info.config(text=f"正在检测: {domain}", foreground="#888888")
        threading.Thread(target=self._do_filter_detect, args=(domain,), daemon=True).start()

    def _do_filter_detect(self, domain: str):
        cached = load_cache(domain)
        if cached:
            self._filter_detection = cached
        else:
            self._filter_detection = _detect_core(domain,
                                                  probe_count=self._cfg_probe.get(),
                                                  threshold=self._cfg_thresh.get(),
                                                  ip_converge=self._cfg_ipc.get(),
                                                  cname_converge=self._cfg_cnc.get(),
                                                  servers=self._cfg_dns_list(),
                                                  timeout=self._cfg_timeout.get(),
                                                  retry=self._cfg_retry.get(),
                                                  max_concurrent=self._cfg_conc.get(),
                                                  verify_round=self._cfg_vr.get())
            save_cache(domain, self._filter_detection)

        def update():
            d = self._filter_detection
            wf = "是" if d["wildcard"] else "否"
            self._f_info.config(
                text=f"检测完成 | 域名: {domain} | 泛解析: {wf} | "
                     f"置信度: {d['confidence']} | 唯一IP: {len(d['ips'])} | 唯一CNAME: {len(d['cnames'])}",
                foreground="#4ec9b0"
            )
        self.root.after(0, update)

    def _browse_filter(self):
        path = filedialog.askopenfilename(title="选择子域文件", filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if path:
            self._f_file.delete(0, "end")
            self._f_file.insert(0, path)
            lines = [ln.strip() for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
            self._filter_subs = lines
            self._f_info.config(text=f"已导入 {len(self._filter_subs)} 个子域，请点击【② 执行过滤】", foreground="#e06000")

    def _on_filter_apply(self):
        if not self._filter_detection:
            messagebox.showwarning("未检测", "请先对根域名执行泛解析检测")
            return
        if not self._filter_subs:
            messagebox.showwarning("未导入", "请先导入子域文件")
            return
        self._f_info.config(text=f"正在过滤 {len(self._filter_subs)} 个子域…", foreground="#888888")
        self._f_prog.config(maximum=len(self._filter_subs), value=0)
        threading.Thread(target=self._do_filter_apply, daemon=True).start()

    def _do_filter_apply(self):
        detection = self._filter_detection
        subs = self._filter_subs

        def clear():
            for item in self._f_tree.get_children():
                self._f_tree.delete(item)
        self.root.after(0, clear)

        kept = 0
        for i, sub in enumerate(subs):
            prefix = sub.split(".")[0].lower()
            if prefix in WHITELIST_PREFIXES:
                tag = "whitelist"
                desc = "白名单保留"
            elif detection.get("wildcard"):
                tag = "real"
                desc = "真实子域 ✅"
                kept += 1
            else:
                tag = "real"
                desc = "真实子域 ✅"
                kept += 1

            def insert(s=sub, t=tag, d=desc, idx=i):
                self._f_tree.insert("", "end", values=(s, t, d))
                self._f_prog.config(value=idx + 1)

            self.root.after(0, insert)

        def done():
            self._f_info.config(
                text=f"过滤完成：{kept}/{len(subs)} 个真实子域保留（{len(subs) - kept} 个被过滤）",
                foreground="#4ec9b0"
            )
        self.root.after(0, done)

    def _on_filter_export(self):
        items = self._f_tree.get_children()
        if not items:
            messagebox.showwarning("无结果", "请先执行过滤")
            return
        path = filedialog.asksaveasfilename(title="导出过滤结果",
                                            defaultextension=".txt",
                                            filetypes=[("文本文件", "*.txt"), ("JSON文件", "*.json")])
        if not path:
            return
        if path.endswith(".json"):
            rows = [{"subdomain": self._f_tree.item(it, "values")[0],
                     "status": self._f_tree.item(it, "values")[1],
                     "note": self._f_tree.item(it, "values")[2]}
                    for it in items]
            Path(path).write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            lines = [self._f_tree.item(it, "values")[0] for it in items]
            Path(path).write_text("\n".join(lines), encoding="utf-8")
        messagebox.showinfo("导出成功", f"已保存: {path}")

    # ------------------------------------------------------------------
    # Tab4：高级设置
    # ------------------------------------------------------------------
    def _build_settings_tab(self):
        frm = ttk.Frame(padding=16)

        self._cfg_probe   = tk.IntVar(value=DEFAULT_PROBE_COUNT)
        self._cfg_thresh  = tk.DoubleVar(value=DEFAULT_THRESHOLD)
        self._cfg_ipc     = tk.IntVar(value=DEFAULT_IP_CONVERGE)
        self._cfg_cnc     = tk.IntVar(value=DEFAULT_CNAME_CONVERGE)
        self._cfg_timeout = tk.DoubleVar(value=DEFAULT_DNS_TIMEOUT)
        self._cfg_retry   = tk.IntVar(value=DEFAULT_DNS_RETRY)
        self._cfg_conc    = tk.IntVar(value=DEFAULT_MAX_CONCURRENT)
        self._cfg_vr      = tk.IntVar(value=DEFAULT_VERIFY_ROUND)
        self._cfg_dns_srv = tk.StringVar()
        self._cfg_nocache = tk.BooleanVar(value=False)

        fields = [
            ("探针数量（-pc）", self._cfg_probe, "个随机探针，建议 8~20"),
            ("解析率阈值（-t）", self._cfg_thresh, "0~1，低于此值不触发泛解析判定"),
            ("IP收敛上限（-ipc）", self._cfg_ipc, "唯一IP超过此值视为非泛解析"),
            ("CNAME收敛上限（-cnc）", self._cfg_cnc, "唯一CNAME超过此值视为非泛解析"),
            ("DNS超时秒数（-to）", self._cfg_timeout, "建议 1.0~5.0"),
            ("DNS重试次数（-rt）", self._cfg_retry, "查询失败后重试次数"),
            ("最大并发数（-mc）", self._cfg_conc, "线程数，并发越高越快（建议 ≤64）"),
        ]

        # 左列
        left = ttk.Frame(frm)
        left.pack(side="left", fill="y", padx=(0, 20))

        for i, (label, var, tip) in enumerate(fields):
            ttk.Label(left, text=label).grid(row=i, column=0, sticky="e", pady=5, padx=4)
            ttk.Entry(left, textvariable=var, width=10).grid(row=i, column=1, sticky="w", pady=5)
            ttk.Label(left, text=tip, foreground="gray").grid(row=i, column=2, sticky="w", pady=5, padx=4)

        row_vr = len(fields)
        ttk.Label(left, text="验证轮次（-vr）").grid(row=row_vr, column=0, sticky="e", pady=5, padx=4)
        ttk.Combobox(left, textvariable=self._cfg_vr, values=[1, 2],
                     state="readonly", width=8).grid(row=row_vr, column=1, sticky="w", pady=5)
        ttk.Label(left, text="1=快速 / 2=严格二次验证", foreground="gray").grid(
            row=row_vr, column=2, sticky="w", pady=5, padx=4)

        row_dns = row_vr + 1
        ttk.Label(left, text="DNS服务器（-ds）").grid(row=row_dns, column=0, sticky="e", pady=5, padx=4)
        ttk.Entry(left, textvariable=self._cfg_dns_srv, width=28).grid(row=row_dns, column=1, columnspan=2, sticky="w", pady=5)
        ttk.Label(left, text="空格分隔，如 8.8.8.8 114.114.114.114", foreground="gray").grid(
            row=row_dns, column=2, sticky="w", pady=5, padx=4)

        row_nc = row_dns + 1
        ttk.Checkbutton(left, text="禁用缓存（强制重新检测）",
                       variable=self._cfg_nocache).grid(
            row=row_nc, column=0, columnspan=2, sticky="w", pady=10)

        # 右列：白名单展示 + 缓存管理
        right = ttk.LabelFrame(frm, text="防误杀白名单", padding=10)
        right.pack(side="left", fill="both", expand=True)

        wl_txt = scrolledtext.ScrolledText(right, height=14, width=32,
                                           state="disabled", relief="solid", bd=1)
        wl_txt.pack()
        wl_txt.config(state="normal")
        for p in sorted(WHITELIST_PREFIXES):
            wl_txt.insert("end", p + "  ")
        wl_txt.config(state="disabled")

        ttk.Button(right, text="打开缓存目录",
                   command=self._open_cache_dir,
                   width=20).pack(pady=(8, 0))
        ttk.Button(right, text="清除所有缓存",
                   command=self._clear_cache,
                   width=20).pack(pady=(4, 0))

        return frm

    def _cfg_dns_list(self):
        srv = self._cfg_dns_srv.get().strip()
        if srv:
            return [s for s in srv.split() if s.strip()]
        return None

    def _open_cache_dir(self):
        import os
        os.startfile(CACHE_FILE.parent)

    def _clear_cache(self):
        if CACHE_FILE.exists():
            CACHE_FILE.write_text("{}", encoding="utf-8")
            messagebox.showinfo("缓存已清除", "所有缓存记录已清空")
        else:
            messagebox.showinfo("无缓存", "当前无缓存文件")

    # ------------------------------------------------------------------
    # 启动
    # ------------------------------------------------------------------
    def run(self):
        self.root.mainloop()


# ============================================================================
# 入口
# ============================================================================
def _excepthook(exc_type, exc_value, exc_traceback):
    import traceback, os
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "error.log")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now()}]")
        traceback.print_exc(file=f)
        f.write("\n")
    raise

sys.excepthook = _excepthook

if __name__ == "__main__":
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.2)
    except Exception:
        pass
    app = WildcardApp(root)
    app.run()