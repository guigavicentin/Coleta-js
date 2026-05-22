#!/usr/bin/env python3
"""
jsrecon2.py — Recon autônomo focado em endpoints de JS para bug bounty / pentest autorizado.

Fluxo:
  1. Enumeração de subdomínios  (subfinder / assetfinder / chaos / github-subdomains)
  2. Scan de portas HTTP/HTTPS   (nmap)
  3. Validação de hosts ativos   (httpx)
  4. Coleta de JS via:
       a) gau + waybackurls + gospider + katana  (URLs históricas + crawl)
       b) Playwright (browser real — captura JS carregado em runtime)
  5. Filtro: apenas .js do domínio alvo e subdomínios
  6. Deduplicação de arquivos JS
  7. Análise de JS (js-beautify + regex rich):
       • Extração de endpoints (GET / POST / PUT / PATCH / DELETE / WS)
       • Query strings e body params
       • Atribuição correta ao subdomínio de origem
  8. Validação dos endpoints via curl (DELETE nunca executado)
       • Salva: status, tamanho, tempo, comando curl exato
  9. Relatório consolidado (TXT + JSONL + HTML interativo filtrável)

Uso:
    python3 jsrecon2.py target.com.br
    python3 jsrecon2.py target.com.br --no-nmap --workers 30
    python3 jsrecon2.py target.com.br --no-subs --no-validate
    python3 jsrecon2.py target.com.br --no-headless
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import hashlib
import json
import logging
import re
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
from urllib.parse import urlparse

import requests
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("[ERRO] Playwright não instalado. Execute:")
    print("       pip install playwright && playwright install chromium")
    sys.exit(1)

try:
    import jsbeautifier
    _BEAUTIFY = True
except ImportError:
    _BEAUTIFY = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# Portas alvo
# ─────────────────────────────────────────────────────────────────────────────

HTTP_PORTS = [
    80, 81, 443, 3000, 3001, 4000, 4443, 5000, 5432, 5900,
    6000, 6443, 6885, 7077, 8000, 8080, 8081, 8181, 8443,
    9000, 9091, 9443, 9999, 10000, 15672, 161, 2075, 2076,
    3306, 3366, 3868, 4044,
]
NMAP_PORTS   = ",".join(str(p) for p in sorted(set(HTTP_PORTS)))
HTTPS_PORTS  = {443, 8443, 9443, 4443, 6443, 2076, 10000}

# ─────────────────────────────────────────────────────────────────────────────
# CDN — descartados antes de qualquer análise
# ─────────────────────────────────────────────────────────────────────────────

_CDN_RE = re.compile(
    r'(?:cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|'
    r'ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com|'
    r'maxcdn\.bootstrapcdn\.com|code\.jquery\.com|'
    r'cdn\.datatables\.net|cdn\.polyfill\.io|'
    r'static\.cloudflareinsights\.com|'
    r'fonts\.googleapis\.com|fonts\.gstatic\.com)',
    re.I,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers gerais
# ─────────────────────────────────────────────────────────────────────────────

def tool_ok(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(
    cmd: list[str],
    logger: logging.Logger,
    stdin: str | None = None,
    timeout: int = 300,
) -> list[str]:
    try:
        r = subprocess.run(
            cmd, input=stdin, capture_output=True,
            text=True, timeout=timeout,
        )
        if r.stderr:
            logger.debug("[stderr:%s] %s", cmd[0], r.stderr.strip()[:300])
        return [l for l in r.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        logger.warning("Ferramenta ausente: %s", cmd[0])
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Timeout: %s", " ".join(cmd))
        return []
    except Exception as e:
        logger.error("Erro em %s: %s", cmd[0], e)
        return []


def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("jsrecon2")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    ch  = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


def _write(path: Path, lines, logger: logging.Logger) -> None:
    content = [str(l) for l in lines if str(l).strip()]
    if not content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(content) + "\n", encoding="utf-8")
    logger.debug("Salvo: %s (%d linhas)", path, len(content))


def _append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# ─────────────────────────────────────────────────────────────────────────────
# Filtro de domínio alvo
# ─────────────────────────────────────────────────────────────────────────────

def _build_target_filter(root_domain: str, confirmed_hosts: set[str]):
    root = root_domain.lower().lstrip("*.")

    def _ok(url: str) -> bool:
        try:
            host = urlparse(url).netloc.lower().split(":")[0]
        except Exception:
            return False
        if host == root:
            return True
        if host.endswith(f".{root}"):
            return True
        if host in confirmed_hosts:
            return True
        return False

    return _ok


def filter_target_js(
    js_urls: set[str],
    root_domain: str,
    confirmed_hosts: set[str],
    logger: logging.Logger,
) -> set[str]:
    is_target = _build_target_filter(root_domain, confirmed_hosts)
    kept: set[str] = set()
    dropped = 0
    for url in js_urls:
        if is_target(url):
            kept.add(url)
        else:
            dropped += 1
    logger.info(
        "Filtro de target: %d JS mantidos / %d descartados",
        len(kept), dropped,
    )
    return kept


# ─────────────────────────────────────────────────────────────────────────────
# Padrões de endpoints (ricos)
# ─────────────────────────────────────────────────────────────────────────────

def _endpoint_patterns() -> list[tuple[str, re.Pattern, str]]:
    # Q  = qualquer aspas: " ' `
    # NQ = qualquer char exceto aspas e espaço
    Q  = r'[\x22\x27\x60]'
    NQ = r'[^\x22\x27\x60\s]'
    I  = re.I
    ID = re.I | re.DOTALL
    return [
        # ── fetch / axios / http ─────────────────────────────────────────────
        ("fetch_get",      re.compile(rf'(?:fetch|axios\.get|http\.get|this\.\$http\.get|this\.http\.get)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "GET"),
        ("fetch_post",     re.compile(rf'(?:fetch|axios\.post|http\.post|this\.\$http\.post|this\.http\.post)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "POST"),
        ("fetch_put",      re.compile(rf'(?:axios\.put|http\.put|this\.\$http\.put)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "PUT"),
        ("fetch_delete",   re.compile(rf'(?:axios\.delete|http\.delete|this\.\$http\.delete)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "DELETE"),
        ("fetch_patch",    re.compile(rf'(?:axios\.patch|http\.patch|this\.\$http\.patch)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "PATCH"),
        # fetch com method dinâmico: fetch('/path', { method: 'POST' })
        ("fetch_method",   re.compile(rf'fetch\s*\(\s*{Q}({NQ}{{3,}}){Q}\s*,\s*\{{[^}}]*method\s*:\s*[\x22\x27](\w+)[\x22\x27]', I), "DYNAMIC"),
        # fetch com template literal: fetch(`/api/${id}`)
        ("fetch_template", re.compile(r'(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*\x60([^\x60]{3,})\x60', I), "ANY"),
        # ── XMLHttpRequest ───────────────────────────────────────────────────
        ("xhr_open",       re.compile(rf'\.open\s*\(\s*[\x22\x27](\w+)[\x22\x27]\s*,\s*{Q}({NQ}{{3,}}){Q}', I), "XHR"),
        # ── API versioned / GraphQL ───────────────────────────────────────────
        ("api_versioned",  re.compile(rf'{Q}(/api/v\d+[a-zA-Z0-9/_\-]*(?:\?[^\s\x22\x27\x60]*)?){Q}'), "ANY"),
        ("graphql",        re.compile(rf'{Q}((?:/graphql|/gql)(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "POST"),
        ("versioned_path", re.compile(rf'{Q}(/v\d+/[a-zA-Z0-9/_\-]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}'), "ANY"),
        # ── router / href ────────────────────────────────────────────────────
        ("router_path",    re.compile(rf'(?:path|route|to|url)\s*:\s*{Q}(/[a-zA-Z0-9/_\-:]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "GET"),
        ("href_action",    re.compile(rf'(?:href|action)\s*[=:]\s*{Q}(/[a-zA-Z0-9/_\-\.]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "GET"),
        # ── urls com query string completa ────────────────────────────────────
        ("url_with_query", re.compile(rf'{Q}((?:https?://[^\s\x22\x27\x60]+)?/[a-zA-Z0-9/_\-]{{2,}}\?(?:[a-zA-Z0-9_%\-]+=\w+&?)+){Q}', I), "GET"),
        # ── form data / json body ─────────────────────────────────────────────
        ("formdata_post",  re.compile(rf'(?:new\s+FormData|FormData\s*\().*?(?:fetch|axios\.post|http\.post)\s*\(\s*{Q}({NQ}{{3,}}){Q}', ID), "POST"),
        ("json_body_post", re.compile(rf'JSON\.stringify\s*\([^)]*\).*?{Q}(/[a-zA-Z0-9/_\-]{{2,}}){Q}', ID), "POST"),
        # ── WebSocket ────────────────────────────────────────────────────────
        ("websocket",      re.compile(rf'new\s+WebSocket\s*\(\s*{Q}(wss?://[^\s\x22\x27\x60]+){Q}', I), "WS"),
        # ── internal subdomains ───────────────────────────────────────────────
        ("internal_url",   re.compile(r'(https?://(?:internal|admin|dev|staging|api|backend|service)[^\s\x22\x27\x60]{3,})', I), "ANY"),
        # ── environment / config ──────────────────────────────────────────────
        ("env_url",        re.compile(rf'(?:apiUrl|baseUrl|endpointUrl|serviceUrl|backendUrl|API_URL|BASE_URL)\s*[:=]\s*{Q}({NQ}{{5,}}){Q}', I), "ANY"),
        # ── strings de path genéricas (último recurso) ────────────────────────
        ("generic_path",   re.compile(rf'{Q}(/(?:api|v\d|auth|user|admin|account|login|logout|register|profile|settings|upload|download|search|order|payment|checkout|cart|product|item|list|detail|create|update|delete|reset|verify|confirm|token|refresh|oauth|callback)[a-zA-Z0-9/_\-]*){Q}', I), "ANY"),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Extração de body params de um endpoint POST/PUT/PATCH
# ─────────────────────────────────────────────────────────────────────────────

_BODY_PARAMS_RE = re.compile(
    r'(?:body|data|payload)\s*[:=]\s*(?:JSON\.stringify\s*)?\{([^}]{1,600})\}', re.I | re.DOTALL
)
_KEY_RE = re.compile(r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']')


def _extract_body_params(content: str, pos: int) -> list[str]:
    """Tenta extrair chaves do body mais próximo do match."""
    window = content[max(0, pos - 200): pos + 600]
    params = []
    for bm in _BODY_PARAMS_RE.finditer(window):
        for km in _KEY_RE.finditer(bm.group(1)):
            k = km.group(1)
            if k not in ("null", "true", "false", "undefined"):
                params.append(k)
    return list(dict.fromkeys(params))  # dedup mantendo ordem


# ─────────────────────────────────────────────────────────────────────────────
# Estado global thread-safe
# ─────────────────────────────────────────────────────────────────────────────

_analyzed_js:     set[str]        = set()
_analyzed_lock:   threading.Lock  = threading.Lock()
_seen_endpoints:  set[tuple]      = set()
_endpoint_lock:   threading.Lock  = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting + retries (HTTP)
# ─────────────────────────────────────────────────────────────────────────────

_host_sems: dict[str, threading.Semaphore] = {}
_host_lock  = threading.Lock()
_req_logger = logging.getLogger("jsrecon2.req")


def _sem(url: str) -> threading.Semaphore:
    host = urllib.parse.urlparse(url).netloc
    with _host_lock:
        if host not in _host_sems:
            _host_sems[host] = threading.Semaphore(4)
        return _host_sems[host]


def _make_get(cfg: dict):
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        )),
        before_sleep=before_sleep_log(_req_logger, logging.DEBUG),
        reraise=True,
    )
    def _get(url: str, **kw) -> requests.Response:
        with _sem(url):
            r = requests.get(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; jsrecon2/1.0)"},
                timeout=cfg["timeout"],
                verify=False,
                allow_redirects=True,
                **kw,
            )
            if r.status_code == 429:
                time.sleep(min(int(r.headers.get("Retry-After", 10)), 60))
                r.raise_for_status()
            return r
    return _get


# ─────────────────────────────────────────────────────────────────────────────
# Inferir base URL a partir do JS source
# ─────────────────────────────────────────────────────────────────────────────

def _base_from_js_url(js_url: str, root_domain: str) -> str:
    """
    Se o JS veio de api.target.com, o endpoint base é https://api.target.com
    Nunca atribui ao domínio raiz se o JS pertence a subdomínio.
    """
    parsed = urlparse(js_url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{root_domain}"


def _resolve_path(path: str, js_url: str, root_domain: str) -> str:
    """Constrói URL absoluta respeitando a origem do JS."""
    if path.startswith(("http://", "https://", "ws://", "wss://")):
        return path
    base = _base_from_js_url(js_url, root_domain)
    return base + (path if path.startswith("/") else "/" + path)


# ─────────────────────────────────────────────────────────────────────────────
# Persistência de endpoints
# ─────────────────────────────────────────────────────────────────────────────

def _save_endpoint(ep: dict, cfg: dict) -> bool:
    method   = ep.get("method", "UNKNOWN").upper()
    abs_url  = ep.get("absolute_url", "").split("?")[0].rstrip("/") or "/"
    key      = (method if method != "ANY" else "*", abs_url)

    with _endpoint_lock:
        if key in _seen_endpoints:
            return False
        _seen_endpoints.add(key)

    _append(cfg["endpoints_jsonl"], json.dumps(ep, ensure_ascii=False))
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Análise de JS
# ─────────────────────────────────────────────────────────────────────────────

def analyze_js(content: str, js_url: str, cfg: dict, logger: logging.Logger) -> int:
    found = 0

    # Beautify para melhorar extração em JS minificado
    if _BEAUTIFY:
        try:
            content = jsbeautifier.beautify(content)
        except Exception:
            pass

    for label, pattern, method_hint in cfg["endpoint_patterns"]:
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

            # Filtros básicos
            if not path or len(path) < 2:
                continue
            if re.search(r'\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|css|map|txt|pdf)$', path, re.I):
                continue
            # Ignora paths que são apenas variáveis JS
            if re.match(r'^\$\{|^\${|^#|^\.|^//|^/\*', path):
                continue

            abs_url = _resolve_path(path, js_url, cfg["domain"])

            # Extrai query params
            qs = ""
            if "?" in path:
                qs = path.split("?", 1)[1].split("#")[0]

            # Extrai body params para métodos com corpo
            body_params: list[str] = []
            if method in ("POST", "PUT", "PATCH", "DYNAMIC", "ANY"):
                body_params = _extract_body_params(content, m.start())

            ep = {
                "method":      method,
                "path":        path,
                "absolute_url": abs_url,
                "query_params": qs,
                "body_params": body_params,
                "js_source":   js_url,
                "origin_host": urlparse(js_url).netloc or cfg["domain"],
                "label":       label,
            }

            if _save_endpoint(ep, cfg):
                logger.debug("[EP][%s] %s ← %s", method, path[:80], js_url)
                found += 1

    return found


def _is_js(resp: requests.Response, content: str) -> bool:
    ct = resp.headers.get("Content-Type", "")
    if "javascript" in ct or "ecmascript" in ct:
        return True
    s = content.strip()
    if s.startswith(("<html", "<!DOCTYPE", "<?xml")):
        return False
    if re.match(r'^\s*[{\[]', s) and not re.search(
            r'(?:var |let |const |function|=>|\bif\b|\bfor\b)', s[:500]):
        return False
    return True


def process_js_url(url: str, cfg: dict, logger: logging.Logger, get_fn) -> int:
    key = url.split("?")[0]
    with _analyzed_lock:
        if key in _analyzed_js:
            return 0
        _analyzed_js.add(key)

    # Cache em disco
    cache_file = cfg["cache_dir"] / (hashlib.sha1(key.encode()).hexdigest()[:16] + ".json")
    if cache_file.exists() and not cfg.get("no_cache"):
        try:
            d = json.loads(cache_file.read_text(encoding="utf-8"))
            if d.get("v") == "2" and time.time() - d.get("ts", 0) < 86400:
                return analyze_js(d["c"], url, cfg, logger)
        except Exception:
            pass

    try:
        resp = get_fn(url)
    except Exception as e:
        logger.debug("Falha ao baixar %s: %s", url, e)
        return 0

    if resp.status_code != 200:
        return 0

    content = resp.text
    if not _is_js(resp, content):
        return 0

    if not cfg.get("no_cache"):
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(
                json.dumps({"v": "2", "ts": time.time(), "c": content}, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass

    return analyze_js(content, url, cfg, logger)


def analyze_js_list(js_urls: list[str], cfg: dict, logger: logging.Logger) -> int:
    if not js_urls:
        return 0
    total  = 0
    get_fn = _make_get(cfg)
    logger.info("Analisando %d arquivos JS do target…", len(js_urls))
    with ThreadPoolExecutor(max_workers=cfg["workers"]) as ex:
        futs = {ex.submit(process_js_url, u, cfg, logger, get_fn): u for u in js_urls}
        done = 0
        for fut in as_completed(futs):
            done += 1
            if done % 20 == 0:
                logger.info("  Progresso: %d/%d JS analisados", done, len(js_urls))
            try:
                total += fut.result()
            except Exception as e:
                logger.error("Worker error: %s", e)
    return total


# ─────────────────────────────────────────────────────────────────────────────
# Playwright — browser real
# ─────────────────────────────────────────────────────────────────────────────

async def _playwright_crawl(
    url: str,
    timeout_s: int,
    wait_s: int,
    headless: bool,
    logger: logging.Logger,
) -> list[str]:
    js_files: list[str] = []
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

        def on_request(req):
            ru = req.url
            if ".js" in urlparse(ru).path.lower() and ru not in seen:
                if not _CDN_RE.search(ru):
                    seen.add(ru)
                    js_files.append(ru)

        page.on("request", on_request)
        logger.info("  🌐 Browser → %s", url)
        try:
            await page.goto(url, timeout=timeout_s * 1000, wait_until="networkidle")
        except Exception as e:
            logger.debug("  [browser] timeout em %s: %s", url, e)

        if wait_s > 0:
            await asyncio.sleep(wait_s)

        await browser.close()

    return js_files


async def live_crawl_all(
    targets: list[str],
    cfg: dict,
    logger: logging.Logger,
) -> set[str]:
    all_js: set[str] = set()
    for idx, url in enumerate(targets, 1):
        logger.info("[browser %d/%d] %s", idx, len(targets), url)
        try:
            files = await _playwright_crawl(
                url, cfg["live_timeout"], cfg["live_wait"],
                cfg["headless"], logger,
            )
            all_js.update(files)
            logger.info("  → %d JS capturados", len(files))
        except Exception as e:
            logger.error("  [browser] erro em %s: %s", url, e)
    return all_js


# ─────────────────────────────────────────────────────────────────────────────
# Coleta de JS via ferramentas (gau / waybackurls / gospider / katana)
# ─────────────────────────────────────────────────────────────────────────────

def collect_js_tools(
    domain: str,
    alive_urls: list[str],
    cfg: dict,
    logger: logging.Logger,
) -> set[str]:
    js_urls: set[str] = set()
    logger.info("═══ Coleta de JS via ferramentas ═══")

    # gau
    if tool_ok("gau"):
        logger.info("[gau] coletando URLs históricas…")
        lines = run_cmd(["gau", "--subs", domain], logger, timeout=300)
        for l in lines:
            if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                js_urls.add(l.strip())
        logger.info("[gau] %d JS encontrados", len(js_urls))
    else:
        logger.warning("gau não encontrado  |  go install github.com/lc/gau/v2/cmd/gau@latest")

    # waybackurls
    prev = len(js_urls)
    if tool_ok("waybackurls"):
        logger.info("[waybackurls] coletando…")
        lines = run_cmd(["waybackurls", domain], logger, timeout=300)
        for l in lines:
            if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                js_urls.add(l.strip())
        logger.info("[waybackurls] +%d JS", len(js_urls) - prev)
    else:
        logger.warning("waybackurls não encontrado  |  go install github.com/tomnomnom/waybackurls@latest")

    # gospider
    prev = len(js_urls)
    if tool_ok("gospider"):
        logger.info("[gospider] crawling…")
        for url in alive_urls[:30]:  # limita para não demorar muito
            lines = run_cmd(
                ["gospider", "-s", url, "-d", "2", "-t", "5", "--js", "--quiet"],
                logger, timeout=120,
            )
            for l in lines:
                m = re.search(r'https?://[^\s"\'<>]+\.js\b[^\s"\'<>]*', l)
                if m and not _CDN_RE.search(m.group(0)):
                    js_urls.add(m.group(0))
        logger.info("[gospider] +%d JS", len(js_urls) - prev)
    else:
        logger.warning("gospider não encontrado  |  go install github.com/jaeles-project/gospider@latest")

    # katana
    prev = len(js_urls)
    if tool_ok("katana"):
        logger.info("[katana] crawling…")
        for url in alive_urls[:30]:
            lines = run_cmd(
                ["katana", "-u", url, "-d", "3", "-jc", "-silent"],
                logger, timeout=120,
            )
            for l in lines:
                if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                    js_urls.add(l.strip())
        logger.info("[katana] +%d JS", len(js_urls) - prev)
    else:
        logger.warning("katana não encontrado  |  go install github.com/projectdiscovery/katana/cmd/katana@latest")

    logger.info("Total JS via ferramentas (pré-filtro): %d", len(js_urls))
    return js_urls


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 1 — Enumeração de subdomínios
# ─────────────────────────────────────────────────────────────────────────────

def enum_subdomains(domain: str, cfg: dict, logger: logging.Logger) -> set[str]:
    import os
    subs: set[str] = set()
    logger.info("═══ Enumeração de subdomínios ═══")

    chaos_key    = os.environ.get("CHAOS_KEY", "").strip()
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()

    if tool_ok("subfinder"):
        logger.info("[subfinder] …")
        lines = run_cmd(["subfinder", "-d", domain, "-silent"], logger, timeout=300)
        subs.update(lines)
        logger.info("[subfinder] %d subs", len(lines))
    else:
        logger.warning("subfinder não encontrado  |  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

    if tool_ok("assetfinder"):
        logger.info("[assetfinder] …")
        lines = run_cmd(["assetfinder", "--subs-only", domain], logger, timeout=180)
        subs.update(lines)
        logger.info("[assetfinder] %d subs", len(lines))
    else:
        logger.warning("assetfinder não encontrado  |  go install github.com/tomnomnom/assetfinder@latest")

    if tool_ok("chaos") and chaos_key:
        logger.info("[chaos] …")
        lines = run_cmd(["chaos", "-d", domain, "-key", chaos_key, "-silent"], logger, timeout=180)
        subs.update(lines)
        logger.info("[chaos] %d subs", len(lines))
    elif not chaos_key:
        logger.warning("[chaos] pulando — CHAOS_KEY não definida")

    if tool_ok("github-subdomains") and github_token:
        logger.info("[github-subdomains] …")
        lines = run_cmd(["github-subdomains", "-d", domain, "-t", github_token, "-raw"], logger, timeout=120)
        subs.update(lines)
        logger.info("[github-subdomains] %d subs", len(lines))
    elif not github_token:
        logger.warning("[github-subdomains] pulando — GITHUB_TOKEN não definido")

    clean = {
        s.strip().lower() for s in subs
        if s.strip() and "*" not in s and domain in s
    }
    clean.add(domain)

    logger.info("Subdomínios únicos: %d", len(clean))
    _write(cfg["subs_file"], sorted(clean), logger)
    return clean


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 2 — Nmap
# ─────────────────────────────────────────────────────────────────────────────

def nmap_scan(subs: set[str], cfg: dict, logger: logging.Logger) -> dict[str, list[int]]:
    if not tool_ok("nmap"):
        logger.warning("nmap não encontrado — assumindo portas 80 e 443  |  apt install nmap")
        return {s: [80, 443] for s in subs}

    logger.info("═══ Nmap — %d hosts ═══", len(subs))
    hosts_file = cfg["out_dir"] / "_nmap_hosts.txt"
    _write(hosts_file, sorted(subs), logger)

    nmap_out = cfg["out_dir"] / "nmap_results.txt"
    run_cmd([
        "nmap", "-iL", str(hosts_file),
        "-p", NMAP_PORTS, "--open", "-T4",
        "--max-retries", "1", "--host-timeout", "30s",
        "-oN", str(nmap_out), "-n",
    ], logger, timeout=1800)

    open_ports: dict[str, list[int]] = {}
    if nmap_out.exists():
        current = None
        for line in nmap_out.read_text(encoding="utf-8", errors="ignore").splitlines():
            hm = re.match(r'^Nmap scan report for (.+)', line)
            if hm:
                current = re.sub(r'\s*\(.*?\)', '', hm.group(1)).strip()
                open_ports.setdefault(current, [])
            pm = re.match(r'^(\d+)/tcp\s+open', line)
            if pm and current:
                open_ports[current].append(int(pm.group(1)))

    for s in subs:
        if s not in open_ports:
            open_ports[s] = []

    logger.info("[nmap] portas abertas: %d", sum(len(v) for v in open_ports.values()))
    return open_ports


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 3 — httpx
# ─────────────────────────────────────────────────────────────────────────────

def httpx_probe(
    open_ports: dict[str, list[int]],
    cfg: dict,
    logger: logging.Logger,
) -> tuple[list[str], set[str]]:
    logger.info("═══ httpx — validação de hosts ═══")

    candidates: set[str] = set()
    for host, ports in open_ports.items():
        for port in set(ports) | {80, 443}:
            scheme = "https" if port in HTTPS_PORTS else "http"
            candidates.add(f"{scheme}://{host}:{port}")
            if port == 443:
                candidates.add(f"https://{host}")
            if port == 80:
                candidates.add(f"http://{host}")

    if not candidates:
        logger.warning("Nenhum candidato para httpx.")
        return [], set()

    if not tool_ok("httpx"):
        logger.warning("httpx não encontrado — usando candidatos sem validação  |  go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        urls = sorted(candidates)
        hosts = {urlparse(u).netloc.split(":")[0].lower() for u in urls}
        _write(cfg["alive_file"], urls, logger)
        return urls, hosts

    logger.info("[httpx] testando %d candidatos…", len(candidates))
    try:
        result = subprocess.run(
            ["httpx", "-silent",
             "-mc", "200,201,204,301,302,307,308,401,403",
             "-threads", "50", "-timeout", "8",
             "-follow-redirects"],
            input="\n".join(sorted(candidates)) + "\n",
            capture_output=True, text=True, timeout=600,
        )
        urls_clean = [u.strip() for u in result.stdout.splitlines()
                      if u.strip().startswith("http")]
    except Exception as e:
        logger.error("Erro no httpx: %s", e)
        urls_clean = sorted(candidates)

    # Salva IPs únicos
    ips: set[str] = set()
    for u in urls_clean:
        host = urlparse(u).netloc.split(":")[0]
        # Tenta resolver só se for domínio (não IP)
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
            try:
                import socket
                ip = socket.gethostbyname(host)
                ips.add(ip)
            except Exception:
                pass
        else:
            ips.add(host)

    confirmed_hosts = {urlparse(u).netloc.lower().split(":")[0] for u in urls_clean}

    _write(cfg["alive_file"], sorted(set(urls_clean)), logger)
    _write(cfg["out_dir"] / "ips.txt", sorted(ips), logger)
    _write(cfg["out_dir"] / "domains.txt", sorted(confirmed_hosts), logger)
    _write(cfg["out_dir"] / "http_alive.txt", sorted(urls_clean), logger)

    logger.info("[httpx] hosts ativos: %d | IPs únicos: %d", len(urls_clean), len(ips))
    return sorted(set(urls_clean)), confirmed_hosts


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 4 — Coleta de JS (ferramentas + browser)
# ─────────────────────────────────────────────────────────────────────────────

def collect_all_js(
    alive_urls: list[str],
    confirmed_hosts: set[str],
    cfg: dict,
    logger: logging.Logger,
) -> set[str]:
    logger.info("═══ Coleta de JS ═══")
    all_js: set[str] = set()

    # Via ferramentas (gau, waybackurls, gospider, katana)
    tool_js = collect_js_tools(cfg["domain"], alive_urls, cfg, logger)
    all_js.update(tool_js)

    # Via browser (Playwright)
    if not cfg.get("no_live"):
        seen_targets: set[str] = set()
        targets: list[str] = []
        for url in alive_urls:
            parsed = urlparse(url)
            key    = parsed.netloc
            if key not in seen_targets:
                seen_targets.add(key)
                targets.append(f"{parsed.scheme}://{parsed.netloc}")

        logger.info("[browser] %d alvos únicos", len(targets))
        browser_js = asyncio.run(live_crawl_all(targets, cfg, logger))
        all_js.update(browser_js)
        logger.info("[browser] %d JS coletados", len(browser_js))

    # Remove .map
    all_js = {u for u in all_js if not u.endswith(".js.map")}

    # Filtro: apenas JS do alvo
    js_clean = filter_target_js(all_js, cfg["domain"], confirmed_hosts, logger)

    _write(cfg["js_urls_file"], sorted(js_clean), logger)
    logger.info("JS do target (final): %d", len(js_clean))
    return js_clean


# ─────────────────────────────────────────────────────────────────────────────
# Validação de endpoints via curl / requests
# ─────────────────────────────────────────────────────────────────────────────

_DESTRUCTIVE_METHODS = {"DELETE"}
_SKIP_VALIDATE_PATHS = re.compile(
    r'(?:/delete|/remove|/destroy|/drop|/purge|/wipe|/truncate)',
    re.I,
)

_VALIDATION_LOCK = threading.Lock()
_VALIDATED_URLS:  set[str] = set()


def _build_curl(ep: dict) -> str:
    method = ep["method"]
    url    = ep["absolute_url"]
    parts  = [f"curl -sk -o /dev/null -w '%{{http_code}} %{{size_download}} %{{time_total}}'"]
    parts.append(f"-X {method}")
    parts.append("-H 'User-Agent: Mozilla/5.0 (compatible; jsrecon2/1.0)'")
    parts.append("-H 'Accept: application/json, */*'")

    if method in ("POST", "PUT", "PATCH") and ep.get("body_params"):
        body = {k: f"<{k}>" for k in ep["body_params"]}
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"-d '{json.dumps(body)}'")
    elif ep.get("query_params"):
        sep = "&" if "?" in url else "?"
        url = url + sep + ep["query_params"]

    parts.append(f"'{url}'")
    return " ".join(parts)


def validate_endpoint(ep: dict, cfg: dict, logger: logging.Logger) -> dict | None:
    method = ep.get("method", "UNKNOWN").upper()
    url    = ep.get("absolute_url", "")

    # Nunca executa DELETE
    if method in _DESTRUCTIVE_METHODS:
        return {**ep, "status": "SKIPPED", "reason": "DELETE não executado", "curl": _build_curl(ep)}

    # Pula paths destrutivos mesmo em outros métodos
    if _SKIP_VALIDATE_PATHS.search(url):
        return {**ep, "status": "SKIPPED", "reason": "path destrutivo", "curl": _build_curl(ep)}

    # Dedup por URL
    key = url.split("?")[0]
    with _VALIDATION_LOCK:
        if key in _VALIDATED_URLS:
            return None
        _VALIDATED_URLS.add(key)

    curl_cmd = _build_curl(ep)

    try:
        req_method = getattr(requests, method.lower(), requests.get)
        kwargs: dict = {
            "headers": {
                "User-Agent": "Mozilla/5.0 (compatible; jsrecon2/1.0)",
                "Accept":     "application/json, */*",
            },
            "timeout":         cfg["timeout"],
            "verify":          False,
            "allow_redirects": True,
        }

        if method in ("POST", "PUT", "PATCH") and ep.get("body_params"):
            body = {k: f"<{k}>" for k in ep["body_params"]}
            kwargs["json"] = body

        t0   = time.monotonic()
        resp = req_method(url, **kwargs)
        elapsed = round(time.monotonic() - t0, 3)

        result = {
            **ep,
            "status":       resp.status_code,
            "size":         len(resp.content),
            "time_s":       elapsed,
            "content_type": resp.headers.get("Content-Type", ""),
            "curl":         curl_cmd,
        }
        logger.info("[VAL][%s] %s → %d (%d bytes, %.2fs)",
                    method, url[:80], resp.status_code, len(resp.content), elapsed)
        return result

    except Exception as e:
        logger.debug("[VAL] erro em %s: %s", url, e)
        return {
            **ep,
            "status":  "ERROR",
            "error":   str(e)[:120],
            "curl":    curl_cmd,
        }


def validate_all_endpoints(cfg: dict, logger: logging.Logger) -> list[dict]:
    if not cfg["endpoints_jsonl"].exists():
        return []

    endpoints = []
    for line in cfg["endpoints_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            endpoints.append(json.loads(line))
        except Exception:
            pass

    if not endpoints:
        return []

    logger.info("═══ Validação de endpoints (%d) ═══", len(endpoints))
    results = []

    with ThreadPoolExecutor(max_workers=cfg["workers"]) as ex:
        futs = {ex.submit(validate_endpoint, ep, cfg, logger): ep for ep in endpoints}
        for fut in as_completed(futs):
            try:
                r = fut.result()
                if r:
                    results.append(r)
            except Exception as e:
                logger.error("Validation worker error: %s", e)

    # Salva resultados
    val_jsonl = cfg["out_dir"] / "validation.jsonl"
    val_txt   = cfg["out_dir"] / "validation.txt"

    status_groups: dict = collections.defaultdict(list)
    for r in results:
        _append(val_jsonl, json.dumps(r, ensure_ascii=False))
        st = str(r.get("status", "?"))
        status_groups[st].append(r)

    lines_txt = []
    for status_code, items in sorted(status_groups.items(),
                                     key=lambda x: str(x[0])):
        lines_txt.append(f"\n{'═'*60}")
        lines_txt.append(f"  STATUS: {status_code}  ({len(items)} endpoints)")
        lines_txt.append(f"{'═'*60}")
        for r in items:
            lines_txt.append(f"\n[{r.get('method','?')}] {r.get('absolute_url','?')}")
            lines_txt.append(f"  JS Fonte   : {r.get('js_source','?')}")
            if r.get("body_params"):
                lines_txt.append(f"  Body params: {', '.join(r['body_params'])}")
            if r.get("query_params"):
                lines_txt.append(f"  Query      : {r['query_params']}")
            if r.get("time_s"):
                lines_txt.append(f"  Tempo      : {r['time_s']}s | {r.get('size',0)} bytes")
            if r.get("reason"):
                lines_txt.append(f"  Motivo skip: {r['reason']}")
            lines_txt.append(f"  CURL       : {r.get('curl','')}")
            lines_txt.append("-" * 60)

    _write(val_txt, lines_txt, logger)
    logger.info("Validação concluída. Resultados: %d", len(results))

    summary = collections.Counter(str(r.get("status", "?")) for r in results)
    for st, cnt in sorted(summary.items()):
        logger.info("  HTTP %s → %d endpoints", st, cnt)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# HTML Report
# ─────────────────────────────────────────────────────────────────────────────

def write_html_report(
    cfg: dict,
    logger: logging.Logger,
    stats: dict,
    validation_results: list[dict],
) -> None:
    endpoints: list[dict] = []
    if cfg["endpoints_jsonl"].exists():
        for line in cfg["endpoints_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                endpoints.append(json.loads(line))
            except Exception:
                pass

    val_map: dict[str, dict] = {}
    for r in validation_results:
        key = r.get("absolute_url", "").split("?")[0]
        val_map[key] = r

    def _esc(s) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    meth_colors = {
        "GET": "#22c55e", "POST": "#f97316", "PUT": "#3b82f6",
        "DELETE": "#ef4444", "PATCH": "#a855f7", "WS": "#14b8a6",
        "ANY": "#64748b", "XHR": "#eab308", "DYNAMIC": "#64748b",
        "UNKNOWN": "#64748b", "SKIPPED": "#334155",
    }

    status_color = lambda s: (
        "#22c55e" if str(s).startswith("2") else
        "#f97316" if str(s).startswith("3") else
        "#ef4444" if str(s) in ("401", "403") else
        "#94a3b8" if str(s).startswith("4") else
        "#64748b"
    )

    method_opts = "".join(
        f'<option value="{m}">{m}</option>'
        for m in sorted(set(ep.get("method", "?") for ep in endpoints))
    )
    host_opts = "".join(
        f'<option value="{h}">{h}</option>'
        for h in sorted(set(ep.get("origin_host", "?") for ep in endpoints))
    )
    status_opts = "".join(
        f'<option value="{s}">{s}</option>'
        for s in sorted(set(str(r.get("status", "?")) for r in validation_results if r.get("status") != "SKIPPED"))
    )

    rows = ""
    for ep in endpoints:
        method  = ep.get("method", "?")
        mc      = meth_colors.get(method, "#64748b")
        abs_url = ep.get("absolute_url", "")
        key     = abs_url.split("?")[0]
        vr      = val_map.get(key, {})
        status  = vr.get("status", "—")
        sc      = status_color(status)
        path    = _esc(ep.get("path", "")[:100])
        host    = _esc(ep.get("origin_host", ""))
        curl    = _esc(vr.get("curl", ""))
        body_p  = ", ".join(ep.get("body_params", []))
        qp      = _esc(ep.get("query_params", "")[:80])
        time_s  = vr.get("time_s", "")
        size    = vr.get("size", "")
        label   = ep.get("label", "")

        rows += (
            f'<tr data-method="{method}" data-host="{ep.get("origin_host","")}" data-status="{status}">'
            f'<td><span class="badge" style="background:{mc}">{method}</span></td>'
            f'<td class="url-cell mono">{path}</td>'
            f'<td class="url-cell"><a href="{abs_url}" target="_blank">{_esc(abs_url[:90])}</a></td>'
            f'<td class="dim">{host}</td>'
            f'<td><span class="badge" style="background:{sc};font-size:11px">{status}</span></td>'
            f'<td class="dim center">{time_s}{"s" if time_s else ""}</td>'
            f'<td class="dim center">{size}</td>'
            f'<td class="dim">{body_p[:60]}</td>'
            f'<td class="dim">{qp}</td>'
            f'<td class="curl-cell"><code>{curl[:200]}</code></td>'
            f'</tr>\n'
        )

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    status_summary = collections.Counter(str(r.get("status", "?")) for r in validation_results)
    status_cards = "".join(
        f'<div class="card"><div class="n" style="color:{status_color(s)}">{c}</div>'
        f'<div class="l">HTTP {s}</div></div>'
        for s, c in sorted(status_summary.items())
    )

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>jsrecon2 — {cfg['domain']}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0a0c12;--surface:#0f1117;--surface2:#161922;--border:#1e2535;
  --text:#e2e8f0;--dim:#64748b;--accent:#38bdf8;
  --font:'IBM Plex Sans',sans-serif;--mono:'IBM Plex Mono',monospace;
}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);font-size:13px;line-height:1.5}}
a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
code{{font-family:var(--mono);font-size:11px;background:#1a2235;padding:1px 5px;border-radius:3px;color:#7dd3fc}}
header{{background:var(--surface);border-bottom:1px solid var(--border);padding:1rem 1.5rem;display:flex;align-items:center;gap:1rem}}
header h1{{font-size:15px;font-weight:600;letter-spacing:.02em}}
header h1 span{{color:var(--accent)}}
header p{{font-size:11px;color:var(--dim);margin-top:2px}}
.banner{{display:flex;gap:.5rem;padding:.75rem 1.5rem;background:var(--surface2);border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:.4rem .8rem;min-width:80px;text-align:center}}
.card .n{{font-size:20px;font-weight:700;line-height:1.1;font-family:var(--mono)}}
.card .l{{font-size:10px;color:var(--dim);margin-top:1px;text-transform:uppercase;letter-spacing:.06em}}
.ctrl{{display:flex;gap:.6rem;padding:.6rem 1.5rem;background:var(--surface2);border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center}}
.ctrl select,.ctrl input{{background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 8px;font-size:12px;font-family:var(--font)}}
.ctrl input[type=search]{{width:200px}}
.cnt{{font-size:11px;color:var(--dim);margin-left:auto;font-family:var(--mono)}}
.badge{{display:inline-block;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700;color:#fff;white-space:nowrap;font-family:var(--mono);letter-spacing:.04em}}
table{{width:100%;border-collapse:collapse}}
thead th{{background:var(--surface);color:var(--dim);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;padding:7px 10px;text-align:left;border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap;user-select:none}}
thead th:hover{{color:var(--text)}}
td{{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
tr:hover td{{background:var(--surface2)}}
tr.hidden{{display:none}}
.url-cell{{max-width:240px;word-break:break-all;font-size:11px}}
.mono{{font-family:var(--mono);font-size:11px;word-break:break-all;color:#a3e635;max-width:200px}}
.dim{{font-size:11px;color:var(--dim)}}
.center{{text-align:center}}
.curl-cell{{max-width:300px;word-break:break-all}}
.curl-cell code{{display:block;padding:3px 6px;font-size:10px;white-space:pre-wrap}}
footer{{padding:.6rem 1.5rem;font-size:10px;color:#1e2535;border-top:1px solid var(--border);text-align:center;font-family:var(--mono)}}
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:#1e2535;border-radius:3px}}
</style>
</head>
<body>
<header>
  <div>
    <h1>jsrecon2 — <span>{cfg['domain']}</span></h1>
    <p>{ts} · {stats.get('subs',0)} subdomínios · {stats.get('alive',0)} hosts · {stats.get('js',0)} JS · {len(endpoints)} endpoints · {len(validation_results)} validados</p>
  </div>
</header>
<div class="banner">
  <div class="card"><div class="n" style="color:#a855f7">{len(endpoints)}</div><div class="l">Endpoints</div></div>
  <div class="card"><div class="n" style="color:#38bdf8">{stats.get('js',0)}</div><div class="l">JS files</div></div>
  <div class="card"><div class="n" style="color:#34d399">{stats.get('alive',0)}</div><div class="l">Hosts</div></div>
  <div class="card"><div class="n" style="color:#fb923c">{stats.get('subs',0)}</div><div class="l">Subdomains</div></div>
  {status_cards}
</div>
<div class="ctrl">
  <label>Método <select id="mf" onchange="f()"><option value="">Todos</option>{method_opts}</select></label>
  <label>Host <select id="hf" onchange="f()"><option value="">Todos</option>{host_opts}</select></label>
  <label>Status <select id="sf" onchange="f()"><option value="">Todos</option>{status_opts}</select></label>
  <input id="q" type="search" placeholder="Buscar path, URL, curl…" oninput="f()">
  <span id="cnt" class="cnt">{len(endpoints)} / {len(endpoints)}</span>
</div>
<table id="tbl">
<thead><tr>
  <th onclick="sort(0)">Método ↕</th>
  <th onclick="sort(1)">Path ↕</th>
  <th onclick="sort(2)">URL Absoluta ↕</th>
  <th onclick="sort(3)">Host ↕</th>
  <th onclick="sort(4)">Status ↕</th>
  <th>Tempo</th><th>Bytes</th>
  <th>Body params</th><th>Query</th>
  <th>CURL</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
<footer>jsrecon2 · {cfg['domain']} · {len(endpoints)} endpoints · {ts}</footer>
<script>
const rows=Array.from(document.querySelectorAll('#tbl tbody tr'));
const total={len(endpoints)};
function f(){{
  const m=document.getElementById('mf').value;
  const h=document.getElementById('hf').value;
  const s=document.getElementById('sf').value;
  const q=document.getElementById('q').value.toLowerCase();
  let v=0;
  rows.forEach(r=>{{
    const ok=(!m||r.dataset.method===m)&&(!h||r.dataset.host===h)&&(!s||r.dataset.status===s)&&(!q||r.textContent.toLowerCase().includes(q));
    r.classList.toggle('hidden',!ok);
    if(ok)v++;
  }});
  document.getElementById('cnt').textContent=v+' / '+total;
}}
let sd={{}};
function sort(col){{
  const tbody=document.querySelector('#tbl tbody');
  const rs=Array.from(tbody.querySelectorAll('tr'));
  sd[col]=(sd[col]||1)*-1;
  rs.sort((a,b)=>sd[col]*(a.cells[col]?.textContent.trim()||'').localeCompare(b.cells[col]?.textContent.trim()||''));
  rs.forEach(r=>tbody.appendChild(r));
  f();
}}
</script>
</body>
</html>"""

    cfg["summary_html"].write_text(html, encoding="utf-8")
    logger.info("HTML → %s", cfg["summary_html"])


# ─────────────────────────────────────────────────────────────────────────────
# TXT Summary
# ─────────────────────────────────────────────────────────────────────────────

def write_summary_txt(cfg: dict, logger: logging.Logger, stats: dict, val_results: list[dict]) -> None:
    status_summary = collections.Counter(str(r.get("status", "?")) for r in val_results)

    ep_count = sum(
        1 for l in (cfg["endpoints_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines()
                    if cfg["endpoints_jsonl"].exists() else [])
        if l.strip()
    )

    lines = [
        "=" * 64,
        "  JSRECON2 — SUMÁRIO",
        f"  Alvo  : {cfg['domain']}",
        f"  Data  : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"  Saída : {cfg['out_dir']}",
        "=" * 64, "",
        f"  Subdomínios      : {stats.get('subs', 0):>6}",
        f"  Hosts ativos     : {stats.get('alive', 0):>6}",
        f"  JS coletados     : {stats.get('js', 0):>6}",
        f"  Endpoints        : {ep_count:>6}",
        "",
        "  Resultados de validação:",
    ] + [
        f"    HTTP {st:>5}  : {cnt:>4}"
        for st, cnt in sorted(status_summary.items())
    ] + [
        "",
        "  Arquivos gerados:",
    ] + [
        f"    {p.name}"
        for p in [
            cfg["alive_file"],
            cfg["out_dir"] / "ips.txt",
            cfg["out_dir"] / "domains.txt",
            cfg["out_dir"] / "http_alive.txt",
            cfg["js_urls_file"],
            cfg["endpoints_txt"],
            cfg["endpoints_jsonl"],
            cfg["out_dir"] / "validation.txt",
            cfg["out_dir"] / "validation.jsonl",
            cfg["summary_html"],
            cfg["log_file"],
        ]
        if p.exists()
    ] + ["", "=" * 64]

    _write(cfg["summary_txt"], lines, logger)
    for l in lines:
        logger.info(l)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints TXT
# ─────────────────────────────────────────────────────────────────────────────

def write_endpoints_txt(cfg: dict, logger: logging.Logger) -> None:
    if not cfg["endpoints_jsonl"].exists():
        return
    lines = []
    for line in cfg["endpoints_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            ep = json.loads(line)
            m  = ep.get("method", "?")
            lines.append(f"\n[{m}] {ep.get('path', '?')}")
            lines.append(f"  → URL      : {ep.get('absolute_url', '?')}")
            lines.append(f"  → Host     : {ep.get('origin_host', '?')}")
            lines.append(f"  → JS fonte : {ep.get('js_source', '?')}")
            if ep.get("body_params"):
                lines.append(f"  → Body     : {', '.join(ep['body_params'])}")
            if ep.get("query_params"):
                lines.append(f"  → Query    : {ep['query_params']}")
            lines.append("-" * 60)
        except Exception:
            pass
    _write(cfg["endpoints_txt"], lines, logger)


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

def make_cfg(domain: str, args: argparse.Namespace) -> dict:
    out = Path(f"jsrecon2_{domain}")
    out.mkdir(exist_ok=True)
    return {
        "domain":            domain,
        "out_dir":           out,
        "subs_file":         out / "subdomains.txt",
        "alive_file":        out / "hosts_alive.txt",
        "js_urls_file":      out / "js_urls.txt",
        "endpoints_txt":     out / "endpoints.txt",
        "endpoints_jsonl":   out / "endpoints.jsonl",
        "summary_txt":       out / "SUMMARY.txt",
        "summary_html":      out / "SUMMARY.html",
        "log_file":          out / "jsrecon2.log",
        "cache_dir":         out / ".js_cache",
        "endpoint_patterns": _endpoint_patterns(),
        "timeout":           args.timeout,
        "workers":           args.workers,
        "live_timeout":      args.live_timeout,
        "live_wait":         args.live_wait,
        "headless":          not args.no_headless,
        "no_cache":          args.no_cache,
        "no_live":           args.no_live,
        "no_validate":       args.no_validate,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Preflight
# ─────────────────────────────────────────────────────────────────────────────

def preflight(logger: logging.Logger) -> None:
    tools = {
        "subfinder":         "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "assetfinder":       "go install github.com/tomnomnom/assetfinder@latest",
        "chaos":             "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
        "github-subdomains": "go install github.com/gwen001/github-subdomains@latest",
        "nmap":              "apt install nmap  /  brew install nmap",
        "httpx":             "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "gau":               "go install github.com/lc/gau/v2/cmd/gau@latest",
        "waybackurls":       "go install github.com/tomnomnom/waybackurls@latest",
        "gospider":          "go install github.com/jaeles-project/gospider@latest",
        "katana":            "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    }
    ok, missing = [], []
    for t, install in tools.items():
        (ok if tool_ok(t) else missing).append((t, install))

    logger.info("─── Preflight ─────────────────────────────────────────────────")
    logger.info("OK      : %s", ", ".join(t for t, _ in ok) or "nenhuma")
    for t, cmd in missing:
        logger.warning("AUSENTE : %-22s  →  %s", t, cmd)
    logger.info("───────────────────────────────────────────────────────────────")

    if _BEAUTIFY:
        logger.info("js-beautify : disponível (melhora extração em JS minificado)")
    else:
        logger.warning("js-beautify : ausente  →  pip install jsbeautifier")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="jsrecon2",
        description=(
            "Recon autônomo focado em endpoints de JS.\n"
            "Para uso em bug bounty e pentest com escopo autorizado."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 jsrecon2.py target.com.br
  python3 jsrecon2.py target.com.br --no-nmap --workers 30
  python3 jsrecon2.py target.com.br --no-subs --no-live
  python3 jsrecon2.py target.com.br --no-validate       # não faz requests de validação
  python3 jsrecon2.py target.com.br --no-headless       # browser visível (debug)

Variáveis de ambiente opcionais:
  CHAOS_KEY      chave para chaos (ProjectDiscovery)
  GITHUB_TOKEN   token para github-subdomains
        """,
    )
    p.add_argument("domain",          help="Domínio alvo (ex: target.com.br)")
    p.add_argument("--no-subs",       action="store_true", help="Pula enumeração de subdomínios")
    p.add_argument("--no-nmap",       action="store_true", help="Pula scan de portas")
    p.add_argument("--no-live",       action="store_true", help="Pula coleta via browser")
    p.add_argument("--no-validate",   action="store_true", help="Pula validação de endpoints")
    p.add_argument("--no-headless",   action="store_true", help="Abre browser visível (debug)")
    p.add_argument("--no-cache",      action="store_true", help="Ignora cache de JS em disco")
    p.add_argument("--workers",       type=int, default=20, help="Workers paralelos (padrão: 20)")
    p.add_argument("--timeout",       type=int, default=10, help="Timeout HTTP em segundos (padrão: 10)")
    p.add_argument("--live-timeout",  type=int, default=30, help="Timeout do browser (padrão: 30)")
    p.add_argument("--live-wait",     type=int, default=2,  help="Espera após networkidle (padrão: 2)")
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args   = parse_args()
    domain = args.domain.strip()
    for _pfx in ("https://", "http://"):
        if domain.startswith(_pfx):
            domain = domain[len(_pfx):]
    domain = domain.rstrip("/")

    cfg    = make_cfg(domain, args)
    logger = setup_logging(cfg["log_file"])
    stats: dict[str, int] = {}

    logger.info("=" * 66)
    logger.info("  jsrecon2  —  alvo: %s", domain)
    logger.info("  Filtro  : %s  e  *.%s  (apenas JS do target)", domain, domain)
    logger.info("  Saída   : %s", cfg["out_dir"])
    logger.info("=" * 66)

    preflight(logger)

    # ── 1. Subdomínios ────────────────────────────────────────────────────────
    subs = {domain} if args.no_subs else enum_subdomains(domain, cfg, logger)
    if args.no_subs:
        logger.info("--no-subs: usando apenas domínio raiz.")
    stats["subs"] = len(subs)

    # ── 2. Nmap ───────────────────────────────────────────────────────────────
    open_ports = (
        {s: [80, 443] for s in subs}
        if args.no_nmap
        else nmap_scan(subs, cfg, logger)
    )

    # ── 3. httpx ──────────────────────────────────────────────────────────────
    alive_urls, confirmed_hosts = httpx_probe(open_ports, cfg, logger)
    stats["alive"] = len(alive_urls)

    if not alive_urls:
        logger.warning("Nenhum host ativo. Encerrando.")
        sys.exit(0)

    # ── 4. Coleta de JS ────────────────────────────────────────────────────────
    js_urls = collect_all_js(alive_urls, confirmed_hosts, cfg, logger)
    stats["js"] = len(js_urls)

    # ── 5. Análise de JS ───────────────────────────────────────────────────────
    logger.info("═══ Análise de JS (%d arquivos) ═══", len(js_urls))
    total_eps = analyze_js_list(sorted(js_urls), cfg, logger)
    logger.info("Endpoints extraídos: %d", total_eps)

    # ── 5b. Salva endpoints.txt ───────────────────────────────────────────────
    write_endpoints_txt(cfg, logger)

    # ── 6. Validação ───────────────────────────────────────────────────────────
    val_results: list[dict] = []
    if not args.no_validate:
        val_results = validate_all_endpoints(cfg, logger)
    else:
        logger.info("--no-validate: pulando validação de endpoints.")

    # ── 7. Relatórios ─────────────────────────────────────────────────────────
    write_html_report(cfg, logger, stats, val_results)
    write_summary_txt(cfg, logger, stats, val_results)

    logger.info("=" * 66)
    logger.info("  Concluído. Saída: %s", cfg["out_dir"])
    logger.info("=" * 66)


if __name__ == "__main__":
    main()
