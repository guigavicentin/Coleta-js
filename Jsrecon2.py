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
    python3 jsrecon2.py https://api.target.com:8443           (URL completa com porta)
    python3 jsrecon2.py targets.txt                           (arquivo com um alvo por linha)
    python3 jsrecon2.py target.com.br --no-nmap --workers 30
    python3 jsrecon2.py target.com.br --no-subs --no-validate
    python3 jsrecon2.py target.com.br --skip-recon            (reutiliza endpoints.jsonl)
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
from urllib.parse import urlparse, urljoin

import requests
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# FIX: Playwright como import condicional — sys.exit(1) no topo impedia rodar
# com --no-live em ambientes sem o browser instalado.
try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

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
    80, 81, 443, 3000, 3001, 4000, 4443, 5000, 5001, 5432, 5900,
    6000, 6443, 6885, 7077, 8000, 8080, 8081, 8181, 8443,
    9000, 9091, 9443, 9999, 10000, 15672, 161, 2075, 2076,
    3306, 3366, 3868, 4044,
]
NMAP_PORTS   = ",".join(str(p) for p in sorted(set(HTTP_PORTS)))
HTTPS_PORTS  = {443, 8443, 9443, 4443, 6443, 2076, 10000, 5001}

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

# FIX: filtro de template literals JS — evita que fetch(`/api/${id}`) gere
# endpoints inválidos como '/api/${id}/data' que poluem o output.
_TMPL_LITERAL = re.compile(r'\$\{[^}]*\}')

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
# FIX: Parse de alvo — aceita domínio, URL completa com porta e arquivo .txt
# ─────────────────────────────────────────────────────────────────────────────

class Target:
    """Representa um alvo normalizado."""
    def __init__(self, raw: str):
        raw = raw.strip().rstrip("/")
        # Garante scheme para urlparse funcionar
        if "://" not in raw:
            raw_parsed = urlparse(f"placeholder://{raw}")
            self.scheme  = ""
            self.host    = raw_parsed.hostname or raw.split(":")[0]
            self.port    = raw_parsed.port or 0
            self.path    = raw_parsed.path or ""
        else:
            raw_parsed   = urlparse(raw)
            self.scheme  = raw_parsed.scheme
            self.host    = raw_parsed.hostname or ""
            self.port    = raw_parsed.port or 0
            self.path    = raw_parsed.path or ""

        # URL base para coleta direta (sem subfinder/nmap).
        # FIX: preserva o path quando fornecido (ex: /sysmo-broadcast-api/api/).
        # O Playwright e as ferramentas de crawl precisam abrir a URL exata
        # fornecida pelo usuário — sem o path, podem cair numa página vazia/404.
        path_suffix = self.path.rstrip("/") if self.path and self.path != "/" else ""

        if self.scheme and self.port:
            self.base_url = f"{self.scheme}://{self.host}:{self.port}{path_suffix}"
        elif self.scheme:
            self.base_url = f"{self.scheme}://{self.host}{path_suffix}"
        elif self.port:
            s = "https" if self.port in HTTPS_PORTS else "http"
            self.base_url = f"{s}://{self.host}:{self.port}{path_suffix}"
        else:
            self.base_url = ""

        # base sem path — usado para montar URLs absolutas de endpoints
        if self.scheme and self.port:
            self.origin = f"{self.scheme}://{self.host}:{self.port}"
        elif self.scheme:
            self.origin = f"{self.scheme}://{self.host}"
        elif self.port:
            s = "https" if self.port in HTTPS_PORTS else "http"
            self.origin = f"{s}://{self.host}:{self.port}"
        else:
            self.origin = ""

        # Se veio com URL completa, é single-target automaticamente
        self.is_single = bool(self.scheme or self.port)

        # Label para logs e nome de pasta
        if self.scheme and self.port:
            self.label = f"{self.scheme}://{self.host}:{self.port}"
        elif self.scheme:
            self.label = f"{self.scheme}://{self.host}"
        elif self.port:
            self.label = f"{self.host}:{self.port}"
        else:
            self.label = self.host

    def __repr__(self):
        return f"Target({self.label})"

    def safe_dirname(self) -> str:
        """Nome de pasta seguro."""
        return re.sub(r'[^\w.\-]', '_', self.label)


def load_targets(raw_arg: str) -> list[Target]:
    """
    Carrega lista de alvos a partir de:
      - arquivo .txt (um alvo por linha, # = comentário)
      - string direta (domínio ou URL)
    """
    p = Path(raw_arg)
    if p.exists() and p.is_file():
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        targets = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(Target(line))
        return targets
    return [Target(raw_arg)]

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
# Padrões de endpoints
# ─────────────────────────────────────────────────────────────────────────────

def _endpoint_patterns() -> list[tuple[str, re.Pattern, str]]:
    Q  = r'[\x22\x27\x60]'
    NQ = r'[^\x22\x27\x60\s]'
    I  = re.I
    ID = re.I | re.DOTALL
    return [
        ("fetch_get",      re.compile(rf'(?:fetch|axios\.get|http\.get|this\.\$http\.get|this\.http\.get)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "GET"),
        ("fetch_post",     re.compile(rf'(?:fetch|axios\.post|http\.post|this\.\$http\.post|this\.http\.post)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "POST"),
        ("fetch_put",      re.compile(rf'(?:axios\.put|http\.put|this\.\$http\.put)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "PUT"),
        ("fetch_delete",   re.compile(rf'(?:axios\.delete|http\.delete|this\.\$http\.delete)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "DELETE"),
        ("fetch_patch",    re.compile(rf'(?:axios\.patch|http\.patch|this\.\$http\.patch)\s*\(\s*{Q}({NQ}{{3,}}){Q}', I), "PATCH"),
        ("fetch_method",   re.compile(rf'fetch\s*\(\s*{Q}({NQ}{{3,}}){Q}\s*,\s*\{{[^}}]*method\s*:\s*[\x22\x27](\w+)[\x22\x27]', I), "DYNAMIC"),
        # FIX: fetch_template agora só captura literais sem ${...} — template
        # literals com variáveis (${ }) são descartados no filtro posterior.
        ("fetch_template", re.compile(r'(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*\x60([^\x60]{3,})\x60', I), "ANY"),
        ("xhr_open",       re.compile(rf'\.open\s*\(\s*[\x22\x27](\w+)[\x22\x27]\s*,\s*{Q}({NQ}{{3,}}){Q}', I), "XHR"),
        ("api_versioned",  re.compile(rf'{Q}(/api/v\d+[a-zA-Z0-9/_\-]*(?:\?[^\s\x22\x27\x60]*)?){Q}'), "ANY"),
        ("graphql",        re.compile(rf'{Q}((?:/graphql|/gql)(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "POST"),
        ("versioned_path", re.compile(rf'{Q}(/v\d+/[a-zA-Z0-9/_\-]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}'), "ANY"),
        ("router_path",    re.compile(rf'(?:path|route|to|url)\s*:\s*{Q}(/[a-zA-Z0-9/_\-:]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "GET"),
        ("href_action",    re.compile(rf'(?:href|action)\s*[=:]\s*{Q}(/[a-zA-Z0-9/_\-\.]{{3,}}(?:\?[^\s\x22\x27\x60]*)?){Q}', I), "GET"),
        ("url_with_query", re.compile(rf'{Q}((?:https?://[^\s\x22\x27\x60]+)?/[a-zA-Z0-9/_\-]{{2,}}\?(?:[a-zA-Z0-9_%\-]+=\w+&?)+){Q}', I), "GET"),
        ("formdata_post",  re.compile(rf'(?:new\s+FormData|FormData\s*\().*?(?:fetch|axios\.post|http\.post)\s*\(\s*{Q}({NQ}{{3,}}){Q}', ID), "POST"),
        ("json_body_post", re.compile(rf'JSON\.stringify\s*\([^)]*\).*?{Q}(/[a-zA-Z0-9/_\-]{{2,}}){Q}', ID), "POST"),
        ("websocket",      re.compile(rf'new\s+WebSocket\s*\(\s*{Q}(wss?://[^\s\x22\x27\x60]+){Q}', I), "WS"),
        # FIX: internal_url agora só captura URLs do target — antes capturava
        # domínios externos contendo palavras como "internal" no nome.
        # A validação por _is_valid_endpoint() faz o filtro correto.
        ("internal_url",   re.compile(r'(https?://[^\s\x22\x27\x60]{3,})', I), "ANY"),
        ("env_url",        re.compile(rf'(?:apiUrl|baseUrl|endpointUrl|serviceUrl|backendUrl|API_URL|BASE_URL)\s*[:=]\s*{Q}({NQ}{{5,}}){Q}', I), "ANY"),
        ("generic_path",   re.compile(rf'{Q}(/(?:api|v\d|auth|user|admin|account|login|logout|register|profile|settings|upload|download|search|order|payment|checkout|cart|product|item|list|detail|create|update|delete|reset|verify|confirm|token|refresh|oauth|callback)[a-zA-Z0-9/_\-]*){Q}', I), "ANY"),
    ]

# ─────────────────────────────────────────────────────────────────────────────
# FIX: is_valid_endpoint — filtra false positives antes de salvar
# Portado do jsrecon_oob para garantir consistência entre as ferramentas.
# ─────────────────────────────────────────────────────────────────────────────

_STATIC_EXT = re.compile(
    r'\.(png|jpg|jpeg|gif|ico|svg|webp|woff|woff2|ttf|eot|css|map|txt|pdf|zip|gz)$',
    re.I
)

def is_valid_endpoint(path: str, root_domain: str,
                      confirmed_hosts: set[str]) -> tuple[bool, str]:
    """
    Valida se o endpoint pertence ao target e é um endpoint real.
    Retorna (válido, motivo_de_rejeição).
    """
    if not path or len(path) < 3:
        return False, "too_short"

    # FIX: descarta template literals JS — fetch(`/api/${id}`) é inválido como endpoint
    if _TMPL_LITERAL.search(path):
        return False, "js_template_literal"

    # Extensões estáticas
    clean_path = path.split("?")[0]
    if _STATIC_EXT.search(clean_path):
        return False, "static_asset"

    # Paths que são claramente variáveis JS
    if re.match(r'^\$\{|^\${|^#|^\.|^//|^/\*', path):
        return False, "js_variable"

    # Para URLs absolutas: verifica se é do target
    if path.startswith(("http://", "https://", "ws://", "wss://")):
        try:
            host = urlparse(path).netloc.lower().split(":")[0]
        except Exception:
            return False, "parse_error"

        root = root_domain.lower().lstrip("*.")
        if host == root:
            return True, "ok"
        if host.endswith(f".{root}"):
            return True, "ok"
        if host in confirmed_hosts:
            return True, "ok"
        return False, f"external:{host}"

    # Path relativo com /
    if path.startswith("/"):
        return True, "ok"

    return False, "no_domain_no_slash"

# ─────────────────────────────────────────────────────────────────────────────
# Extração de body params
# ─────────────────────────────────────────────────────────────────────────────

_BODY_PARAMS_RE = re.compile(
    r'(?:body|data|payload)\s*[:=]\s*(?:JSON\.stringify\s*)?\{([^}]{1,600})\}', re.I | re.DOTALL
)
_KEY_RE = re.compile(r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,40})["\']')


def _extract_body_params(content: str, pos: int) -> list[str]:
    window = content[max(0, pos - 200): pos + 600]
    params = []
    for bm in _BODY_PARAMS_RE.finditer(window):
        for km in _KEY_RE.finditer(bm.group(1)):
            k = km.group(1)
            if k not in ("null", "true", "false", "undefined"):
                params.append(k)
    return list(dict.fromkeys(params))

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

# FIX: GlobalRateLimiter para validação — evita flood no alvo
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

_val_limiter = GlobalRateLimiter(0.3)  # sobrescrito em make_cfg()


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
# Resolução de URL
# ─────────────────────────────────────────────────────────────────────────────

def _base_from_js_url(js_url: str, root_domain: str) -> str:
    parsed = urlparse(js_url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{root_domain}"


def _resolve_path(path: str, js_url: str, root_domain: str) -> str:
    """
    FIX: usa urljoin para paths relativos, respeitando ../ e caminhos sem /.
    Antes: path relativo sem / ignorava o path base do arquivo JS.
    Agora: urljoin(js_url, path) resolve corretamente contra a URL do JS.
    """
    if path.startswith(("http://", "https://", "ws://", "wss://")):
        return path
    if path.startswith("/"):
        # Path absoluto — usa só scheme+host do JS
        parsed = urlparse(js_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        return f"https://{root_domain}{path}"
    # Path relativo — resolve contra a URL do JS (respeita ../)
    return urljoin(js_url, path)

# ─────────────────────────────────────────────────────────────────────────────
# Persistência de endpoints
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_method_key(method: str) -> str:
    """
    FIX: normaliza método para a chave de dedup.
    ANY/DYNAMIC/XHR/WS → '*' para evitar que o mesmo endpoint
    extraído por dois padrões diferentes (ex: fetch_get + generic_path)
    passe pela dedup como keys distintos ('GET', url) e ('*', url).
    """
    if method in ("ANY", "DYNAMIC", "XHR"):
        return "*"
    return method.upper()


def _save_endpoint(ep: dict, cfg: dict) -> bool:
    method   = _normalize_method_key(ep.get("method", "UNKNOWN"))
    abs_url  = ep.get("absolute_url", "").split("?")[0].rstrip("/") or "/"
    key      = (method, abs_url)

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

    if _BEAUTIFY:
        try:
            content = jsbeautifier.beautify(content)
        except Exception:
            pass

    root_domain    = cfg["domain"]
    confirmed_hosts = cfg.get("confirmed_hosts", set())

    for label, pattern, method_hint in cfg["endpoint_patterns"]:
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

            if not path or len(path) < 2:
                continue

            # FIX: validação centralizada que inclui filtro de template literals,
            # extensões estáticas e verificação de domínio.
            valid, reason = is_valid_endpoint(path, root_domain, confirmed_hosts)
            if not valid:
                logger.debug("[DROP][%s] %s ← %s", reason, path[:80], js_url)
                continue

            abs_url = _resolve_path(path, js_url, root_domain)

            qs = ""
            if "?" in path:
                qs = path.split("?", 1)[1].split("#")[0]

            body_params: list[str] = []
            if method in ("POST", "PUT", "PATCH", "DYNAMIC", "ANY"):
                body_params = _extract_body_params(content, m.start())

            ep = {
                "method":       method,
                "path":         path,
                "absolute_url": abs_url,
                "query_params": qs,
                "body_params":  body_params,
                "js_source":    js_url,
                "origin_host":  urlparse(js_url).netloc or root_domain,
                "label":        label,
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
                # FIX: timeout por future — evita thread presa em JS que nunca responde
                total += fut.result(timeout=30)
            except TimeoutError:
                logger.warning("  Worker JS timeout (30s)")
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
# Coleta de JS via ferramentas
# ─────────────────────────────────────────────────────────────────────────────

def collect_js_tools(
    domain: str,
    alive_urls: list[str],
    cfg: dict,
    logger: logging.Logger,
    single_target: bool = False,
) -> set[str]:
    """
    FIX: modo single_target — gau e waybackurls sem --subs, gospider/katana
    só nas URLs do domínio exato. Evita coletar JS de subdomínios fora do escopo
    quando o alvo foi especificado como URL exata.
    """
    js_urls: set[str] = set()
    logger.info("═══ Coleta de JS via ferramentas (%s) ═══",
                "single-target" if single_target else "full")

    # gau
    if tool_ok("gau"):
        logger.info("[gau] coletando URLs históricas…")
        gau_args = ["gau", domain]
        if not single_target:
            gau_args = ["gau", "--subs", domain]
        lines = run_cmd(gau_args, logger, timeout=300)
        before = len(js_urls)
        for l in lines:
            if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                js_urls.add(l.strip())
        logger.info("[gau] +%d JS", len(js_urls) - before)
    else:
        logger.warning("gau não encontrado  |  go install github.com/lc/gau/v2/cmd/gau@latest")

    # waybackurls
    if tool_ok("waybackurls"):
        logger.info("[waybackurls] coletando…")
        lines = run_cmd(["waybackurls", domain], logger, timeout=300)
        before = len(js_urls)
        for l in lines:
            if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                js_urls.add(l.strip())
        logger.info("[waybackurls] +%d JS", len(js_urls) - before)
    else:
        logger.warning("waybackurls não encontrado  |  go install github.com/tomnomnom/waybackurls@latest")

    # gospider
    if tool_ok("gospider"):
        logger.info("[gospider] crawling…")
        # single_target: só URLs do host exato
        target_urls = alive_urls
        if single_target:
            target_urls = [u for u in alive_urls
                           if urlparse(u).netloc.lower().split(":")[0] == domain.lower()]
        before = len(js_urls)
        for url in target_urls[:30]:
            lines = run_cmd(
                ["gospider", "-s", url, "-d", "2", "-t", "5", "--js", "--quiet"],
                logger, timeout=120,
            )
            for l in lines:
                m = re.search(r'https?://[^\s"\'<>]+\.js\b[^\s"\'<>]*', l)
                if m and not _CDN_RE.search(m.group(0)):
                    js_urls.add(m.group(0))
        logger.info("[gospider] +%d JS", len(js_urls) - before)
    else:
        logger.warning("gospider não encontrado  |  go install github.com/jaeles-project/gospider@latest")

    # katana
    if tool_ok("katana"):
        logger.info("[katana] crawling…")
        before = len(js_urls)
        for url in alive_urls[:30]:
            lines = run_cmd(
                ["katana", "-u", url, "-d", "3", "-jc", "-silent"],
                logger, timeout=120,
            )
            for l in lines:
                if ".js" in urlparse(l).path.lower() and not _CDN_RE.search(l):
                    js_urls.add(l.strip())
        logger.info("[katana] +%d JS", len(js_urls) - before)
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

    ips: set[str] = set()
    for u in urls_clean:
        host = urlparse(u).netloc.split(":")[0]
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
    single_target: bool = False,
) -> set[str]:
    logger.info("═══ Coleta de JS ═══")
    all_js: set[str] = set()

    tool_js = collect_js_tools(cfg["domain"], alive_urls, cfg, logger,
                               single_target=single_target)
    all_js.update(tool_js)

    if not cfg.get("no_live"):
        if not HAS_PLAYWRIGHT:
            logger.warning("[browser] Playwright não instalado — pulando coleta via browser.")
            logger.warning("          pip install playwright && playwright install chromium")
        else:
            seen_targets: set[str] = set()
            targets: list[str] = []
            for url in alive_urls:
                parsed = urlparse(url)
                # FIX: single_target — só abre o host exato, ignora subdomínios
                if single_target and parsed.netloc.lower().split(":")[0] != cfg["domain"].lower():
                    continue
                # FIX: usa a URL completa incluindo path (ex: https://host:5001/api/v1/)
                # Antes montava só scheme://netloc, descartando o path fornecido pelo usuário.
                # Dedup por netloc — evita abrir o mesmo host duas vezes se alive_urls
                # tiver variações de porta, mas preserva a primeira URL com path.
                key = parsed.netloc
                if key not in seen_targets:
                    seen_targets.add(key)
                    targets.append(url)

            logger.info("[browser] %d alvos únicos", len(targets))
            browser_js = asyncio.run(live_crawl_all(targets, cfg, logger))
            all_js.update(browser_js)
            logger.info("[browser] %d JS coletados", len(browser_js))

    all_js = {u for u in all_js if not u.endswith(".js.map")}
    js_clean = filter_target_js(all_js, cfg["domain"], confirmed_hosts, logger)

    _write(cfg["js_urls_file"], sorted(js_clean), logger)
    logger.info("JS do target (final): %d", len(js_clean))
    return js_clean

# ─────────────────────────────────────────────────────────────────────────────
# Validação de endpoints via requests
# ─────────────────────────────────────────────────────────────────────────────

_DESTRUCTIVE_METHODS = {"DELETE"}
_SKIP_VALIDATE_PATHS = re.compile(
    r'(?:/delete|/remove|/destroy|/drop|/purge|/wipe|/truncate)',
    re.I,
)

_VALIDATION_LOCK = threading.Lock()
_VALIDATED_URLS:  set[str] = set()

# FIX: mapa de normalização de método para requests — ANY/DYNAMIC nunca
# devem chegar como requests.any() (não existe) — antes causava fallback
# para GET silencioso, perdendo endpoints POST.
_METHOD_NORMALIZE = {
    "ANY":     "get",
    "DYNAMIC": "post",
    "XHR":     "get",
    "WS":      None,    # WebSocket — não valida via HTTP
    "GET":     "get",
    "POST":    "post",
    "PUT":     "put",
    "PATCH":   "patch",
    "DELETE":  "delete",
    "UNKNOWN": "get",
}


def _build_curl(ep: dict) -> str:
    method = ep.get("method", "GET")
    url    = ep.get("absolute_url", "")
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
    method     = ep.get("method", "UNKNOWN").upper()
    url        = ep.get("absolute_url", "")

    if method in _DESTRUCTIVE_METHODS:
        return {**ep, "status": "SKIPPED", "reason": "DELETE não executado", "curl": _build_curl(ep)}

    if _SKIP_VALIDATE_PATHS.search(url):
        return {**ep, "status": "SKIPPED", "reason": "path destrutivo", "curl": _build_curl(ep)}

    # FIX: WS — não valida via HTTP
    req_method_str = _METHOD_NORMALIZE.get(method, "get")
    if req_method_str is None:
        return {**ep, "status": "SKIPPED", "reason": "WebSocket — não validado via HTTP", "curl": ""}

    key = url.split("?")[0]
    with _VALIDATION_LOCK:
        if key in _VALIDATED_URLS:
            return None
        _VALIDATED_URLS.add(key)

    curl_cmd   = _build_curl(ep)
    req_method = getattr(requests, req_method_str)

    try:
        kwargs: dict = {
            "headers": {
                "User-Agent": "Mozilla/5.0 (compatible; jsrecon2/1.0)",
                "Accept":     "application/json, */*",
            },
            "timeout":         cfg["timeout"],
            "verify":          False,
            "allow_redirects": True,
        }

        if req_method_str in ("post", "put", "patch") and ep.get("body_params"):
            body = {k: f"<{k}>" for k in ep["body_params"]}
            kwargs["json"] = body

        # FIX: rate limit antes de cada request de validação
        _val_limiter.acquire()

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
                # FIX: timeout por future
                r = fut.result(timeout=30)
                if r:
                    results.append(r)
            except TimeoutError:
                logger.warning("  Validation future timeout (30s)")
            except Exception as e:
                logger.error("Validation worker error: %s", e)

    val_jsonl = cfg["out_dir"] / "validation.jsonl"
    val_txt   = cfg["out_dir"] / "validation.txt"

    status_groups: dict = collections.defaultdict(list)
    for r in results:
        _append(val_jsonl, json.dumps(r, ensure_ascii=False))
        st = str(r.get("status", "?"))
        status_groups[st].append(r)

    lines_txt = []
    for status_code, items in sorted(status_groups.items(), key=lambda x: str(x[0])):
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
# FIX: fontes do Google removidas — falha em rede air-gapped / offline.
# Usa font-family system stack.
# FIX: mensagem quando não há endpoints.
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

    def status_color(s):
        s = str(s)
        if s.startswith("2"):   return "#22c55e"
        if s.startswith("3"):   return "#f97316"
        if s in ("401","403"):  return "#ef4444"
        if s.startswith("4"):   return "#94a3b8"
        return "#64748b"

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
        for s in sorted(set(str(r.get("status", "?")) for r in validation_results
                            if r.get("status") != "SKIPPED"))
    )

    if endpoints:
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
    else:
        # FIX: mensagem quando não há endpoints em vez de tabela vazia
        rows = '<tr><td colspan="10" style="text-align:center;padding:2rem;color:#64748b">Nenhum endpoint encontrado nesta sessão.</td></tr>'

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
/* FIX: font-family system stack — sem dependência de Google Fonts (falha offline) */
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0a0c12;--surface:#0f1117;--surface2:#161922;--border:#1e2535;
  --text:#e2e8f0;--dim:#64748b;--accent:#38bdf8;
  --font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --mono:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
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
# TXT Summary e Endpoints
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

def make_cfg(domain: str, args: argparse.Namespace,
             out_suffix: str = "") -> dict:
    """
    out_suffix permite diferenciar pastas quando múltiplos alvos são
    processados em sequência (ex: jsrecon2_host1/, jsrecon2_host2/).
    """
    safe_name = re.sub(r'[^\w.\-]', '_', out_suffix or domain)
    out = Path(f"jsrecon2_{safe_name}")
    out.mkdir(exist_ok=True)

    delay = getattr(args, "delay", 0.3)

    global _val_limiter
    _val_limiter = GlobalRateLimiter(delay)

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
        "confirmed_hosts":   set(),   # preenchido após httpx
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

    if HAS_PLAYWRIGHT:
        logger.info("Playwright  : disponível")
    else:
        logger.warning("Playwright  : ausente  →  pip install playwright && playwright install chromium")

    if _BEAUTIFY:
        logger.info("js-beautify : disponível")
    else:
        logger.warning("js-beautify : ausente  →  pip install jsbeautifier")
    logger.info("───────────────────────────────────────────────────────────────")

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
  # Domínio normal — fluxo completo
  python3 jsrecon2.py target.com.br

  # URL específica com porta — pula subfinder/nmap automaticamente
  python3 jsrecon2.py https://api.target.com:8443
  python3 jsrecon2.py https://broadcast.sysmo.com.br:5001

  # Arquivo com múltiplos alvos (um por linha, # = comentário)
  python3 jsrecon2.py targets.txt

  # Opções comuns
  python3 jsrecon2.py target.com.br --no-nmap --workers 30
  python3 jsrecon2.py target.com.br --no-subs --no-live
  python3 jsrecon2.py target.com.br --no-validate
  python3 jsrecon2.py target.com.br --skip-recon     # reutiliza endpoints.jsonl
  python3 jsrecon2.py target.com.br --no-headless    # browser visível (debug)
  python3 jsrecon2.py target.com.br --delay 0.5      # rate limit na validação

Variáveis de ambiente opcionais:
  CHAOS_KEY      chave para chaos (ProjectDiscovery)
  GITHUB_TOKEN   token para github-subdomains
        """,
    )
    p.add_argument("target",          help="Domínio, URL completa ou arquivo .txt com alvos")
    p.add_argument("--no-subs",       action="store_true", help="Pula enumeração de subdomínios")
    p.add_argument("--no-nmap",       action="store_true", help="Pula scan de portas")
    p.add_argument("--no-live",       action="store_true", help="Pula coleta via browser")
    p.add_argument("--no-validate",   action="store_true", help="Pula validação de endpoints")
    p.add_argument("--no-headless",   action="store_true", help="Abre browser visível (debug)")
    p.add_argument("--no-cache",      action="store_true", help="Ignora cache de JS em disco")
    p.add_argument("--skip-recon",    action="store_true",
                   help="Pula recon e vai direto para validação (requer endpoints.jsonl existente)")
    p.add_argument("--workers",       type=int,   default=20,  help="Workers paralelos (padrão: 20)")
    p.add_argument("--timeout",       type=int,   default=10,  help="Timeout HTTP em segundos (padrão: 10)")
    p.add_argument("--delay",         type=float, default=0.3, help="Delay entre validações em segundos (padrão: 0.3)")
    p.add_argument("--live-timeout",  type=int,   default=30,  help="Timeout do browser (padrão: 30)")
    p.add_argument("--live-wait",     type=int,   default=2,   help="Espera após networkidle (padrão: 2)")
    return p.parse_args()

# ─────────────────────────────────────────────────────────────────────────────
# Processamento de um alvo
# ─────────────────────────────────────────────────────────────────────────────

def run_target(target: Target, args: argparse.Namespace,
               logger: logging.Logger) -> None:
    """
    Executa o fluxo completo para um alvo.
    Chamado para cada alvo quando --target é um arquivo .txt.
    """
    domain = target.host
    cfg    = make_cfg(domain, args, out_suffix=target.safe_dirname())
    stats: dict[str, int] = {}

    logger.info("=" * 66)
    logger.info("  jsrecon2  —  alvo: %s", target.label)
    if target.is_single:
        logger.info("  Modo     : single-target (subfinder/nmap pulados)")
    logger.info("  Filtro   : %s  e  *.%s  (apenas JS do target)", domain, domain)
    logger.info("  Saída    : %s", cfg["out_dir"])
    logger.info("=" * 66)

    # ── --skip-recon: carrega endpoints.jsonl existente e vai direto para validação
    if args.skip_recon:
        if not cfg["endpoints_jsonl"].exists():
            logger.error("--skip-recon: endpoints.jsonl não encontrado em %s", cfg["out_dir"])
            logger.error("Execute sem --skip-recon primeiro para gerar os endpoints.")
            return
        ep_count = sum(1 for l in cfg["endpoints_jsonl"].read_text().splitlines() if l.strip())
        logger.info("--skip-recon: %d endpoints carregados de sessão anterior.", ep_count)
        # confirmed_hosts não disponível — usa set vazio (validação já tem URLs absolutas)
        cfg["confirmed_hosts"] = set()
        val_results: list[dict] = []
        if not args.no_validate:
            val_results = validate_all_endpoints(cfg, logger)
        write_html_report(cfg, logger, {}, val_results)
        write_summary_txt(cfg, logger, {}, val_results)
        return

    # ── 1. Single-target: gera alive_urls diretamente da URL fornecida
    if target.is_single:
        # FIX: usa base_url que preserva o path (ex: https://host:5001/api/v1/).
        # O Playwright e os crawlers precisam abrir a URL exata para encontrar
        # o JS correto — sem o path a página pode ser 404 ou vazia.
        base = target.base_url or f"https://{domain}"
        alive_urls      = [base]
        confirmed_hosts: set[str] = {domain}
        subs            = {domain}
        stats["subs"]   = 1
        stats["alive"]  = len(alive_urls)
        _write(cfg["subs_file"],  [domain], logger)
        _write(cfg["alive_file"], alive_urls, logger)
        logger.info("Single-target: abrindo %s diretamente.", base)

    else:
        # ── 1. Subdomínios ────────────────────────────────────────────────────
        subs = {domain} if args.no_subs else enum_subdomains(domain, cfg, logger)
        if args.no_subs:
            logger.info("--no-subs: usando apenas domínio raiz.")
        stats["subs"] = len(subs)

        # ── 2. Nmap ───────────────────────────────────────────────────────────
        open_ports = (
            {s: [80, 443] for s in subs}
            if args.no_nmap
            else nmap_scan(subs, cfg, logger)
        )

        # ── 3. httpx ──────────────────────────────────────────────────────────
        alive_urls, confirmed_hosts = httpx_probe(open_ports, cfg, logger)
        stats["alive"] = len(alive_urls)

        if not alive_urls:
            logger.warning("Nenhum host ativo em %s. Pulando.", target.label)
            return

    # Disponibiliza confirmed_hosts para o filtro de endpoints
    cfg["confirmed_hosts"] = confirmed_hosts

    # ── 4. Coleta de JS ───────────────────────────────────────────────────────
    js_urls = collect_all_js(alive_urls, confirmed_hosts, cfg, logger,
                              single_target=target.is_single)
    stats["js"] = len(js_urls)

    # ── 5. Análise de JS ──────────────────────────────────────────────────────
    logger.info("═══ Análise de JS (%d arquivos) ═══", len(js_urls))
    total_eps = analyze_js_list(sorted(js_urls), cfg, logger)
    logger.info("Endpoints extraídos: %d", total_eps)

    write_endpoints_txt(cfg, logger)

    # ── 6. Validação ──────────────────────────────────────────────────────────
    val_results = []
    if not args.no_validate:
        val_results = validate_all_endpoints(cfg, logger)
    else:
        logger.info("--no-validate: pulando validação de endpoints.")

    # ── 7. Relatórios ─────────────────────────────────────────────────────────
    write_html_report(cfg, logger, stats, val_results)
    write_summary_txt(cfg, logger, stats, val_results)

    logger.info("=" * 66)
    logger.info("  Concluído: %s  →  %s", target.label, cfg["out_dir"])
    logger.info("=" * 66)

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    # Carrega alvos (arquivo .txt ou alvo direto)
    targets = load_targets(args.target)

    if not targets:
        print("Nenhum alvo encontrado.")
        sys.exit(1)

    # Logger global (antes de criar cfg individual por alvo)
    log_dir = Path(f"jsrecon2_{re.sub(r'[^\\w.\\-]', '_', targets[0].safe_dirname())}")
    log_dir.mkdir(exist_ok=True)
    logger = setup_logging(log_dir / "jsrecon2.log")

    preflight(logger)

    if len(targets) > 1:
        logger.info("Modo multi-alvo: %d alvos carregados de '%s'",
                    len(targets), args.target)

    # FIX: Playwright requer --no-live se não instalado
    if not HAS_PLAYWRIGHT and not args.no_live:
        logger.warning(
            "Playwright não instalado — coleta via browser desativada automaticamente.\n"
            "Para ativar: pip install playwright && playwright install chromium\n"
            "Para suprimir este aviso: passe --no-live"
        )
        args.no_live = True

    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            logger.info("\n[%d/%d] Processando: %s", i, len(targets), target.label)
        try:
            run_target(target, args, logger)
        except KeyboardInterrupt:
            logger.warning("Interrompido pelo usuário.")
            sys.exit(0)
        except Exception as e:
            logger.error("Erro ao processar %s: %s", target.label, e)
            if len(targets) == 1:
                raise
            # Multi-alvo: continua para o próximo mesmo em caso de erro


if __name__ == "__main__":
    main()
