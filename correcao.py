#!/usr/bin/env python3
"""
jsanalyze.py — Coleta e analisa arquivos JS de uma URL.

Fluxo:
  1. Abre a URL no browser (Playwright) e captura todos os .js carregados
  2. Baixa cada JS e analisa:
       • Segredos / credenciais (40+ padrões)
       • Endpoints (GET/POST/PUT/DELETE/PATCH/WS)
       • Source maps expostos (*.js.map)
  3. Gera relatório HTML interativo + TXT + JSONL

Uso:
  python3 jsanalyze.py https://appaqpago.minhaconta.zoop.com.br/login
  python3 jsanalyze.py https://site.com --out resultado/
  python3 jsanalyze.py https://site.com --no-headless   # browser visível
  python3 jsanalyze.py https://site.com --timeout 60 --wait 8

Dependências:
  pip install playwright requests tenacity
  playwright install chromium
"""

from __future__ import annotations

import argparse
import asyncio
import base64 as _b64
import collections
import csv
import hashlib
import json
import logging
import math
import re
import sys
import threading
import time
import urllib.parse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

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
    print("[ERRO] Playwright não instalado.")
    print("       pip install playwright && playwright install chromium")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("jsanalyze")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _rx(p: str, f: int = 0) -> re.Pattern:
    return re.compile(p, f)

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = collections.Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())

def _extract_val(raw: str) -> str:
    m = re.search(r'[:=]\s*["\']?([^\s"\'`,;]{4,})', raw)
    return m.group(1).strip() if m else raw.strip()

_PLACEHOLDER_RE = re.compile(
    r'^(enter|your|change|example|placeholder|sample|dummy|fake|'
    r'test|demo|default|secret|senha|password|passwd|pass|'
    r'my[-_]?pass(word)?|new[-_]?pass(word)?|old[-_]?pass(word)?|'
    r'confirm|repeat|retype|current|xxxx+|\*+|\.{3,}|#{3,}|'
    r'changeme|mustchange|123456|abcdef|qwerty|letmein|welcome|admin|'
    r'<[^>]+>|\$\{[^}]+\}|%[a-z_]+%)', re.I,
)
_UI_CONTEXT_RE = re.compile(
    r'(label|placeholder|hint|aria[-_]label|title|description|'
    r'tooltip|helper|message|text|i18n|translate|t\(|'
    r'console\.log|console\.warn|console\.error|comment|//)', re.I,
)

def _is_real_cred(raw: str, ctx: str = "") -> bool:
    v = _extract_val(raw)
    if len(v) < 8 or _PLACEHOLDER_RE.match(v):
        return False
    if _UI_CONTEXT_RE.search(ctx):
        return False
    return _entropy(v) >= 3.2

def _is_real_jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    for part in parts[:2]:
        try:
            obj = json.loads(_b64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            if not isinstance(obj, dict):
                return False
        except Exception:
            return False
    try:
        h = json.loads(_b64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        if "alg" not in h:
            return False
    except Exception:
        return False
    return True

# ─────────────────────────────────────────────────────────────────────────────
# Severidade
# ─────────────────────────────────────────────────────────────────────────────

SECRET_SEVERITY: dict[str, str] = {
    "aws_access_key": "CRITICAL", "private_key": "CRITICAL",
    "stripe_secret": "CRITICAL", "braintree_token": "CRITICAL",
    "gcp_service_account": "CRITICAL", "hashicorp_vault": "CRITICAL",
    "azure_storage_key": "CRITICAL", "js_secret_key": "CRITICAL",
    "github_pat": "HIGH", "github_oauth": "HIGH", "gitlab_pat": "HIGH",
    "openai_key": "HIGH", "sendgrid_key": "HIGH", "slack_token": "HIGH",
    "supabase_service_role": "HIGH", "mongodb_dsn": "HIGH",
    "postgres_dsn": "HIGH", "mysql_dsn": "HIGH", "google_api_key": "HIGH",
    "firebase_url": "HIGH", "twilio_auth_token": "HIGH",
    "basic_auth_hardcoded": "HIGH", "basic_auth_btoa": "HIGH",
    "basic_auth_b64_raw": "HIGH", "hardcoded_credentials": "HIGH",
    "btoa_decoded": "HIGH", "btoa_creds": "HIGH", "firebase_app_id": "HIGH",
    "firebase_config_block": "HIGH",
    "jwt": "MEDIUM", "stripe_publishable": "MEDIUM", "slack_webhook": "MEDIUM",
    "sentry_dsn": "MEDIUM", "mapbox_token": "MEDIUM", "supabase_anon_key": "MEDIUM",
    "mailgun_api_key": "MEDIUM", "auth_header_hardcoded": "MEDIUM",
    "firebase_sender_id": "MEDIUM",
    "firebase_measurement_id": "LOW", "generic_api_key": "LOW",
    "generic_token": "LOW", "generic_secret": "LOW", "bearer_token": "LOW",
    "password_field": "LOW", "bcrypt_hash": "LOW",
}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
_CASE_SENSITIVE = frozenset({
    "aws_access_key", "github_pat", "github_oauth", "gitlab_pat",
    "npm_token", "stripe_secret", "stripe_publishable", "openai_key",
    "jwt", "bcrypt_hash", "private_key", "supabase_anon_key",
})

def _sev(t: str) -> str:
    return SECRET_SEVERITY.get(t, "UNKNOWN")

def _norm_val(type_name: str, value: str) -> str:
    v = value.strip().strip("'\"`")
    if type_name not in _CASE_SENSITIVE:
        v = v.lower()
    if "://" in v:
        v = v.split("?")[0].rstrip("/")
    return v

# ─────────────────────────────────────────────────────────────────────────────
# Padrões de segredos
# ─────────────────────────────────────────────────────────────────────────────

def _secret_patterns() -> dict[str, re.Pattern]:
    return {
        "google_api_key":          _rx(r'AIza[0-9A-Za-z\-_]{35}'),
        "firebase_url":            _rx(r'https?://[a-z0-9\-]+\.firebaseio\.com', re.I),
        "js_secret_key":           _rx(r'secrete?[Kk]ey\s*[:=]\s*["\']([^"\']{6,})["\']', re.I),
        "firebase_app_id":         _rx(r'appId\s*[:=]\s*["\'](\d+:\d+:\w+:[a-f0-9]{16,})["\']', re.I),
        "firebase_sender_id":      _rx(r'messagingSenderId\s*[:=]\s*["\'](\d{8,})["\']', re.I),
        "firebase_measurement_id": _rx(r'measurementId\s*[:=]\s*["\']([A-Z0-9\-]{8,})["\']', re.I),
        "firebase_config_block":   _rx(r'apiKey\s*:\s*["\']([^"\']{20,})["\'][^}]{0,200}authDomain\s*:\s*["\']([^"\']+)["\']', re.I | re.DOTALL),
        "gcp_service_account":     _rx(r'"type"\s*:\s*"service_account"'),
        "aws_access_key":          _rx(r'AKIA[0-9A-Z]{16}'),
        "azure_storage_key":       _rx(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
        "stripe_secret":           _rx(r'sk_live_[0-9a-zA-Z]{24,}'),
        "stripe_publishable":      _rx(r'pk_live_[0-9a-zA-Z]{24,}'),
        "braintree_token":         _rx(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'),
        "sendgrid_key":            _rx(r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}'),
        "mailgun_api_key":         _rx(r'key-[0-9a-zA-Z]{32}'),
        "twilio_auth_token":       _rx(r'\bSK[a-z0-9]{32}\b'),
        "github_pat":              _rx(r'gh[pousr]_[A-Za-z0-9]{36}'),
        "github_oauth":            _rx(r'gho_[A-Za-z0-9]{36}'),
        "gitlab_pat":              _rx(r'glpat-[A-Za-z0-9\-_]{20}'),
        "npm_token":               _rx(r'npm_[A-Za-z0-9]{36}'),
        "hashicorp_vault":         _rx(r'hvs\.[A-Za-z0-9_\-]{90,}'),
        "sentry_dsn":              _rx(r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+'),
        "openai_key":              _rx(r'sk-[a-zA-Z0-9]{48}'),
        "slack_token":             _rx(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'),
        "slack_webhook":           _rx(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
        "mongodb_dsn":             _rx(r'mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
        "postgres_dsn":            _rx(r'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
        "mysql_dsn":               _rx(r'mysql://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
        "mapbox_token":            _rx(r'pk\.eyJ1[A-Za-z0-9._\-]{20,}'),
        "supabase_anon_key":       _rx(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{43}'),
        "supabase_service_role":   _rx(r'(?:SUPABASE_SERVICE_ROLE_KEY|service_role)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{100,})["\']', re.I),
        "private_key":             _rx(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "jwt":                     _rx(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),
        "bcrypt_hash":             _rx(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'),
        "generic_api_key":         _rx(r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
        "generic_token":           _rx(r'(?:access[_-]?token|auth[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', re.I),
        "generic_secret":          _rx(r'(?:client[_-]?secret|app[_-]?secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-/+=]{20,})["\']', re.I),
        "bearer_token":            _rx(r'Authorization:\s*Bearer\s+([A-Za-z0-9_\-\.]{20,})', re.I),
        "password_field":          _rx(r'(?:password|passwd|senha)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),
        "basic_auth_btoa":         _rx(r'Basic\s*["\']?\s*\+\s*btoa\s*\(\s*["\']([^"\']{3,100})["\']\s*\)', re.I),
        "btoa_creds":              _rx(r'\bbtoa\s*\(\s*["\']([^"\']{2,100})["\']\s*\)', re.I),
        "basic_auth_b64_raw":      _rx(r'(?:Authorization|authorization)\s*[:\s=]+["\']?\s*Basic\s+([A-Za-z0-9+/]{8,}={0,2})', re.I),
        "hardcoded_credentials":   _rx(r'(?:username|user|login|usr)\s*[:=]\s*["\']([^"\']{2,50})["\']\s{0,5}.{0,80}(?:password|passwd|pass|pwd|senha)\s*[:=]\s*["\']([^"\']{2,})["\']', re.I),
        "auth_header_hardcoded":   _rx(r'["\']Authorization["\']\s*:\s*["\']Basic\s+([A-Za-z0-9+/]{8,}={0,2})["\']', re.I),
    }

_GENERIC_PATTERNS = frozenset({
    "generic_api_key", "generic_token", "generic_secret",
    "bearer_token", "password_field", "auth_header_hardcoded",
})

# ─────────────────────────────────────────────────────────────────────────────
# Padrões de endpoints
# ─────────────────────────────────────────────────────────────────────────────

def _endpoint_patterns() -> list[tuple[str, re.Pattern, str]]:
    return [
        ("api_versioned",      _rx(r'["\`](/api/v\d+[a-zA-Z0-9/_\-]*(?:\?[^\s"\'`]*)?)["\`]'), "ANY"),
        ("graphql",            _rx(r'["\`]((?:/graphql|/gql)(?:\?[^\s"\'`]*)?)["\`\s/]', re.I), "POST"),
        ("versioned_path",     _rx(r'["\`](/v\d+/[a-zA-Z0-9/_\-]{4,}(?:\?[^\s"\'`]*)?)["\`]'), "ANY"),
        ("fetch_get",          _rx(r'(?:fetch|axios\.get|http\.get)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "GET"),
        ("fetch_post",         _rx(r'(?:fetch|axios\.post|http\.post)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "POST"),
        ("fetch_put",          _rx(r'(?:axios\.put|http\.put)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "PUT"),
        ("fetch_delete",       _rx(r'(?:axios\.delete|http\.delete)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "DELETE"),
        ("fetch_patch",        _rx(r'(?:axios\.patch|http\.patch)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "PATCH"),
        ("fetch_dynamic",      _rx(r'fetch\s*\(\s*["\`]([^"\'`\s]{4,})["\`]\s*,\s*\{[^}]*method\s*:\s*["\'](\w+)["\']', re.I), "DYNAMIC"),
        ("router_path",        _rx(r'(?:path|route|to)\s*:\s*["\`](/[a-zA-Z0-9/_\-:]{3,}(?:\?[^\s"\'`]*)?)["\`]', re.I), "GET"),
        ("url_with_query",     _rx(r'["\`]((?:https?://[^\s"\'`]+)?/[a-zA-Z0-9/_\-]{2,}\?(?:[a-zA-Z0-9_\-]+=\w+&?)+)["\`]', re.I), "GET"),
        ("websocket",          _rx(r'new\s+WebSocket\s*\(\s*["\`](wss?://[^\s"\'`]+)["\`]', re.I), "WS"),
    ]

# ─────────────────────────────────────────────────────────────────────────────
# Estado global thread-safe
# ─────────────────────────────────────────────────────────────────────────────

_seen_secrets:   set[tuple]     = set()
_secrets_lock:   threading.Lock = threading.Lock()
_secret_write:   threading.Lock = threading.Lock()
_seen_endpoints: set[tuple]     = set()
_endpoint_write: threading.Lock = threading.Lock()
_analyzed_js:    set[str]       = set()
_analyzed_lock:  threading.Lock = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# Persistência
# ─────────────────────────────────────────────────────────────────────────────

def _append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def _save_secret(finding: dict, cfg: dict) -> bool:
    finding = {**finding, "severity": _sev(finding["type"])}
    key = (finding["type"], _norm_val(finding["type"], finding["value"]))
    with _secrets_lock:
        if key in _seen_secrets:
            return False
        _seen_secrets.add(key)
    with _secret_write:
        _append(cfg["secrets_txt"],
                f"[{finding['severity']}] [{finding['type']}] {finding['url']}\n"
                f"VALUE  : {finding['value']}\n"
                f"CONTEXT: {finding['context'][:300]}\n" + "-" * 60)
        new_csv = not cfg["secrets_csv"].exists()
        cfg["secrets_csv"].parent.mkdir(parents=True, exist_ok=True)
        with open(cfg["secrets_csv"], "a", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["severity", "type", "url", "value", "context"])
            if new_csv:
                w.writeheader()
            w.writerow({k: finding.get(k, "")[:300] if k == "context" else finding.get(k, "")
                        for k in ["severity", "type", "url", "value", "context"]})
        _append(cfg["secrets_jsonl"], json.dumps({
            "severity": finding["severity"], "type": finding["type"],
            "url": finding["url"], "value": finding["value"],
            "context": finding["context"][:300],
        }, ensure_ascii=False))
    return True

def _abs_url(path: str, base: str) -> str:
    if path.startswith(("http://", "https://", "ws://", "wss://")):
        return path
    parsed = urlparse(base)
    return f"{parsed.scheme}://{parsed.netloc}" + (path if path.startswith("/") else "/" + path)

def _save_endpoint(ep: dict, cfg: dict) -> bool:
    method = ep.get("method", "UNKNOWN").upper()
    path = ep.get("path", "").strip()
    path_base = path.split("?")[0].rstrip("/") or "/"
    key = (method if method != "ANY" else "_", path_base)
    with _endpoint_write:
        if key in _seen_endpoints:
            return False
        _seen_endpoints.add(key)
        abs_u = ep.get("absolute_url", "")
        line = (f"[{method}] {path}\n"
                f"  → Absoluta : {abs_u}\n"
                f"  → Fonte JS : {ep.get('js_url', '?')}\n" + "-" * 60)
        _append(cfg["endpoints_txt"], line)
        _append(cfg["endpoints_jsonl"], json.dumps({
            "method": method, "path": path, "absolute_url": abs_u,
            "js_source": ep.get("js_url", ""),
        }, ensure_ascii=False))
    return True

# ─────────────────────────────────────────────────────────────────────────────
# Análise de JS
# ─────────────────────────────────────────────────────────────────────────────

def analyze_js(content: str, url: str, cfg: dict, logger: logging.Logger) -> int:
    found = 0
    lines = content.splitlines()

    def _line_at(pos: int) -> str:
        n = 0
        for l in lines:
            n += len(l) + 1
            if n >= pos:
                return l
        return ""

    for name, pattern in cfg["secret_patterns"].items():
        for m in pattern.finditer(content):
            raw = m.group(0)
            value = m.group(1) if m.lastindex and m.lastindex >= 1 else raw
            if name in _GENERIC_PATTERNS:
                if not _is_real_cred(value, _line_at(m.start())):
                    continue
            if name == "jwt" and not _is_real_jwt(value):
                continue
            ctx = content[max(0, m.start()-90):min(len(content), m.end()+90)].replace("\r", " ").replace("\n", " ")
            finding = {"type": name, "value": value, "url": url, "context": ctx}
            if _save_secret(finding, cfg):
                logger.warning("[!!!] %s → %s | %s", name, value[:80], url)
                found += 1

    # btoa
    for bm in re.finditer(r'\bbtoa\s*\(\s*["\'](.*?)["\'\']\s*\)', content, re.I):
        raw_val = bm.group(1)
        ctx = content[max(0, bm.start()-80):min(len(content), bm.end()+80)].replace("\n", " ")
        if _save_secret({"type": "btoa_decoded", "value": raw_val, "url": url, "context": ctx}, cfg):
            logger.warning("[!!!] btoa → '%s' | %s", raw_val, url)
            found += 1

    for label, pattern, method_hint in cfg["endpoint_patterns"]:
        for m in pattern.finditer(content):
            path = (m.group(1) or "").strip().strip("\"'`")
            if not path or len(path) < 2:
                continue
            if re.search(r'\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|css)$', path, re.I):
                continue
            method = (m.group(2).upper() if method_hint == "DYNAMIC"
                      and m.lastindex and m.lastindex >= 2 else method_hint)
            ep = {"method": method, "path": path,
                  "absolute_url": _abs_url(path, url), "js_url": url}
            if _save_endpoint(ep, cfg):
                logger.debug("[EP][%s] %s", method, path)

    return found

# ─────────────────────────────────────────────────────────────────────────────
# Source maps
# ─────────────────────────────────────────────────────────────────────────────

def check_sourcemap(js_url: str, cfg: dict, logger: logging.Logger) -> bool:
    map_url = js_url.split("?")[0] + ".map"
    try:
        r = requests.get(map_url, timeout=cfg["timeout"], verify=False,
                         headers={"User-Agent": "Mozilla/5.0 jsanalyze"})
        if r.status_code == 200 and len(r.content) > 100:
            ct = r.headers.get("content-type", "")
            size = len(r.content)
            logger.warning("[MAP] Exposto: %s (%d bytes)", map_url, size)
            _append(cfg["maps_txt"], map_url)
            _append(cfg["maps_jsonl"], json.dumps({
                "js_url": js_url, "map_url": map_url,
                "size": size, "content_type": ct,
            }, ensure_ascii=False))
            return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# Download + análise
# ─────────────────────────────────────────────────────────────────────────────

_req_logger = logging.getLogger("jsanalyze.req")

def _make_get(cfg: dict):
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=20),
        retry=retry_if_exception_type((
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        )),
        before_sleep=before_sleep_log(_req_logger, logging.DEBUG),
        reraise=True,
    )
    def _get(url: str) -> requests.Response:
        return requests.get(url, headers={"User-Agent": "Mozilla/5.0 jsanalyze"},
                            timeout=cfg["timeout"], verify=False, allow_redirects=True)
    return _get

def process_js_url(url: str, cfg: dict, logger: logging.Logger, get_fn) -> int:
    key = url.split("?")[0]
    with _analyzed_lock:
        if key in _analyzed_js:
            return 0
        _analyzed_js.add(key)

    try:
        resp = get_fn(url)
    except Exception as e:
        logger.debug("Falha: %s — %s", url, e)
        return 0

    if resp.status_code != 200:
        return 0

    ct = resp.headers.get("Content-Type", "")
    content = resp.text
    s = content.strip()
    if s.startswith(("<html", "<HTML", "<!DOCTYPE", "<?xml")):
        return 0
    if not ("javascript" in ct or "ecmascript" in ct or
            key.endswith(".js") or key.endswith(".mjs")):
        if re.match(r'^\s*[{\[]', s) and not re.search(
                r'(?:var |let |const |function|=>|\bif\b|\bfor\b)', s[:500]):
            return 0

    logger.info("  [analisando] %s", url[:80])
    found = analyze_js(content, url, cfg, logger)
    check_sourcemap(url, cfg, logger)
    return found

def analyze_all(js_urls: list[str], cfg: dict, logger: logging.Logger) -> int:
    if not js_urls:
        return 0
    get_fn = _make_get(cfg)
    total = 0
    logger.info("Analisando %d arquivos JS…", len(js_urls))
    with ThreadPoolExecutor(max_workers=cfg["workers"]) as ex:
        futs = {ex.submit(process_js_url, u, cfg, logger, get_fn): u for u in js_urls}
        for fut in as_completed(futs):
            try:
                total += fut.result()
            except Exception as e:
                logger.error("Worker error: %s", e)
    return total

# ─────────────────────────────────────────────────────────────────────────────
# Playwright — coleta JS ao vivo
# ─────────────────────────────────────────────────────────────────────────────

async def collect_js(url: str, timeout_s: int, wait_s: int,
                     headless: bool, logger: logging.Logger) -> list[str]:
    js_urls: list[str] = []
    seen: set[str] = set()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=headless,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
            ],
        )
        ctx = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            locale="pt-BR",
            timezone_id="America/Sao_Paulo",
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=True,
        )
        page = await ctx.new_page()
        await page.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )

        def on_request(req):
            ru = req.url
            rpath = urlparse(ru).path.lower()
            if ru not in seen and (rpath.endswith(".js") or rpath.endswith(".mjs") or ".js?" in rpath):
                seen.add(ru)
                js_urls.append(ru)
                logger.debug("  [JS] %s", ru)

        page.on("request", on_request)

        logger.info("  🌐 Abrindo %s", url)
        try:
            await page.goto(url, timeout=timeout_s * 1000, wait_until="load")
        except Exception as e:
            logger.warning("  [nav] %s — continuando", e)

        await asyncio.sleep(max(wait_s, 2))

        try:
            await page.evaluate("""
                async () => {
                    const delay = ms => new Promise(r => setTimeout(r, ms));
                    for (let i = 0; i < 5; i++) {
                        window.scrollBy(0, window.innerHeight);
                        await delay(600);
                    }
                    window.scrollTo(0, 0);
                }
            """)
        except Exception:
            pass

        await asyncio.sleep(2)

        # Tenta asset-manifest
        try:
            html = await page.content()
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for m in re.finditer(r'(?:src|href)=["\']([^"\']*?\.(?:js|mjs)(?:\?[^"\']*)?)["\']', html, re.I):
                raw = m.group(1)
                if raw.startswith("/"):
                    raw = urljoin(base, raw)
                if raw.startswith("http") and raw not in seen:
                    seen.add(raw)
                    js_urls.append(raw)
        except Exception:
            pass

        await browser.close()

    logger.info("  → %d JS encontrados", len(js_urls))
    return js_urls

# ─────────────────────────────────────────────────────────────────────────────
# Relatório HTML
# ─────────────────────────────────────────────────────────────────────────────

def write_html(cfg: dict, logger: logging.Logger, stats: dict) -> None:
    findings: list[dict] = []
    endpoints: list[dict] = []
    maps: list[dict] = []

    if cfg["secrets_jsonl"].exists():
        for line in cfg["secrets_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                o = json.loads(line)
                o.setdefault("severity", _sev(o.get("type", "")))
                findings.append(o)
            except Exception:
                pass

    if cfg["endpoints_jsonl"].exists():
        for line in cfg["endpoints_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                endpoints.append(json.loads(line))
            except Exception:
                pass

    if cfg["maps_jsonl"].exists():
        for line in cfg["maps_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                maps.append(json.loads(line))
            except Exception:
                pass

    findings.sort(key=lambda x: (_SEVERITY_ORDER.get(x.get("severity", "UNKNOWN"), 4), x.get("type", "")))

    sev_colors = {"CRITICAL": "#c0392b", "HIGH": "#e67e22",
                  "MEDIUM": "#2980b9", "LOW": "#27ae60", "UNKNOWN": "#7f8c8d"}
    meth_colors = {"GET": "#27ae60", "POST": "#e67e22", "PUT": "#2980b9",
                   "DELETE": "#c0392b", "PATCH": "#8e44ad", "WS": "#16a085",
                   "ANY": "#7f8c8d", "UNKNOWN": "#7f8c8d", "DYNAMIC": "#7f8c8d"}
    sev_counts = {s: sum(1 for f in findings if f.get("severity") == s)
                  for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    def _esc(s): return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    secret_rows = ""
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        color = sev_colors.get(sev, "#7f8c8d")
        url = f.get("url", "")
        secret_rows += (
            f'<tr data-sev="{sev}" data-type="{f.get("type","")}">'
            f'<td><span class="badge" style="background:{color}">{sev}</span></td>'
            f'<td><code>{f.get("type","")}</code></td>'
            f'<td class="url-cell"><a href="{url}" target="_blank">{url[:90]}</a></td>'
            f'<td class="mono">{_esc(f.get("value","")[:120])}</td>'
            f'<td class="ctx">{_esc(f.get("context","")[:200])}</td></tr>\n'
        )

    ep_rows = ""
    for ep in endpoints:
        m = ep.get("method", "?")
        mc = meth_colors.get(m, "#7f8c8d")
        abs_ = ep.get("absolute_url", "")
        ep_rows += (
            f'<tr><td><span class="badge" style="background:{mc}">{m}</span></td>'
            f'<td class="mono">{_esc(ep.get("path","")[:100])}</td>'
            f'<td class="url-cell"><a href="{abs_}" target="_blank">{abs_[:90]}</a></td>'
            f'<td class="ctx">{_esc(ep.get("js_source","")[:80])}</td></tr>\n'
        )

    map_rows = ""
    for mp in maps:
        map_rows += (
            f'<tr>'
            f'<td class="url-cell mono"><a href="{mp.get("js_url","")}" target="_blank">'
            f'{_esc(mp.get("js_url","")[:90])}</a></td>'
            f'<td class="url-cell"><a href="{mp.get("map_url","")}" target="_blank" style="color:#4ade80;font-weight:600">'
            f'{_esc(mp.get("map_url","")[:90])}</a></td>'
            f'<td class="center">{_esc(mp.get("size","?"))}</td>'
            f'</tr>\n'
        )

    types_opts = "".join(f'<option value="{t}">{t}</option>'
                         for t in sorted(set(f.get("type", "") for f in findings)))
    method_opts = "".join(f'<option value="{m}">{m}</option>'
                          for m in sorted(set(ep.get("method", "") for ep in endpoints)))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>jsanalyze — {_esc(cfg['target_url'])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;font-size:14px}}
a{{color:#60a5fa;text-decoration:none}}a:hover{{text-decoration:underline}}
code{{font-family:'SFMono-Regular',Consolas,monospace;font-size:12px;background:#1e2130;padding:1px 5px;border-radius:3px}}
header{{background:#1a1d2e;border-bottom:1px solid #2d3148;padding:1rem 1.5rem}}
header h1{{font-size:15px;font-weight:600;color:#f1f5f9}}
header p{{font-size:12px;color:#64748b;margin-top:4px}}
.banner{{display:flex;gap:.75rem;padding:.75rem 1.5rem;background:#141620;border-bottom:1px solid #2d3148;flex-wrap:wrap}}
.card{{background:#1a1d2e;border:1px solid #2d3148;border-radius:6px;padding:.5rem .9rem;min-width:90px;text-align:center}}
.card .n{{font-size:22px;font-weight:700;line-height:1.1}}
.card .l{{font-size:11px;color:#64748b;margin-top:2px}}
.tabs{{display:flex;padding:0 1.5rem;background:#141620;border-bottom:1px solid #2d3148}}
.tab{{padding:.6rem 1.2rem;cursor:pointer;font-size:13px;color:#64748b;border-bottom:2px solid transparent}}
.tab.active{{color:#f1f5f9;border-bottom-color:#60a5fa}}
.tab-content{{display:none}}.tab-content.active{{display:block}}
.ctrl{{display:flex;gap:.75rem;padding:.65rem 1.5rem;background:#141620;border-bottom:1px solid #2d3148;flex-wrap:wrap;align-items:center}}
.ctrl select,.ctrl input{{background:#1a1d2e;border:1px solid #2d3148;border-radius:5px;color:#e2e8f0;padding:5px 8px;font-size:13px}}
.ctrl input[type=search]{{width:220px}}
.cnt{{font-size:12px;color:#64748b;margin-left:auto}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}}
table{{width:100%;border-collapse:collapse}}
thead th{{background:#1a1d2e;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;padding:8px 10px;text-align:left;border-bottom:1px solid #2d3148;white-space:nowrap}}
td{{padding:7px 10px;border-bottom:1px solid #1e2130;vertical-align:top}}
tr:hover td{{background:#1a1d2e}}tr.hidden{{display:none}}
.url-cell{{max-width:280px;word-break:break-all;font-size:12px}}
.mono{{font-family:'SFMono-Regular',Consolas,monospace;font-size:11px;word-break:break-all;max-width:200px;color:#a3e635}}
.ctx{{font-size:11px;color:#64748b;max-width:260px;word-break:break-all}}
.center{{text-align:center;color:#94a3b8;font-size:12px}}
footer{{padding:.75rem 1.5rem;font-size:11px;color:#334155;border-top:1px solid #1e2130;text-align:center}}
</style>
</head>
<body>
<header>
  <h1>jsanalyze — {_esc(cfg['target_url'])}</h1>
  <p>{ts} · {stats.get('js',0)} JS analisados · {len(findings)} segredos · {len(endpoints)} endpoints · {len(maps)} source maps</p>
</header>
<div class="banner">
  {"".join(f'<div class="card"><div class="n" style="color:{sev_colors[s]}">{sev_counts[s]}</div><div class="l">{s}</div></div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW"])}
  <div class="card"><div class="n" style="color:#60a5fa">{len(endpoints)}</div><div class="l">Endpoints</div></div>
  <div class="card"><div class="n" style="color:#4ade80">{len(maps)}</div><div class="l">Source Maps</div></div>
  <div class="card"><div class="n" style="color:#a78bfa">{stats.get('js',0)}</div><div class="l">JS</div></div>
</div>
<div class="tabs">
  <div class="tab active" onclick="switchTab('s',this)">🔑 Segredos ({len(findings)})</div>
  <div class="tab" onclick="switchTab('e',this)">🔗 Endpoints ({len(endpoints)})</div>
  <div class="tab" onclick="switchTab('m',this)">🗺️ Source Maps ({len(maps)})</div>
</div>

<div id="tab-s" class="tab-content active">
<div class="ctrl">
  <label>Severidade <select id="sf" onchange="fs()"><option value="">Todas</option>
    <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
  </select></label>
  <label>Tipo <select id="tf" onchange="fs()"><option value="">Todos</option>{types_opts}</select></label>
  <input id="ss" type="search" placeholder="Buscar…" oninput="fs()">
  <span id="sc" class="cnt">{len(findings)} de {len(findings)}</span>
</div>
<table><thead><tr><th>Sev</th><th>Tipo</th><th>URL</th><th>Valor</th><th>Contexto</th></tr></thead>
<tbody id="sb">{secret_rows}</tbody></table>
</div>

<div id="tab-e" class="tab-content">
<div class="ctrl">
  <label>Método <select id="mf" onchange="fe()"><option value="">Todos</option>{method_opts}</select></label>
  <input id="es" type="search" placeholder="Buscar…" oninput="fe()">
  <span id="ec" class="cnt">{len(endpoints)} de {len(endpoints)}</span>
</div>
<table><thead><tr><th>Método</th><th>Path</th><th>URL Absoluta</th><th>JS Fonte</th></tr></thead>
<tbody id="eb">{ep_rows}</tbody></table>
</div>

<div id="tab-m" class="tab-content">
<div class="ctrl">
  <input id="ms" type="search" placeholder="Buscar…" oninput="fm()">
  <span id="mc2" class="cnt">{len(maps)} de {len(maps)}</span>
</div>
<table><thead><tr><th>JS URL</th><th>MAP URL</th><th>Size</th></tr></thead>
<tbody id="mb">{map_rows}</tbody></table>
</div>

<footer>jsanalyze · {_esc(cfg['target_url'])} · {ts}</footer>
<script>
function switchTab(n,el){{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');document.getElementById('tab-'+n).classList.add('active');
}}
const sr=Array.from(document.querySelectorAll('#sb tr'));
function fs(){{
  const sv=document.getElementById('sf').value,tv=document.getElementById('tf').value,
        q=document.getElementById('ss').value.toLowerCase();
  let v=0;
  sr.forEach(r=>{{const ok=(!sv||r.dataset.sev===sv)&&(!tv||r.dataset.type===tv)&&(!q||r.textContent.toLowerCase().includes(q));r.classList.toggle('hidden',!ok);if(ok)v++;}});
  document.getElementById('sc').textContent=v+' de {len(findings)}';
}}
const er=Array.from(document.querySelectorAll('#eb tr'));
function fe(){{
  const mv=document.getElementById('mf').value,q=document.getElementById('es').value.toLowerCase();
  let v=0;
  er.forEach(r=>{{const b=r.cells[0]?.querySelector('.badge')?.textContent||'';
    const ok=(!mv||b===mv)&&(!q||r.textContent.toLowerCase().includes(q));r.classList.toggle('hidden',!ok);if(ok)v++;}});
  document.getElementById('ec').textContent=v+' de {len(endpoints)}';
}}
const mr=Array.from(document.querySelectorAll('#mb tr'));
function fm(){{
  const q=document.getElementById('ms').value.toLowerCase();
  let v=0;
  mr.forEach(r=>{{const ok=!q||r.textContent.toLowerCase().includes(q);r.classList.toggle('hidden',!ok);if(ok)v++;}});
  document.getElementById('mc2').textContent=v+' de {len(maps)}';
}}
</script>
</body>
</html>"""

    cfg["report_html"].write_text(html, encoding="utf-8")
    logger.info("HTML → %s", cfg["report_html"])

# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="jsanalyze",
        description="Coleta e analisa JS de uma URL: segredos, endpoints e source maps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 jsanalyze.py https://appaqpago.minhaconta.zoop.com.br/login
  python3 jsanalyze.py https://site.com --out resultados/
  python3 jsanalyze.py https://site.com --timeout 60 --wait 8
  python3 jsanalyze.py https://site.com --no-headless   # browser visível
        """,
    )
    p.add_argument("url",            help="URL alvo")
    p.add_argument("--out",          default="", help="Diretório de saída (padrão: jsanalyze_<host>)")
    p.add_argument("--timeout",      type=int, default=10, help="Timeout HTTP em segundos (padrão: 10)")
    p.add_argument("--wait",         type=int, default=5,  help="Segundos extras após load (padrão: 5)")
    p.add_argument("--live-timeout", type=int, default=40, help="Timeout do browser (padrão: 40)")
    p.add_argument("--workers",      type=int, default=10, help="Workers paralelos (padrão: 10)")
    p.add_argument("--no-headless",  action="store_true",  help="Abre browser visível (debug)")
    return p.parse_args()

def make_cfg(url: str, args: argparse.Namespace) -> dict:
    host = urlparse(url).netloc.replace(":", "_")
    out = Path(args.out) if args.out else Path(f"jsanalyze_{host}")
    out.mkdir(parents=True, exist_ok=True)
    return {
        "target_url":      url,
        "out_dir":         out,
        "secrets_txt":     out / "secrets.txt",
        "secrets_csv":     out / "secrets.csv",
        "secrets_jsonl":   out / "secrets.jsonl",
        "endpoints_txt":   out / "endpoints.txt",
        "endpoints_jsonl": out / "endpoints.jsonl",
        "maps_txt":        out / "maps.txt",
        "maps_jsonl":      out / "maps.jsonl",
        "report_html":     out / "REPORT.html",
        "log_file":        out / "jsanalyze.log",
        "secret_patterns": _secret_patterns(),
        "endpoint_patterns": _endpoint_patterns(),
        "timeout":         args.timeout,
        "workers":         args.workers,
    }

def main() -> None:
    args = parse_args()
    url = args.url if args.url.startswith("http") else "https://" + args.url

    cfg = make_cfg(url, args)
    logger = setup_logging(cfg["log_file"])
    stats: dict = {}

    logger.info("=" * 60)
    logger.info("jsanalyze — %s", url)
    logger.info("Saída    — %s", cfg["out_dir"])
    logger.info("=" * 60)

    # 1. Coleta JS via browser
    logger.info("═══ Coletando JS via browser ═══")
    js_urls = asyncio.run(collect_js(
        url=url,
        timeout_s=args.live_timeout,
        wait_s=args.wait,
        headless=not args.no_headless,
        logger=logger,
    ))
    stats["js"] = len(js_urls)

    if not js_urls:
        logger.warning("Nenhum JS encontrado. Encerrando.")
        sys.exit(0)

    # 2. Análise
    logger.info("═══ Análise de JS (%d arquivos) ═══", len(js_urls))
    total_secrets = analyze_all(js_urls, cfg, logger)
    stats["secrets"] = total_secrets

    ep_count = sum(1 for l in cfg["endpoints_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines()
                   if l.strip()) if cfg["endpoints_jsonl"].exists() else 0
    maps_count = sum(1 for l in cfg["maps_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines()
                     if l.strip()) if cfg["maps_jsonl"].exists() else 0

    # 3. Relatório
    write_html(cfg, logger, stats)

    logger.info("=" * 60)
    logger.info("JS analisados   : %d", stats["js"])
    logger.info("Segredos        : %d → %s", total_secrets, cfg["secrets_txt"])
    logger.info("Endpoints       : %d → %s", ep_count, cfg["endpoints_txt"])
    logger.info("Source maps     : %d → %s", maps_count, cfg["maps_txt"])
    logger.info("Relatório HTML  : %s", cfg["report_html"])
    logger.info("=" * 60)

if __name__ == "__main__":
    main()
