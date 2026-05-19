#!/usr/bin/env python3
"""
jsrecon.py — Reconhecimento completo e autônomo focado em JavaScript.

Fluxo:
  1. Enumeração de subdomínios  (subfinder / assetfinder / chaos / github-subdomains)
  2. Scan rápido de portas HTTP/HTTPS com nmap
  3. Validação de hosts ativos com httpx  (domínio + subdomínios + portas)
  4. Coleta de JS ao vivo via browser real  (Playwright / Chromium)
  5. Filtragem: mantém APENAS JS cujo host pertence ao target
       (host == dominio.alvo  OU  host termina com .dominio.alvo)
  6. Deduplicação global de arquivos JS
  7. Análise de JS (somente arquivos do target):
       • Segredos / credenciais (40+ padrões, entropia, anti-FP)
       • Detecção de ofuscação por char-code arrays
       • Validação estrutural de JWT
       • Extração rica de endpoints (GET / POST / PUT / DELETE / PATCH / WS)
       • Query strings e parâmetros GET/POST
  8. mapscout  — detecção de source maps expostos (*.js.map reais)
  9. Relatório consolidado  (TXT + JSONL + HTML interativo filtrável)

Dependências Python:
    pip install playwright requests tenacity
    playwright install chromium

Ferramentas externas (opcionais — a ausência é avisada, não fatal):
    subfinder, assetfinder, chaos, github-subdomains, nmap, httpx
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# Portas HTTP/HTTPS alvo
# ─────────────────────────────────────────────────────────────────────────────

HTTP_PORTS = [
    80, 81, 443, 3000, 3001, 4000, 4443, 5000, 5432, 5900,
    6000, 6443, 6885, 7077, 8000, 8080, 8081, 8181, 8443,
    9000, 9091, 9443, 9999, 10000, 15672, 161, 2075, 2076,
    3306, 3366, 3868, 4044,
]
NMAP_PORTS = ",".join(str(p) for p in sorted(set(HTTP_PORTS)))

# ─────────────────────────────────────────────────────────────────────────────
# CDN — lista de domínios de CDN pública conhecidos (pré-filtro rápido)
# ─────────────────────────────────────────────────────────────────────────────

_CDN_RE = re.compile(
    r'(?:cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|'
    r'ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com|'
    r'maxcdn\.bootstrapcdn\.com|code\.jquery\.com|'
    r'cdn\.datatables\.net|cdn\.polyfill\.io|'
    r'static\.cloudflareinsights\.com)',
    re.I,
)

# ─────────────────────────────────────────────────────────────────────────────
# Filtro de domínio alvo  ← NOVO  ← NOVO  ← NOVO
# ─────────────────────────────────────────────────────────────────────────────

def _build_target_filter(root_domain: str, confirmed_hosts: set[str]) -> callable:
    """
    Retorna uma função que aceita uma URL e indica se ela pertence ao target.

    Regras (qualquer uma basta):
      1. host == root_domain                  → target.com.br
      2. host termina com .root_domain        → api.target.com.br
      3. host está em confirmed_hosts         → hosts confirmados pelo httpx
    """
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
    """
    Filtra URLs de JS, mantendo APENAS as que pertencem ao target.
    Loga estatísticas de descarte.
    """
    is_target = _build_target_filter(root_domain, confirmed_hosts)
    kept: set[str] = set()
    dropped: list[str] = []

    for url in js_urls:
        if is_target(url):
            kept.add(url)
        else:
            dropped.append(url)

    logger.info(
        "Filtro de target: %d JS mantidos / %d descartados (terceiros / fora do escopo)",
        len(kept), len(dropped),
    )
    if dropped:
        logger.debug("Exemplos descartados: %s", dropped[:5])

    return kept


# ─────────────────────────────────────────────────────────────────────────────
# Qualidade / anti-falso-positivo
# ─────────────────────────────────────────────────────────────────────────────

_MIN_VALUE_LEN   = 8
_MIN_ENTROPY     = 3.2
_DECODED_ENTROPY_MIN = 3.5

_PLACEHOLDER_RE = re.compile(
    r'^(enter|your|change|example|placeholder|sample|dummy|fake|'
    r'test|demo|default|secret|senha|password|passwd|pass|'
    r'my[-_]?pass(word)?|new[-_]?pass(word)?|old[-_]?pass(word)?|'
    r'confirm|repeat|retype|current|xxxx+|\*+|\.{3,}|#{3,}|'
    r'changeme|mustchange|123456|abcdef|qwerty|letmein|welcome|admin|'
    r'<[^>]+>|\$\{[^}]+\}|%[a-z_]+%)',
    re.I,
)
_UI_CONTEXT_RE = re.compile(
    r'(label|placeholder|hint|aria[-_]label|title|description|'
    r'tooltip|helper|message|text|i18n|translate|t\(|'
    r'console\.log|console\.warn|console\.error|comment|//)',
    re.I,
)

# ─────────────────────────────────────────────────────────────────────────────
# Severidade
# ─────────────────────────────────────────────────────────────────────────────

SECRET_SEVERITY: dict[str, str] = {
    "aws_access_key":          "CRITICAL",
    "private_key":             "CRITICAL",
    "stripe_secret":           "CRITICAL",
    "braintree_token":         "CRITICAL",
    "gcp_service_account":     "CRITICAL",
    "hashicorp_vault":         "CRITICAL",
    "azure_storage_key":       "CRITICAL",
    "github_pat":              "HIGH",
    "github_oauth":            "HIGH",
    "gitlab_pat":              "HIGH",
    "openai_key":              "HIGH",
    "sendgrid_key":            "HIGH",
    "slack_token":             "HIGH",
    "supabase_service_role":   "HIGH",
    "mongodb_dsn":             "HIGH",
    "postgres_dsn":            "HIGH",
    "mysql_dsn":               "HIGH",
    "google_api_key":          "HIGH",
    "firebase_url":            "HIGH",
    "twilio_auth_token":       "HIGH",
    "basic_auth_hardcoded":    "HIGH",
    "basic_auth_btoa":         "HIGH",
    "basic_auth_b64_raw":      "HIGH",
    "hardcoded_credentials":   "HIGH",
    "btoa_decoded":            "HIGH",
    "btoa_creds":              "HIGH",
    "js_secret_key":           "CRITICAL",
    "firebase_app_id":         "HIGH",
    "jwt":                     "MEDIUM",
    "stripe_publishable":      "MEDIUM",
    "slack_webhook":           "MEDIUM",
    "sentry_dsn":              "MEDIUM",
    "mapbox_token":            "MEDIUM",
    "supabase_anon_key":       "MEDIUM",
    "mailgun_api_key":         "MEDIUM",
    "auth_header_hardcoded":   "MEDIUM",
    "firebase_sender_id":      "MEDIUM",
    "firebase_measurement_id": "LOW",
    "firebase_config_block":   "HIGH",
    "generic_api_key":         "LOW",
    "generic_token":           "LOW",
    "generic_secret":          "LOW",
    "bearer_token":            "LOW",
    "password_field":          "LOW",
    "bcrypt_hash":             "LOW",
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
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _rx(p: str, f: int = 0) -> re.Pattern:
    return re.compile(p, f)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq  = collections.Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _extract_val(raw: str) -> str:
    m = re.search(r'[:=]\s*["\']?([^\s"\'`,;]{4,})', raw)
    return m.group(1).strip() if m else raw.strip()


def _is_real_cred(raw: str, ctx: str = "") -> bool:
    v = _extract_val(raw)
    if len(v) < _MIN_VALUE_LEN or _PLACEHOLDER_RE.match(v):
        return False
    if _UI_CONTEXT_RE.search(ctx):
        return False
    return _entropy(v) >= _MIN_ENTROPY


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


def tool_ok(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(cmd: list[str], logger: logging.Logger,
            stdin: str | None = None, timeout: int = 300) -> list[str]:
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True,
                           text=True, timeout=timeout)
        if r.stderr:
            logger.debug("[stderr:%s] %s", cmd[0], r.stderr.strip()[:200])
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


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("jsrecon")
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


# ─────────────────────────────────────────────────────────────────────────────
# Padrões de segredos
# ─────────────────────────────────────────────────────────────────────────────

def _secret_patterns() -> dict[str, re.Pattern]:
    return {
        "google_api_key":          _rx(r'AIza[0-9A-Za-z\-_]{35}'),
        "google_oauth_client":     _rx(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
        "firebase_url":            _rx(r'https?://[a-z0-9\-]+\.firebaseio\.com', re.I),
        "js_secret_key":           _rx(r'secrete?[Kk]ey\s*[:=]\s*["\']([^"\']{6,})["\']', re.I),
        "firebase_app_id":         _rx(r'appId\s*[:=]\s*["\'](\d+:\d+:\w+:[a-f0-9]{16,})["\']', re.I),
        "firebase_sender_id":      _rx(r'messagingSenderId\s*[:=]\s*["\'](\d{8,})["\']', re.I),
        "firebase_measurement_id": _rx(r'measurementId\s*[:=]\s*["\']([A-Z0-9\-]{8,})["\']', re.I),
        "firebase_config_block":   _rx(r'apiKey\s*:\s*["\']([^"\']{20,})["\'][^}]{0,200}authDomain\s*:\s*["\']([^"\']+)["\']', re.I | re.DOTALL),
        "env_config_key":          _rx(r'(?:apiUrl|baseUrl|endpointUrl|serviceUrl|backendUrl)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),
        "gcp_service_account":     _rx(r'"type"\s*:\s*"service_account"'),
        "aws_access_key":          _rx(r'AKIA[0-9A-Z]{16}'),
        "amazon_mws":              _rx(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
        "azure_storage_key":       _rx(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
        "digitalocean_token":      _rx(r'dop_v1_[a-f0-9]{64}'),
        "stripe_secret":           _rx(r'sk_live_[0-9a-zA-Z]{24,}'),
        "stripe_publishable":      _rx(r'pk_live_[0-9a-zA-Z]{24,}'),
        "stripe_webhook":          _rx(r'whsec_[a-zA-Z0-9]{32,}'),
        "braintree_token":         _rx(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'),
        "sendgrid_key":            _rx(r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}'),
        "mailgun_api_key":         _rx(r'key-[0-9a-zA-Z]{32}'),
        "mailchimp_api_key":       _rx(r'[0-9a-f]{32}-us[0-9]{1,2}'),
        "twilio_account_sid":      _rx(r'\bAC[a-z0-9]{32}\b'),
        "twilio_auth_token":       _rx(r'\bSK[a-z0-9]{32}\b'),
        "github_pat":              _rx(r'gh[pousr]_[A-Za-z0-9]{36}'),
        "github_oauth":            _rx(r'gho_[A-Za-z0-9]{36}'),
        "gitlab_pat":              _rx(r'glpat-[A-Za-z0-9\-_]{20}'),
        "gitlab_pipeline":         _rx(r'glptt-[a-f0-9]{40}'),
        "npm_token":               _rx(r'npm_[A-Za-z0-9]{36}'),
        "pypi_token":              _rx(r'pypi-[A-Za-z0-9_\-]{50,}'),
        "dockerhub_pat":           _rx(r'dckr_pat_[A-Za-z0-9_\-]{27}'),
        "hashicorp_vault":         _rx(r'hvs\.[A-Za-z0-9_\-]{90,}'),
        "new_relic_key":           _rx(r'NRAK-[A-Z0-9]{27}'),
        "sentry_dsn":              _rx(r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+'),
        "grafana_token":           _rx(r'glc_[A-Za-z0-9+/]{32,}'),
        "openai_key":              _rx(r'sk-[a-zA-Z0-9]{48}'),
        "slack_token":             _rx(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'),
        "slack_webhook":           _rx(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
        "mongodb_dsn":             _rx(r'mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
        "postgres_dsn":            _rx(r'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
        "mysql_dsn":               _rx(r'mysql://[^:\s]+:[^@\s]+@[^\s"\'`]+', re.I),
        "redis_dsn":               _rx(r'redis://:([^@\s]+)@[^\s"\'`]+', re.I),
        "shopify_token":           _rx(r'shp(?:at|ss)_[a-fA-F0-9]{32}'),
        "mapbox_token":            _rx(r'pk\.eyJ1[A-Za-z0-9._\-]{20,}'),
        "notion_token":            _rx(r'secret_[A-Za-z0-9]{43}'),
        "linear_api_key":          _rx(r'lin_api_[A-Za-z0-9]{40}'),
        "supabase_url":            _rx(r'https://[a-z0-9]{20}\.supabase\.co', re.I),
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
        ("internal_subdomain", _rx(r'(https?://(?:internal|admin|dev|staging|api)\.[a-z0-9\-]+\.[a-z]+[^\s"\'`]*)'), "ANY"),
        ("fetch_get",          _rx(r'(?:fetch|axios\.get|http\.get|request\.get|this\.\$http\.get)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "GET"),
        ("fetch_post",         _rx(r'(?:fetch|axios\.post|http\.post|request\.post|this\.\$http\.post)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "POST"),
        ("fetch_put",          _rx(r'(?:axios\.put|http\.put|request\.put)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "PUT"),
        ("fetch_delete",       _rx(r'(?:axios\.delete|http\.delete|request\.delete)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "DELETE"),
        ("fetch_patch",        _rx(r'(?:axios\.patch|http\.patch|request\.patch)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I), "PATCH"),
        ("fetch_dynamic",      _rx(r'fetch\s*\(\s*["\`]([^"\'`\s]{4,})["\`]\s*,\s*\{[^}]*method\s*:\s*["\'](\w+)["\']', re.I), "DYNAMIC"),
        ("query_string_get",   _rx(r'(?:new\s+URLSearchParams|qs\.stringify|querystring\.stringify)\s*\([^)]*\).*?["\`](/[a-zA-Z0-9/_\-]{2,})["\`]', re.I | re.DOTALL), "GET"),
        ("json_body_post",     _rx(r'body\s*:\s*JSON\.stringify\s*\([^)]*\).*?["\`](/[a-zA-Z0-9/_\-]{2,})["\`]', re.I | re.DOTALL), "POST"),
        ("formdata_post",      _rx(r'new\s+FormData\s*\([^)]*\).*?(?:fetch|axios\.post)\s*\(\s*["\`]([^"\'`\s]{4,})["\`]', re.I | re.DOTALL), "POST"),
        ("router_path",        _rx(r'(?:path|route|to)\s*:\s*["\`](/[a-zA-Z0-9/_\-:]{3,}(?:\?[^\s"\'`]*)?)["\`]', re.I), "GET"),
        ("href_path",          _rx(r'(?:href|src|action)\s*[=:]\s*["\`](/[a-zA-Z0-9/_\-\.]{4,}(?:\?[^\s"\'`]*)?)["\`]', re.I), "GET"),
        ("url_with_query",     _rx(r'["\`]((?:https?://[^\s"\'`]+)?/[a-zA-Z0-9/_\-]{2,}\?(?:[a-zA-Z0-9_\-]+=\w+&?)+)["\`]', re.I), "GET"),
        ("websocket",          _rx(r'new\s+WebSocket\s*\(\s*["\`](wss?://[^\s"\'`]+)["\`]', re.I), "WS"),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Ofuscação por char-code arrays
# ─────────────────────────────────────────────────────────────────────────────

_CHARCODE_RE = re.compile(r'\[\s*(\d{2,3}(?:\s*,\s*\d{2,3}){5,})\s*\]')
_DECODED_CHECKS: list[tuple[str, re.Pattern | None]] = [
    ("bcrypt_hash_decoded",  re.compile(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}')),
    ("google_key_decoded",   re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("aws_key_decoded",      re.compile(r'AKIA[0-9A-Z]{16}')),
    ("jwt_decoded",          re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')),
    ("high_entropy_decoded", None),
]


def _decode_charcode(s: str) -> str | None:
    try:
        codes = [int(x.strip()) for x in s.split(",")]
        if any(c < 32 or c > 126 for c in codes):
            return None
        return "".join(chr(c) for c in codes)
    except ValueError:
        return None


def scan_obfuscation(content: str, url: str, logger: logging.Logger) -> list[dict]:
    results = []
    for m in _CHARCODE_RE.finditer(content):
        decoded = _decode_charcode(m.group(1))
        if not decoded or len(decoded) < 8:
            continue
        label = None
        for lbl, pat in _DECODED_CHECKS:
            if pat is None:
                if _entropy(decoded) >= _DECODED_ENTROPY_MIN:
                    label = lbl
                break
            if pat.search(decoded):
                label = lbl
                break
        if label:
            ctx = content[max(0, m.start()-60):min(len(content), m.end()+60)].replace("\n", " ")
            logger.warning("[!!!] %s (ofuscado) → %s | decoded: %s", label, url, decoded[:80])
            results.append({"type": label, "value": decoded, "context": ctx, "url": url})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Estado global thread-safe
# ─────────────────────────────────────────────────────────────────────────────

_analyzed_js:    set[str]       = set()
_analyzed_lock:  threading.Lock = threading.Lock()
_seen_secrets:   set[tuple]     = set()
_secrets_lock:   threading.Lock = threading.Lock()
_secret_write:   threading.Lock = threading.Lock()
_seen_endpoints: set[tuple]     = set()
_endpoint_write: threading.Lock = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# Escrita de arquivos
# ─────────────────────────────────────────────────────────────────────────────

def _write(path: Path, lines, logger: logging.Logger) -> bool:
    content = [str(l) for l in lines if str(l).strip()]
    if not content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(content) + "\n", encoding="utf-8")
    logger.debug("Salvo: %s (%d linhas)", path, len(content))
    return True


def _append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting + retries
# ─────────────────────────────────────────────────────────────────────────────

_host_sems: dict[str, threading.Semaphore] = {}
_host_lock  = threading.Lock()
_req_logger = logging.getLogger("jsrecon.req")


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
                headers={"User-Agent": "Mozilla/5.0 jsrecon"},
                timeout=cfg["timeout"],
                verify=False,
                allow_redirects=True,
                **kw,
            )
            if r.status_code == 429:
                time.sleep(min(int(r.headers.get("Retry-After", 10)), 60))
                r.raise_for_status()
            elif r.status_code == 503:
                time.sleep(5)
                r.raise_for_status()
            return r
    return _get


# ─────────────────────────────────────────────────────────────────────────────
# Persistência de segredos
# ─────────────────────────────────────────────────────────────────────────────

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
            "severity": finding["severity"],
            "type":     finding["type"],
            "url":      finding["url"],
            "value":    finding["value"],
            "context":  finding["context"][:300],
        }, ensure_ascii=False))
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Persistência de endpoints
# ─────────────────────────────────────────────────────────────────────────────

def _abs_url(path: str, js_url: str, domain: str) -> str:
    if path.startswith(("http://", "https://", "ws://", "wss://")):
        return path
    base = f"https://{domain}"
    return base + (path if path.startswith("/") else "/" + path)


def _query_params(url_or_path: str) -> str:
    if "?" not in url_or_path:
        return ""
    qs = url_or_path.split("?", 1)[1].split("#")[0]
    try:
        parsed = urllib.parse.parse_qs(qs, keep_blank_values=True)
        return "&".join(f"{k}={v}" for k, vs in parsed.items() for v in vs)
    except Exception:
        return qs


def _save_endpoint(ep: dict, cfg: dict) -> bool:
    method    = ep.get("method", "UNKNOWN").upper()
    path      = ep.get("path", "").strip()
    path_base = path.split("?")[0].rstrip("/") or "/"
    key       = (method if method != "ANY" else "_", path_base)

    with _endpoint_write:
        if key in _seen_endpoints:
            return False
        _seen_endpoints.add(key)

        abs_u = ep.get("absolute_url") or _abs_url(path, ep.get("js_url", ""), cfg["domain"])
        line  = (f"[{method}] {path}\n"
                 f"  → Absoluta : {abs_u}\n"
                 f"  → Fonte JS : {ep.get('js_url','?')}\n")
        if ep.get("query_params"):
            line += f"  → Query    : {ep['query_params']}\n"
        line += "-" * 60
        _append(cfg["endpoints_txt"], line)
        _append(cfg["endpoints_jsonl"], json.dumps({
            "method":       method,
            "path":         path,
            "absolute_url": abs_u,
            "query_params": ep.get("query_params", ""),
            "js_source":    ep.get("js_url", ""),
        }, ensure_ascii=False))
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Análise de conteúdo JS
# ─────────────────────────────────────────────────────────────────────────────

def analyze_js(content: str, url: str, cfg: dict, logger: logging.Logger) -> int:
    found  = 0
    lines  = content.splitlines()
    domain = cfg["domain"]

    def _line_at(pos: int) -> str:
        n = 0
        for l in lines:
            n += len(l) + 1
            if n >= pos:
                return l
        return ""

    # ── Segredos ─────────────────────────────────────────────────────────────
    for name, pattern in cfg["secret_patterns"].items():
        for m in pattern.finditer(content):
            raw   = m.group(0)
            value = m.group(1) if m.lastindex and m.lastindex >= 1 else raw

            if name in _GENERIC_PATTERNS:
                if not _is_real_cred(value, _line_at(m.start())):
                    continue
            if name == "jwt" and not _is_real_jwt(value):
                continue

            ctx     = content[max(0, m.start()-90):min(len(content), m.end()+90)].replace("\r", " ").replace("\n", " ")
            finding = {"type": name, "value": value, "url": url, "context": ctx}
            if _save_secret(finding, cfg):
                logger.warning("[!!!] %s → %s | %s", name, value[:80], url)
                found += 1

    # ── Ofuscação ─────────────────────────────────────────────────────────────
    for obf in scan_obfuscation(content, url, logger):
        _save_secret(obf, cfg)
        found += 1

    # ── btoa() ────────────────────────────────────────────────────────────────
    _btoa_re = re.compile(r'\bbtoa\s*\(\s*["\'](.*?)["\'\']\s*\)', re.I)
    for bm in _btoa_re.finditer(content):
        raw_val = bm.group(1)
        ctx     = content[max(0, bm.start()-80):min(len(content), bm.end()+80)].replace("\n", " ")
        finding = {"type": "btoa_decoded", "value": raw_val, "url": url, "context": ctx}
        if _save_secret(finding, cfg):
            decoded = ""
            try:
                import base64 as _b64mod
                decoded = _b64mod.b64decode(raw_val + "==").decode("utf-8", errors="replace")
            except Exception:
                pass
            if decoded and decoded != raw_val:
                logger.warning("[!!!] btoa decoded → '%s' (claro: '%s') | %s", raw_val, decoded, url)
            else:
                logger.warning("[!!!] btoa hardcoded → '%s' | %s", raw_val, url)
            found += 1

    # ── Endpoints ─────────────────────────────────────────────────────────────
    for label, pattern, method_hint in cfg["endpoint_patterns"]:
        for m in pattern.finditer(content):
            path = (m.group(1) or "").strip().strip("\"'`")
            if not path or len(path) < 2:
                continue
            if re.search(r'\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|css)$', path, re.I):
                continue
            method = (m.group(2).upper() if method_hint == "DYNAMIC"
                      and m.lastindex and m.lastindex >= 2 else method_hint)
            ep = {
                "method":       method,
                "path":         path,
                "absolute_url": _abs_url(path, url, domain),
                "query_params": _query_params(path),
                "js_url":       url,
            }
            if _save_endpoint(ep, cfg):
                logger.debug("[EP][%s] %s ← %s", method, path, url)

    return found


def is_js(resp: requests.Response, content: str) -> bool:
    ct = resp.headers.get("Content-Type", "")
    if "javascript" in ct or "ecmascript" in ct:
        return True
    s = content.strip()
    if s.startswith(("<html", "<HTML", "<!DOCTYPE", "<!doctype", "<?xml")):
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
            if d.get("v") == "1" and time.time() - d.get("ts", 0) < 86400:
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
    if not is_js(resp, content):
        return 0

    if not cfg.get("no_cache"):
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps({"v": "1", "ts": time.time(), "c": content},
                                             ensure_ascii=False), encoding="utf-8")
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
        for fut in as_completed(futs):
            try:
                total += fut.result()
            except Exception as e:
                logger.error("Worker error: %s", e)
    return total


# ─────────────────────────────────────────────────────────────────────────────
# Playwright — coleta JS ao vivo
# ─────────────────────────────────────────────────────────────────────────────

async def _playwright_crawl(
    url: str,
    timeout_s: int,
    wait_s: int,
    headless: bool,
    logger: logging.Logger,
) -> list[dict]:
    """
    Versão corrigida: usa response interception + scroll + manifest parse.
    Captura chunks JS com hash no nome (ex: 956.8df871f4bf4dee8.js).
    """
    from playwright.async_api import async_playwright
    import re, json

    js_files: list[dict] = []
    seen: set[str] = set()

    def _is_js_url(resp_url: str, content_type: str) -> bool:
        """Aceita a URL se o path termina em .js OU se o Content-Type é JS."""
        path = urlparse(resp_url).path.lower()
        ct   = (content_type or "").lower()
        path_ok = path.endswith(".js") or ".js?" in path
        ct_ok   = "javascript" in ct or "ecmascript" in ct
        return path_ok or ct_ok

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

        # ── Intercepta RESPOSTAS (não requests) ──────────────────────────────
        async def on_response(resp):
            try:
                resp_url = resp.url
                ct       = resp.headers.get("content-type", "")
                if resp_url in seen:
                    return
                if _is_js_url(resp_url, ct):
                    seen.add(resp_url)
                    parsed = urlparse(resp_url)
                    js_files.append({
                        "url":      resp_url,
                        "domain":   parsed.netloc,
                        "path":     parsed.path,
                        "resource": "script",
                    })
            except Exception:
                pass

        page.on("response", on_response)

        # ── Navega com wait_until="load" (mais tolerante) ────────────────────
        logger.info("  🌐 Browser → %s", url)
        try:
            await page.goto(
                url,
                timeout=timeout_s * 1000,
                wait_until="load",           # <── era "networkidle"
            )
        except Exception as e:
            logger.debug("  [browser] load timeout em %s: %s", url, e)

        # ── Pausa inicial para scripts assíncronos ────────────────────────────
        await asyncio.sleep(max(wait_s, 3))

        # ── Scroll para disparar lazy loading ────────────────────────────────
        try:
            await page.evaluate("""
                async () => {
                    const delay = ms => new Promise(r => setTimeout(r, ms));
                    for (let i = 0; i < 5; i++) {
                        window.scrollBy(0, window.innerHeight);
                        await delay(600);
                    }
                    window.scrollTo(0, 0);
                    await delay(500);
                }
            """)
        except Exception as e:
            logger.debug("  [browser] scroll error: %s", e)

        # ── Segunda pausa pós-scroll ──────────────────────────────────────────
        await asyncio.sleep(2)

        # ── Tenta extrair URLs do manifesto webpack / asset-manifest ─────────
        manifest_urls = await _extract_manifest_urls(page, url, logger)
        for mu in manifest_urls:
            if mu not in seen:
                seen.add(mu)
                parsed = urlparse(mu)
                js_files.append({
                    "url":      mu,
                    "domain":   parsed.netloc,
                    "path":     parsed.path,
                    "resource": "script_manifest",
                })

        await browser.close()

    logger.info("  → %d JS capturados (bruto, pré-filtro)", len(js_files))
    return js_files


async def _extract_manifest_urls(page, base_url: str, logger: logging.Logger) -> list[str]:
    """
    Tenta ler asset-manifest.json / webpack-manifest / __webpack_modules__
    para descobrir URLs de chunks que o scroll pode não ter disparado.
    """
    import re, json
    import requests
    from urllib.parse import urljoin

    found: list[str] = []

    # 1. Manifesto estático comum em React/CRA e Next.js
    for manifest_path in [
        "/asset-manifest.json",
        "/static/asset-manifest.json",
        "/_next/static/chunks/",
        "/webpack-stats.json",
    ]:
        try:
            manifest_url = urljoin(base_url, manifest_path)
            r = requests.get(manifest_url, timeout=8, verify=False,
                             headers={"User-Agent": "Mozilla/5.0 jsrecon"})
            if r.status_code == 200 and "javascript" in r.headers.get("content-type", "").lower() or \
               r.status_code == 200 and manifest_path.endswith(".json"):
                data = r.json()
                # CRA format: {"files": {"main.js": "/static/js/main.xxx.js"}}
                files = data.get("files", data)
                for k, v in (files.items() if isinstance(files, dict) else {}.items()):
                    if isinstance(v, str) and v.endswith(".js"):
                        found.append(urljoin(base_url, v))
                if found:
                    logger.info("  [manifest] %d URLs via %s", len(found), manifest_path)
                    break
        except Exception:
            pass

    # 2. Extrai URLs de chunks do HTML já carregado
    try:
        html = await page.content()
        # Padrão: src="/static/js/936.abc123.chunk.js" ou src="/123.abc.js"
        for m in re.finditer(
            r'(?:src|href)=["\']([^"\']*?\.(?:js|mjs)(?:\?[^"\']*)?)["\']',
            html,
            re.I,
        ):
            chunk_url = m.group(1)
            if chunk_url.startswith("/"):
                from urllib.parse import urljoin
                chunk_url = urljoin(base_url, chunk_url)
            if chunk_url.startswith("http"):
                found.append(chunk_url)

        # Padrão webpack: "chunk": "956.8df871f4bf4dee8"
        for m in re.finditer(r'"([0-9a-f]{3,4}\.[0-9a-f]{16,})"', html):
            name = m.group(1)
            found.append(urljoin(base_url, f"/static/js/{name}.chunk.js"))
            found.append(urljoin(base_url, f"/{name}.js"))

    except Exception as e:
        logger.debug("  [manifest] html parse error: %s", e)

    return list(set(found))


async def live_crawl_all(targets: list[str], cfg: dict,
                          logger: logging.Logger) -> set[str]:
    """Roda o Playwright em cada alvo e retorna set de URLs de JS brutas (sem filtro de domínio)."""
    all_js: set[str] = set()
    total = len(targets)
    for idx, url in enumerate(targets, 1):
        logger.info("[live %d/%d] %s", idx, total, url)
        try:
            files = await _playwright_crawl(
                url, cfg["live_timeout"], cfg["live_wait"],
                cfg["headless"], logger,
            )
            for f in files:
                js_url = f["url"]
                # Filtro de CDN apenas (filtro de domínio é feito depois)
                if not _CDN_RE.search(js_url):
                    all_js.add(js_url)
        except Exception as e:
            logger.error("  [browser] erro em %s: %s", url, e)

    logger.info("[live-crawler] total de JS bruto (pré-filtro de domínio): %d", len(all_js))
    return all_js


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

    if tool_ok("chaos"):
        if not chaos_key:
            logger.warning("[chaos] pulando — CHAOS_KEY não definida.")
        else:
            logger.info("[chaos] …")
            lines = run_cmd(["chaos", "-d", domain, "-key", chaos_key, "-silent"], logger, timeout=180)
            subs.update(lines)
            logger.info("[chaos] %d subs", len(lines))
    else:
        logger.warning("chaos não encontrado  |  go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest")

    if tool_ok("github-subdomains"):
        if not github_token:
            logger.warning("[github-subdomains] pulando — GITHUB_TOKEN não definido.")
        else:
            logger.info("[github-subdomains] …")
            lines = run_cmd(["github-subdomains", "-d", domain, "-t", github_token, "-raw"], logger, timeout=120)
            subs.update(lines)
            logger.info("[github-subdomains] %d subs", len(lines))
    else:
        logger.warning("github-subdomains não encontrado  |  go install github.com/gwen001/github-subdomains@latest")

    clean = {
        s.strip().lower() for s in subs
        if s.strip()
        and "*" not in s
        and domain in s
        and s.strip().lower() != domain
    }
    clean.add(domain)

    logger.info("Subdomínios únicos (total): %d", len(clean))
    _write(cfg["subs_file"], sorted(clean), logger)
    return clean


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 2 — Nmap
# ─────────────────────────────────────────────────────────────────────────────

def nmap_scan(subs: set[str], cfg: dict, logger: logging.Logger) -> dict[str, list[int]]:
    if not tool_ok("nmap"):
        logger.warning("nmap não encontrado — pulando scan de portas  |  apt install nmap")
        return {s: [80, 443] for s in subs}

    logger.info("═══ Nmap — %d hosts × %d portas ═══", len(subs), len(HTTP_PORTS))

    hosts_file = cfg["out_dir"] / "_nmap_hosts.txt"
    _write(hosts_file, sorted(subs), logger)

    nmap_out = cfg["out_dir"] / "nmap_results.txt"
    cmd = [
        "nmap", "-iL", str(hosts_file),
        "-p", NMAP_PORTS,
        "--open", "-T4",
        "--max-retries", "1",
        "--host-timeout", "30s",
        "-oN", str(nmap_out),
        "-n",
    ]
    logger.info("[nmap] rodando…")
    run_cmd(cmd, logger, timeout=1800)

    open_ports: dict[str, list[int]] = {}
    if nmap_out.exists():
        current_host = None
        for line in nmap_out.read_text(encoding="utf-8", errors="ignore").splitlines():
            hm = re.match(r'^Nmap scan report for (.+)', line)
            if hm:
                h = re.sub(r'\s*\(.*?\)', '', hm.group(1)).strip()
                current_host = h
                open_ports.setdefault(current_host, [])
            pm = re.match(r'^(\d+)/tcp\s+open', line)
            if pm and current_host:
                open_ports[current_host].append(int(pm.group(1)))

    for s in subs:
        if s not in open_ports:
            open_ports[s] = []

    total_open = sum(len(v) for v in open_ports.values())
    logger.info("[nmap] portas abertas encontradas: %d", total_open)

    summary = [f"{h}: {','.join(map(str,ports)) or 'nenhuma'}"
               for h, ports in sorted(open_ports.items())]
    _write(cfg["out_dir"] / "nmap_summary.txt", summary, logger)
    return open_ports


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 3 — httpx
# ─────────────────────────────────────────────────────────────────────────────

def httpx_probe(
    open_ports: dict[str, list[int]],
    cfg: dict,
    logger: logging.Logger,
) -> tuple[list[str], set[str]]:
    """
    Retorna (alive_urls, confirmed_hosts).
    confirmed_hosts é o set de hostnames confirmados ativos — usado pelo filtro de JS.
    """
    logger.info("═══ httpx — validação de hosts ativos ═══")

    HTTPS_PORTS = {443, 8443, 9443, 4443, 6443, 2076, 10000}

    candidates: set[str] = set()
    for host, ports in open_ports.items():
        base_ports = set(ports) | {80, 443}
        for port in base_ports:
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
        logger.warning("httpx não encontrado — usando candidatos sem validação  |  "
                       "go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        urls = sorted(candidates)
        hosts = {urlparse(u).netloc.split(":")[0].lower() for u in urls}
        _write(cfg["alive_file"], urls, logger)
        return urls, hosts

    candidate_list = sorted(candidates)
    logger.info("[httpx] testando %d candidatos…", len(candidate_list))

    try:
        result = subprocess.run(
            ["httpx", "-silent",
             "-mc", "200,201,204,301,302,307,308,401,403",
             "-threads", "50",
             "-timeout", "8",
             "-follow-redirects"],
            input="\n".join(candidate_list) + "\n",
            capture_output=True, text=True, timeout=600,
        )
        urls_clean = [u.strip() for u in result.stdout.splitlines()
                      if u.strip().startswith("http")]
    except subprocess.TimeoutExpired:
        logger.warning("Timeout no httpx — usando candidatos sem filtrar.")
        urls_clean = candidate_list
    except Exception as e:
        logger.error("Erro no httpx: %s", e)
        urls_clean = candidate_list

    # Extrai hostnames confirmados
    confirmed_hosts = {
        urlparse(u).netloc.lower().split(":")[0]
        for u in urls_clean
    }

    _write(cfg["alive_file"], urls_clean, logger)
    logger.info("[httpx] hosts ativos: %d", len(urls_clean))
    logger.info("[httpx] hostnames confirmados: %d", len(confirmed_hosts))
    return urls_clean, confirmed_hosts


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 4 — Coleta de JS ao vivo (Playwright)
# ─────────────────────────────────────────────────────────────────────────────

def collect_live_js(
    alive_urls: list[str],
    confirmed_hosts: set[str],
    cfg: dict,
    logger: logging.Logger,
) -> set[str]:
    logger.info("═══ Coleta de JS ao vivo (browser) ═══")

    seen_targets: set[str] = set()
    targets: list[str] = []
    for url in alive_urls:
        parsed = urlparse(url)
        key    = parsed.netloc
        if key not in seen_targets:
            seen_targets.add(key)
            base = f"{parsed.scheme}://{parsed.netloc}"
            targets.append(base)

    logger.info("Alvos para browser: %d", len(targets))

    # Coleta bruta (todos os JS que o browser carregar)
    js_raw = asyncio.run(live_crawl_all(targets, cfg, logger))

    # ── FILTRO DE DOMÍNIO ─────────────────────────────────────────────────────
    # Remove .map e aplica filtro: apenas JS do domínio alvo e subdomínios
    js_no_maps = {u for u in js_raw if not u.endswith(".js.map")}
    js_clean   = filter_target_js(js_no_maps, cfg["domain"], confirmed_hosts, logger)

    _write(cfg["js_urls_file"], sorted(js_clean), logger)
    logger.info(
        "JS do target salvos: %d → %s",
        len(js_clean), cfg["js_urls_file"],
    )
    return js_clean


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 5 — mapscout (chamado ao final)
# ─────────────────────────────────────────────────────────────────────────────

def run_mapscout(
    js_urls: set[str],
    confirmed_hosts: set[str],
    cfg: dict,
    logger: logging.Logger,
) -> int:
    """Importa e executa o mapscout programaticamente."""
    logger.info("═══ mapscout — source maps expostos ═══")
    try:
        import mapscout
    except ImportError:
        logger.error(
            "mapscout.py não encontrado. Coloque mapscout.py no mesmo diretório que jsrecon.py."
        )
        return 0

    findings = mapscout.run(
        js_urls=sorted(js_urls),
        root_domain=cfg["domain"],
        out_dir=cfg["out_dir"],
        extra_hosts=confirmed_hosts,
        workers=cfg["workers"],
        timeout=cfg["timeout"],
        logger=logger,
    )
    return len(findings)


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

def make_cfg(domain: str, args: argparse.Namespace) -> dict:
    out = Path(f"jsrecon_{domain}")
    out.mkdir(exist_ok=True)

    return {
        "domain":            domain,
        "out_dir":           out,
        "subs_file":         out / "subdomains.txt",
        "alive_file":        out / "hosts_alive.txt",
        "js_urls_file":      out / "js_urls.txt",
        "secrets_txt":       out / "secrets.txt",
        "secrets_csv":       out / "secrets.csv",
        "secrets_jsonl":     out / "secrets.jsonl",
        "endpoints_txt":     out / "endpoints.txt",
        "endpoints_jsonl":   out / "endpoints.jsonl",
        "summary_txt":       out / "SUMMARY.txt",
        "summary_html":      out / "SUMMARY.html",
        "log_file":          out / "jsrecon.log",
        "cache_dir":         out / ".js_cache",
        "secret_patterns":   _secret_patterns(),
        "endpoint_patterns": _endpoint_patterns(),
        "timeout":           args.timeout,
        "workers":           args.workers,
        "live_timeout":      args.live_timeout,
        "live_wait":         args.live_wait,
        "headless":          not args.no_headless,
        "no_cache":          args.no_cache,
        "no_mapscout":       args.no_mapscout,
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
    }
    ok, missing = [], []
    for t, install in tools.items():
        (ok if tool_ok(t) else missing).append((t, install))

    logger.info("─── Preflight ───────────────────────────────────────")
    logger.info("OK   : %s", ", ".join(t for t, _ in ok) or "nenhuma")
    for t, cmd in missing:
        logger.warning("AUSENTE : %-22s  instalar: %s", t, cmd)
    logger.info("────────────────────────────────────────────────────")


# ─────────────────────────────────────────────────────────────────────────────
# Relatórios
# ─────────────────────────────────────────────────────────────────────────────

def _sev_summary(jsonl: Path) -> list[str]:
    counts: dict[str, int] = collections.Counter()
    sevs:   dict[str, str] = {}
    if not jsonl.exists():
        return []
    for line in jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            o = json.loads(line)
            t = o.get("type", "?")
            counts[t] += 1
            sevs[t] = o.get("severity", "UNKNOWN")
        except Exception:
            pass
    return [
        f"    [{sevs.get(t,'?')}] {t}: {n}"
        for t, n in sorted(counts.items(),
                           key=lambda x: (_SEVERITY_ORDER.get(sevs.get(x[0], "UNKNOWN"), 4), -x[1]))
    ]


def write_summary_txt(cfg: dict, logger: logging.Logger, stats: dict) -> None:
    def c(p: Path) -> int:
        if not p.exists():
            return 0
        return sum(1 for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip())

    maps_file = cfg["out_dir"] / "maps_exposed.jsonl"
    maps_count = c(maps_file) if maps_file.exists() else 0

    lines = [
        "=" * 64,
        "  JSRECON — SUMÁRIO",
        f"  Alvo  : {cfg['domain']}",
        f"  Saída : {cfg['out_dir']}",
        "=" * 64, "",
        f"  Subdomínios encontrados  : {str(stats.get('subs', 0)).rjust(6)}",
        f"  Hosts ativos (httpx)     : {str(stats.get('alive', 0)).rjust(6)}",
        f"  JS coletados (target)    : {str(stats.get('js', 0)).rjust(6)}",
        "",
        f"  Segredos encontrados     : {str(stats.get('secrets', 0)).rjust(6)}",
    ] + _sev_summary(cfg["secrets_jsonl"]) + [
        "",
        f"  Endpoints extraídos      : {str(c(cfg['endpoints_jsonl'])).rjust(6)}",
        f"  Source maps expostos     : {str(maps_count).rjust(6)}",
        "", "=" * 64,
        "", "  Arquivos gerados:",
    ] + [f"    {p.name}" for p in [
        cfg["secrets_txt"], cfg["secrets_csv"], cfg["secrets_jsonl"],
        cfg["endpoints_txt"], cfg["endpoints_jsonl"],
        cfg["out_dir"] / "maps_exposed.txt",
        cfg["out_dir"] / "maps_exposed.jsonl",
        cfg["out_dir"] / "maps_exposed.html",
        cfg["alive_file"], cfg["js_urls_file"],
        cfg["summary_html"], cfg["log_file"],
    ] if p.exists()] + ["", "=" * 64]

    _write(cfg["summary_txt"], lines, logger)
    for l in lines:
        logger.info(l)


def write_summary_html(cfg: dict, logger: logging.Logger, stats: dict) -> None:
    findings:  list[dict] = []
    endpoints: list[dict] = []
    maps:      list[dict] = []

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

    maps_jsonl = cfg["out_dir"] / "maps_exposed.jsonl"
    if maps_jsonl.exists():
        for line in maps_jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                maps.append(json.loads(line))
            except Exception:
                pass

    findings.sort(key=lambda x: (_SEVERITY_ORDER.get(x.get("severity", "UNKNOWN"), 4), x.get("type", "")))

    sev_colors = {
        "CRITICAL": "#c0392b", "HIGH": "#e67e22",
        "MEDIUM":   "#2980b9", "LOW":  "#27ae60", "UNKNOWN": "#7f8c8d",
    }
    meth_colors = {
        "GET": "#27ae60", "POST": "#e67e22", "PUT": "#2980b9",
        "DELETE": "#c0392b", "PATCH": "#8e44ad", "WS": "#16a085",
        "ANY": "#7f8c8d", "UNKNOWN": "#7f8c8d", "DYNAMIC": "#7f8c8d",
    }

    sev_counts = {s: sum(1 for f in findings if f.get("severity") == s)
                  for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    def _esc(s: str) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    secret_rows = ""
    for f in findings:
        sev   = f.get("severity", "UNKNOWN")
        color = sev_colors.get(sev, "#7f8c8d")
        url   = f.get("url", "")
        val   = _esc(f.get("value", "")[:120])
        ctx   = _esc(f.get("context", "")[:200])
        secret_rows += (
            f'<tr data-sev="{sev}" data-type="{f.get("type","")}">'
            f'<td><span class="badge" style="background:{color}">{sev}</span></td>'
            f'<td><code>{f.get("type","")}</code></td>'
            f'<td class="url-cell"><a href="{url}" target="_blank">{url[:100]}</a></td>'
            f'<td class="mono">{val}</td>'
            f'<td class="ctx">{ctx}</td></tr>\n'
        )

    ep_rows = ""
    for ep in endpoints:
        m    = ep.get("method", "?")
        mc   = meth_colors.get(m, "#7f8c8d")
        path = _esc(ep.get("path", "")[:120])
        abs_ = ep.get("absolute_url", "")
        qp   = _esc(ep.get("query_params", "")[:80])
        src  = _esc(ep.get("js_source", "")[:80])
        ep_rows += (
            f'<tr><td><span class="badge" style="background:{mc}">{m}</span></td>'
            f'<td class="mono">{path}</td>'
            f'<td class="url-cell"><a href="{abs_}" target="_blank">{abs_[:80]}</a></td>'
            f'<td class="ctx">{qp}</td>'
            f'<td class="ctx">{src}</td></tr>\n'
        )

    map_rows = ""
    for mp in maps:
        map_rows += (
            f'<tr>'
            f'<td class="url-cell mono"><a href="{mp.get("js_url","")}" target="_blank">'
            f'{_esc(mp.get("js_url","")[:100])}</a></td>'
            f'<td class="url-cell"><a href="{mp.get("map_url","")}" target="_blank" style="color:#4ade80;font-weight:600">'
            f'{_esc(mp.get("map_url","")[:100])}</a></td>'
            f'<td class="center">{_esc(mp.get("size","?"))}</td>'
            f'<td class="center">{_esc(mp.get("content_type","")[:40])}</td>'
            f'</tr>\n'
        )

    types_opts  = "".join(f'<option value="{t}">{t}</option>'
                           for t in sorted(set(f.get("type","") for f in findings)))
    method_opts = "".join(f'<option value="{m}">{m}</option>'
                           for m in sorted(set(ep.get("method","") for ep in endpoints)))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>jsrecon — {cfg['domain']}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;font-size:14px}}
a{{color:#60a5fa;text-decoration:none}}a:hover{{text-decoration:underline}}
code{{font-family:'SFMono-Regular',Consolas,monospace;font-size:12px;background:#1e2130;padding:1px 5px;border-radius:3px}}
header{{background:#1a1d2e;border-bottom:1px solid #2d3148;padding:1rem 1.5rem}}
header h1{{font-size:16px;font-weight:600;color:#f1f5f9}}
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
thead th{{background:#1a1d2e;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;padding:8px 10px;text-align:left;cursor:pointer;border-bottom:1px solid #2d3148;white-space:nowrap;user-select:none}}
thead th:hover{{color:#f1f5f9}}
td{{padding:7px 10px;border-bottom:1px solid #1e2130;vertical-align:top}}
tr:hover td{{background:#1a1d2e}}tr.hidden{{display:none}}
.url-cell{{max-width:260px;word-break:break-all;font-size:12px}}
.mono{{font-family:'SFMono-Regular',Consolas,monospace;font-size:11px;word-break:break-all;max-width:200px;color:#a3e635}}
.ctx{{font-size:11px;color:#64748b;max-width:260px;word-break:break-all}}
.center{{text-align:center;white-space:nowrap;color:#94a3b8;font-size:12px}}
footer{{padding:.75rem 1.5rem;font-size:11px;color:#334155;border-top:1px solid #1e2130;text-align:center}}
</style>
</head>
<body>
<header>
  <h1>jsrecon — {cfg['domain']}</h1>
  <p>{ts} · {stats.get('subs',0)} subs · {stats.get('alive',0)} hosts ativos · {stats.get('js',0)} JS (target) · {len(findings)} segredos · {len(endpoints)} endpoints · {len(maps)} source maps</p>
</header>
<div class="banner">
  {"".join(f'<div class="card"><div class="n" style="color:{sev_colors[s]}">{sev_counts[s]}</div><div class="l">{s}</div></div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW"])}
  <div class="card"><div class="n" style="color:#60a5fa">{len(endpoints)}</div><div class="l">Endpoints</div></div>
  <div class="card"><div class="n" style="color:#4ade80">{len(maps)}</div><div class="l">Source Maps</div></div>
  <div class="card"><div class="n" style="color:#a78bfa">{stats.get('js',0)}</div><div class="l">JS (target)</div></div>
  <div class="card"><div class="n" style="color:#34d399">{stats.get('alive',0)}</div><div class="l">Hosts ativos</div></div>
  <div class="card"><div class="n" style="color:#fb923c">{stats.get('subs',0)}</div><div class="l">Subdomínios</div></div>
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
<table id="st"><thead><tr>
  <th onclick="sort('st',0)">Sev ↕</th><th onclick="sort('st',1)">Tipo ↕</th>
  <th onclick="sort('st',2)">URL ↕</th><th>Valor</th><th>Contexto</th>
</tr></thead><tbody>{secret_rows}</tbody></table>
</div>

<div id="tab-e" class="tab-content">
<div class="ctrl">
  <label>Método <select id="mf" onchange="fe()"><option value="">Todos</option>{method_opts}</select></label>
  <input id="es" type="search" placeholder="Buscar…" oninput="fe()">
  <span id="ec" class="cnt">{len(endpoints)} de {len(endpoints)}</span>
</div>
<table id="et"><thead><tr>
  <th onclick="sort('et',0)">Método ↕</th><th onclick="sort('et',1)">Path ↕</th>
  <th onclick="sort('et',2)">URL Absoluta ↕</th><th>Query Params</th><th>JS Fonte</th>
</tr></thead><tbody>{ep_rows}</tbody></table>
</div>

<div id="tab-m" class="tab-content">
<div class="ctrl">
  <input id="ms" type="search" placeholder="Buscar…" oninput="fm()">
  <span id="mc2" class="cnt">{len(maps)} de {len(maps)}</span>
</div>
<table id="mt"><thead><tr>
  <th onclick="sort('mt',0)">JS URL ↕</th><th onclick="sort('mt',1)">MAP URL ↕</th>
  <th>Size</th><th>Content-Type</th>
</tr></thead><tbody>{map_rows}</tbody></table>
</div>

<footer>jsrecon · {cfg['domain']} · {len(findings)} segredos · {len(endpoints)} endpoints · {len(maps)} source maps · {ts}</footer>
<script>
function switchTab(n,el){{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');document.getElementById('tab-'+n).classList.add('active');
}}
const sr=Array.from(document.querySelectorAll('#st tbody tr'));
function fs(){{
  const sv=document.getElementById('sf').value,tv=document.getElementById('tf').value,
        q=document.getElementById('ss').value.toLowerCase();
  let v=0;
  sr.forEach(r=>{{const ok=(!sv||r.dataset.sev===sv)&&(!tv||r.dataset.type===tv)&&(!q||r.textContent.toLowerCase().includes(q));r.classList.toggle('hidden',!ok);if(ok)v++;}});
  document.getElementById('sc').textContent=v+' de {len(findings)}';
}}
const er=Array.from(document.querySelectorAll('#et tbody tr'));
function fe(){{
  const mv=document.getElementById('mf').value,q=document.getElementById('es').value.toLowerCase();
  let v=0;
  er.forEach(r=>{{const b=r.cells[0]?.querySelector('.badge')?.textContent||'';
    const ok=(!mv||b===mv)&&(!q||r.textContent.toLowerCase().includes(q));r.classList.toggle('hidden',!ok);if(ok)v++;}});
  document.getElementById('ec').textContent=v+' de {len(endpoints)}';
}}
const mr=Array.from(document.querySelectorAll('#mt tbody tr'));
function fm(){{
  const q=document.getElementById('ms').value.toLowerCase();
  let v=0;
  mr.forEach(r=>{{const ok=!q||r.textContent.toLowerCase().includes(q);r.classList.toggle('hidden',!ok);if(ok)v++;}});
  document.getElementById('mc2').textContent=v+' de {len(maps)}';
}}
let sd={{}};
function sort(tid,col){{
  const tbody=document.querySelector('#'+tid+' tbody');
  const rs=Array.from(tbody.querySelectorAll('tr'));
  const k=tid+col;sd[k]=(sd[k]||1)*-1;
  rs.sort((a,b)=>sd[k]*(a.cells[col]?.textContent.trim()||'').localeCompare(b.cells[col]?.textContent.trim()||''));
  rs.forEach(r=>tbody.appendChild(r));
  if(tid==='st')fs();else if(tid==='et')fe();else fm();
}}
</script>
</body>
</html>"""

    cfg["summary_html"].write_text(html, encoding="utf-8")
    logger.info("HTML → %s", cfg["summary_html"])


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="jsrecon",
        description=(
            "Recon autônomo de JS: subs → nmap → httpx → browser → "
            "filtro de JS do target → análise → mapscout."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 jsrecon.py target.com.br
  python3 jsrecon.py target.com.br --no-nmap --workers 30
  python3 jsrecon.py target.com.br --no-subs --live-timeout 45
  python3 jsrecon.py target.com.br --no-headless       # browser visível (debug)
  python3 jsrecon.py target.com.br --no-mapscout       # pula detecção de source maps
        """,
    )
    p.add_argument("domain",         help="Domínio alvo (ex: target.com.br)")
    p.add_argument("--no-subs",      action="store_true", help="Pula enumeração de subdomínios")
    p.add_argument("--no-nmap",      action="store_true", help="Pula scan de portas com nmap")
    p.add_argument("--no-live",      action="store_true", help="Pula coleta de JS via browser")
    p.add_argument("--no-headless",  action="store_true", help="Abre o browser visível (debug)")
    p.add_argument("--no-cache",     action="store_true", help="Ignora cache de JS em disco")
    p.add_argument("--no-mapscout",  action="store_true", help="Pula detecção de source maps expostos")
    p.add_argument("--workers",      type=int, default=20, help="Workers de análise JS (padrão: 20)")
    p.add_argument("--timeout",      type=int, default=10, help="Timeout HTTP em segundos (padrão: 10)")
    p.add_argument("--live-timeout", type=int, default=30, help="Timeout do browser em segundos (padrão: 30)")
    p.add_argument("--live-wait",    type=int, default=2,  help="Segundos extras após networkidle (padrão: 2)")
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
            break
    domain = domain.rstrip("/")

    cfg    = make_cfg(domain, args)
    logger = setup_logging(cfg["log_file"])
    stats: dict[str, int] = {}

    logger.info("=" * 60)
    logger.info("jsrecon  —  alvo: %s", domain)
    logger.info("Filtro  : %s  e  *.%s  (apenas JS do target)", domain, domain)
    logger.info("Saída   : %s", cfg["out_dir"])
    logger.info("=" * 60)

    preflight(logger)

    # ── 1. Subdomínios ────────────────────────────────────────────────────────
    if args.no_subs:
        logger.info("--no-subs: usando apenas o domínio raiz.")
        subs = {domain}
    else:
        subs = enum_subdomains(domain, cfg, logger)
    stats["subs"] = len(subs)

    # ── 2. Nmap ───────────────────────────────────────────────────────────────
    if args.no_nmap:
        logger.info("--no-nmap: assumindo portas 80 e 443 para cada host.")
        open_ports = {s: [80, 443] for s in subs}
    else:
        open_ports = nmap_scan(subs, cfg, logger)

    # ── 3. httpx ──────────────────────────────────────────────────────────────
    alive_urls, confirmed_hosts = httpx_probe(open_ports, cfg, logger)
    stats["alive"] = len(alive_urls)

    if not alive_urls:
        logger.warning("Nenhum host ativo encontrado — encerrando.")
        sys.exit(0)

    # ── 4. Coleta de JS ao vivo + FILTRO DE DOMÍNIO ───────────────────────────
    if args.no_live:
        logger.info("--no-live: pulando coleta via browser.")
        js_urls: set[str] = set()
    else:
        js_urls = collect_live_js(alive_urls, confirmed_hosts, cfg, logger)
    stats["js"] = len(js_urls)

    # ── 5. Análise de JS (somente target) ─────────────────────────────────────
    logger.info("═══ Análise de JS (%d arquivos do target) ═══", len(js_urls))
    total_secrets = analyze_js_list(sorted(js_urls), cfg, logger)
    stats["secrets"] = total_secrets

    if total_secrets:
        logger.warning("[!!!] Segredos encontrados: %d → %s", total_secrets, cfg["secrets_txt"])
    else:
        logger.info("Nenhum segredo encontrado.")

    ep_count = 0
    if cfg["endpoints_jsonl"].exists():
        ep_count = sum(
            1 for l in cfg["endpoints_jsonl"].read_text(encoding="utf-8", errors="ignore").splitlines()
            if l.strip()
        )
    logger.info("Endpoints extraídos: %d → %s", ep_count, cfg["endpoints_txt"])

    # ── 6. mapscout ───────────────────────────────────────────────────────────
    maps_count = 0
    if not args.no_mapscout:
        maps_count = run_mapscout(js_urls, confirmed_hosts, cfg, logger)
        stats["maps"] = maps_count
    else:
        logger.info("--no-mapscout: pulando detecção de source maps.")

    # ── 7. Relatórios ─────────────────────────────────────────────────────────
    write_summary_txt(cfg, logger, stats)
    write_summary_html(cfg, logger, stats)

    logger.info("=" * 60)
    logger.info("Concluído. Saída: %s", cfg["out_dir"])
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
