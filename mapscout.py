#!/usr/bin/env python3
"""
mapscout.py — Detecção de JavaScript Source Maps expostos.

Recebe uma lista de URLs de JS e verifica se o arquivo .map correspondente
está publicamente acessível e é um source map real (JSON válido).

Pode ser chamado diretamente pelo jsrecon.py ou usado de forma standalone.

Uso standalone:
    python3 mapscout.py -f js_urls.txt --domains subdomains.txt
    python3 mapscout.py -f js_urls.txt --domain ifood.com.br
    cat js_urls.txt | python3 mapscout.py --domain ifood.com.br

Dependências Python:
    pip install requests tenacity
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import threading
import time
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# Estado global thread-safe
# ─────────────────────────────────────────────────────────────────────────────

_checked:       set[str]        = set()
_checked_lock:  threading.Lock  = threading.Lock()
_findings:      list[dict]      = []
_findings_lock: threading.Lock  = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(log_file: Path | None = None, quiet: bool = False) -> logging.Logger:
    logger = logging.getLogger("mapscout")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.WARNING if quiet else logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# ─────────────────────────────────────────────────────────────────────────────
# Filtro de domínio alvo
# ─────────────────────────────────────────────────────────────────────────────

def _build_domain_filter(root_domain: str, extra_hosts: set[str]) -> callable:
    """
    Retorna uma função que aceita uma URL e diz se ela pertence ao target.
    Regras:
      - host == root_domain
      - host termina com .root_domain
      - host está no conjunto extra_hosts (subdomínios confirmados pelo httpx)
    """
    root = root_domain.lower().lstrip("*.")

    def _ok(url: str) -> bool:
        host = urlparse(url).netloc.lower().split(":")[0]
        if host == root:
            return True
        if host.endswith(f".{root}"):
            return True
        if host in extra_hosts:
            return True
        return False

    return _ok


# ─────────────────────────────────────────────────────────────────────────────
# HTTP — semáforo por host + retry
# ─────────────────────────────────────────────────────────────────────────────

_host_sems: dict[str, threading.Semaphore] = {}
_host_lock  = threading.Lock()
_req_logger = logging.getLogger("mapscout.req")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}


def _sem(url: str) -> threading.Semaphore:
    host = urlparse(url).netloc
    with _host_lock:
        if host not in _host_sems:
            _host_sems[host] = threading.Semaphore(4)
        return _host_sems[host]


def _make_get(timeout: int):
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=2, max=15),
        retry=retry_if_exception_type((
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        )),
        before_sleep=before_sleep_log(_req_logger, logging.DEBUG),
        reraise=False,
    )
    def _get(url: str, stream: bool = False) -> requests.Response | None:
        with _sem(url):
            r = requests.get(
                url,
                headers=HEADERS,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                stream=stream,
            )
            if r.status_code == 429:
                time.sleep(min(int(r.headers.get("Retry-After", 10)), 30))
            return r
    return _get


# ─────────────────────────────────────────────────────────────────────────────
# Validação real do .map
# ─────────────────────────────────────────────────────────────────────────────

# Indicadores que confirmam um source map JSON real
_SOURCEMAP_KEYS = re.compile(
    r'"version"\s*:\s*3|"sources"\s*:\s*\[|"mappings"\s*:|'
    r'"sourceRoot"\s*:|"sourcesContent"\s*:',
    re.I,
)
# Indicadores de página de erro / WAF / HTML
_ERROR_PAGE_RE = re.compile(
    r'<html|<!doctype|<body|access denied|forbidden|not found|'
    r'cloudflare|captcha|error\s+\d{3}',
    re.I,
)
# Tamanho mínimo razoável de um source map real (bytes lidos para checar)
_PEEK_BYTES = 4096
_MIN_MAP_SIZE = 64


def _is_real_sourcemap(resp: requests.Response) -> bool:
    """
    Valida se a resposta é um source map JavaScript real.
    Critérios (qualquer um basta):
      1. Content-Type contém 'json' ou 'sourcemap'
      2. Os primeiros bytes contêm chaves típicas de source map v3
    Rejeita se:
      - Status != 200
      - Conteúdo parece HTML / página de erro
      - Tamanho trivialmente pequeno
    """
    if resp.status_code != 200:
        return False

    ct = resp.headers.get("Content-Type", "").lower()

    # Lê apenas os primeiros bytes para não baixar arquivos enormes
    try:
        # stream=True foi passado — lê chunk inicial
        peek = b""
        for chunk in resp.iter_content(chunk_size=_PEEK_BYTES):
            peek += chunk
            break
        resp.close()
        text = peek.decode("utf-8", errors="replace")
    except Exception:
        return False

    if len(text.strip()) < _MIN_MAP_SIZE:
        return False

    if _ERROR_PAGE_RE.search(text[:512]):
        return False

    # Content-Type JSON já é forte indicador
    if "json" in ct or "sourcemap" in ct or "octet-stream" in ct:
        if _SOURCEMAP_KEYS.search(text):
            return True
        # Mesmo sem as chaves, se o CT é JSON e não é HTML, aceita
        if "json" in ct and not _ERROR_PAGE_RE.search(text[:512]):
            return True

    # Sem CT ideal: exige presença das chaves de source map
    if _SOURCEMAP_KEYS.search(text):
        return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Verificação de .map por URL
# ─────────────────────────────────────────────────────────────────────────────

def check_map(
    js_url: str,
    get_fn,
    domain_ok: callable,
    logger: logging.Logger,
) -> dict | None:
    """
    Verifica se <js_url>.map existe e é um source map real.
    Retorna dict com o finding ou None.
    """
    key = js_url.split("?")[0]

    # Filtro de domínio — só checa URLs do target
    if not domain_ok(js_url):
        logger.debug("[SKIP domain] %s", js_url)
        return None

    with _checked_lock:
        if key in _checked:
            return None
        _checked.add(key)

    map_url = key + ".map"

    try:
        resp = get_fn(map_url, stream=True)
    except Exception as e:
        logger.debug("Erro ao checar %s: %s", map_url, e)
        return None

    if resp is None:
        return None

    parsed = urlparse(js_url)
    domain = parsed.netloc
    status = resp.status_code
    size   = resp.headers.get("Content-Length", "?")
    ct     = resp.headers.get("Content-Type", "")

    if not _is_real_sourcemap(resp):
        logger.debug("[%d / não-sourcemap] %s", status, map_url)
        return None

    finding = {
        "js_url":       js_url,
        "map_url":      map_url,
        "domain":       domain,
        "status":       status,
        "size":         size,
        "content_type": ct,
        "ts":           datetime.now(timezone.utc).isoformat(),
    }

    with _findings_lock:
        _findings.append(finding)

    logger.warning("[MAP REAL EXPOSTO] %s  (size: %s, ct: %s)", map_url, size, ct)
    return finding


def check_all(
    js_urls: list[str],
    root_domain: str,
    extra_hosts: set[str],
    workers: int,
    timeout: int,
    logger: logging.Logger,
) -> list[dict]:
    """Verifica todos os JS em paralelo. Retorna lista de findings."""
    if not js_urls:
        logger.warning("Nenhuma URL JS fornecida.")
        return []

    domain_ok = _build_domain_filter(root_domain, extra_hosts)
    get_fn    = _make_get(timeout)

    # Filtra antes de paralelizar para logar o total real
    target_urls = [u for u in js_urls if domain_ok(u)]
    skipped     = len(js_urls) - len(target_urls)

    logger.info(
        "mapscout: %d JS do target (ignorados %d fora do escopo)",
        len(target_urls), skipped,
    )

    if not target_urls:
        logger.warning("Nenhuma URL pertence ao target %s / *.%s", root_domain, root_domain)
        return []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {
            ex.submit(check_map, u, get_fn, domain_ok, logger): u
            for u in target_urls
        }
        done = 0
        for fut in as_completed(futs):
            done += 1
            if done % 50 == 0 or done == len(target_urls):
                logger.info("  mapscout: %d/%d verificados…", done, len(target_urls))
            try:
                fut.result()
            except Exception as e:
                logger.debug("Worker error: %s", e)

    return list(_findings)


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def write_txt(findings: list[dict], path: Path, logger: logging.Logger) -> None:
    if not findings:
        return
    lines = []
    by_domain: dict[str, list[dict]] = {}
    for f in findings:
        by_domain.setdefault(f["domain"], []).append(f)

    for domain, items in sorted(by_domain.items()):
        lines += [
            "═" * 60,
            f"  DOMÍNIO: {domain}  ({len(items)} map(s) exposto(s))",
            "═" * 60,
        ]
        for item in items:
            lines += [
                f"  JS  : {item['js_url']}",
                f"  MAP : {item['map_url']}",
                f"  Size: {item['size']}  CT: {item['content_type']}",
                "-" * 56,
            ]
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("TXT → %s", path)


def write_jsonl(findings: list[dict], path: Path, logger: logging.Logger) -> None:
    if not findings:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for item in findings:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    logger.info("JSONL → %s", path)


def write_html(
    findings: list[dict],
    path: Path,
    domain_label: str,
    logger: logging.Logger,
) -> None:
    if not findings:
        logger.info("Nenhum finding — HTML não gerado.")
        return

    by_domain: dict[str, list[dict]] = {}
    for f in findings:
        by_domain.setdefault(f["domain"], []).append(f)

    domain_cards = ""
    for domain, items in sorted(by_domain.items()):
        rows = ""
        for item in items:
            rows += (
                f"<tr>"
                f'<td class="url-cell mono"><a href="{item["js_url"]}" target="_blank">'
                f'{_esc(item["js_url"][:120])}</a></td>'
                f'<td class="url-cell"><a href="{item["map_url"]}" target="_blank" class="map-link">'
                f'{_esc(item["map_url"][:120])}</a></td>'
                f'<td class="center">{_esc(item["size"])}</td>'
                f'<td class="center">{_esc(item["content_type"][:40])}</td>'
                f'<td class="center ts">{item["ts"][:19].replace("T", " ")}</td>'
                "</tr>\n"
            )
        domain_cards += f"""
<div class="domain-card" data-domain="{_esc(domain)}">
  <div class="domain-header">
    <span class="domain-name">{_esc(domain)}</span>
    <span class="badge">{len(items)} map{"s" if len(items) > 1 else ""}</span>
    <button class="open-all" onclick="openAll('{_esc(domain)}')">Abrir todos</button>
  </div>
  <table>
    <thead><tr>
      <th>JS URL</th><th>MAP URL</th><th>Size</th><th>Content-Type</th><th>Timestamp</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
"""

    ts            = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_domains = len(by_domain)
    domain_opts   = "".join(
        f'<option value="{_esc(d)}">{_esc(d)} ({len(items)})</option>'
        for d, items in sorted(by_domain.items())
    )

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mapscout — {_esc(domain_label)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;font-size:14px}}
a{{color:#60a5fa;text-decoration:none}}a:hover{{text-decoration:underline}}
header{{background:#1a1d2e;border-bottom:1px solid #2d3148;padding:1rem 1.5rem;display:flex;align-items:center;gap:1rem}}
header h1{{font-size:16px;font-weight:700;color:#f1f5f9;flex:1}}
header p{{font-size:12px;color:#64748b}}
.banner{{display:flex;gap:.75rem;padding:.75rem 1.5rem;background:#141620;border-bottom:1px solid #2d3148;flex-wrap:wrap}}
.stat{{background:#1a1d2e;border:1px solid #2d3148;border-radius:6px;padding:.5rem .9rem;text-align:center;min-width:90px}}
.stat .n{{font-size:22px;font-weight:700;line-height:1.1}}
.stat .l{{font-size:11px;color:#64748b;margin-top:2px}}
.ctrl{{display:flex;gap:.75rem;padding:.65rem 1.5rem;background:#141620;border-bottom:1px solid #2d3148;flex-wrap:wrap;align-items:center}}
.ctrl select,.ctrl input{{background:#1a1d2e;border:1px solid #2d3148;border-radius:5px;color:#e2e8f0;padding:5px 8px;font-size:13px}}
.ctrl input[type=search]{{width:260px}}
.cnt{{font-size:12px;color:#64748b;margin-left:auto}}
.content{{padding:1rem 1.5rem;display:flex;flex-direction:column;gap:1rem}}
.domain-card{{background:#1a1d2e;border:1px solid #2d3148;border-radius:8px;overflow:hidden}}
.domain-header{{display:flex;align-items:center;gap:.75rem;padding:.65rem 1rem;background:#141620;border-bottom:1px solid #2d3148}}
.domain-name{{font-weight:600;color:#f1f5f9;font-size:13px;flex:1}}
.badge{{background:#ef4444;color:#fff;font-size:11px;font-weight:700;padding:2px 9px;border-radius:12px}}
.open-all{{background:#1e3a5f;border:1px solid #2563eb;color:#60a5fa;border-radius:5px;padding:3px 10px;font-size:12px;cursor:pointer}}
.open-all:hover{{background:#2563eb;color:#fff}}
table{{width:100%;border-collapse:collapse}}
thead th{{background:#141620;color:#94a3b8;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;padding:7px 10px;text-align:left;border-bottom:1px solid #1e2130}}
td{{padding:7px 10px;border-bottom:1px solid #1e2130;vertical-align:top;font-size:12px}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#141620}}
.url-cell{{word-break:break-all;max-width:340px}}
.mono{{font-family:'SFMono-Regular',Consolas,monospace;font-size:11px}}
.map-link{{color:#4ade80;font-weight:600}}
.center{{text-align:center;white-space:nowrap;color:#94a3b8}}
.ts{{font-size:11px;color:#64748b}}
.hidden{{display:none}}
footer{{padding:.75rem 1.5rem;font-size:11px;color:#334155;border-top:1px solid #1e2130;text-align:center;margin-top:1rem}}
</style>
</head>
<body>
<header>
  <h1>🗺️ mapscout — {_esc(domain_label)}</h1>
  <p>{ts}</p>
</header>
<div class="banner">
  <div class="stat"><div class="n" style="color:#ef4444">{len(findings)}</div><div class="l">Maps expostos</div></div>
  <div class="stat"><div class="n" style="color:#f97316">{total_domains}</div><div class="l">Domínios</div></div>
</div>
<div class="ctrl">
  <label>Domínio
    <select id="df" onchange="filter()">
      <option value="">Todos</option>{domain_opts}
    </select>
  </label>
  <input id="qs" type="search" placeholder="Buscar URL, domínio…" oninput="filter()">
  <span id="cnt" class="cnt">{total_domains} domínio(s) · {len(findings)} map(s)</span>
</div>
<div class="content" id="cards">{domain_cards}</div>
<footer>mapscout · {_esc(domain_label)} · {len(findings)} source map(s) exposto(s) · {ts}</footer>
<script>
const domainLinks = {{}};
document.querySelectorAll('.domain-card').forEach(card => {{
  const d = card.dataset.domain;
  domainLinks[d] = Array.from(card.querySelectorAll('.map-link')).map(a => a.href);
}});
function openAll(domain) {{
  (domainLinks[domain] || []).forEach(url => window.open(url, '_blank'));
}}
const cards = Array.from(document.querySelectorAll('.domain-card'));
function filter() {{
  const df = document.getElementById('df').value;
  const q  = document.getElementById('qs').value.toLowerCase();
  let visible = 0;
  cards.forEach(card => {{
    const ok = (!df || card.dataset.domain === df) && (!q || card.textContent.toLowerCase().includes(q));
    card.classList.toggle('hidden', !ok);
    if (ok) visible++;
  }});
  document.getElementById('cnt').textContent = visible + ' domínio(s) visível(is)';
}}
</script>
</body>
</html>"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    logger.info("HTML → %s", path)


# ─────────────────────────────────────────────────────────────────────────────
# Entry-point programático (chamado pelo jsrecon)
# ─────────────────────────────────────────────────────────────────────────────

def run(
    js_urls: list[str],
    root_domain: str,
    out_dir: Path,
    *,
    extra_hosts: set[str] | None = None,
    workers: int = 20,
    timeout: int = 8,
    logger: logging.Logger | None = None,
) -> list[dict]:
    """
    API programática para uso pelo jsrecon.py.

    Parâmetros
    ----------
    js_urls      : lista de URLs JS coletadas
    root_domain  : domínio raiz do alvo (ex: ifood.com.br)
    out_dir      : diretório de saída (onde salvar os relatórios)
    extra_hosts  : conjunto de hosts confirmados pelo httpx (opcional)
    workers      : paralelismo
    timeout      : timeout HTTP em segundos
    logger       : logger do jsrecon (opcional; cria um novo se None)
    """
    if logger is None:
        logger = setup_logging(out_dir / "mapscout.log")

    logger.info("═══ mapscout — detecção de source maps ═══")

    findings = check_all(
        js_urls,
        root_domain=root_domain,
        extra_hosts=extra_hosts or set(),
        workers=workers,
        timeout=timeout,
        logger=logger,
    )

    if findings:
        write_txt(findings,  out_dir / "maps_exposed.txt",  logger)
        write_jsonl(findings, out_dir / "maps_exposed.jsonl", logger)
        write_html(findings,  out_dir / "maps_exposed.html", root_domain, logger)
        logger.warning(
            "[mapscout] %d source map(s) REAL(IS) exposto(s) → %s",
            len(findings), out_dir / "maps_exposed.html",
        )
    else:
        logger.info("[mapscout] Nenhum source map exposto encontrado.")

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CLI standalone
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mapscout",
        description="Detecta JavaScript Source Maps (.map) expostos e válidos.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # A partir de lista de JS já coletados
  python3 mapscout.py -f jsrecon_ifood.com.br/js_urls.txt --domain ifood.com.br

  # Com arquivo de subdomínios para filtro mais preciso
  python3 mapscout.py -f js_urls.txt --domain ifood.com.br --domains subdomains.txt

  # Stdin
  cat js_urls.txt | python3 mapscout.py --domain ifood.com.br
        """,
    )

    p.add_argument("-f", "--file",    metavar="FILE",   help="Arquivo com URLs JS (uma por linha)")
    p.add_argument("--domain",        metavar="DOMAIN", required=True,
                   help="Domínio raiz do alvo (ex: ifood.com.br)")
    p.add_argument("--domains",       metavar="FILE",
                   help="Arquivo com subdomínios válidos (ex: saída do jsrecon subdomains.txt)")
    p.add_argument("-o", "--output-dir", metavar="DIR", default="mapscout_out",
                   help="Diretório de saída (padrão: mapscout_out)")
    p.add_argument("--workers",  type=int, default=20, help="Workers paralelos (padrão: 20)")
    p.add_argument("--timeout",  type=int, default=8,  help="Timeout HTTP em segundos (padrão: 8)")
    p.add_argument("--quiet",    action="store_true",  help="Menos output no terminal")
    return p.parse_args()


def main() -> None:
    args    = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    logger  = setup_logging(out_dir / "mapscout.log", quiet=args.quiet)

    # Lê URLs JS
    urls: list[str] = []
    if args.file:
        path = Path(args.file)
        if not path.exists():
            logger.error("Arquivo não encontrado: %s", args.file)
            sys.exit(1)
        raw  = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        urls = [l.strip() for l in raw if l.strip().startswith("http")]
        logger.info("URLs lidas do arquivo: %d", len(urls))
    elif not sys.stdin.isatty():
        raw  = sys.stdin.read().splitlines()
        urls = [l.strip() for l in raw if l.strip().startswith("http")]
        logger.info("URLs lidas do stdin: %d", len(urls))
    else:
        logger.error("Forneça -f FILE ou pipe via stdin.")
        sys.exit(1)

    # Subdomínios extras (opcional)
    extra_hosts: set[str] = set()
    if args.domains:
        dp = Path(args.domains)
        if dp.exists():
            extra_hosts = {
                l.strip().lower() for l in dp.read_text(encoding="utf-8", errors="ignore").splitlines()
                if l.strip()
            }
            logger.info("Subdomínios válidos carregados: %d", len(extra_hosts))

    run(
        js_urls=urls,
        root_domain=args.domain,
        out_dir=out_dir,
        extra_hosts=extra_hosts,
        workers=args.workers,
        timeout=args.timeout,
        logger=logger,
    )


if __name__ == "__main__":
    main()
