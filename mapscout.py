#!/usr/bin/env python3
"""
mapscout.py — Detecção de JavaScript Source Maps expostos.

Inspirado no DotMap (extensão de browser), mas em linha de comando.
Recebe uma lista de URLs de JS (ou coleta via Playwright) e verifica
se o arquivo .map correspondente está publicamente acessível.

Fluxo:
  1. Entrada: lista de URLs JS (arquivo ou stdin) ou domínio direto
  2. Coleta ao vivo opcional via Playwright (--live)
  3. HEAD request para <url>.map em cada arquivo JS
  4. Relatório: TXT + JSONL + HTML interativo

Dependências Python:
    pip install requests playwright tenacity
    playwright install chromium   (apenas se usar --live)

Uso:
    # A partir de lista de JS já coletados (ex: saída do jsrecon)
    python3 mapscout.py -f js_urls.txt

    # Coleta ao vivo direto do domínio
    python3 mapscout.py --live exemplo.com.br

    # Stdin (pipe)
    cat js_urls.txt | python3 mapscout.py

    # Com relatório HTML
    python3 mapscout.py -f js_urls.txt --html
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# CDN — ignora JS de terceiros
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
# Estado global thread-safe
# ─────────────────────────────────────────────────────────────────────────────

_checked:      set[str]       = set()
_checked_lock: threading.Lock = threading.Lock()
_findings:     list[dict]     = []
_findings_lock: threading.Lock = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(log_file: Path | None = None) -> logging.Logger:
    logger = logging.getLogger("mapscout")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
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
# HTTP — semáforo por host + retry
# ─────────────────────────────────────────────────────────────────────────────

_host_sems: dict[str, threading.Semaphore] = {}
_host_lock  = threading.Lock()
_req_logger = logging.getLogger("mapscout.req")


def _sem(url: str) -> threading.Semaphore:
    host = urlparse(url).netloc
    with _host_lock:
        if host not in _host_sems:
            _host_sems[host] = threading.Semaphore(4)
        return _host_sems[host]


def _make_head(timeout: int):
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
    def _head(url: str) -> requests.Response | None:
        with _sem(url):
            r = requests.head(
                url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    )
                },
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            if r.status_code == 429:
                time.sleep(min(int(r.headers.get("Retry-After", 10)), 30))
            return r
    return _head


# ─────────────────────────────────────────────────────────────────────────────
# Verificação de .map
# ─────────────────────────────────────────────────────────────────────────────

def check_map(js_url: str, head_fn, logger: logging.Logger) -> dict | None:
    """
    Verifica se <js_url>.map retorna HTTP 200.
    Retorna dict com o finding ou None.
    """
    # Normaliza: remove query string para a chave de dedup
    key = js_url.split("?")[0]
    with _checked_lock:
        if key in _checked:
            return None
        _checked.add(key)

    map_url = key + ".map"

    try:
        resp = head_fn(map_url)
    except Exception as e:
        logger.debug("Erro ao checar %s: %s", map_url, e)
        return None

    if resp is None:
        return None

    parsed   = urlparse(js_url)
    domain   = parsed.netloc
    status   = resp.status_code
    size     = resp.headers.get("Content-Length", "?")
    ct       = resp.headers.get("Content-Type", "")

    if status == 200:
        finding = {
            "js_url":   js_url,
            "map_url":  map_url,
            "domain":   domain,
            "status":   status,
            "size":     size,
            "content_type": ct,
            "ts":       datetime.now(timezone.utc).isoformat(),
        }
        with _findings_lock:
            _findings.append(finding)
        logger.warning("[MAP EXPOSTO] %s  (size: %s, ct: %s)", map_url, size, ct)
        return finding

    logger.debug("[%d] %s", status, map_url)
    return None


def check_all(js_urls: list[str], workers: int, timeout: int,
              logger: logging.Logger) -> list[dict]:
    """Verifica todos os JS em paralelo. Retorna lista de findings."""
    if not js_urls:
        logger.warning("Nenhuma URL JS fornecida.")
        return []

    head_fn = _make_head(timeout)
    logger.info("Verificando %d arquivos JS (workers=%d)…", len(js_urls), workers)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_map, u, head_fn, logger): u for u in js_urls}
        done = 0
        for fut in as_completed(futs):
            done += 1
            if done % 100 == 0:
                logger.info("  %d/%d verificados…", done, len(js_urls))
            try:
                fut.result()
            except Exception as e:
                logger.debug("Worker error: %s", e)

    return list(_findings)


# ─────────────────────────────────────────────────────────────────────────────
# Coleta ao vivo com Playwright
# ─────────────────────────────────────────────────────────────────────────────

async def _playwright_collect(url: str, timeout_s: int, wait_s: int,
                               headless: bool, logger: logging.Logger) -> list[str]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.error("Playwright não instalado. Execute:")
        logger.error("  pip install playwright && playwright install chromium")
        return []

    js_urls: list[str] = []
    seen: set[str] = set()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        ctx     = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
        )
        page = await ctx.new_page()

        def on_request(req):
            ru     = req.url
            parsed = urlparse(ru)
            path   = parsed.path.lower()
            # Captura .js mas ignora .js.map (não queremos checar mapa do mapa)
            if ".js" in path and not path.endswith(".js.map") and ru not in seen:
                if not _CDN_RE.search(ru):
                    seen.add(ru)
                    js_urls.append(ru)

        page.on("request", on_request)
        logger.info("  🌐 Browser → %s", url)
        try:
            await page.goto(url, timeout=timeout_s * 1000, wait_until="networkidle")
        except Exception as e:
            logger.debug("  [browser] timeout em %s: %s", url, e)

        if wait_s > 0:
            await asyncio.sleep(wait_s)

        await browser.close()

    logger.info("  → %d JS capturados ao vivo", len(js_urls))
    return js_urls


def live_collect(targets: list[str], timeout_s: int, wait_s: int,
                 headless: bool, logger: logging.Logger) -> list[str]:
    """Roda Playwright em cada alvo e retorna lista de JS únicos."""
    all_js: list[str] = []
    seen: set[str] = set()

    async def _run():
        for idx, url in enumerate(targets, 1):
            logger.info("[live %d/%d] %s", idx, len(targets), url)
            urls = await _playwright_collect(url, timeout_s, wait_s, headless, logger)
            for u in urls:
                key = u.split("?")[0]
                if key not in seen:
                    seen.add(key)
                    all_js.append(u)

    asyncio.run(_run())
    logger.info("Total JS coletados ao vivo (únicos): %d", len(all_js))
    return all_js


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

def write_txt(findings: list[dict], path: Path, logger: logging.Logger) -> None:
    if not findings:
        return
    lines = []
    # Agrupa por domínio (mesma UX do DotMap)
    by_domain: dict[str, list[dict]] = {}
    for f in findings:
        by_domain.setdefault(f["domain"], []).append(f)

    for domain, items in sorted(by_domain.items()):
        lines.append(f"{'═'*60}")
        lines.append(f"  DOMÍNIO: {domain}  ({len(items)} map(s) exposto(s))")
        lines.append(f"{'═'*60}")
        for item in items:
            lines.append(f"  JS  : {item['js_url']}")
            lines.append(f"  MAP : {item['map_url']}")
            lines.append(f"  Size: {item['size']}  CT: {item['content_type']}")
            lines.append(f"  {'-'*56}")
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


def write_html(findings: list[dict], path: Path, domain_label: str,
               logger: logging.Logger) -> None:
    if not findings:
        return

    def _esc(s: str) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Agrupa por domínio
    by_domain: dict[str, list[dict]] = {}
    for f in findings:
        by_domain.setdefault(f["domain"], []).append(f)

    domain_cards = ""
    for domain, items in sorted(by_domain.items()):
        rows = ""
        for item in items:
            rows += (
                f'<tr>'
                f'<td class="url-cell mono"><a href="{item["js_url"]}" target="_blank">'
                f'{_esc(item["js_url"][:120])}</a></td>'
                f'<td class="url-cell"><a href="{item["map_url"]}" target="_blank" class="map-link">'
                f'{_esc(item["map_url"][:120])}</a></td>'
                f'<td class="center">{_esc(item["size"])}</td>'
                f'<td class="center">{_esc(item["content_type"][:40])}</td>'
                f'<td class="center ts">{item["ts"][:19].replace("T"," ")}</td>'
                f'</tr>\n'
            )
        domain_cards += f"""
<div class="domain-card" data-domain="{_esc(domain)}">
  <div class="domain-header">
    <span class="domain-name">{_esc(domain)}</span>
    <span class="badge">{len(items)} map{"s" if len(items)>1 else ""}</span>
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

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_domains = len(by_domain)

    # Monta opções de domínio para o filtro
    domain_opts = "".join(
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
.banner{{display:flex;gap:.75rem;padding:.75rem 1.5rem;background:#141620;border-bottom:1px solid #2d3148;flex-wrap:wrap;align-items:center}}
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
  <div class="stat"><div class="n" style="color:#a78bfa">{sum(1 for f in findings if f.get("size","?")!="?")}</div><div class="l">Com tamanho</div></div>
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
<div class="content" id="cards">
{domain_cards}
</div>
<footer>mapscout · {_esc(domain_label)} · {len(findings)} source map(s) exposto(s) · {ts}</footer>
<script>
// Mapa de links por domínio (para "Abrir todos")
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
    const domainMatch = !df || card.dataset.domain === df;
    const textMatch   = !q  || card.textContent.toLowerCase().includes(q);
    const show = domainMatch && textMatch;
    card.classList.toggle('hidden', !show);
    if (show) visible++;
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
# Leitura de entrada
# ─────────────────────────────────────────────────────────────────────────────

def read_js_urls(args: argparse.Namespace, logger: logging.Logger) -> list[str]:
    """Lê URLs de JS de arquivo, stdin ou gera a partir de domínio."""
    urls: list[str] = []

    # A partir de arquivo
    if args.file:
        path = Path(args.file)
        if not path.exists():
            logger.error("Arquivo não encontrado: %s", args.file)
            sys.exit(1)
        raw = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        urls = [l.strip() for l in raw if l.strip() and l.strip().startswith("http")]
        logger.info("URLs lidas do arquivo: %d", len(urls))

    # A partir de stdin (pipe)
    elif not sys.stdin.isatty() and not args.live:
        raw = sys.stdin.read().splitlines()
        urls = [l.strip() for l in raw if l.strip() and l.strip().startswith("http")]
        logger.info("URLs lidas do stdin: %d", len(urls))

    # Coleta ao vivo via Playwright
    if args.live:
        domain = args.live.strip()
        for pfx in ("https://", "http://"):
            if domain.startswith(pfx):
                domain = domain[len(pfx):]
        domain = domain.rstrip("/")

        targets = [f"https://{domain}", f"http://{domain}"]
        logger.info("Modo live: coletando JS de %s…", domain)
        live_urls = live_collect(
            targets,
            timeout_s=args.live_timeout,
            wait_s=args.live_wait,
            headless=not args.no_headless,
            logger=logger,
        )
        # Merge com os que vieram de arquivo/stdin (se houver)
        existing = set(u.split("?")[0] for u in urls)
        for u in live_urls:
            if u.split("?")[0] not in existing:
                urls.append(u)
        logger.info("Total após merge com live: %d", len(urls))

    if not urls:
        logger.error("Nenhuma URL JS fornecida. Use -f, stdin ou --live.")
        sys.exit(1)

    # Remove duplicatas por URL base
    seen: set[str] = set()
    dedup: list[str] = []
    for u in urls:
        key = u.split("?")[0]
        if key not in seen:
            seen.add(key)
            dedup.append(u)

    logger.info("URLs únicas após dedup: %d", len(dedup))
    return dedup


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mapscout",
        description="Detecta JavaScript Source Maps (.map) expostos publicamente.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Verifica lista de JS coletados pelo jsrecon
  python3 mapscout.py -f jsrecon_exemplo.com.br/js_urls.txt

  # Coleta ao vivo e verifica
  python3 mapscout.py --live exemplo.com.br

  # Pipe
  cat js_urls.txt | python3 mapscout.py

  # Tudo junto com relatório HTML
  python3 mapscout.py --live exemplo.com.br -f extra_js.txt --html -o resultados/
        """,
    )

    src = p.add_argument_group("Fonte de URLs")
    src.add_argument("-f", "--file",       metavar="FILE",   help="Arquivo com URLs JS (uma por linha)")
    src.add_argument("--live",             metavar="DOMAIN", help="Coleta ao vivo via Playwright no domínio")
    src.add_argument("--no-headless",      action="store_true", help="Abre browser visível (debug)")
    src.add_argument("--live-timeout",     type=int, default=30, metavar="S",
                     help="Timeout de navegação do browser em segundos (padrão: 30)")
    src.add_argument("--live-wait",        type=int, default=2,  metavar="S",
                     help="Segundos extras após networkidle (padrão: 2)")

    out = p.add_argument_group("Saída")
    out.add_argument("-o", "--output-dir", metavar="DIR",    help="Diretório de saída (padrão: ./mapscout_out)")
    out.add_argument("--html",             action="store_true", help="Gera relatório HTML interativo")
    out.add_argument("--no-txt",           action="store_true", help="Não gera relatório TXT")
    out.add_argument("--no-jsonl",         action="store_true", help="Não gera JSONL")
    out.add_argument("--quiet",            action="store_true", help="Menos output no terminal")

    perf = p.add_argument_group("Performance")
    perf.add_argument("--workers",  type=int, default=20,  help="Workers paralelos (padrão: 20)")
    perf.add_argument("--timeout",  type=int, default=8,   help="Timeout HTTP por request em segundos (padrão: 8)")

    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    # Diretório de saída
    out_dir = Path(args.output_dir) if args.output_dir else Path("mapscout_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    log_file = out_dir / "mapscout.log"
    logger   = setup_logging(log_file)

    if args.quiet:
        logging.getLogger("mapscout").setLevel(logging.WARNING)

    # Label do alvo para relatórios
    domain_label = args.live or (Path(args.file).stem if args.file else "stdin")

    logger.info("=" * 56)
    logger.info("mapscout — %s", domain_label)
    logger.info("Saída: %s", out_dir)
    logger.info("=" * 56)

    # ── 1. Lê/coleta URLs de JS ───────────────────────────────────────────────
    js_urls = read_js_urls(args, logger)

    # ── 2. Verifica .map ──────────────────────────────────────────────────────
    findings = check_all(js_urls, workers=args.workers, timeout=args.timeout, logger=logger)

    # ── 3. Relatórios ─────────────────────────────────────────────────────────
    logger.info("=" * 56)
    if findings:
        logger.warning("Source maps expostos encontrados: %d", len(findings))

        # Agrupa por domínio para resumo no terminal
        by_domain: dict[str, int] = {}
        for f in findings:
            by_domain[f["domain"]] = by_domain.get(f["domain"], 0) + 1
        for domain, count in sorted(by_domain.items(), key=lambda x: -x[1]):
            logger.warning("  %-40s %d map(s)", domain, count)

        if not args.no_txt:
            write_txt(findings, out_dir / "maps_exposed.txt", logger)
        if not args.no_jsonl:
            write_jsonl(findings, out_dir / "maps_exposed.jsonl", logger)
        if args.html:
            write_html(findings, out_dir / "maps_exposed.html", domain_label, logger)
    else:
        logger.info("Nenhum source map exposto encontrado.")

    logger.info("Verificados: %d JS  |  Expostos: %d maps", len(js_urls), len(findings))
    logger.info("Log: %s", log_file)
    logger.info("=" * 56)


if __name__ == "__main__":
    main()
