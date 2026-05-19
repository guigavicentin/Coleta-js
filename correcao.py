#!/usr/bin/env python3
"""
correcao.py — Coleta standalone de arquivos JavaScript via browser real.

Uso:
  python3 correcao.py <domínio ou URL>
  python3 correcao.py zoop.com.br
  python3 correcao.py https://cartexpress.minhaconta.zoop.com.br
  python3 correcao.py zoop.com.br --timeout 60 --wait 8 --show-browser
  python3 correcao.py zoop.com.br --urls-only          # só imprime as URLs

Dependências:
  pip install playwright requests
  playwright install chromium
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
import urllib3
from pathlib import Path
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("[ERRO] Playwright não instalado.")
    print("       pip install playwright && playwright install chromium")
    sys.exit(1)

import requests


# ─────────────────────────────────────────────────────────────────────────────
# CDN conhecidos — sempre descartados
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
# Filtro de domínio alvo
# ─────────────────────────────────────────────────────────────────────────────

def _belongs_to_target(js_url: str, root: str, extra_hosts: set[str]) -> bool:
    try:
        host = urlparse(js_url).netloc.lower().split(":")[0]
    except Exception:
        return False
    root = root.lower().lstrip("*.")
    return host == root or host.endswith(f".{root}") or host in extra_hosts


# ─────────────────────────────────────────────────────────────────────────────
# Detecta se é JS pelo path ou pelo Content-Type
# ─────────────────────────────────────────────────────────────────────────────

def _is_js(url: str, content_type: str) -> bool:
    path = urlparse(url).path.lower()
    ct   = (content_type or "").lower()
    return (
        path.endswith(".js")
        or path.endswith(".mjs")
        or ".js?" in path
        or "javascript" in ct
        or "ecmascript" in ct
    )


# ─────────────────────────────────────────────────────────────────────────────
# Extrai URLs extras do manifesto webpack / HTML
# ─────────────────────────────────────────────────────────────────────────────

async def _extract_manifest_urls(page, base_url: str, logger: logging.Logger) -> list[str]:
    found: list[str] = []

    # 1. asset-manifest.json (React CRA, Vite)
    for mpath in ["/asset-manifest.json", "/static/asset-manifest.json", "/webpack-stats.json"]:
        try:
            murl = urljoin(base_url, mpath)
            r = requests.get(murl, timeout=8, verify=False,
                             headers={"User-Agent": "Mozilla/5.0 jsrecon"})
            if r.status_code == 200:
                data = r.json()
                files = data.get("files", data)
                if isinstance(files, dict):
                    for v in files.values():
                        if isinstance(v, str) and v.endswith(".js"):
                            found.append(urljoin(base_url, v))
                if found:
                    logger.info("  [manifest] %d URLs via %s", len(found), mpath)
                    break
        except Exception:
            pass

    # 2. Tags <script src> no HTML já renderizado
    try:
        html = await page.content()

        for m in re.finditer(
            r'(?:src|href)=["\']([^"\']*?\.(?:js|mjs)(?:\?[^"\']*)?)["\']',
            html, re.I,
        ):
            raw = m.group(1)
            if raw.startswith("/"):
                raw = urljoin(base_url, raw)
            if raw.startswith("http"):
                found.append(raw)

        # Padrão de chunk webpack: "956.8df871f4bf4dee8"
        for m in re.finditer(r'"([0-9a-f]{3,4}\.[0-9a-f]{14,})"', html):
            name = m.group(1)
            found.append(urljoin(base_url, f"/static/js/{name}.chunk.js"))
            found.append(urljoin(base_url, f"/{name}.js"))

    except Exception as e:
        logger.debug("  [manifest] html parse error: %s", e)

    return list(set(found))


# ─────────────────────────────────────────────────────────────────────────────
# Crawl principal
# ─────────────────────────────────────────────────────────────────────────────

async def crawl(
    url: str,
    timeout_s: int,
    wait_s: int,
    headless: bool,
    logger: logging.Logger,
) -> list[str]:
    """Abre a URL no browser, captura todos os JS e retorna lista de URLs."""
    seen: set[str]       = set()
    js_urls: list[str]   = []

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

        # ── Intercepta RESPOSTAS (captura content-type real) ─────────────────
        async def on_response(resp):
            try:
                rurl = resp.url
                ct   = resp.headers.get("content-type", "")
                if rurl not in seen and _is_js(rurl, ct):
                    seen.add(rurl)
                    js_urls.append(rurl)
                    logger.debug("  [JS] %s", rurl)
            except Exception:
                pass

        page.on("response", on_response)

        # ── Navega (wait_until="load" é mais tolerante que networkidle) ───────
        logger.info("  🌐  Abrindo %s", url)
        try:
            await page.goto(url, timeout=timeout_s * 1000, wait_until="load")
        except Exception as e:
            logger.warning("  [nav] %s — continuando mesmo assim", e)

        # ── Pausa inicial ─────────────────────────────────────────────────────
        await asyncio.sleep(max(wait_s, 3))

        # ── Scroll para disparar lazy-load / code splitting ───────────────────
        try:
            await page.evaluate("""
                async () => {
                    const delay = ms => new Promise(r => setTimeout(r, ms));
                    for (let i = 0; i < 6; i++) {
                        window.scrollBy(0, window.innerHeight);
                        await delay(700);
                    }
                    window.scrollTo(0, 0);
                    await delay(600);
                }
            """)
            logger.info("  [scroll] feito")
        except Exception as e:
            logger.debug("  [scroll] %s", e)

        # ── Pausa pós-scroll ──────────────────────────────────────────────────
        await asyncio.sleep(3)

        # ── Manifesto / HTML para chunks não disparados ───────────────────────
        extras = await _extract_manifest_urls(page, url, logger)
        for u in extras:
            if u not in seen:
                seen.add(u)
                js_urls.append(u)

        await browser.close()

    return js_urls


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="correcao",
        description="Coleta arquivos JS de uma URL via browser real (Playwright).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 correcao.py zoop.com.br
  python3 correcao.py https://cartexpress.minhaconta.zoop.com.br
  python3 correcao.py zoop.com.br --timeout 60 --wait 8
  python3 correcao.py zoop.com.br --all-domains       # não filtra por domínio
  python3 correcao.py zoop.com.br --urls-only         # só URLs, sem log
  python3 correcao.py zoop.com.br --show-browser      # abre janela do Chrome
  python3 correcao.py zoop.com.br --out js_urls.txt   # salva em arquivo
        """,
    )
    p.add_argument("target",        help="Domínio ou URL alvo (ex: zoop.com.br)")
    p.add_argument("--timeout",     type=int, default=40,  help="Timeout do browser em segundos (padrão: 40)")
    p.add_argument("--wait",        type=int, default=5,   help="Segundos extras após load (padrão: 5)")
    p.add_argument("--show-browser",action="store_true",   help="Abre janela visível do Chrome (não headless)")
    p.add_argument("--all-domains", action="store_true",   help="Inclui JS de domínios terceiros (sem filtro)")
    p.add_argument("--urls-only",   action="store_true",   help="Imprime só as URLs, sem logs")
    p.add_argument("--out",         default="",            help="Salva URLs em arquivo (ex: --out js.txt)")
    return p.parse_args()


def setup_logger(quiet: bool) -> logging.Logger:
    logger = logging.getLogger("correcao")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stderr if quiet else sys.stdout)
    ch.setLevel(logging.WARNING if quiet else logging.INFO)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(ch)
    return logger


def normalise_url(target: str) -> tuple[str, str]:
    """Retorna (url_completa, domínio_raiz)."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    root = urlparse(target).netloc.lower().lstrip("www.")
    return target, root


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args   = parse_args()
    logger = setup_logger(quiet=args.urls_only)

    url, root = normalise_url(args.target)

    if not args.urls_only:
        logger.info("=" * 56)
        logger.info("Alvo   : %s", url)
        logger.info("Root   : %s", root)
        logger.info("Timeout: %ds  |  Wait: %ds", args.timeout, args.wait)
        logger.info("=" * 56)

    # Coleta bruta
    all_js = asyncio.run(crawl(
        url       = url,
        timeout_s = args.timeout,
        wait_s    = args.wait,
        headless  = not args.show_browser,
        logger    = logger,
    ))

    # Filtro de domínio (salvo se --all-domains)
    if args.all_domains:
        filtered = [u for u in all_js if not _CDN_RE.search(u)]
    else:
        filtered = [
            u for u in all_js
            if not _CDN_RE.search(u) and _belongs_to_target(u, root, set())
        ]

    filtered.sort()

    if not args.urls_only:
        logger.info("")
        logger.info("─── Resultado ───────────────────────────────────────")
        logger.info("JS bruto capturado   : %d", len(all_js))
        logger.info("Após filtro de domínio: %d", len(filtered))
        logger.info("─────────────────────────────────────────────────────")

    # Saída
    for u in filtered:
        print(u)

    if args.out:
        out = Path(args.out)
        out.write_text("\n".join(filtered) + "\n", encoding="utf-8")
        if not args.urls_only:
            logger.info("Salvo em: %s", out)

    if not args.urls_only:
        logger.info("Concluído.")


if __name__ == "__main__":
    main()
