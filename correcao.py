"""
SUBSTITUIÇÃO para a função _playwright_crawl em jsrecon.py
─────────────────────────────────────────────────────────────────────────────
Problema original:
  • page.on("request") intercepta ANTES de os chunks serem solicitados
  • .js no path falha para URLs do tipo /956.8df871f4bf4dee81ca1a.js
    (sem subpasta, hash no nome — o check original usava .js in path, OK)
  • wait_until="networkidle" para cedo: webpack carrega chunks em lazy load
    APÓS a rede "silenciar" pela primeira vez

Correções aplicadas:
  1. Usar page.on("response") em vez de page.on("request")
     → captura DEPOIS que o browser realmente recebeu o arquivo
     → dá para checar Content-Type: application/javascript
  2. Scroll automático até o fundo da página
     → dispara lazy-load de rotas / componentes
  3. wait_until="load" (mais tolerante que networkidle)
     + asyncio.sleep generoso depois
  4. Extrair URLs do manifesto webpack/asset-manifest automaticamente
  5. Checar tanto o path (".js" no caminho) quanto o Content-Type da resposta

Uso: copie esta função para dentro de jsrecon.py substituindo a original.
─────────────────────────────────────────────────────────────────────────────
"""

import asyncio
import logging
from urllib.parse import urlparse

# ──────────────────────────────────────────────────────────────────────────────
# Função principal (substitui a original em jsrecon.py)
# ──────────────────────────────────────────────────────────────────────────────

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


# ──────────────────────────────────────────────────────────────────────────────
# INSTRUÇÕES DE INTEGRAÇÃO
# ──────────────────────────────────────────────────────────────────────────────
#
# 1. No jsrecon.py, substitua toda a função _playwright_crawl pela versão
#    acima (incluindo _extract_manifest_urls como função auxiliar).
#
# 2. Opcionalmente, aumente o live_wait padrão no parse_args:
#       --live-wait default=5  (era 2)
#
# 3. Para o site da imagem (cartexpress), rode:
#       python3 jsrecon.py cartexpress.minhaconta.zoop.com.br \
#           --no-subs --no-nmap --live-timeout 45 --live-wait 5
#
# ──────────────────────────────────────────────────────────────────────────────
