# jsrecon

**Reconhecimento autônomo focado em JavaScript** — descobre subdomínios, valida hosts ativos, coleta arquivos JS **exclusivamente do target**, analisa segredos e endpoints, e detecta source maps expostos.

---

## Fluxo de execução

```
jsrecon.py target.com.br
      │
      ▼
  1. Subdomínios        subfinder · assetfinder · chaos · github-subdomains
      │
      ▼
  2. Nmap               scan de portas HTTP/HTTPS em todos os hosts
      │
      ▼
  3. httpx              valida hosts ativos → lista de hostnames confirmados
      │
      ▼
  4. Browser (Playwright)
      │  coleta todos os JS carregados pelas páginas
      │
      ▼
  5. Filtro de domínio  ← APENAS target.com.br e *.target.com.br
      │  JS de terceiros, CDNs e outros domínios são descartados
      │
      ▼
  6. Análise de JS      segredos · endpoints · ofuscação · btoa()
      │
      ▼
  7. mapscout           detecta *.js.map reais e públicos
      │
      ▼
  8. Relatórios         TXT · CSV · JSONL · HTML interativo
```

---

## Instalação

### Dependências Python

```bash
pip install playwright requests tenacity
playwright install chromium
```

### Ferramentas externas (opcionais — ausência é avisada, não é fatal)

| Ferramenta | Instalar |
|---|---|
| subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| assetfinder | `go install github.com/tomnomnom/assetfinder@latest` |
| chaos | `go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest` |
| github-subdomains | `go install github.com/gwen001/github-subdomains@latest` |
| nmap | `apt install nmap` / `brew install nmap` |
| httpx | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |

### Variáveis de ambiente (opcionais)

```bash
export CHAOS_KEY="sua_chave_chaos"       # projectdiscovery.io
export GITHUB_TOKEN="ghp_..."            # para github-subdomains
```

---

## Uso

### Básico

```bash
python3 jsrecon.py target.com.br
```

### Opções

```bash
# Sem enumeração de subdomínios (só o domínio raiz)
python3 jsrecon.py target.com.br --no-subs

# Sem nmap (assume 80 e 443 para todos)
python3 jsrecon.py target.com.br --no-nmap

# Sem coleta via browser (analisa JS de lista existente)
python3 jsrecon.py target.com.br --no-live

# Browser visível — útil para debug de sites com bot-protection
python3 jsrecon.py target.com.br --no-headless

# Sem detecção de source maps
python3 jsrecon.py target.com.br --no-mapscout

# Mais workers e timeout maior
python3 jsrecon.py target.com.br --workers 40 --timeout 15 --live-timeout 45

# Ignorar cache de JS em disco
python3 jsrecon.py target.com.br --no-cache
```

| Flag | Padrão | Descrição |
|---|---|---|
| `--no-subs` | — | Pula enumeração de subdomínios |
| `--no-nmap` | — | Pula scan de portas |
| `--no-live` | — | Pula coleta via browser |
| `--no-headless` | — | Abre o browser visível |
| `--no-cache` | — | Ignora cache de JS em disco |
| `--no-mapscout` | — | Pula detecção de source maps |
| `--workers` | 20 | Workers paralelos de análise |
| `--timeout` | 10 | Timeout HTTP em segundos |
| `--live-timeout` | 30 | Timeout de navegação do browser |
| `--live-wait` | 2 | Segundos extras após `networkidle` |

---

## Filtro de domínio

O jsrecon coleta **todos** os arquivos JS que o browser carrega, mas **analisa somente** os que pertencem ao target:

| URL do JS | Pertence ao target `target.com.br`? |
|---|---|
| `https://target.com.br/app.js` | ✅ sim |
| `https://api.target.com.br/chunk.js` | ✅ sim |
| `https://static.target.com.br/v2/main.js` | ✅ sim |
| `https://cdn.jsdelivr.net/jquery.min.js` | ❌ não |
| `https://analytics.google.com/ga.js` | ❌ não |
| `https://pagamentos-externos.com/lib.js` | ❌ não |

Regra: `host == dominio` **ou** `host termina com .dominio`.

---

## Saída

Todos os arquivos são salvos em `jsrecon_<domínio>/`:

```
jsrecon_target.com.br/
├── SUMMARY.html          ← relatório principal (segredos + endpoints + maps)
├── SUMMARY.txt
├── secrets.txt           ← segredos legíveis
├── secrets.csv
├── secrets.jsonl
├── endpoints.txt         ← endpoints extraídos
├── endpoints.jsonl
├── maps_exposed.txt      ← source maps expostos (mapscout)
├── maps_exposed.jsonl
├── maps_exposed.html
├── subdomains.txt
├── hosts_alive.txt
├── js_urls.txt           ← JS do target analisados
├── nmap_results.txt
├── nmap_summary.txt
├── jsrecon.log
└── .js_cache/            ← cache de JS (invalidado em 24h)
```

### HTML interativo

`SUMMARY.html` contém três abas filtráveis:

- **🔑 Segredos** — filtro por severidade (CRITICAL / HIGH / MEDIUM / LOW) e tipo
- **🔗 Endpoints** — filtro por método HTTP (GET / POST / PUT / DELETE / PATCH / WS)
- **🗺️ Source Maps** — todos os `.js.map` reais encontrados expostos

---

## Segredos detectados (40+ padrões)

| Severidade | Tipos |
|---|---|
| CRITICAL | AWS Access Key, Private Key, Stripe Secret, GCP Service Account, HashiCorp Vault, Azure Storage Key, JS Secret Key |
| HIGH | GitHub PAT, GitLab PAT, OpenAI Key, SendGrid, Slack Token, MongoDB/Postgres/MySQL DSN, Google API Key, Firebase URL, Basic Auth hardcoded, btoa() credentials |
| MEDIUM | JWT, Stripe Publishable, Slack Webhook, Sentry DSN, Mapbox Token, Supabase Anon Key |
| LOW | Generic API Key, Generic Token, Generic Secret, Bearer Token, Password Field, bcrypt hash |

Recursos anti-falso-positivo:
- Análise de entropia (Shannon) — descarta valores de baixa aleatoriedade
- Blocklist de placeholders (`example`, `changeme`, `123456`, `${VAR}`, etc.)
- Detecção de contexto UI (label, placeholder, console.log, comentários)
- Validação estrutural de JWT (header + payload decodificáveis + campo `alg`)
- Deduplicação global por tipo + valor normalizado

---

## mapscout

Detecta arquivos `*.js.map` publicamente acessíveis e **reais** (não apenas HTTP 200 — valida o conteúdo JSON).

### Standalone

```bash
# A partir de lista gerada pelo jsrecon
python3 mapscout.py -f jsrecon_target.com.br/js_urls.txt --domain target.com.br

# Com arquivo de subdomínios para filtro mais preciso
python3 mapscout.py \
  -f jsrecon_target.com.br/js_urls.txt \
  --domain target.com.br \
  --domains jsrecon_target.com.br/subdomains.txt

# Stdin
cat js_urls.txt | python3 mapscout.py --domain target.com.br

# Com relatório HTML
python3 mapscout.py -f js_urls.txt --domain target.com.br -o resultados/
```

| Flag | Descrição |
|---|---|
| `-f FILE` | Arquivo com URLs JS (uma por linha) |
| `--domain` | Domínio raiz do alvo (obrigatório) |
| `--domains FILE` | Arquivo de subdomínios válidos (saída do jsrecon) |
| `-o DIR` | Diretório de saída (padrão: `mapscout_out`) |
| `--workers` | Workers paralelos (padrão: 20) |
| `--timeout` | Timeout HTTP em segundos (padrão: 8) |
| `--quiet` | Menos output no terminal |

### Validação de source maps

O mapscout não aceita qualquer HTTP 200 — ele valida que o conteúdo é um source map JavaScript real:

1. Faz GET com stream (lê apenas os primeiros ~4 KB)
2. Rejeita respostas HTML (páginas de erro, WAF, captcha)
3. Verifica presença de chaves típicas do formato source map v3: `"version":3`, `"sources"`, `"mappings"`, `"sourceRoot"`, `"sourcesContent"`
4. Aceita `Content-Type: application/json` combinado com ausência de HTML

---

## Estrutura dos arquivos

```
jsrecon.py       ← ferramenta principal
mapscout.py      ← detecção de source maps (standalone ou chamado pelo jsrecon)
README.md
```

Os dois arquivos devem estar no **mesmo diretório** para a integração automática funcionar.

---

## Aviso legal

Esta ferramenta foi desenvolvida para uso em programas de bug bounty e testes de penetração **com autorização explícita**. O uso não autorizado contra sistemas de terceiros é ilegal. O autor não se responsabiliza pelo uso indevido.
