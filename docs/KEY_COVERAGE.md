# GitScout Key Coverage

Secret types detected by `gitscout.py`. See `SECRET_PATTERNS` in the source for the live list.

## LLM / AI providers

| Provider | Covered | Detection method |
|---|---|---|
| **Anthropic** (Claude) | Yes | `sk-ant-...` / `sk-ant-api03-...` prefix |
| **OpenRouter** | Yes | `sk-or-v1-...` prefix |
| **OpenAI** | Yes | `sk-...`, `sk-proj-...`, `sk-live-...` prefixes |
| **Together AI** | Yes | `TOGETHER_API_KEY=...` context pattern |
| **Groq** | Yes | `gsk_...` prefix |
| **Hugging Face** | Yes | `hf_...` prefix |
| **Google** (Gemini / AI) | Yes | `AIza...` prefix |
| **Replicate** | Yes | `r8_...` prefix |
| **xAI** (Grok) | Yes | `xai-...` prefix |
| **Perplexity** | Yes | `pplx-...` prefix |
| **Fireworks AI** | Yes | `fw_...` prefix |
| **Cohere** | Yes | `cohere_api_key=...` context pattern |
| **Mistral** | Yes | `mistral_api_key=...` context pattern |
| **DeepSeek** | Yes | `deepseek_api_key=...` context pattern |
| **All above (env files)** | Yes | `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, `TOGETHER_API_KEY`, etc. |

## Cloud & infrastructure

| Type | Covered |
|---|---|
| AWS Access Key ID (`AKIA...`) | Yes |
| AWS Secret Access Key | Yes |
| MongoDB / MySQL / PostgreSQL connection strings | Yes |

## Auth & credentials

| Type | Covered |
|---|---|
| Generic tokens / API keys / auth keys | Yes |
| JWT / OIDC tokens | Yes |
| Passwords (contextual) | Yes |
| SSH public keys | Yes |
| PEM / private keys | Yes |
| Email addresses | Yes |
| SMTP credentials | Yes |

## Framework / config files

| Type | Covered |
|---|---|
| WordPress `wp-config.php` | Yes |
| PHPMailer SMTP | Yes |
| CodeIgniter config | Yes |
| PHP DB variables | Yes |
| `.env` style variables (`DB_*`, `API_KEY`, etc.) | Yes |

## Output

Findings are stored in **DuckDB** at `./findings.duckdb` (default).

```bash
python3 query_findings.py summary
python3 query_findings.py interesting
python3 query_findings.py sql "SELECT secret_type, repo, filename FROM findings WHERE secret_type LIKE '%API%' ORDER BY detected_at DESC LIMIT 20"
```

Optional JSONL export: `--logfile path.jsonl`