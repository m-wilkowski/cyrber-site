# CYRBER — Claude Code Memory

## Projekt
- Autonomiczna platforma pentestingowa (AI 70% / Human 20% / Hardware 10%)
- Stos: Python 3.12+, FastAPI, Celery, Redis, PostgreSQL 16, Docker Compose
- AI: Claude Opus 4 (primary), Ollama llama3.2 (fallback)
- Repo: `~/cyrber/`, GitHub: m-wilkowski/cyrber-site, branch: master
- Transfer prompt: `CYRBER_Transfer_Prompt.md` w repo root (kopia źródłowa w ~/Downloads/)

## Kluczowe pliki
- `modules/ai_analysis.py` — AI agent, cross-module correlation, ContextManager
- `modules/tasks.py` — Celery full_scan_task + publish_progress() Redis pub/sub (49 kroków)
- `config/models.yaml` — YAML model routing per task
- `modules/evilginx_phishing.py` — Evilginx2 SQLite reader + 7 endpointów (uwaga: nazwa pliku z _phishing)
- `backend/main.py` — FastAPI, SSE endpoint /scan/stream/{task_id}, JWT auth
- `static/index.html` — główny UI (cyberpunk dark theme), SSE client + polling fallback
- `static/phishing.html` — Phishing Campaign Wizard (4-step)
- `CYRBER_Transfer_Prompt.md` — dokument kontekstowy dla nowych sesji Claude

## Preferencje Michała
- Język: polski
- Styl: konkretnie, bez owijania w bawełnę
- Pracuje w Claude Code (terminal)
- Commity: konwencja `feat:/fix:/docs:` po angielsku
- Dokumenty: .docx profesjonalnie, bez śladów AI
- Kończy temat z emoji wilka

## Stan na 23.02.2026
- 45+ modułów skanujących (web, recon, SSL, network, AD, exploitation, social engineering)
- ContextManager: dynamiczny budżet tokenów, 29 testów
- YAML model routing: Opus/Sonnet/Haiku per task type
- Evilginx2: backend + docker + 40 testów
- Phishing Campaign Wizard: 4-step UI z AI email generator; wizard bugfixy ✅ zamknięte
- UI polish: exploit chain karty, business impact grid, risk score ring glow
- Polling timeout: 3/10/6 min per endpoint type
- SSE streaming ✅: Redis pub/sub → EventSourceResponse, 49 kroków per skan, connectSSE() + polling fallback; token via query param (SSE nie obsługuje headers); sse-starlette>=1.6.1
- Backlog nowy priorytet: LuaN1ao inspiracje (Reflector, confidence score, RAG PayloadsAllTheThings)
- Transfer prompt zaktualizowany i w repo (sekcje 4, 10, 13)

## Sesje — szczegoly
- Patrz: [sessions.md](sessions.md)
