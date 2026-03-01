# CYRBER — Claude Code Memory

## Projekt
- Autonomiczna platforma pentestingowa (AI 70% / Human 20% / Hardware 10%)
- Stos: Python 3.12+, FastAPI, Celery, Redis, PostgreSQL 16, Docker Compose
- AI: LiteLLM abstraction layer — Anthropic (primary) → OpenAI → DeepSeek → Ollama (fallback chain)
- Repo: `~/cyrber/`, GitHub: m-wilkowski/cyrber-site, branch: master
- Transfer prompt: `CYRBER_Transfer_Prompt.md` w repo root

## Kluczowe pliki
- `backend/main.py` — FastAPI app shell (~152 LOC): middleware, include_router × 22
- `backend/deps.py` — shared deps: JWT/auth, limiter, audit, risk helpers, finding classification
- `backend/schemas.py` — 20 Pydantic models
- `backend/routers/` — 22 router files (pages, auth, admin, scans, scan_tools, topology, osint, phishing, offensive, verify, intelligence, remediation, dashboard, mens, mind, mirror, proof, findings, compliance, organizations, lex, llm, integrations)
- `modules/integrations/` — integration layer: base.py (ABC), els.py (CEF syslog+ES), webhook.py (POST+HMAC), models.py (ORM), __init__.py (IntegrationManager)
- `backend/routers/pages.py` — 23 page routes + /api/health + root redirect → /overview
- `modules/database.py` — SQLAlchemy ORM, 31 tabel, 6 ForeignKeys, init_db() via Alembic upgrade, auto-seal hook
- `alembic/` — migracje; 0001-0013; `alembic.ini` w repo root
- `static/nav.js` — shared navbar IIFE (expert/client dual mode), renders into #cyrber-nav-root
- `static/cyrber-config.js` — global config: PACKAGE_NAMES mapping, getPackageDisplay(), renderPackageBadge()
- `static/theme.css` — design system (dark/light) + nav + animations, `static/theme.js` — toggle
- `static/logo.jpg` — oficjalne logo trójgłowego wilka (266 KB)
- `tests/` — NIE jest volume-mounted w Docker; `docker compose cp` do kontenera
- Patrz [files.md](files.md) dla pełnej listy plików

### Strony HTML (22 strony)
- 22 stron (20 z shared nav.js + login.html + report.html bez nav)
- `static/reports.html` — RAPORTY placeholder (PDF Export, Executive Summary, Technical Report)
- `static/overview.html` — strona startowa z onboarding panel (gdy brak skanów)
- `static/index.html` — SCAN page (route: /scan), hero z rotating rings + logo
- `static/dashboard.html` — Dashboard (route: /dashboard → 301 → /overview)
- Pełna lista: patrz [files.md](files.md)

## Preferencje Michała
- Język: polski, styl: konkretnie, bez owijania
- Commity: `feat:/fix:/docs:` po angielsku
- Kończy temat z emoji wilka 🐺

## Stan na 01.03.2026
- 50+ modułów skanujących, pipeline 52 kroków
- Auth: JWT + RBAC (admin/operator/viewer), licencje HMAC-SHA256 (4 tiery: SPECULATOR→SCOUT, EXCUBITOR→GUARD, HARUSPEX→AUGUR, PRAEFECTUS→COMMAND)
- Nav: dual-mode shared nav.js — Expert (EN+latin) / Client (PL), toggle w localStorage
  - Expert: MISSIONS▾ | RATIO▾ | ANIMUS▾ | FATUM▾ | MIRROR▾ | PROOF▾ | CHRONICLE▾
  - Client: PRZEGLĄD | MISJE▾ | ZAGROŻENIA | COMPLIANCE | RAPORTY
  - Default: operator/admin → expert, viewer → client
- Routing: GET / → /overview (307), GET /ui → /overview (301), GET /dashboard → /overview (301), GET /scan → index.html
- Login redirect: → /overview (nie /ui)
- 22 stron HTML (20 z shared nav.js + login + report)
- DB: 31 tabel ORM (+ integration_configs), 6 ForeignKeys, 10 indexes, Alembic rev 0013 head
- Testy: 520 passed (496 + 24 integration); `test_security_gate.py` + `test_misp_integration.py` broken

### Sesje 24-27.02 — patrz [sessions.md](sessions.md)
- Code review, hardening, ForeignKeys, split main.py, integration tests
- LEX, MENS, Three-Head, MIRROR, PROOF, GUI polish, DB indexes, Celery timeouts

### Sesja 01.03.2026 cz.1-4 — patrz [sessions.md](sessions.md)
- Findings browser + Compliance dashboard + Operator panel
- MENS v2 + LEX v2, Theatrum Belli v2, first MENS mission (DVWA)
- LiteLLM abstraction layer + per-org routing (migration 0012)

### Sesja 01.03.2026 cz.5 — Dual Navigation + Overview Landing + Package Names
- `18c2e64` feat: dual navigation — client (PL) / expert (EN+latin)
  - `static/nav.js`: shared navbar IIFE, 2 tryby (expert/client), toggle + localStorage
  - 21 HTML files: usunięty inline nav (~130 LOC each) → `<div id="cyrber-nav-root">` + `<script src="/static/nav.js">`
  - `static/reports.html`: RAPORTY placeholder (3 karty: PDF, Executive Summary, Technical Report)
  - `theme.css`: +.cyrber-nav-client, +.nav-mode-toggle CSS
- `e43af7a` feat: /overview as landing page + onboarding panel + /scan route
  - `login.html`: redirect → /overview (nie /ui)
  - `pages.py`: GET / → 307 /overview, GET /ui → 301 /overview, GET /dashboard → 301 /overview, GET /scan → index.html
  - `overview.html`: onboarding panel gdy brak skanów (🐺 Witaj w CYRBER + URUCHOM PIERWSZĄ MISJĘ)
- `86efc6d` feat: package display name mapping — SCOUT/GUARD/AUGUR/COMMAND
  - `static/cyrber-config.js`: PACKAGE_NAMES mapping, renderPackageBadge()
  - overview.html + organizations.html: używają renderPackageBadge()

### Sesja 01.03.2026 cz.6 — Integration Layer
- `415f64b` feat: integration layer — ELS SIEM + Webhook + IntegrationManager
  - `modules/integrations/` package: base.py (ABC), els.py (CEF syslog+ES), webhook.py (HMAC-SHA256), models.py (ORM), __init__.py (singleton)
  - `alembic/versions/migration_0013.py`: integration_configs table (JSONB config per org)
  - `backend/routers/integrations.py`: 7 CRUD endpoints (list/create/get/update/delete/test/toggle)
  - `modules/mind_agent.py`: +_notify_findings() in learn(), +_notify_mission_event() in run()
  - `static/admin.html`: INTEGRACJE tab (ELS/Webhook/Jira/GitLab cards)
  - `tests/test_integrations.py`: 24 tests (CEF format, syslog, webhook HMAC, manager dispatch, factory)

### Następna sesja — priorytety
1. Hardware head bridge (cyrber-hw-bridge)
2. ~~Dług techniczny P2: Alembic, ForeignKeys, split main.py, MENS, Celery timeouts, queue separation, LiteLLM~~

## Ważne wzorce techniczne
- Docker volumes: `static/`, `modules/`, `backend/`, `config/`, `knowledge_base/`, `alembic/`, `alembic.ini` — montowane; `tests/` — NIE (docker compose cp)
- Docker service names: `api`, `worker`, `beat`, `db`, `redis`, `nginx`, `zap`, `gophish`, `beef`, `evilginx`, `dvwa`, `ollama`, `garak`
- generate_verdict() w verify.py: wywołuje Claude Haiku — w testach ZAWSZE mockować (`side_effect=ImportError` na ClaudeProvider lub `@patch generate_verdict`)
- `build_topology()` teraz w `backend/routers/topology.py` (nie w main.py) — testy importują z nowej lokalizacji
- Deploy po zmianach: `docker compose restart api` (brak --reload w uvicorn)
- SSE auth: token przez query param (EventSource nie obsługuje custom headers)
- exploit_chains w DB: dict `{"chains": [...]}` nie lista
- Health check: `curl -sk https://localhost/api/health` (przez nginx, nie bezpośrednio :8000)
- Login response: klucz `token` (nie `access_token`)
- Redis: wymaga hasła od 27.02 — REDIS_URL z `redis://:password@redis:6379/0`
- Celery tasks: wszystkie 13 mają bind=True + soft_time_limit/time_limit + SoftTimeLimitExceeded handler; full_scan_task ciało w `_execute_full_scan()`
- Celery task tests: AST parsing (`test_tasks.py`) — parsuje source pliki zamiast importować obiekty (inne testy mockują `modules.tasks` via `sys.modules`)
- Startup: `_check_production_secrets()` w main.py ostrzega o default secrets
- Integration tests: `app.dependency_overrides[get_current_user]` dla auth, `@patch("backend.routers.<router>.<func>")` dla DB/Celery — NIE `sys.modules` na `modules.database`/`modules.verify` (psuje inne testy)
- Full suite: `--ignore=tests/test_security_gate.py --ignore=tests/tests/ --ignore=tests/test_misp_integration.py --ignore=tests/test_mind_legacy.py`
- MENS v2: `modules/mind_agent.py` (agent) + `modules/mens_task.py` (Celery) + `backend/routers/mens.py` (API /api/mens + SSE stream)
- MENS v2 agent: `MensAgent(mission_id, policy: LexPolicy, db, llm_client)` — sync methods, Integer DB PKs
- MENS v2 Celery: `run_mens_mission(mission_db_id: int, target, policy_dict, org_id)` — reconstructs LexPolicy from dict
- MENS v2 tests: `_DB_PATCH = "backend.routers.mens.SessionLocal"`, 27 tests
- MENS v1 (legacy): `backend/mind_agent.py` + `backend/routers/mind.py` remain but NOT mounted in main.py
- MENS Celery: `sys.path.insert` INSIDE task function body (not module level) — Celery prefork workers don't inherit module-level path
- MENS three-head: `classify_head()` in modules/mind_agent.py (v2) and backend/mind_agent.py (v1 legacy)
- MIRROR: `_update_mirror_profile()` in mens_task.py called on mission completion (lazy import to avoid circular)
- MIRROR genome: Claude Opus via `MirrorEngine.generate_genome()`, mocked in tests via `@patch("backend.mirror.MirrorEngine.generate_genome")`
- MIRROR tests: `_DB_PATCH = "backend.routers.mirror.SessionLocal"` (same pattern as mind tests)
- PROOF: `_get_proof_secret()` uses JWT_SECRET from deps.py; X-Proof-Key header auth (env PROOF_API_KEY, default "proof_demo_key")
- PROOF auto-seal: in `save_scan()` (database.py) — guarded by `AUTO_SEAL=true` env, lazy import ProofEngine
- PROOF tests: `_DB_PATCH = "backend.routers.proof.SessionLocal"`, X-Proof-Key headers for verify/feed
- Nav: shared `static/nav.js` renders into `#cyrber-nav-root`, dual mode expert/client, `/auth/me` resolves default mode
- Nav toggle: `localStorage.cyrber_nav_mode` = 'expert'|'client', `_cyrberToggleNav()` global
- Nav pages without nav.js: login.html, report.html (standalone)
- Package names: `static/cyrber-config.js` → `PACKAGE_NAMES` mapping, `renderPackageBadge(key)` returns HTML
- Routing: / → /overview (307), /ui → /overview (301), /dashboard → /overview (301), /scan → index.html
- Integrations: `modules/integrations/` package — BaseIntegration ABC, IntegrationManager singleton, JSONB config per org
- Integrations MENS hook: lazy import IntegrationManager in mind_agent.py, try/except — never breaks mission execution
- Integrations ELS: CEF syslog (UDP/TCP) + Elasticsearch POST, env config ELS_SYSLOG_HOST/PORT/PROTOCOL
- Integrations webhook: POST JSON + HMAC-SHA256 via X-CYRBER-Signature header, 2 retries, 10s timeout
- Integrations tests: `test_integrations.py` — 24 tests, no FastAPI dependency (pure unit tests)
- CSP: `script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com` — all external JS must come from cdnjs (NOT d3js.org!)
- Login: POST /auth/login → `{token}`, remember me = localStorage, forget = sessionStorage+localStorage, redirect → /overview
- Findings extraction: `_extract_findings()` in findings.py — DRY helper reused by compliance.py; extracts nuclei/zap/sqlmap/testssl/nikto/generic
- Compliance: NIS2/DORA/GDPR requirements with keyword-based finding matching; GDPR always WARNING (no personal data inventory)
- Organizations API: `response_model` removed from list endpoint (was stripping extra fields like security_score/package/last_alert)
- Organizations page: operator-only access via `/auth/me` check → redirect to `/overview` if not operator/admin
- JWT library: `from jose import jwt` (python-jose), NOT `import jwt` (PyJWT) — kontener ma tylko jose
- MENS FK fix: mens_task.py MUST `import Organization` before `MensMissionModel` — SQLAlchemy needs FK target table registered in Base.metadata
- MENS SSE: `/api/mens/missions/{id}/stream?token=JWT` — jose decode, async generator, heartbeat, auto-stop on completed/aborted
- Nginx SSE: each SSE endpoint needs dedicated `location` with `proxy_buffering off` + `proxy_cache off`
- DVWA target: use container IP (172.18.0.x) not hostname `dvwa` — LEX scope_cidrs checks IP resolution
- Nav links: `/theatrum` (new) replaces `/mission-control` (legacy still works); pathname map has both
- LiteLLM: `modules/llm_router.py` — `CyrberLLM` singleton `cyrber_llm`, `complete(prompt, system, task_type)` z fallback chain
- LiteLLM config: `config/llm_config.yaml` — providers (enabled/priority/models/api_key_env), task_routing (task→tier)
- LiteLLM task tiers: reasoning (opus), analysis (sonnet), fast (haiku), airgap (ollama only)
- LiteLLM tests: `_TEST_CONFIG` dict passed to `CyrberLLM(config=...)`, `@patch("litellm.completion")` for mocking
- LLM provider swap: `get_provider(task="mens")` instead of `ClaudeProvider(model="claude-opus-4-20250514")` — model resolved via models.yaml
- LLM per-org routing: `cyrber_llm.complete(prompt, org_id=X)` → loads org.llm_mode from DB; local/airgap → ollama only; cloud → preferred_provider first
- LLM org settings: `_get_org_llm_settings(org_id)` queries DB Organization table for llm_mode/preferred_provider/ollama_base_url
- LLM PATCH: `/api/organizations/{id}/llm-settings` → updates org LLM config (admin/operator only)
- LLM startup banner: `_print_llm_status()` in main.py — prints active providers + per-org LLM mode/provider

## Decyzje architektoniczne — 01.03.2026 (popołudnie)

### Metasploit — Explicit Authorization Gate
Metasploit wchodzi do CYRBER jako P2 Sprint 3.
Wymagana bramka zgody L3 przed uruchomieniem:
- L1: skan — podpisany kontrakt przy onboardingu
- L2: eksploitacja — potwierdzenie per misję w GUI + timestamp w DB
- L3: Metasploit/RCE — upload podpisanego PDF autoryzacyjnego
- L4: credential dump — L3 + ograniczone okno czasowe
LEX policy engine sprawdza poziom zgody przed każdą akcją.
TESTIMONIUM zapisuje: kto wyraził zgodę, kiedy, co wykonano.
Argument sprzedażowy: jedyna platforma z audit trailem zgód dla NIS2.

### Wazuh — integracja CEF, nie komponent CYRBER
Wazuh NIE jest wbudowany w CYRBER.
Wazuh = jeden moduł integrations/wazuh.py w Sprint 2.
Działa przez ten sam CEF syslog co ELS — zero dodatkowej pracy.
Nie promujemy jako "Wazuh w CYRBER" — promujemy
"integrujemy się z Twoim SIEM niezależnie jaki masz".
Dla klientów bez SIEM: CYRBER PULSE zastępuje podstawowy monitoring.

### Podział odpowiedzialności SIEM tier
SCOUT: CYRBER PULSE wystarczy — klient nie potrzebuje SIEM
GUARD: Wazuh opcjonalnie przez CEF — dla klientów którzy już go mają
AUGUR: Wazuh lub ELS — pełna integracja
COMMAND: ELS lub enterprise SIEM — natywna integracja dwukanałowa
