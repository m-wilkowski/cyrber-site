# CYRBER – Transfer Prompt (stan: luty 2026)

Jesteś asystentem Michała Wilkowskiego przy projekcie **CYRBER** – autonomicznej platformy do pentestingu. Poniżej kompletny kontekst projektu, aktualny stan techniczny, zespół, backlog i decyzje które zostały podjęte. Czytaj uważnie zanim zaczniesz pomagać.

---

## 1. Kim jest Michał i czym jest CYRBER

**Michał Wilkowski** – presales engineer w Energylogserver (SIEM/SOAR, firma EMCA Software), certyfikat OSCP, pentester i red team. Na co dzień pracuje na Fedora Linux, wdraża systemy na Oracle Linux 8/9. Twórca i główny developer CYRBER.

**CYRBER** to platforma do autonomicznego testowania bezpieczeństwa. Łączy trzy warstwy:
- **AI (70%)** – automatyczne skanowanie, analiza wyników, exploit chainy, raporty PDF
- **Human (20%)** – ekspert waliduje wyniki, bierze odpowiedzialność
- **Hardware (10%)** – WiFi Pineapple, Flipper Zero, Raspberry Pi Remote Sensor (planowane)

Nazwa: Cerberus + Cyber. Trzy głowy = trzy warstwy.

**Projekt ma ~3 tygodnie** (start ~5.02.2026). Nie jest gotowy do sprzedaży – jest w fazie aktywnego developmentu. Sekwencja: software → AI integration → testy → hardware → sprzedaż.

---

## 2. Zespół

| Osoba | Rola | Narzędzia |
|-------|------|-----------|
| Michał | Założyciel, lead dev, pentester | GitHub (owner), Discord, Fedora |
| Syn starszy (technikum IT) | Frontend developer, strona cyrber.pl | GitHub (Write), Discord |
| Syn młodszy (11 lat) | Tester, pomysły, świeże spojrzenie | GitHub (Read), Discord |

**Koordynacja:** GitHub do kodu (branch protection na main, PRy), Discord do komunikacji, Signal prywatny.

Syn starszy dostał briefing (dokument CYRBER_Briefing_WWW.docx) z opisem projektu i zadaniem zbudowania strony cyrber.pl od podstaw (własny kod, bez Wix/Webflow). Narzędzia i framework – jego decyzja.

---

## 3. Infrastruktura techniczna

**Lokalizacja:** `~/cyrber/` na Fedora (localhost)
**GitHub:** https://github.com/m-wilkowski/cyrber-site (branch: master)

**Stos:**
- Backend: Python 3.12+, FastAPI, Celery, Redis, PostgreSQL 16
- AI Primary: Claude Opus 4 (Anthropic API)
- AI Fallback: Ollama llama3.2 (offline, 120s timeout)
- Kontenery: Docker Compose – 7 serwisów

**Działające kontenery:**
```
cyrber-api-1      FastAPI backend        :8000
cyrber-worker-1   Celery worker
cyrber-beat-1     Celery scheduler
cyrber-db-1       PostgreSQL             :5432
cyrber-redis-1    Redis                  :6379
cyrber-zap-1      OWASP ZAP              :8090  (port zmapowany po naprawie)
cyrber-gophish-1  GoPhish                :3333, :8080
```

**DVWA** dodana do docker-compose.yml jako guinea pig:
```yaml
dvwa:
  image: vulnerables/web-dvwa
  ports:
    - "8888:80"
  restart: unless-stopped
```

**Nginx Reverse Proxy:**
```
cyrber-nginx-1    Nginx reverse proxy    :443 (HTTPS), :80 (redirect)
```
Self-signed TLS cert (ważny do 2029), security headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options), rate limiting (10r/s burst 20).

**Backend:** 176 endpointów API (138 GET, 30 POST, 1 PUT, 1 PATCH, 6 DELETE)
**Testy:** 278 testów w 13 plikach (test_verify 100, test_evilginx_phishing 40, test_context_manager 29, test_certipy 28, test_evilginx 16, test_intel_sources 15 i inne)

**Auth:** JWT (HS256) + RBAC (admin/operator/viewer). Login: POST /auth/login → token. Domyślnie: admin:cyrber2024.

**System licencji:** On-prem HMAC-SHA256 (`modules/license.py`). Tier: demo (1 skan/dzień, SZCZENIAK only) / basic (10/dzień) / pro (50/dzień) / enterprise (unlimited). Plik licencji: `/etc/cyrber/license.key`. GET /license/status, POST /license/activate.

**Hardening:** Docker no-new-privileges, read-only root fs (nginx), rate limiting na API (slowapi), security headers via nginx

---

## 4. Zaimplementowane moduły (80 plików Python, ~24 000 linii)

### Web Application
- Nuclei (14 000+ templates)
- OWASP ZAP (własny kontener, port 8090)
- Wapiti (timeout: 120s, max-scan-time: 600s)
- Nikto
- SQLmap (timeout: 60s, retries: 2)
- Gobuster
- WPScan
- Joomscan
- CMSmap
- Droopescan
- Retire.js

### Recon / OSINT
- Nmap
- Masscan
- Whatweb
- Whois
- Subfinder
- Amass
- httpx
- Katana
- Fierce
- DNSx (dangling CNAME, SPF/DKIM/DMARC)
- theHarvester
- Sherlock (400+ platform)
- Maigret (500+ platform)
- Holehe (120+ platform)

### SSL/TLS
- Testssl
- SSLyze

### Network / Infrastructure
- Naabu
- Netdiscover
- Arp-scan
- Fping
- Traceroute
- NBTscan
- SNMPwalk
- Onesixtyone
- IKE-scan

### Active Directory / Windows
- NetExec (SMB enumeration)
- Enum4linux-ng
- BloodHound (bloodhound-python)
- SMBmap
- Responder (analyze mode)
- Impacket (Kerberoasting, AS-REP Roasting, DCSync, SID enum)
- Certipy (modules/certipy_scan.py) — AD CS enumeration, ESC1–ESC13 detection, MITRE T1649; certipy-ad 5.0.4 (zależność netexec); profil CERBER; credentials via CERTIPY_USER/PASS/DOMAIN/DC_IP

### Exploitation Intelligence
- SearchSploit

### Context Management
- ContextManager (modules/ai_analysis.py) — dynamiczny budżet tokenów per model: Claude 180k, Ollama 6k; estimate_tokens(), truncate_findings() by severity, build_context_aware_prompt(); 29 testów jednostkowych

### Configuration
- YAML Model Routing (config/models.yaml) — Opus dla exploit_chains/hacker_narrative, Sonnet dla ai_analysis/agent, Haiku dla false_positive_filter/llm_analyze/phishing_email; cache per-task w llm_provider.py

### RAG Knowledge Base
- `modules/rag_knowledge.py` — RAGKnowledge class, FAISS IndexFlatIP, fastembed BAAI/bge-small-en-v1.5; 141 plików MD PayloadsAllTheThings, 3386 chunków; POST /rag/build-index, GET /rag/search; `_fetch_rag_context()` w ai_analysis.py (top5 critical/high, 15% budżet kontekstu)
- Dockerfile fix: exploitdb przez git clone (apt nie istnieje w Debian bookworm)

### OSINT / Metadata
- Exiftool (modules/exiftool_scan.py) — ekstrakcja EXIF z obrazków na target URL (max 5); GPS/device/software/datetime/artist; risk high (GPS), medium (device), low (brak danych); always-run w pipeline; libimage-exiftool-perl 13.25

### Social Engineering
- GoPhish (własny kontener)
- Evilginx2 (modules/evilginx.py) — SQLite reader: sessions, phishlets, config, stats; 11 endpointów: legacy `/evilginx/*` (stats/sessions/phishlets/config) + nowe `/api/evilginx/*` (status/lures/credentials); 40 testów; docker-compose profile phishing
- BeEF-XSS (modules/beef_xss.py) — REST API client: login z token cache, hooks/modules/run_module/logs; 9 endpointów /beef/*; docker-compose profile phishing; janes/beef image, port 3001; config/beef.yaml z custom credentials
- Phishing Campaign Wizard (static/phishing.html) — 4-step wizard: Recon Data → Attack Vector → Kampania → Review & Launch; GoPhish + Evilginx2 wybór trybu; checkbox zgody prawnej; AI email generator POST /phishing/generate-email

### AI/LLM Security
- Garak (docker/garak/, modules/garak_scan.py) — NVIDIA garak 0.14.0 w osobnym kontenerze (torch+transformers ~4GB); mini FastAPI wrapper (server.py); async scan z poll; 40+ probe'ów (prompt injection, jailbreak, encoding, data leakage); OWASP LLM Top 10; 5 endpointów /garak/*; profil ai-security; probe categories: prompt_injection, data_leakage, toxicity, jailbreak, full

### Frontend / UI
- Scan View (static/index.html, 1383 linie) — **przepisany od zera**: 3-step flow (target→profil→start), animated pulsing ring hero, target validation (domain/IP/CIDR), profile cards z license lock overlay (admin bypass licencji), SSE live feed z typewriter effect (30ms/char) + terminal panel (surowy output SSE obok), 17 faz funkcjonalnych (MODULE_LABELS z 52 modułów), progress bar z ETA, completion screen, recent scans (5 ostatnich)
- Scan Detail (static/scan_detail.html, 1367 linii) — pełna strona szczegółów skanu: hero (risk ring + target + badges), 6 zakładek (Overview/Findings/Moduły/AI Analysis/Report/Remediation), sparkline security score trend w Overview, floating AI agent chat (POST /api/scan-agent, Claude Haiku + scan context, sessionStorage history), enrichment badges (KEV/EUVD/MISP/EPSS/ATT&CK)
- Dashboard (static/dashboard.html, 2365 linii) — **przepisany od zera**: KPI bar (4 karty), filtry (data/profil/ryzyko/target + debounce), sortowalna tabela z paginacją, slide-in drilldown (4 zakładki), pure CSS/SVG, MISP export. Klik wiersza → scan detail (desktop) / drilldown (mobile)
- Cache-busting headers — no-cache na /ui, /dashboard, /scheduler, /phishing, /osint, /scan/{id}/detail
- SSE Streaming (static/index.html + backend/main.py) — real-time postęp skanowania: connectSSE() primary z fallback na polling; GET /scan/stream/{task_id}?token=JWT; Redis pub/sub 49 kroków per skan
- Network Topology (static/topology.html) — D3.js v7 force-directed graph wizualizacja topologii sieci ze skanów; `build_topology()` parsuje nmap/netdiscover/arpscan/nbtscan/bloodhound/traceroute/certipy; node types: cloud/target/gateway/host/dc; risk per node z nuclei findings; API: GET /api/scan/{task_id}/topology; scan selector dropdown, KPI strip, legenda, zoom/drag, side panel po kliknięciu noda
- AI Explain per Finding — POST /api/explain-finding: Claude Haiku, Redis cache 24h (klucz: explain:{name}:{severity})
- AI Scan Agent — POST /api/scan-agent: Claude Haiku + kontekst skanu (target, risk, findings top 15, chains top 3), conversation history

---

## 5. AI Agent (modules/ai_analysis.py)

**Primary:** Claude Opus 4 | **Fallback:** Ollama llama3.2

### Cross-module correlation (dodane w ostatniej sesji)
6 funkcji (~370 linii) w `modules/ai_analysis.py`:

| Funkcja | Co robi |
|---------|---------|
| `_categorize_web_vuln` | Normalizuje nazwy podatności do 18 kategorii |
| `_correlate_service_attack_surface` | port → service+version → whatweb → searchsploit → NVD CVEs (CVSS≥7) |
| `_correlate_ad_attack_paths` | Cross-ref users z enum4linux+netexec+bloodhound, mapy ścieżek ataku |
| `_correlate_web_exploit_chains` | Grupuje web vulns, identyfikuje CONFIRMED (2+ skanery), sqlmap+gobuster+nikto |
| `_correlate_network_smb_exposure` | Merge SMB z 3 źródeł, lateral movement chain |
| `_build_correlation_graph` | Orchestrator, łączy 4 correlatory, hard cap 3000 znaków |

Prompt do LLM zawiera sekcję `=== KORELACJE MIEDZYMODULOWE ===` między KONTEKST a FINDINGS.

### Output AI:
- `executive_summary` – ~200 słów dla CISO/CEO
- `attack_narrative` – ~300 słów, scenariusz z perspektywy hakera
- `exploit_chain` – kroki: technique/tool/CVE/MITRE/impact/likelihood
- `business_impact` – ryzyko EUR, compliance RODO/NIS2/ISO27001, downtime
- `remediation_priority` – priorytet 1–10, effort, deadline
- `risk_score` – 0–100 (Critical=40, High=20, Medium=5, Low=1)

---

## 6. Profile skanowania

| Profil | Moduły | Czas | Cena |
|--------|--------|------|------|
| SZCZENIAK | 12 | ~30 min | €4 000 |
| STRAŻNIK | 34 | ~2h | €7 500 (domyślny) |
| CERBER | 39 | ~4h+ | €15 000+ |

---

## 7. GUI / Frontend

- `/ui` – index.html: **przepisany od zera** — 3-step scan launcher (target→profil→start), hero z animowanym pulsing ring, walidacja target (domain/IP/CIDR), profile cards z license lock overlay, SSE live feed z typewriter effect (30ms/char), 17 faz funkcjonalnych (MODULE_LABELS), progress bar z ETA, completion screen ze statystykami + link do scan detail, recent scans (5 ostatnich)
- `/scan/{task_id}/detail` – scan_detail.html: pełna strona szczegółów skanu — hero (risk ring + target + badges), 6 zakładek (Overview z KPI+bar chart+top findings+sparkline trend, Findings z severity toggles + WYJAŚNIJ AI, Moduły grid z expand JSON, AI Analysis z narrative+chains timeline, Report z iframe preview, Remediation z task cards+inline edit+TRACK ALL+RETEST), floating AI agent chat (POST /api/scan-agent, Claude Haiku + kontekst skanu, sessionStorage history)
- `/dashboard` – **przepisany od zera**: KPI bar (4 karty), filtry (data/profil/ryzyko/target + debounce), sortowalna tabela z paginacją (20/stronę), prawy slide-in drilldown panel (50% width, cubic-bezier) z 4 zakładkami: Summary (CSS conic-gradient risk ring, narrative, business impact, compliance), Findings (filtr severity + WYJAŚNIJ AI per finding), Moduły (grid ~44 modułów, expand JSON), Exploit Chains (vertical timeline, confidence badges). BEZ Chart.js — pure CSS/SVG. Klik wiersza → /scan/{task_id}/detail (desktop), drilldown fallback (mobile ≤768px). **Security Score Timeline**: SVG line chart + stacked bars + 3 KPI (poprawa/fix rate/trend) + target selector dropdown.
- `/login` – login.html (258 linii): JWT auth form, localStorage token, redirect do /ui
- `/command-center` – command_center.html (892 linii): unified dashboard trzech głównych widoków, szybki dostęp do skanów/alertów/akcji
- `/scheduler` – scheduler.html (342 linie): planowanie skanów (CRUD), lista zaplanowanych, cron-style
- `/phishing` – phishing.html (1565 linii): GoPhish UI + Phishing Campaign Wizard (4-step), Evilginx2 monitor (sessions/credentials/lures), BeEF hooks
- `/osint` – osint.html (1269 linii): Deep OSINT Scanner — 5 typów (domain/IP/email/phone/username), progress tracking, historia z PDF export, moduły: Sherlock/Maigret/Holehe/theHarvester/WHOIS/subfinder/httpx
- `/topology` – topology.html (455 linii): D3.js v7 force-directed graph wizualizacja topologii sieci ze skanów; `build_topology()` parsuje nmap/netdiscover/arpscan/nbtscan/bloodhound/traceroute/certipy; node types: cloud/target/gateway/host/dc; risk glow per node; zoom/drag; side panel po kliknięciu; scan selector dropdown; KPI strip (hosts/ports/edges/risk)
- `/verify` – verify.html (1348 linii): CYRBER VERIFY — fraud detection dla URL/email/firmy; 14 OSINT źródeł (WHOIS, GSB, VT, URLhaus, GreyNoise, Wayback, MX, RDAP, crt.sh, SPF/DMARC, IPinfo, AbuseIPDB, OTX, Tranco); tabs UI: wyniki + raport AI + historia; bidirectional scoring 0-100
- `/admin` – admin.html (1333 linie): Admin Panel — zarządzanie użytkownikami (CRUD), role RBAC, status licencji, system info, Intel Sync (status/logi/SYNC NOW), audit log
- `/report/{task_id}` – report.html (733 linie): Client Report View — raport dla CEO/managera, czytelny bez technicznego żargonu, risk gauge, compliance badges, recommendations
- PDF Report – automatyczny, WeasyPrint + Jinja2
- AI Explain per Finding – POST /api/explain-finding: Claude Haiku tłumaczy znalezisko po polsku (CO TO JEST / CZYM GROZI / JAK NAPRAWIĆ), Redis cache 24h (klucz: explain:{name}:{severity})

**Frontend stats:** 12 plików HTML, ~13 300 linii, vanilla JS (zero frameworków), authFetch() z JWT 401 handler, esc()/escHtml() XSS protection

**Notify:** Email + Slack + Discord + Telegram

---

## 8. Naprawione bugi (ostatnia sesja)

1. **ZAP port** – brak `ports: "8090:8090"` w docker-compose.yml → ZAP API niedostępne z localhost. Naprawione.
2. **ZAP alert parser** – `alert_name` niepoprawnie mapowany → 0/205 alertów zamiast 205/205. Naprawione.
3. **pdf_report.py** – `{{}}` w f-stringu (enum4linux, netexec) → `TypeError: unhashable type: 'dict'`. Naprawione (2 miejsca).
4. **Wapiti timeout** – 30s → 120s, max-scan-time 300s → 600s.
5. **SQLmap timeout** – 30s → 60s, retries 1 → 2.

### Frontend Security Audit (sesja 26.02.2026 — część 5-6)

Pełny audyt bezpieczeństwa wszystkich 12 plików HTML (2 sesje, ~22 bugi):

| Plik | Bugi | Typy | Commit |
|------|------|------|--------|
| index.html | 2 | XSS risk_level | `97e9d17` |
| scan_detail.html | 3 | XSS, delete double-click, dedup auth/me | `0b739c1` |
| login.html | 1 | double-submit guard | `957c057` |
| dashboard.html | 3 | XSS risk, malware_signature, module | `d35b37a` |
| phishing.html | 3 | XSS status, review values, double-click | `ef75a9a` |
| osint.html | 4 | XSS inline onclick→data-attrs, country | `e9ec943` |
| verify.html | 3 | XSS inline onclick→data-attrs, icon, risk | `8da6471` |
| admin.html | 3 | XSS role, inline onclick→data-attrs, status | `91ea2e2` |
| scheduler.html | 0 | — | — |
| topology.html | 1 | XSS d.risk unescaped | `9912137` |
| report.html | — | (audyt wcześniej) | `b80cc4b`+ |
| command_center.html | — | (audyt wcześniej) | — |

**Wzorce naprawione:**
1. **escHtml()/esc() nie escapuje `'`** — inline `onclick="fn('${escHtml(data)}')"` = JS injection. Fix: `data-*` atrybuty + `addEventListener`
2. **Backend string data w innerHTML bez escape** — risk_level, status, role, country, malware_signature, module name
3. **Brak disabled guard na buttonach** — double-click/double-submit

---

## 9. Wyniki testu end-to-end (DVWA, profil STRAŻNIK)

Skan STRAŻNIK na DVWA (localhost:8888), 350 sekund:
- ZAP: 205 alertów (1 High SQL Injection, 18 Medium, 46 Low, 140 Info)
- Gobuster: 12 ścieżek (/config, /php.ini, /phpinfo.php)
- Whatweb: Apache 2.4.25, PHP, DVWA
- AI risk_score: **100/100 Critical**
- Exploit chain: 6 kroków (Service Discovery → SQLi → Session Hijacking)
- Business impact: €150 000, RODO + NIS2
- PDF: 15 sekcji, wszystkie obecne

**Pipeline działa end-to-end od skanu do PDF raportu.**

---

## 10. CYRBER LOOP – ZREALIZOWANE ✅

### Koncept: zamknięta pętla bezpieczeństwa

CYRBER przestaje być jednorazowym skanerem i staje się **ciągłym procesem bezpieczeństwa**. Pętla:

```
ZNAJDŹ → ZROZUM → NAPRAW → SPRAWDŹ → (powtórz)
```

| Faza | Co robi | Komponent | Status |
|------|---------|-----------|--------|
| **ZNAJDŹ** | Skan 50+ modułami, exploit chainy, AI analiza | Istniejący pipeline (52 kroków) | ✅ |
| **ZROZUM** | AI tłumaczy per finding, business impact, compliance | AI Explain, Scan Agent, raporty | ✅ |
| **NAPRAW** | Remediation Tracker — zadania z właścicielem/deadlinem | Tabela DB + API CRUD + UI tab | ✅ |
| **SPRAWDŹ** | Auto-retest po oznaczeniu "naprawione" | Targeted re-scan per finding | ✅ |

### ✅ Remediation Tracker (zrealizowany)
- Tabela PostgreSQL: `remediation_tasks` (13 kolumn + 4 retest: id, scan_id, finding_name, finding_severity, finding_module, owner, deadline, status, notes, created_at, updated_at, verified_at, retest_task_id, retest_status, retest_at, retest_result)
- Status: open → in_progress → fixed → verified / wontfix
- UI: 6. zakładka REMEDIATION w scan_detail.html — karty z kolorowym left-border per status, inline edit (owner/deadline/notes/status), TRACK ALL (bulk create z deduplicją), filtry severity/status
- API: 5 endpointów (GET/POST /api/scan/{task_id}/remediation, PATCH/DELETE /api/remediation/{id}, POST /api/scan/{task_id}/remediation/bulk)
- RBAC: admin/operator = edycja, viewer = readonly, admin = delete
- Audit log na każdej mutacji

### ✅ Intelligence Sync (zrealizowany)
- `modules/intelligence_sync.py` — synchronizacja publicznych baz podatności
- CISA KEV: 1527 rekordów Known Exploited Vulnerabilities, pełny katalog
- FIRST EPSS: Exploit Prediction Scoring System, batch po 100 CVE
- NVD CVE 2.0: on-demand fetch per CVE (CVSS, CWE, opis, referencje)
- 4 tabele cache: `kev_cache`, `epss_cache`, `cve_cache`, `intel_sync_log`
- Celery Beat: codzienny sync o 3:00 AM (`run_intel_sync` task)
- `enrich_finding(cve_id)` → CVSS + EPSS + KEV + calculated priority (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- `calculate_priority()` — CVSS + EPSS + KEV multi-factor
- API: GET /api/intel/status, POST /api/intel/sync, GET /api/intel/enrich/{cve_id}
- Admin panel: zakładka INTEL SYNC ze statystykami, logami, przyciskiem SYNC NOW

### ✅ Auto-retest (zrealizowany)
- Po oznaczeniu zadania jako "fixed" → przycisk RETEST w UI
- `run_targeted_retest()` w intelligence_sync.py: dynamiczny import skanera (13 modułów), analiza wyników (_check_finding_in_results: name match, findings lists, CVE pattern)
- Celery task `retest_finding`: uruchamia re-scan, aktualizuje status → verified (nie znaleziono) / reopened (wciąż podatne)
- API: POST /api/remediation/{id}/retest, GET /api/remediation/{id}/retest/status
- UI: RETEST badge (pending/running/passed/failed), polling 5s, evidence panel
- Testowane end-to-end: create → fix → retest → verified (0.2s)

### ✅ Security Score Timeline (zrealizowany)
- **Dashboard** (static/dashboard.html):
  - Target selector dropdown z GET /api/dashboard/security-scores (10 targetów, trend ikony, score)
  - SVG Line Chart (pure JS, zero bibliotek): oś Y 0-100 z gridlines, linia kolorowana (green<40, orange 40-70, red>70), area fill gradient 0.15 opacity, klikalne punkty → /scan/{task_id}/detail, tooltip on hover (date + score + findings)
  - SVG Stacked Bars: mini słupki critical/high/medium/low per skan
  - 3 KPI karty: POPRAWA (improvement first→last), FIX RATE (% remediated/total), TREND badge (IMPROVING/STABLE/DEGRADING)
- **Scan Detail** (static/scan_detail.html):
  - Mini sparkline SVG 150x40px w zakładce OVERVIEW (panel SECURITY SCORE TREND)
  - Ostatnie 5 skanów targetu, linia + area fill, kolorowanie per trend
  - Label: "Trend: ↓ poprawa (70 → 40)"
- API: GET /api/target/{target}/timeline, GET /api/dashboard/security-scores

### Do zrealizowania (kolejne sesje)
- **Compliance Evidence PDF** — GET /report/{task_id}/compliance?framework=nis2
- **Integracje zewnętrzne** — Jira webhook, GitHub Issues (MISP ✅ zrealizowane sesja 25.02)
- **Notyfikacje do ownera** — email/Slack/Discord po retest

### Model biznesowy — subskrypcja CYRBER LOOP

| Plan | Cena/msc | Zawartość |
|------|----------|-----------|
| **LOOP Starter** | €299 | 1 target, skany tygodniowe, Remediation Tracker, email notify |
| **LOOP Professional** | €699 | 5 targetów, skany dzienne, auto-retest, Jira/GitHub integration, compliance PDF |
| **LOOP Enterprise** | €1 499 | Unlimited targets, continuous scanning, custom integrations, dedicated support, SLA 4h |

Uzupełnia jednorazowe pentest (SZCZENIAK/STRAŻNIK/CERBER) o model recurring revenue.

---

## 11. Backlog (priorytety)

### Priorytet 0 – Następna sesja
1. **Hardware head bridge** (cyrber-hw-bridge — WiFi Pineapple, Flipper Zero)

### Zrealizowane z Priorytet 0
- ~~ATT&CK full sync + ENISA EU VDB~~ ✅ (sesja 25.02)
- ~~Dark/Light theme toggle~~ ✅ (sesja 25.02 — Design System)
- ~~Pentest-as-Code CI/CD~~ ✅ (sesja 25.02)
- ~~MISP integration~~ ✅ (sesja 25.02)
- ~~Network topology visualization~~ ✅ (sesja 26.02 — D3.js)

### Priorytet 1 – AI Integration (w toku)
- Cross-module reasoning ✅
- ContextManager ✅ (29 testów)
- YAML model routing ✅
- SSE streaming ✅ — Redis pub/sub + EventSourceResponse, 49 kroków, polling fallback
- AI Explain per Finding ✅ — Claude Haiku, Redis cache 24h
- Chain summarization — zapobieganie overflow (w toku)

### Priorytet 2 – AI/LLM Security Scanner
- Garak ✅ — osobny kontener Docker, 40+ probe'ów, profil ai-security, async scan z poll
- Token Turbulenz – fuzzer prompt injection
- Damn Vulnerable LLM Agent – guinea pig do testowania
- Arcanum PI Taxonomy (Jason Haddix) – taksonomia technik prompt injection
- Nuclei custom templates dla LLM endpoints

### Priorytet – LuaN1ao inspiracje ✅
- Reflector pattern ✅ — reflect_on_scan() w ai_analysis.py, klasyfikacja modułów ok/empty/error/missing
- Causal chain confidence score ✅ — "confidence": 0.0-1.0 per krok exploit_chain, UI badge CONFIRMED/LIKELY/THEORETICAL
- RAG z PayloadsAllTheThings ✅ — FAISS + fastembed, 3386 chunków, _fetch_rag_context() w ai_analysis.py, 15% budżet kontekstu

### Priorytet 3 – Social Engineering
- Evilginx2 ✅ — backend + docker + 40 testów
- Phishing Campaign Wizard ✅ — 4-step UI
- Wizard bugfixy ✅ — JWT auth i AI GENERATE działały od początku; naprawiony fetch phishletów z /evilginx/phishlets
- BeEF-XSS ✅ — REST API client (modules/beef_xss.py), 9 endpointów /beef/*, docker-compose profile phishing
- ~~SET~~ — odrzucony: 100% interaktywny TUI (raw_input menus), brak REST API, brak trybu headless; funkcjonalność pokryta przez GoPhish (spearphishing) + BeEF (browser exploitation) + Evilginx2 (credential harvesting)

### Priorytet 4 – DevSecOps / CI/CD Security
- Nord Stream – wyciąganie secrets z CI/CD
- Gato – GitHub Attack Toolkit
- ADOKit – Azure DevOps Attack Toolkit
- Pentest-as-code integracja

### Priorytet 5 – Architecture Upgrade
- LangGraph – zastąpienie agent.py, checkpointy, stop/resume
- Neo4j knowledge graph – wizualizacja ataków
- MCP (Model Context Protocol) – każde narzędzie jako MCP server
- pgvector – semantyczne wyszukiwanie podobnych skanów
- Multi-agent roles (Researcher/Developer/Executor)

### Priorytet 6 – AD / Windows (rozszerzenie) ✅
- Certipy ✅ — AD CS enumeration, ESC1–ESC13, profil CERBER, credentials via env vars

### Priorytet 7 – OSINT rozszerzenia
- Exiftool ✅ — EXIF metadata extraction, GPS/device/datetime, always-run w pipeline
- GreyNoise ✅ — intel source (sesja 25.02)
- Blackbird – 600+ platform, AI profiling
- URLScan.io, Fullhunt.io (darmowe tier)
- HaveIBeenPwned ($3.50/msc)

### Priorytet 8 – Hardware (po stabilizacji software)
- WiFi Pineapple Mark VII – REST API wrapper
- Flipper Zero – pyflipper (RFID/NFC/Sub-GHz/BadUSB)
- Raspberry Pi Remote Sensor – Netbird mesh VPN
- Proxmark3 – Faza 2

### Zrealizowane – Sesja 24.02.2026 (część 1: infrastruktura + UI)
- Admin Panel UI ✅ — static/admin.html, CRUD użytkowników, role RBAC, status licencji
- RBAC ✅ — admin/operator/viewer, dekoratory require_role(), JWT claims
- System licencji ✅ — on-prem HMAC-SHA256, 4 tiery (demo/basic/pro/enterprise), modules/license.py
- Hardening ✅ — security headers (nginx), rate limiting (slowapi), Docker no-new-privileges
- Nginx reverse proxy ✅ — HTTPS/TLS self-signed 2029, redirect HTTP→HTTPS
- Command Center ✅ — static/command_center.html, unified dashboard
- Auto-Flow po skanie ✅ — rekomendowane akcje po zakończeniu skanu
- Client Report View ✅ — static/report.html, GET /report/{task_id}, raport dla CEO
- Dashboard rewrite ✅ — KPI, filtry, sortowanie, paginacja, drilldown 4-tab, bez Chart.js
- AI Explain per Finding ✅ — Claude Haiku + Redis cache 24h
- Scan Detail Page ✅ — static/scan_detail.html, 5 zakładek, floating AI agent chat (POST /api/scan-agent)
- Scan View rewrite ✅ — index.html od zera: 3-step flow, SSE live feed, typewriter, MODULE_LABELS, license lock
- Dashboard redirect ✅ — klik wiersza → /scan/{task_id}/detail (desktop), drilldown (mobile)
- Terminal panel ✅ — surowy techniczny podgląd SSE obok live feed podczas skanowania
- Admin bypass licencji ✅ — rola admin omija lock profili, licencja ogranicza tylko klientów
- Nav ✅ — SCAN | DASHBOARD | PHISHING | SCHEDULER | OSINT | TOPOLOGY | VERIFY | ADMIN (+ LOGOUT)
- Bugfix scan-agent ✅ — exploit_chains dict→list extraction (TypeError: unhashable type 'slice')

### Zrealizowane – Sesja 24.02.2026 (część 2: CYRBER LOOP)
- **Remediation Tracker** ✅ — tabela `remediation_tasks` (17 kolumn), 5 endpointów API, 8 funkcji CRUD, UI tab w scan_detail.html (karty, inline edit, TRACK ALL bulk, filtry, RBAC)
- **Intelligence Sync** ✅ — modules/intelligence_sync.py, KEV (1527 rekordów), EPSS (batch), NVD on-demand, 4 tabele cache, Celery Beat 3:00 AM, enrich_finding() z calculated priority, admin panel INTEL SYNC tab
- **Auto-retest** ✅ — run_targeted_retest() (13 modułów, dynamiczny import), retest_finding Celery task, 2 endpointy API, UI RETEST button z polling 5s, verified/reopened flow
- **Security Score Timeline** ✅ — dashboard SVG line chart (pure JS, zero bibliotek) + stacked bars + 3 KPI + target selector, scan_detail sparkline SVG 150x40, 2 endpointy API (timeline + security-scores)

### Zrealizowane – Sesja 25.02.2026
- **ATT&CK Full Sync** ✅ — sync_attack() STIX→DB, 6 tabel ORM, CAPEC-CWE map, ENISA EUVD, Celery Beat weekly/daily
- **GUI Design System** ✅ — static/theme.css dark/light, 10 stron zaktualizowanych, auto-switch prefers-color-scheme
- **Pentest-as-Code CI/CD** ✅ — CI profile (6 modułów, ~3 min), SARIF 2.1.0, GitHub Actions (reusable workflow + dispatch), 23 testów
- **MISP Integration** ✅ — bidirectional (import IOC + export findings), PyMISP, enterprise tier, 5 testów
- **Enrichment Badges** ✅ — KEV/EUVD/MISP/EPSS/ATT&CK per finding w scan_detail, dashboard, report
- **Shodan/URLhaus/GreyNoise** ✅ — 3 nowe intel sources (zero API key), 15 testów

### Zrealizowane – Sesja 26.02.2026
- **ExploitDB + MalwareBazaar** ✅ — 2 nowe intel sources (12 total), abuse.ch integration, 6 testów
- **CYRBER VERIFY v2-v4** ✅ — 14 OSINT źródeł, bidirectional scoring, edukacyjny AI raport, tabs UI redesign, narrative/problems/positives, 46 testów
- **Network Topology** ✅ — D3.js force-directed graph, build_topology() pure function, GET /api/scan/{task_id}/topology, 8 testów
- **Fix test_verify.py** ✅ — mockowanie generate_verdict() (Claude Haiku), 100 testów w 7s (zamiast hang)
- **Frontend 404 audit & fixes** ✅ — extract_cves() dict/None handling, ZAP healthcheck endpoint, /api/me→/auth/me w topology.html, /evilginx/lures→/api/evilginx/lures w phishing.html; pełny audit 27 fetch() paths z 11 plików HTML → 0 404-ek
- **Frontend Security Audit (XSS)** ✅ — pełny audyt bezpieczeństwa 12 plików HTML (2 sesje): ~22 bugi XSS naprawione (unescaped innerHTML, inline onclick→data-attrs, double-click guards); wzorce: escHtml() nie escapuje `'` w JS strings; 18 commitów security fix

### Must-have przed pierwszym pilotem
- ~~Claude Code Security scan własnego kodu~~ ✅ (frontend XSS audit — 12 plików, ~22 bugów naprawionych)
- Demo video (5 minut)
- NDA + kontrakt pentestingowy
- Landing page cyrber.pl (realizuje syn)

---

## 12. Model biznesowy

**Cel:** SMB (50–250 pracowników), sektor publiczny (NIS2/RODO), startupy.
**Nie target:** Enterprise €50k+
**Geograficznie:** Polska primary, EU secondary
**Pierwsza sprzedaż:** Sieć Energylogserver (warm leads)

**Ceny (jednorazowy pentest):**
- SZCZENIAK: €4 000
- STRAŻNIK: €7 500
- CERBER: €15 000+

**Ceny (CYRBER LOOP — subskrypcja):**
- LOOP Starter: €299/msc (1 target, tygodniowe skany)
- LOOP Professional: €699/msc (5 targetów, dzienne skany, auto-retest, integracje)
- LOOP Enterprise: €1 499/msc (unlimited, continuous, SLA 4h)

**Continuous Monitoring:** €999/msc (legacy, zastępowany przez LOOP)

**Finansowanie:** Bootstrap, próg rentowności po pierwszym projekcie.

---

## 13. Styl pracy z Michałem

- Pracuje z Claude Code (terminal) – daje prompty, wkleja outputy
- Oczekuje konkretnych, gotowych do wklejenia promptów dla Claude Code
- Nie lubi owijania w bawełnę – mów wprost
- Projekt traktuje poważnie – synowie to realny team, nie zabawa
- Dokumenty generuj jako .docx (profesjonalnie, bez śladów AI)
- Odpowiadaj po polsku
- Używaj 🐺 na końcu gdy temat jest zamknięty

---

## 14. Aktualny stan commitów

Ostatnie commity na master (stan 26.02.2026 → najnowsze na górze):
```
9912137 fix: escape d.risk in topology side panel innerHTML
91ea2e2 fix: XSS in admin.html — role badge, inline onclick, intel status
8da6471 fix: XSS in verify.html — inline onclick, unescaped icon and risk class
e9ec943 fix: XSS in osint.html — inline onclick replaced with data attributes
ef75a9a fix: XSS escaping + double-click guard in phishing.html
d35b37a fix: XSS escaping in dashboard.html — risk, malware_signature, module name
0b739c1 fix: scan_detail.html XSS escaping, delete double-click, dedupe auth/me
97e9d17 fix: index.html escape risk_level in recent scans innerHTML
957c057 fix: login.html double-submit guard on authenticate button
b80cc4b fix: topology.html add authFetch 401 handler, consistent nav, footer
aec8895 fix: admin.html add 401 handler to authFetch, double-click guards on modals
203ece2 fix: verify.html Enter key duplicate guard, XSS escaping for candidates & URLs
4936da8 fix: osint.html Enter key duplicate scan, PDF error handling, XSS escaping
d175061 fix: scheduler.html XSS escaping, double-click guard, null-safe, json catch
4f73436 fix: phishing.html AI generate double-send guard, XSS escaping, json catch
8d0a37b fix: scan_detail.html prevent AI chat double-send via Enter key
dca326d fix: dashboard.html KPI label CRITICAL FINDINGS → TOTAL FINDINGS
51726aa fix: index.html MODULE_LABELS sync with backend pipeline
2c99bb7 fix: phishing.html POST /evilginx/lures → /api/evilginx/lures
ea659ce fix: /api/me → /auth/me endpoint alignment in topology.html
57075e5 fix: ZAP healthcheck endpoint
409bfcf fix: extract_cves() handle dict/None items in sequence join
00364e0 feat: network topology + fix tests
6e94728 feat: certipy tests - 28 testów ESC1-ESC13
5e799c6 fix: verify_company - realistyczny flow dla PL firm
994531b feat: verify_company - wyszukiwanie po nazwie firmy
a3272ec fix: verify_company false positive - nuanced scoring
2c8c529 fix: URLhaus + MalwareBazaar Auth-Key authentication
5f9ca32 fix: CYRBER VERIFY - 3 bugi + false positive protection
0898c1b feat: CYRBER VERIFY v4 - edukacyjny raport AI
0b6a3de feat: CYRBER VERIFY v3 - redesign UI + zakładka RAPORT AI
3467fae feat: CYRBER VERIFY v2 - 7 nowych zrodel + bidirectional scoring
cbea0ed feat: CYRBER VERIFY live - ageotrans.eu PODEJRZANE 60/100
5d7541d feat: Evilginx2 integration - social engineering / MITM phishing
c932157 feat: MalwareBazaar integration
0b5e870 feat: ExploitDB integration
6eb8d80 feat: enrichment badges UI + MISP export
e31c387 feat: MISP integration
6ea40b7 feat: Pentest-as-Code CI/CD
4db4d8f feat: Design System dark/light theme
560b19c feat: Security Score Timeline UI
d9ca69c feat: Auto-retest - CYRBER LOOP krok 2
649ed45 feat: Intelligence Sync - KEV/NVD/EPSS enrichment
4ed42fe feat: Remediation Tracker - CYRBER LOOP krok 1
```

---

## 15. Projekty do analizy

### Sirius Scan (https://github.com/SiriusScan/Sirius)
Open-source vulnerability scanner, 978 gwiazdek, MIT, stack: Go + Next.js + RabbitMQ + PostgreSQL.

**Co warto zaadaptować do CYRBER:**
1. Remote Agents architektura - sirius-engine używa gRPC (port 50051) + RabbitMQ do komunikacji agent↔serwer.
   Inspiracja dla hardware head (Flipper Zero, WiFi Pineapple jako agenty raportujące do CYRBER).
   Plik do analizy: sirius-engine/

2. ~~Network topology visualization~~ — ✅ ZREALIZOWANE (sesja 26.02.2026) — D3.js force-directed graph, /topology

3. Visual workflow editor - drag-and-drop konfiguracja modułów.
   Rozważyć dla enterprise tier jako alternatywa dla poziomów Szczeniak/Strażnik/Cerber.

**Czego NIE brać:**
- Stack Go - przepisywanie backendu bez sensu
- RabbitMQ zamiast Redis/Celery - mamy działający system

**Priorytet analizy:** średni, przy sprincie hardware head

---

## 16. Hardware Head — architektura (zaplanowana)

**Wzorzec:** cyrber-hw-bridge (Python daemon na laptopie operatora)

**Urządzenia:**
- **WiFi Pineapple** — REST API port 1471, OpenWRT/ARM
- **Flipper Zero** — USB serial (`/dev/ttyACM0`) lub BLE, pyserial

**Jak działa:**
- Bridge rejestruje się w CYRBER jako hardware agent z UUID
- Wyniki trafiają przez istniejące endpointy API do Redis/Celery

**Referencja:** SiriusScan/app-agent (gRPC wzorzec, MIT) — https://github.com/SiriusScan/app-agent
NIE kopiować stack Go/gRPC, zaadaptować KONCEPT modułowego agenta w Pythonie.

**Priorytet:** sprint po social engineering (Evilginx2)

---

*Transfer prompt zaktualizowany: 26 luty 2026 (po frontend security audit — 80 modułów, 176 endpointów, 278 testów, 12 stron HTML)*
