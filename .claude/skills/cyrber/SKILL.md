# CYRBER Platform — Agent Skill

## Kiedy używać tego skilla
Używaj zawsze gdy pracujesz nad projektem CYRBER (~/cyrber/), piszesz kod do modułów skanujących, backendu FastAPI, frontendu, testów jednostkowych lub dokumentacji platformy.

---

## Opis projektu

CYRBER to autonomiczna platforma security reconnaissance łącząca AI, hardware i ludzką ekspertyzę do testów penetracyjnych. Architektura "trzy głowy Cerberusa": AI (70%) + Human (20%) + Hardware (10%).

**Właściciel:** Michał Wilkowski (presales/pentester, Energylogserver)  
**Stack:** Python 3.12+, FastAPI, Celery, Redis, PostgreSQL 16, Docker Compose  
**AI:** Claude Opus 4 (primary), Ollama llama3.2 (fallback)  
**Lokalizacja:** ~/cyrber/ na Fedora Linux  
**Remote:** master branch, git push origin master

---

## Struktura projektu

```
~/cyrber/
├── backend/
│   └── main.py              # FastAPI app, wszystkie endpointy, JWT auth
├── modules/
│   ├── tasks.py             # Celery tasks, full_scan_task(), publish_progress()
│   ├── ai_analysis.py       # ContextManager, analyze_scan_results(), reflect_on_scan()
│   ├── exploit_chains.py    # generate_exploit_chains() z confidence score
│   ├── hacker_narrative.py  # generowanie narracji hakerskiej
│   ├── false_positive_filter.py
│   ├── llm_provider.py      # get_provider(task=), YAML model routing
│   ├── evilginx.py          # SQLite reader dla Evilginx2
│   ├── rag_knowledge.py     # RAG/FAISS z PayloadsAllTheThings
│   └── database.py          # SQLAlchemy models: Scan, AuditLog, Schedule
├── config/
│   └── models.yaml          # task → model mapping (Opus/Sonnet/Haiku)
├── static/
│   ├── index.html           # główny UI (~5000 linii, dark cyberpunk)
│   ├── phishing.html        # Phishing Campaign Wizard (4 kroki)
│   ├── dashboard.html
│   ├── scheduler.html
│   └── osint.html
├── tests/
│   ├── test_context_manager.py   # 29 testów
│   └── test_evilginx.py          # 40 testów
├── knowledge_base/
│   └── PayloadsAllTheThings/     # RAG knowledge base
├── docker-compose.yml
└── requirements.txt
```

---

## Docker Compose — serwisy

| Serwis | Port | Opis |
|--------|------|------|
| api | 8000 | FastAPI (uvicorn) |
| worker | — | Celery worker |
| beat | — | Celery beat (scheduler) |
| db | 5432 | PostgreSQL 16 |
| redis | 6379 | Redis (broker + pub/sub) |
| zap | 8090 | OWASP ZAP (unhealthy OK) |
| dvwa | 8888 | DVWA (target testowy) |
| gophish | 3333/8080 | GoPhish |
| evilginx | 443/80/53 | Evilginx2 (profile: phishing) |

**Restart po zmianach:**
```bash
docker compose restart api worker
docker cp static/index.html cyrber-api-1:/app/static/index.html  # szybki update UI
```

---

## Model routing (config/models.yaml)

| Task | Model |
|------|-------|
| exploit_chains, hacker_narrative | claude-opus-4-20250514 |
| ai_analysis, agent | claude-sonnet-4-20250514 |
| false_positive_filter, llm_analyze, phishing_email | claude-haiku-4-5-20251001 |

Wywołanie: `get_provider(task="exploit_chains")`

---

## Profile skanowania

| Profil | Moduły | Cena |
|--------|--------|------|
| SZCZENIAK | 12 podstawowych | €4,000 |
| STRAZNIK | 34 (default) | €7,500 |
| CERBER | 45+ wszystkie | €15,000+ |

---

## Kluczowe wzorce kodu

### publish_progress (tasks.py)
```python
publish_progress(task_id, "nmap", "started", completed, total)
# ... wykonanie modułu ...
publish_progress(task_id, "nmap", "done", completed + 1, total)
completed += 1
```

### Nowy moduł skanujący
```python
def run_nowy_modul(target: str) -> dict:
    try:
        # logika
        return {"findings": [...], "count": n}
    except Exception as e:
        return {"error": str(e), "findings": []}
```

### Nowy endpoint FastAPI
```python
@app.get("/nowy-endpoint")
async def nowy_endpoint(current_user=Depends(get_current_user)):
    # logika
    return {"result": ...}
```

### Nigdy nie blokuj skanu
```python
try:
    result["nowy_modul"] = reflect_on_scan(...)
except Exception:
    pass  # nigdy nie zatrzymuj głównego flow
```

---

## UI — zasady (static/index.html)

**Paleta kolorów:**
- Tło: `#0a0a0f` (główne), `#111118` (karty)
- Akcent: `#00ff88` (zielony neon — primary)
- Alert: `#ff4444` (czerwony), `#ff8800` (pomarańczowy)
- Tekst: `#e0e0e0` (główny), `#888` (secondary)

**Wzorzec karty:**
```css
border-left: 3px solid #00ff88;
background: rgba(0, 255, 136, 0.05);
border-radius: 4px;
padding: 12px 16px;
```

**Badges severity:**
- CRITICAL: `rgba(255,68,68,0.2)` + border `rgba(255,68,68,0.4)`
- HIGH: `rgba(255,136,0,0.2)` + border `rgba(255,136,0,0.4)`
- MEDIUM: `rgba(255,204,0,0.2)` + border `rgba(255,204,0,0.4)`
- LOW: `rgba(0,136,255,0.2)` + border `rgba(0,136,255,0.4)`

**Auth w fetchach:** zawsze `authFetch()` zamiast `fetch()` (dodaje JWT header)

---

## Auth

- Basic Auth: `admin:cyrber2024` (legacy, niektóre endpointy)
- JWT: `POST /auth/login` → token w localStorage/sessionStorage
- SSE: token jako query param `?token=JWT` (SSE nie obsługuje headers)

---

## SSE Streaming

Każdy moduł w tasks.py wysyła eventy przez Redis pub/sub:
```python
publish_progress(task_id, module_name, "started"|"done"|"error"|"skipped", completed, total)
```
Frontend łączy się przez `connectSSE(taskId)` z fallbackiem na `pollStatus()`.

---

## Confidence Score (exploit chains)

Każdy krok exploit chain ma pole `confidence: 0.0-1.0`:
- `>= 0.8` → badge CONFIRMED (zielony)
- `0.5-0.79` → badge LIKELY (żółty)  
- `< 0.5` → badge THEORETICAL (szary)

---

## Reflector pattern

Po każdym skanie `reflect_on_scan(scan_results, profile)` klasyfikuje moduły:
`ok | empty | error | missing` i generuje rekomendacje dla następnego skanu.
Wynik trafia do `result["reflection"]` w raw_data JSON.

---

## Testy

```bash
docker exec cyrber-api-1 python -m pytest tests/ -v
# lub pojedynczy plik:
docker exec cyrber-api-1 python -m pytest tests/test_evilginx.py -v
```

Każdy nowy moduł powinien mieć testy jednostkowe w `tests/test_<moduł>.py`.

---

## Commit convention

```bash
git add <pliki>
git commit -m "typ: krótki opis po polsku"
git push origin master
```

Typy: `feat` / `fix` / `docs` / `test` / `refactor`

Po każdym milestone: zaktualizuj `CYRBER_Transfer_Prompt.md` i zsynchronizuj `~/Downloads/CYRBER_Transfer_Prompt.md`.

---

## Backlog (Top priorytety)

1. RAG z PayloadsAllTheThings (FAISS) — w toku
2. Shannon integration (white-box web pentesting, profil CERBER)
3. Reflector pattern ✅
4. Confidence score exploit chains ✅
5. SSE streaming ✅
6. Exiftool (OSINT/awareness)
7. BeEF-XSS, SET (social engineering)
8. Certipy (AD CS, dopełnienie BloodHound)

---

## Ważne — nigdy nie rób

- Nie commituj API keys, haseł, tokenów
- Nie używaj `fetch()` w UI zamiast `authFetch()`
- Nie blokuj głównego flow skanu przez moduł pomocniczy
- Nie używaj hard-coded slicing `[:40]` zamiast ContextManager
- Nie modyfikuj bez potrzeby istniejących testów
