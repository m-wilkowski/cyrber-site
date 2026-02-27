"""GoPhish proxy + phishing email generation."""

from fastapi import APIRouter, Depends, HTTPException, Request
import os
import json
import requests as http_requests

from backend.deps import limiter, get_current_user, require_role, audit
from backend.schemas import PhishingCampaignCreate, PhishingEmailGenerate

router = APIRouter(tags=["phishing"])

# ── GoPhish config ──
GOPHISH_URL = os.getenv("GOPHISH_URL", "http://gophish:3333")
GOPHISH_API_KEY = os.getenv("GOPHISH_API_KEY", "")


def _gophish_headers():
    return {"Authorization": f"Bearer {GOPHISH_API_KEY}", "Content-Type": "application/json"}


def _gophish_get(path: str):
    r = http_requests.get(f"{GOPHISH_URL}/api/{path}", headers=_gophish_headers(), timeout=15, verify=False)
    r.raise_for_status()
    return r.json()


def _gophish_post(path: str, data: dict):
    r = http_requests.post(f"{GOPHISH_URL}/api/{path}", headers=_gophish_headers(), json=data, timeout=15, verify=False)
    r.raise_for_status()
    return r.json()


def _gophish_delete(path: str):
    r = http_requests.delete(f"{GOPHISH_URL}/api/{path}", headers=_gophish_headers(), timeout=15, verify=False)
    r.raise_for_status()
    return r.json() if r.text else {"status": "deleted"}


@router.get("/phishing/campaigns")
async def phishing_campaigns(user: dict = Depends(get_current_user)):
    try:
        campaigns = _gophish_get("campaigns/")
        result = []
        for c in campaigns:
            stats = c.get("stats", {}) or {}
            result.append({
                "id": c.get("id"),
                "name": c.get("name", ""),
                "status": c.get("status", ""),
                "created_date": c.get("created_date", ""),
                "stats": {
                    "sent": stats.get("sent", 0),
                    "opened": stats.get("opened", 0),
                    "clicked": stats.get("clicked", 0),
                    "submitted_data": stats.get("submitted_data", 0),
                    "error": stats.get("error", 0),
                    "total": stats.get("total", 0),
                },
            })
        return result
    except http_requests.ConnectionError:
        raise HTTPException(status_code=503, detail="GoPhish not available — start with: docker compose --profile phishing up -d")
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/phishing/generate-email")
@limiter.limit("10/minute")
async def phishing_generate_email(
    request: Request,
    data: PhishingEmailGenerate,
    user: dict = Depends(require_role("admin", "operator")),
):
    try:
        from modules.llm_provider import get_provider
        provider = get_provider(task="phishing_email")

        techs_str = ", ".join(data.technologies[:15]) if data.technologies else "brak danych"
        vulns_str = ", ".join(data.vulnerabilities[:10]) if data.vulnerabilities else "brak danych"
        emails_str = ", ".join(data.emails[:10]) if data.emails else "brak danych"

        prompt = f"""Jesteś ekspertem od security awareness testing. Wygeneruj realistyczny email phishingowy (do celów autoryzowanego testu penetracyjnego) na podstawie danych rekonesansu.

DANE REKONESANSU:
- Cel: {data.target}
- Poziom ryzyka: {data.risk_level} (score: {data.risk_score}/100)
- Technologie: {techs_str}
- Znalezione emaile: {emails_str}
- Podatności: {vulns_str}
- Podsumowanie: {data.executive_summary[:500] if data.executive_summary else 'brak'}

WYMAGANIA:
- Język: {"polski" if data.language == "pl" else data.language}
- Email musi być przekonujący i dopasowany do kontekstu technologicznego celu
- Body w HTML, użyj {{{{.URL}}}} jako placeholder na link GoPhish
- Zwróć TYLKO JSON (bez markdown):

{{"subject": "temat emaila", "body": "<p>treść HTML z linkiem <a href=\\"{{{{.URL}}}}\\">kliknij</a></p>", "pretext": "krótki opis pretekstu użytego w emailu"}}"""

        response_text = provider.chat(prompt, max_tokens=1500)

        clean = response_text.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        try:
            result = json.loads(clean.strip())
        except json.JSONDecodeError:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            result = json.loads(response_text[start:end])

        audit(request, user, "phishing_generate_email", data.target)
        return {"status": "ok", "provider": provider.name, **result}

    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse LLM response as JSON: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email generation failed: {str(e)}")


@router.post("/phishing/campaigns")
async def phishing_create_campaign(
    request: Request,
    campaign: PhishingCampaignCreate,
    user: dict = Depends(require_role("admin", "operator")),
):
    try:
        smtp_name = f"CYRBER-{campaign.domain}"
        try:
            profiles = _gophish_get("smtp/")
            profile = next((p for p in profiles if p["name"] == smtp_name), None)
        except Exception:
            profile = None

        if not profile:
            profile = _gophish_post("smtp/", {
                "name": smtp_name,
                "host": f"{campaign.domain}:25",
                "from_address": f"security@{campaign.domain}",
                "ignore_cert_errors": True,
            })
        smtp_id = profile["id"]

        tmpl_name = f"CYRBER-{campaign.name}"
        template = _gophish_post("templates/", {
            "name": tmpl_name,
            "subject": campaign.subject,
            "html": campaign.email_body,
        })
        tmpl_id = template["id"]

        page_id = None
        if campaign.landing_url:
            page_name = f"CYRBER-LP-{campaign.name}"
            page = _gophish_post("pages/", {
                "name": page_name,
                "capture_credentials": True,
                "capture_passwords": True,
                "redirect_url": "",
                "html": f'<html><body><script>window.location="{campaign.landing_url}";</script></body></html>',
            })
            page_id = page["id"]

        group_name = f"CYRBER-{campaign.name}-targets"
        targets_list = [
            {"first_name": "", "last_name": "", "email": email, "position": ""}
            for email in campaign.targets
        ]
        group = _gophish_post("groups/", {
            "name": group_name,
            "targets": targets_list,
        })
        group_id = group["id"]

        camp_payload = {
            "name": campaign.name,
            "template": {"id": tmpl_id},
            "smtp": {"id": smtp_id},
            "groups": [{"id": group_id}],
            "launch_date": "2000-01-01T00:00:00Z",
        }
        if page_id:
            camp_payload["page"] = {"id": page_id}
        else:
            fallback_page = _gophish_post("pages/", {
                "name": f"CYRBER-blank-{campaign.name}",
                "html": "<html><body>Thank you.</body></html>",
                "capture_credentials": False,
            })
            camp_payload["page"] = {"id": fallback_page["id"]}

        result = _gophish_post("campaigns/", camp_payload)
        audit(request, user, "phishing_create", campaign.name)
        return {"id": result.get("id"), "name": result.get("name"), "status": result.get("status")}

    except http_requests.ConnectionError:
        raise HTTPException(status_code=503, detail="GoPhish not available")
    except http_requests.HTTPError as e:
        detail = e.response.text if e.response else str(e)
        raise HTTPException(status_code=502, detail=f"GoPhish error: {detail}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/phishing/campaigns/{campaign_id}")
async def phishing_delete_campaign(
    request: Request,
    campaign_id: int,
    user: dict = Depends(require_role("admin", "operator")),
):
    try:
        result = _gophish_delete(f"campaigns/{campaign_id}")
        audit(request, user, "phishing_delete", str(campaign_id))
        return result
    except http_requests.ConnectionError:
        raise HTTPException(status_code=503, detail="GoPhish not available")
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@router.get("/phishing/campaigns/{campaign_id}/results")
async def phishing_campaign_results(campaign_id: int, user: dict = Depends(get_current_user)):
    try:
        campaign = _gophish_get(f"campaigns/{campaign_id}")
        results = campaign.get("results", [])
        timeline = campaign.get("timeline", [])
        stats = campaign.get("stats", {}) or {}

        events = []
        for ev in timeline:
            events.append({
                "email": ev.get("email", ""),
                "message": ev.get("message", ""),
                "time": ev.get("time", ""),
            })

        return {
            "campaign_id": campaign_id,
            "name": campaign.get("name", ""),
            "status": campaign.get("status", ""),
            "stats": {
                "total": stats.get("total", len(results)),
                "sent": stats.get("sent", 0),
                "opened": stats.get("opened", 0),
                "clicked": stats.get("clicked", 0),
                "submitted_data": stats.get("submitted_data", 0),
                "error": stats.get("error", 0),
            },
            "events": events,
        }
    except http_requests.ConnectionError:
        raise HTTPException(status_code=503, detail="GoPhish not available")
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
