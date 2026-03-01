"""CYRBER VERIFY + AI explain finding."""

from fastapi import APIRouter, Depends, HTTPException, Request
import json

from backend.deps import (
    limiter, get_current_user, require_role, audit, REDIS_URL, _logger,
)
from backend.schemas import VerifyRequest, ExplainFindingRequest

router = APIRouter(tags=["verify"])


@router.post("/api/verify")
@limiter.limit("10/minute")
async def api_verify(
    request: Request,
    body: VerifyRequest,
    user: dict = Depends(require_role("admin", "operator")),
):
    import redis.asyncio as aioredis

    query = body.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query is required")

    from modules.verify import CyrberVerify, detect_query_type
    qtype = body.type.lower()
    if qtype == "auto":
        qtype = detect_query_type(query)

    country = body.country.upper()
    if country == "AUTO":
        country = "PL"

    # Redis cache (1h)
    cache_key = f"verify:{qtype}:{query}".replace(" ", "_").lower()
    try:
        async with aioredis.from_url(REDIS_URL) as r:
            cached = await r.get(cache_key)
            if cached:
                return json.loads(cached)
    except Exception:
        pass

    v = CyrberVerify()
    try:
        if qtype == "url":
            result = v.verify_url(query)
        elif qtype == "email":
            result = v.verify_email(query)
        elif qtype == "company":
            result = v.verify_company(query, country=country)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown type: {qtype}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Verification failed: {str(exc)}")

    # Save to DB
    try:
        from modules.database import save_verify_result
        result["id"] = save_verify_result(result, created_by=user.get("username", "unknown"))
    except Exception as exc:
        _logger.warning(f"Failed to save verify result: {exc}")

    # Cache in Redis (1h)
    try:
        async with aioredis.from_url(REDIS_URL) as r:
            await r.setex(cache_key, 3600, json.dumps(result, ensure_ascii=False, default=str))
    except Exception:
        pass

    audit(request, user, "verify", f"{qtype}:{query}")
    return result


@router.get("/api/verify/history")
async def api_verify_history(user: dict = Depends(require_role("admin", "operator"))):
    from modules.database import get_verify_history
    return get_verify_history(limit=50)


@router.get("/api/verify/{result_id}")
async def api_verify_get(result_id: int, user: dict = Depends(require_role("admin", "operator"))):
    from modules.database import get_verify_result_by_id
    result = get_verify_result_by_id(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Verify result not found")
    return result


# ── AI Explain Finding ──

@router.post("/api/explain-finding")
@limiter.limit("20/minute")
async def explain_finding(
    request: Request,
    body: ExplainFindingRequest,
    user: dict = Depends(get_current_user),
):
    import redis.asyncio as aioredis

    cache_key = f"explain:{body.finding_name}:{body.severity}".replace(" ", "_")

    try:
        async with aioredis.from_url(REDIS_URL) as r:
            cached = await r.get(cache_key)
            if cached:
                return json.loads(cached)
    except Exception:
        pass

    from modules.llm_provider import get_provider
    prompt = (
        "You are a cybersecurity expert. Explain this finding to a business owner "
        "in plain English, without technical jargon.\n\n"
        f"Finding: {body.finding_name}\n"
        f"Description: {body.finding_description}\n"
        f"Target: {body.target}\n"
        f"Severity: {body.severity}\n\n"
        "Respond EXACTLY in JSON format (no markdown):\n"
        '{"explanation": "What this is - 2-3 sentences", '
        '"risk": "Business impact - 2-3 sentences", '
        '"fix": "How to fix it - 2-3 sentences"}'
    )
    try:
        provider = get_provider(task="classify")
        response_text = provider.chat(prompt, max_tokens=600)
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

        try:
            async with aioredis.from_url(REDIS_URL) as r:
                await r.setex(cache_key, 86400, json.dumps(result, ensure_ascii=False))
        except Exception:
            pass

        return result
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI explain failed: {str(e)}")
