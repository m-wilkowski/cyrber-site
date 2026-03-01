"""LLM provider status and test API."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.deps import get_current_user, require_role

router = APIRouter(prefix="/api/llm", tags=["llm"])


# ── Schemas ──────────────────────────────────────────────────

class LLMTestRequest(BaseModel):
    provider: str
    prompt: str = "Say 'hello' in one word."
    org_id: Optional[int] = None


# ── Endpoints ────────────────────────────────────────────────

@router.get("/status")
def llm_status(
    org_id: Optional[int] = None,
    user: dict = Depends(get_current_user),
):
    """Return status of all configured LLM providers.

    If org_id is provided, also returns org-specific LLM settings.
    """
    from modules.llm_router import cyrber_llm

    providers = cyrber_llm.get_active_providers()
    # Find default (first enabled + available)
    default = None
    for name, info in sorted(providers.items(), key=lambda x: x[1]["priority"]):
        if info["enabled"] and info["available"]:
            default = name
            break

    result = {
        "providers": providers,
        "default": default,
    }

    if org_id:
        org_settings = cyrber_llm._get_org_llm_settings(org_id)
        if org_settings:
            result["org_settings"] = org_settings

    return result


@router.post("/test")
def llm_test(
    body: LLMTestRequest,
    user: dict = Depends(require_role("admin", "operator")),
):
    """Test a specific LLM provider with a prompt. Admin/operator only."""
    from modules.llm_router import cyrber_llm

    result = cyrber_llm.test_provider(body.provider, body.prompt, org_id=body.org_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result
