"""
CyrberLLM — multi-provider LLM router with fallback chain.

Uses LiteLLM as the abstraction layer so swapping models requires
only a config change (config/llm_config.yaml), not code changes.

Fallback chain: Anthropic → OpenAI → DeepSeek → Ollama
Special case: task_type="airgap" → ONLY Ollama (no external API calls).

Usage:
    from modules.llm_router import cyrber_llm
    result = cyrber_llm.complete("Analyze this scan", task_type="analysis")
"""

import os
import logging
import pathlib
import time

log = logging.getLogger("cyrber_llm")

_CONFIG_PATHS = [
    pathlib.Path(__file__).resolve().parent.parent / "config" / "llm_config.yaml",
    pathlib.Path("/app/config/llm_config.yaml"),
]


def _load_config() -> dict:
    """Load config/llm_config.yaml, return empty dict on failure."""
    for path in _CONFIG_PATHS:
        if path.is_file():
            try:
                import yaml
                with open(path) as f:
                    return yaml.safe_load(f) or {}
            except Exception as exc:
                log.warning("[CyrberLLM] failed to load %s: %s", path, exc)
    return {}


class CyrberLLM:
    """Multi-provider LLM router with automatic fallback."""

    def __init__(self, config: dict | None = None):
        self._config = config if config is not None else _load_config()
        self._providers_cfg = self._config.get("providers", {})
        self._task_routing = self._config.get("task_routing", {})

    def _get_provider_chain(self, task_type: str | None = None) -> list[dict]:
        """Return ordered list of provider configs to try.

        For airgap tasks, only Ollama is returned.
        Otherwise, enabled providers sorted by priority (ascending).
        """
        tier = self._task_routing.get(task_type, "analysis") if task_type else "analysis"

        if tier == "airgap":
            ollama_cfg = self._providers_cfg.get("ollama")
            if ollama_cfg:
                return [{"name": "ollama", **ollama_cfg}]
            return []

        chain = []
        for name, cfg in self._providers_cfg.items():
            if not cfg.get("enabled", False):
                continue
            chain.append({"name": name, **cfg})

        chain.sort(key=lambda p: p.get("priority", 99))
        return chain

    def _resolve_model(self, task_type: str | None, provider_name: str) -> str:
        """Map task_type → tier → concrete model for given provider."""
        tier = self._task_routing.get(task_type, "analysis") if task_type else "analysis"
        if tier == "airgap":
            tier = "reasoning"

        provider_cfg = self._providers_cfg.get(provider_name, {})
        models = provider_cfg.get("models", {})
        return models.get(tier, models.get("analysis", "claude-sonnet-4-20250514"))

    def _provider_available(self, provider_cfg: dict) -> bool:
        """Check if a provider has the required credentials."""
        name = provider_cfg.get("name", "")

        if name == "ollama":
            return True  # local, no API key needed

        api_key_env = provider_cfg.get("api_key_env")
        if api_key_env:
            return bool(os.getenv(api_key_env))

        return True

    def _get_org_llm_settings(self, org_id: int) -> dict | None:
        """Load LLM settings for organization from DB.

        Returns dict with llm_mode, preferred_provider, ollama_base_url
        or None if org not found or DB unavailable.
        """
        try:
            from modules.database import SessionLocal
            from modules.organizations import Organization
            db = SessionLocal()
            try:
                org = db.query(Organization).filter(
                    Organization.id == org_id
                ).first()
                if not org:
                    return None
                return {
                    "llm_mode": org.llm_mode or "cloud",
                    "preferred_provider": org.preferred_provider or "anthropic",
                    "ollama_base_url": org.ollama_base_url,
                }
            finally:
                db.close()
        except Exception as exc:
            log.warning("[CyrberLLM] failed to load org %s settings: %s", org_id, exc)
            return None

    def _get_org_provider_chain(self, org_settings: dict, task_type: str | None = None) -> list[dict]:
        """Build provider chain respecting org-level LLM settings.

        - local/airgap: only Ollama (with optional custom base_url)
        - cloud: preferred provider first, then normal fallback chain
        """
        llm_mode = org_settings.get("llm_mode", "cloud")

        if llm_mode in ("local", "airgap"):
            # Only Ollama — no external API calls
            ollama_cfg = dict(self._providers_cfg.get("ollama", {}))
            ollama_cfg["name"] = "ollama"
            # Override base_url if org has custom one
            custom_url = org_settings.get("ollama_base_url")
            if custom_url:
                ollama_cfg["base_url"] = custom_url
            ollama_cfg["enabled"] = True
            return [ollama_cfg]

        # Cloud mode: reorder to put preferred_provider first
        preferred = org_settings.get("preferred_provider", "anthropic")
        chain = self._get_provider_chain(task_type)

        # Move preferred to front
        preferred_entries = [p for p in chain if p["name"] == preferred]
        other_entries = [p for p in chain if p["name"] != preferred]
        return preferred_entries + other_entries

    def complete(
        self,
        prompt: str,
        system: str | None = None,
        task_type: str | None = None,
        max_tokens: int = 1024,
        temperature: float | None = None,
        org_id: int | None = None,
    ) -> str:
        """Execute LLM completion with automatic fallback chain.

        Args:
            prompt: User prompt text.
            system: Optional system prompt.
            task_type: Task identifier for routing (e.g., "mens", "classify").
            max_tokens: Max output tokens.
            temperature: Optional temperature override.
            org_id: Organization ID for per-org routing. If provided,
                    org's llm_mode/preferred_provider override global config.

        Returns:
            Response text from the first successful provider.

        Raises:
            RuntimeError: If all providers in the chain fail.
        """
        import litellm

        # Per-org routing: load org settings and build custom chain
        org_settings = None
        if org_id:
            org_settings = self._get_org_llm_settings(org_id)

        if org_settings:
            chain = self._get_org_provider_chain(org_settings, task_type)
            log.info(
                "[CyrberLLM] org=%d mode=%s preferred=%s chain=%s",
                org_id, org_settings["llm_mode"],
                org_settings["preferred_provider"],
                [p["name"] for p in chain],
            )
        else:
            chain = self._get_provider_chain(task_type)

        if not chain:
            raise RuntimeError(
                f"[CyrberLLM] no providers available for task_type={task_type}"
            )

        errors = []
        for provider_cfg in chain:
            name = provider_cfg["name"]
            if not self._provider_available(provider_cfg):
                log.debug("[CyrberLLM] skipping %s — no API key", name)
                continue

            model = self._resolve_model(task_type, name)

            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            kwargs: dict = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
            }

            if temperature is not None:
                kwargs["temperature"] = temperature

            # Ollama needs api_base
            base_url = provider_cfg.get("base_url")
            if base_url:
                kwargs["api_base"] = base_url

            # Set API key from env for litellm
            api_key_env = provider_cfg.get("api_key_env")
            if api_key_env:
                api_key = os.getenv(api_key_env)
                if api_key:
                    kwargs["api_key"] = api_key

            start = time.monotonic()
            try:
                log.info(
                    "[CyrberLLM] calling %s model=%s task=%s",
                    name, model, task_type,
                )
                response = litellm.completion(**kwargs)
                elapsed = time.monotonic() - start
                text = response.choices[0].message.content or ""
                log.info(
                    "[CyrberLLM] %s responded in %.1fs (%d chars)",
                    name, elapsed, len(text),
                )
                return text
            except Exception as exc:
                elapsed = time.monotonic() - start
                log.warning(
                    "[CyrberLLM] %s failed after %.1fs: %s",
                    name, elapsed, exc,
                )
                errors.append(f"{name}: {exc}")

        raise RuntimeError(
            f"[CyrberLLM] all providers failed for task_type={task_type}: "
            + "; ".join(errors)
        )

    def complete_sync(self, prompt: str, **kwargs) -> str:
        """Alias for complete() — litellm.completion is synchronous."""
        return self.complete(prompt, **kwargs)

    def get_active_providers(self) -> dict:
        """Return status dict for each configured provider."""
        result = {}
        for name, cfg in self._providers_cfg.items():
            available = self._provider_available({"name": name, **cfg})
            result[name] = {
                "enabled": cfg.get("enabled", False),
                "available": available,
                "priority": cfg.get("priority", 99),
                "models": cfg.get("models", {}),
            }
            if name == "ollama":
                result[name]["base_url"] = cfg.get("base_url", "")
        return result

    def test_provider(
        self,
        provider_name: str,
        prompt: str = "Say 'hello' in one word.",
        org_id: int | None = None,
    ) -> dict:
        """Test a specific provider and return response + latency.

        If org_id is provided and provider is 'ollama', uses org's
        custom ollama_base_url if set.
        """
        import litellm

        cfg = self._providers_cfg.get(provider_name)
        if not cfg:
            return {"error": f"unknown provider: {provider_name}"}

        if not cfg.get("enabled", False):
            return {"error": f"provider {provider_name} is disabled"}

        pcfg = {"name": provider_name, **cfg}
        if not self._provider_available(pcfg):
            return {"error": f"provider {provider_name} has no API key"}

        models = cfg.get("models", {})
        model = models.get("fast", models.get("analysis", ""))

        kwargs: dict = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 50,
        }

        base_url = cfg.get("base_url")
        # Override base_url with org-specific Ollama URL
        if org_id and provider_name == "ollama":
            org_settings = self._get_org_llm_settings(org_id)
            if org_settings and org_settings.get("ollama_base_url"):
                base_url = org_settings["ollama_base_url"]
        if base_url:
            kwargs["api_base"] = base_url

        api_key_env = cfg.get("api_key_env")
        if api_key_env:
            api_key = os.getenv(api_key_env)
            if api_key:
                kwargs["api_key"] = api_key

        start = time.monotonic()
        try:
            response = litellm.completion(**kwargs)
            elapsed = time.monotonic() - start
            text = response.choices[0].message.content or ""
            return {
                "provider": provider_name,
                "model": model,
                "response": text.strip(),
                "latency_ms": round(elapsed * 1000),
            }
        except Exception as exc:
            elapsed = time.monotonic() - start
            return {
                "provider": provider_name,
                "model": model,
                "error": str(exc),
                "latency_ms": round(elapsed * 1000),
            }


# ── Singleton ────────────────────────────────────────────────
cyrber_llm = CyrberLLM()
