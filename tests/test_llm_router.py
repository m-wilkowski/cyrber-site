"""Tests for CyrberLLM router and LiteLLMProvider."""

import os
import sys
import importlib
from unittest.mock import patch, MagicMock
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _real_llm_provider():
    """Force-reload modules.llm_provider in case test_mens mocked it."""
    mod_name = "modules.llm_provider"
    if mod_name in sys.modules and isinstance(sys.modules[mod_name], MagicMock):
        del sys.modules[mod_name]
    import modules.llm_provider
    importlib.reload(modules.llm_provider)
    return modules.llm_provider


# ── CyrberLLM unit tests ────────────────────────────────────

_TEST_CONFIG = {
    "providers": {
        "anthropic": {
            "enabled": True,
            "models": {
                "reasoning": "claude-opus-4-5",
                "analysis": "claude-sonnet-4-20250514",
                "fast": "claude-haiku-4-5-20251001",
            },
            "api_key_env": "ANTHROPIC_API_KEY",
            "priority": 1,
        },
        "openai": {
            "enabled": False,
            "models": {
                "reasoning": "gpt-4o",
                "analysis": "gpt-4o",
                "fast": "gpt-4o-mini",
            },
            "api_key_env": "OPENAI_API_KEY",
            "priority": 2,
        },
        "ollama": {
            "enabled": True,
            "models": {
                "reasoning": "ollama/dolphin3",
                "analysis": "ollama/dolphin3",
                "fast": "ollama/dolphin3",
            },
            "base_url": "http://ollama:11434",
            "priority": 4,
        },
    },
    "task_routing": {
        "mens": "reasoning",
        "reasoning": "reasoning",
        "analysis": "analysis",
        "ai_analysis": "analysis",
        "classify": "fast",
        "summary": "fast",
        "airgap": "airgap",
    },
}


def _make_llm(config=None):
    from modules.llm_router import CyrberLLM
    return CyrberLLM(config=config or _TEST_CONFIG)


def _mock_response(text="hello"):
    """Create a mock litellm completion response."""
    msg = MagicMock()
    msg.content = text
    choice = MagicMock()
    choice.message = msg
    resp = MagicMock()
    resp.choices = [choice]
    return resp


# ── Task routing tests ───────────────────────────────────────

class TestTaskRouting:

    def test_reasoning_task_resolves_to_opus(self):
        llm = _make_llm()
        model = llm._resolve_model("mens", "anthropic")
        assert "opus" in model.lower()

    def test_analysis_task_resolves_to_sonnet(self):
        llm = _make_llm()
        model = llm._resolve_model("ai_analysis", "anthropic")
        assert "sonnet" in model.lower()

    def test_fast_task_resolves_to_haiku(self):
        llm = _make_llm()
        model = llm._resolve_model("classify", "anthropic")
        assert "haiku" in model.lower()

    def test_unknown_task_defaults_to_analysis(self):
        llm = _make_llm()
        model = llm._resolve_model("unknown_task", "anthropic")
        assert "sonnet" in model.lower()

    def test_airgap_only_returns_ollama(self):
        llm = _make_llm()
        chain = llm._get_provider_chain("airgap")
        assert len(chain) == 1
        assert chain[0]["name"] == "ollama"


# ── Provider chain tests ─────────────────────────────────────

class TestProviderChain:

    def test_disabled_provider_excluded(self):
        llm = _make_llm()
        chain = llm._get_provider_chain("analysis")
        names = [p["name"] for p in chain]
        assert "openai" not in names

    def test_chain_sorted_by_priority(self):
        llm = _make_llm()
        chain = llm._get_provider_chain("analysis")
        priorities = [p.get("priority", 99) for p in chain]
        assert priorities == sorted(priorities)

    def test_enabled_providers_in_chain(self):
        llm = _make_llm()
        chain = llm._get_provider_chain("analysis")
        names = [p["name"] for p in chain]
        assert "anthropic" in names
        assert "ollama" in names


# ── Fallback tests ───────────────────────────────────────────

class TestFallback:

    @patch("litellm.completion")
    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"})
    def test_complete_returns_string(self, mock_comp):
        mock_comp.return_value = _mock_response("test response")
        llm = _make_llm()
        result = llm.complete("Hello", task_type="classify")
        assert result == "test response"
        mock_comp.assert_called_once()

    @patch("litellm.completion")
    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"})
    def test_system_prompt_passed(self, mock_comp):
        mock_comp.return_value = _mock_response("ok")
        llm = _make_llm()
        llm.complete("Hello", system="Be brief", task_type="classify")
        call_kwargs = mock_comp.call_args[1]
        messages = call_kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "Be brief"

    @patch("litellm.completion")
    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"})
    def test_fallback_on_primary_failure(self, mock_comp):
        mock_comp.side_effect = [
            Exception("anthropic down"),
            _mock_response("ollama response"),
        ]
        llm = _make_llm()
        result = llm.complete("Hello", task_type="classify")
        assert result == "ollama response"
        assert mock_comp.call_count == 2

    @patch("litellm.completion")
    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"})
    def test_all_fail_raises_runtime_error(self, mock_comp):
        mock_comp.side_effect = Exception("all down")
        llm = _make_llm()
        with pytest.raises(RuntimeError, match="all providers failed"):
            llm.complete("Hello", task_type="classify")


# ── get_active_providers tests ───────────────────────────────

class TestActiveProviders:

    def test_structure(self):
        llm = _make_llm()
        providers = llm.get_active_providers()
        assert "anthropic" in providers
        assert "ollama" in providers
        assert "openai" in providers
        for name, info in providers.items():
            assert "enabled" in info
            assert "available" in info
            assert "priority" in info
            assert "models" in info

    def test_disabled_marked(self):
        llm = _make_llm()
        providers = llm.get_active_providers()
        assert providers["openai"]["enabled"] is False

    def test_ollama_has_base_url(self):
        llm = _make_llm()
        providers = llm.get_active_providers()
        assert "base_url" in providers["ollama"]


# ── Config loading test ──────────────────────────────────────

class TestConfigLoading:

    def test_empty_config_no_crash(self):
        from modules.llm_router import CyrberLLM
        llm = CyrberLLM(config={"providers": {}, "task_routing": {}})
        providers = llm.get_active_providers()
        assert providers == {}

    def test_no_providers_raises_on_complete(self):
        llm = _make_llm(config={"providers": {}, "task_routing": {}})
        with pytest.raises(RuntimeError, match="no providers available"):
            llm.complete("Hello")


# ── LiteLLMProvider tests ────────────────────────────────────

class TestLiteLLMProvider:

    @patch("litellm.completion")
    def test_chat_returns_text(self, mock_comp):
        mock_comp.return_value = _mock_response("hello")
        mod = _real_llm_provider()
        provider = mod.LiteLLMProvider(model="claude-haiku-4-5-20251001")
        result = provider.chat("Say hello")
        assert result == "hello"

    def test_name_is_litellm(self):
        mod = _real_llm_provider()
        provider = mod.LiteLLMProvider()
        assert provider.name == "litellm"

    def test_is_available(self):
        mod = _real_llm_provider()
        provider = mod.LiteLLMProvider()
        assert provider.is_available() is True

    def test_make_user_msg(self):
        mod = _real_llm_provider()
        provider = mod.LiteLLMProvider()
        msg = provider.make_user_msg("test")
        assert msg == {"role": "user", "content": "test"}

    def test_make_tool_result_msgs(self):
        mod = _real_llm_provider()
        provider = mod.LiteLLMProvider()
        results = [("call_1", "result text")]
        msgs = provider.make_tool_result_msgs(results)
        assert len(msgs) == 1
        assert msgs[0]["role"] == "tool"
        assert msgs[0]["tool_call_id"] == "call_1"


# ── Per-org routing tests ────────────────────────────────────

class TestPerOrgRouting:

    def test_org_local_mode_returns_ollama_only(self):
        llm = _make_llm()
        org_settings = {"llm_mode": "local", "preferred_provider": "anthropic", "ollama_base_url": None}
        chain = llm._get_org_provider_chain(org_settings, "classify")
        assert len(chain) == 1
        assert chain[0]["name"] == "ollama"

    def test_org_airgap_mode_returns_ollama_only(self):
        llm = _make_llm()
        org_settings = {"llm_mode": "airgap", "preferred_provider": "anthropic", "ollama_base_url": None}
        chain = llm._get_org_provider_chain(org_settings, "reasoning")
        assert len(chain) == 1
        assert chain[0]["name"] == "ollama"

    def test_org_local_custom_url(self):
        llm = _make_llm()
        org_settings = {"llm_mode": "local", "preferred_provider": "anthropic", "ollama_base_url": "http://custom:11434"}
        chain = llm._get_org_provider_chain(org_settings, "classify")
        assert chain[0]["base_url"] == "http://custom:11434"

    def test_org_cloud_mode_preferred_first(self):
        """Cloud mode with preferred_provider should put it first in chain."""
        llm = _make_llm()
        org_settings = {"llm_mode": "cloud", "preferred_provider": "ollama", "ollama_base_url": None}
        chain = llm._get_org_provider_chain(org_settings, "classify")
        assert chain[0]["name"] == "ollama"

    def test_org_cloud_default_keeps_anthropic_first(self):
        llm = _make_llm()
        org_settings = {"llm_mode": "cloud", "preferred_provider": "anthropic", "ollama_base_url": None}
        chain = llm._get_org_provider_chain(org_settings, "classify")
        assert chain[0]["name"] == "anthropic"

    @patch("litellm.completion")
    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test"})
    def test_complete_with_org_id_uses_org_settings(self, mock_comp):
        """When org_id is provided and org has local mode, should use ollama."""
        mock_comp.return_value = _mock_response("ollama response")
        llm = _make_llm()

        org_settings = {"llm_mode": "local", "preferred_provider": "anthropic", "ollama_base_url": None}
        with patch.object(llm, "_get_org_llm_settings", return_value=org_settings):
            result = llm.complete("Hello", task_type="classify", org_id=1)

        assert result == "ollama response"
        # Should have called with ollama model, not anthropic
        call_kwargs = mock_comp.call_args[1]
        assert "ollama" in call_kwargs["model"]


# ── get_provider factory test ────────────────────────────────

class TestGetProviderFactory:

    def test_litellm_choice(self):
        mod = _real_llm_provider()
        provider = mod.get_provider(force="litellm", task="classify")
        assert provider.name == "litellm"
