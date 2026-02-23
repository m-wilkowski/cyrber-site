"""Tests for ai_analysis.ContextManager."""

import json

import pytest

from modules.ai_analysis import ContextManager, _MAX_DESCRIPTION_CHARS


# ── estimate_tokens ──────────────────────────────────────────────


class TestEstimateTokens:

    def test_empty_string(self):
        assert ContextManager.estimate_tokens("") == 0

    def test_short_text(self):
        # "hello" = 5 chars → 5/3.5 ≈ 1
        result = ContextManager.estimate_tokens("hello")
        assert result >= 1

    def test_long_text(self):
        text = "A" * 3500
        result = ContextManager.estimate_tokens(text)
        assert result == 1000  # 3500 / 3.5

    def test_json_string(self):
        data = {"name": "SQL Injection", "severity": "critical", "desc": "x" * 200}
        text = json.dumps(data)
        result = ContextManager.estimate_tokens(text)
        # Should be proportional to length
        assert result == int(len(text) / 3.5)

    def test_returns_at_least_one_for_nonempty(self):
        assert ContextManager.estimate_tokens("a") >= 1

    def test_scales_roughly_linearly(self):
        t1 = ContextManager.estimate_tokens("A" * 100)
        t2 = ContextManager.estimate_tokens("A" * 1000)
        # int() truncation means it won't be exact; allow ±2% drift
        assert abs(t2 - t1 * 10) <= t1 * 10 * 0.02 + 1


# ── get_model_context_limit ──────────────────────────────────────


class TestGetModelContextLimit:

    def test_claude_opus(self):
        assert ContextManager.get_model_context_limit("claude-opus-4-20250514") == 180_000

    def test_claude_sonnet(self):
        assert ContextManager.get_model_context_limit("claude-sonnet-4-20250514") == 180_000

    def test_claude_haiku(self):
        assert ContextManager.get_model_context_limit("claude-haiku-3-5-20241022") == 180_000

    def test_llama32(self):
        assert ContextManager.get_model_context_limit("llama3.2") == 6_000

    def test_llama3(self):
        assert ContextManager.get_model_context_limit("llama3:latest") == 6_000

    def test_mistral(self):
        assert ContextManager.get_model_context_limit("mistral") == 6_000

    def test_ollama_fallback(self):
        # Provider name "ollama" used as fallback
        assert ContextManager.get_model_context_limit("ollama") == 6_000

    def test_unknown_model(self):
        assert ContextManager.get_model_context_limit("gpt-4o") == 50_000

    def test_case_insensitive(self):
        assert ContextManager.get_model_context_limit("Claude-Opus-4") == 180_000


# ── truncate_findings ────────────────────────────────────────────


class TestTruncateFindings:

    def test_empty_findings(self):
        result = ContextManager.truncate_findings([], budget_tokens=1000)
        assert result == []

    def test_all_fit(self):
        findings = [
            {"name": "XSS", "severity": "high", "description": "short"},
            {"name": "SQLi", "severity": "critical", "description": "short"},
        ]
        result = ContextManager.truncate_findings(findings, budget_tokens=10_000)
        # No truncation marker expected
        assert not any(f.get("_truncated") for f in result)
        assert len(result) == 2

    def test_severity_order_preserved(self):
        """Critical findings should come first even if input is unsorted."""
        findings = [
            {"name": "info-thing", "severity": "info", "description": "a"},
            {"name": "critical-vuln", "severity": "critical", "description": "b"},
            {"name": "low-issue", "severity": "low", "description": "c"},
        ]
        result = ContextManager.truncate_findings(findings, budget_tokens=10_000)
        non_meta = [f for f in result if not f.get("_truncated")]
        assert non_meta[0]["severity"] == "critical"

    def test_long_description_truncated(self):
        findings = [
            {"name": "Vuln", "severity": "high", "description": "X" * 2000},
        ]
        result = ContextManager.truncate_findings(findings, budget_tokens=10_000)
        non_meta = [f for f in result if not f.get("_truncated")]
        assert len(non_meta) == 1
        assert len(non_meta[0]["description"]) == _MAX_DESCRIPTION_CHARS + 3  # +3 for "..."

    def test_budget_exceeded_drops_findings(self):
        findings = [
            {"name": f"vuln-{i}", "severity": "medium", "description": "A" * 400}
            for i in range(50)
        ]
        result = ContextManager.truncate_findings(findings, budget_tokens=500)
        non_meta = [f for f in result if not f.get("_truncated")]
        truncation = [f for f in result if f.get("_truncated")]
        assert len(non_meta) < 50
        assert len(truncation) == 1
        assert truncation[0]["dropped"] == 50 - len(non_meta)

    def test_severity_priority_under_tight_budget(self):
        """With room for only ~1 finding, it should be the critical one."""
        findings = [
            {"name": "low-vuln", "severity": "low", "description": "A" * 100},
            {"name": "crit-vuln", "severity": "critical", "description": "B" * 100},
        ]
        # Budget for roughly 1 finding
        one_finding_cost = ContextManager.estimate_tokens(
            json.dumps(findings[0], ensure_ascii=False)
        )
        result = ContextManager.truncate_findings(findings, budget_tokens=one_finding_cost + 5)
        non_meta = [f for f in result if not f.get("_truncated")]
        assert len(non_meta) == 1
        assert non_meta[0]["name"] == "crit-vuln"

    def test_dropped_by_severity_counts(self):
        findings = [
            {"name": "c", "severity": "critical", "description": "x" * 300},
            {"name": "h", "severity": "high", "description": "x" * 300},
            {"name": "m", "severity": "medium", "description": "x" * 300},
            {"name": "l", "severity": "low", "description": "x" * 300},
        ]
        # Very tight budget — only 1 finding fits
        one_cost = ContextManager.estimate_tokens(
            json.dumps({"name": "c", "severity": "critical", "description": "x" * 300},
                       ensure_ascii=False)
        )
        result = ContextManager.truncate_findings(findings, budget_tokens=one_cost + 5)
        truncation = [f for f in result if f.get("_truncated")]
        assert len(truncation) == 1
        dbs = truncation[0]["dropped_by_severity"]
        # Critical fits, the rest are dropped
        assert "critical" not in dbs
        assert dbs.get("high", 0) == 1


# ── build_context_aware_prompt ───────────────────────────────────


class TestBuildContextAwarePrompt:

    @staticmethod
    def _make_findings(n, desc_len=200):
        sevs = ["critical", "high", "medium", "low", "info"]
        return [
            {"name": f"vuln-{i}", "severity": sevs[i % len(sevs)],
             "source": "nuclei", "description": "D" * desc_len}
            for i in range(n)
        ]

    @staticmethod
    def _make_ports(n):
        return [{"port": 80 + i, "service": f"svc-{i}", "version": f"1.{i}"}
                for i in range(n)]

    @staticmethod
    def _metadata():
        return {
            "target": "example.com", "profile": "STRAZNIK",
            "modules_ran": 10, "sev_counts": {"critical": 5, "high": 10},
            "risk_score": 75, "mitre": ["T1059"], "cwe": ["CWE-89"],
            "owasp": ["A03 Injection"],
        }

    def test_claude_fits_everything(self):
        """With 180k budget, moderate data should all fit."""
        findings = self._make_findings(50)
        ports = self._make_ports(20)
        corr = "Correlation line\n" * 30

        f_out, p_out, c_out, _ = ContextManager.build_context_aware_prompt(
            findings, ports, corr, self._metadata(), "claude-sonnet-4-20250514",
        )
        # Everything should fit
        real_findings = [f for f in f_out if not f.get("_note")]
        assert len(real_findings) == 50
        assert len(p_out) == 20
        assert c_out == corr

    def test_ollama_trims_aggressively(self):
        """With 6k budget, 100 findings + 50 ports must be trimmed."""
        findings = self._make_findings(100, desc_len=400)
        ports = self._make_ports(50)
        corr = "Correlation\n" * 50

        f_out, p_out, c_out, _ = ContextManager.build_context_aware_prompt(
            findings, ports, corr, self._metadata(), "llama3.2",
        )
        real_findings = [f for f in f_out if not f.get("_note")]
        assert len(real_findings) < 100
        assert len(p_out) < 50

    def test_total_prompt_within_budget(self):
        """The assembled prompt must not exceed the model's context limit."""
        findings = self._make_findings(200, desc_len=600)
        ports = self._make_ports(60)
        corr = "Chain data\n" * 200

        for model, limit in [("claude-sonnet-4-20250514", 180_000), ("llama3.2", 6_000)]:
            f_out, p_out, c_out, _ = ContextManager.build_context_aware_prompt(
                findings, ports, corr, self._metadata(), model,
            )
            total_text = (
                json.dumps(f_out, ensure_ascii=False)
                + json.dumps(p_out, ensure_ascii=False)
                + c_out
                + json.dumps(self._metadata(), ensure_ascii=False)
            )
            total_tokens = ContextManager.estimate_tokens(total_text)
            assert total_tokens <= limit, (
                f"{model}: {total_tokens} tokens exceeds {limit}"
            )

    def test_correlations_have_highest_priority(self):
        """Even with tight budget, correlations should be included."""
        findings = self._make_findings(50, desc_len=400)
        ports = self._make_ports(20)
        corr = "Important correlation data"

        _, _, c_out, _ = ContextManager.build_context_aware_prompt(
            findings, ports, corr, self._metadata(), "llama3.2",
        )
        assert c_out == corr  # short correlation should survive

    def test_critical_findings_prioritized_over_low(self):
        """Under tight budget, critical findings survive while low are dropped."""
        # All critical
        crit = [{"name": f"crit-{i}", "severity": "critical",
                 "source": "nuclei", "description": "C" * 200}
                for i in range(10)]
        # All low
        low = [{"name": f"low-{i}", "severity": "low",
                "source": "nikto", "description": "L" * 200}
               for i in range(10)]

        f_out, _, _, _ = ContextManager.build_context_aware_prompt(
            crit + low, [], "", self._metadata(), "llama3.2",
        )
        real = [f for f in f_out if not f.get("_note")]
        if len(real) < 20:
            # Some were dropped; criticals should dominate
            crit_count = sum(1 for f in real if f["severity"] == "critical")
            low_count = sum(1 for f in real if f["severity"] == "low")
            assert crit_count >= low_count

    def test_empty_inputs(self):
        f_out, p_out, c_out, rag_out = ContextManager.build_context_aware_prompt(
            [], [], "", self._metadata(), "claude-sonnet-4-20250514",
        )
        assert f_out == []
        assert p_out == []
        assert c_out == ""
        assert rag_out == ""

    def test_note_added_when_findings_dropped(self):
        findings = self._make_findings(200, desc_len=500)
        f_out, _, _, _ = ContextManager.build_context_aware_prompt(
            findings, [], "", self._metadata(), "llama3.2",
        )
        notes = [f for f in f_out if f.get("_note")]
        real = [f for f in f_out if not f.get("_note")]
        if len(real) < 200:
            assert len(notes) == 1
            assert "omitted" in notes[0]["_note"]
