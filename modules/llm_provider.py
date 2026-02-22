"""
Unified LLM provider abstraction for CYRBER.

Supports:
  - claude  (Anthropic API)
  - ollama  (local Ollama — Mistral, Llama, etc.)

Config via .env:
  LLM_PROVIDER=claude          # or: ollama
  ANTHROPIC_API_KEY=sk-...
  CLAUDE_MODEL=claude-sonnet-4-20250514
  OLLAMA_URL=http://localhost:11434
  OLLAMA_MODEL=mistral

Model routing via config/models.yaml (optional):
  tasks:
    ai_analysis: "claude-sonnet-4-20250514"
    exploit_chains: "claude-opus-4-20250514"
  default: "claude-sonnet-4-20250514"
"""

import os
import json
import logging
import pathlib
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

from dotenv import load_dotenv
load_dotenv()

log = logging.getLogger("llm_provider")


# ── Model config loading ─────────────────────────────────────

_model_config: dict | None = None

_CONFIG_PATHS = [
    pathlib.Path(__file__).resolve().parent.parent / "config" / "models.yaml",
    pathlib.Path("/app/config/models.yaml"),   # Docker mount
]


def load_model_config() -> dict:
    """Load config/models.yaml. Returns empty dict on missing file / parse error."""
    global _model_config
    if _model_config is not None:
        return _model_config

    for path in _CONFIG_PATHS:
        if path.is_file():
            try:
                import yaml
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                _model_config = data
                log.info("[model_routing] loaded config from %s", path)
                return _model_config
            except Exception as exc:
                log.warning("[model_routing] failed to load %s: %s", path, exc)

    _model_config = {}
    return _model_config


def _resolve_model_for_task(task: str | None) -> str:
    """Resolve model name for a given task using YAML config, env, or default."""
    cfg = load_model_config()
    env_default = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")

    if task and cfg:
        tasks = cfg.get("tasks", {})
        if task in tasks:
            model = tasks[task]
            log.info("[model_routing] task=%s model=%s (yaml)", task, model)
            return model

    yaml_default = cfg.get("default")
    if yaml_default:
        model = yaml_default
        log.info("[model_routing] task=%s model=%s (yaml default)", task, model)
        return model

    log.info("[model_routing] task=%s model=%s (env)", task, env_default)
    return env_default


# ── Data classes ──────────────────────────────────────────────

@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class LLMResponse:
    """Normalized response from any LLM provider."""
    text: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"       # "end_turn" | "tool_use"
    _raw: object = field(default=None, repr=False)


# ── Abstract interface ────────────────────────────────────────

class LLMProvider(ABC):
    """Common interface for LLM providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for logging / metadata."""
        ...

    @abstractmethod
    def chat(self, prompt: str, system: str | None = None,
             max_tokens: int = 1024) -> str:
        """Simple single-turn chat.  Returns raw text."""
        ...

    @abstractmethod
    def chat_with_tools(self, messages: list, tools: list[dict],
                        system: str | None = None,
                        max_tokens: int = 4096) -> LLMResponse:
        """Chat with tool-calling support.  Returns structured response."""
        ...

    # ── message builders (format depends on provider) ──

    @abstractmethod
    def make_user_msg(self, content: str) -> dict:
        ...

    @abstractmethod
    def make_assistant_msgs(self, response: LLMResponse) -> list[dict]:
        """Return message(s) to append to history after an assistant turn."""
        ...

    @abstractmethod
    def make_tool_result_msgs(self,
                              results: list[tuple[str, str]]) -> list[dict]:
        """Return message(s) for tool results.
        results: [(tool_call_id, content_string), ...]"""
        ...

    def is_available(self) -> bool:
        """Check if this provider is reachable."""
        return True


# ── Claude (Anthropic) ────────────────────────────────────────

class ClaudeProvider(LLMProvider):

    def __init__(self, model: str | None = None):
        import anthropic
        self._client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY"))
        self._model = model or os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")

    @property
    def name(self):
        return "claude"

    # ── simple chat ──

    def chat(self, prompt, system=None, max_tokens=1024):
        kw = dict(model=self._model, max_tokens=max_tokens,
                  messages=[{"role": "user", "content": prompt}])
        if system:
            kw["system"] = system
        msg = self._client.messages.create(**kw)
        return msg.content[0].text

    # ── tool-calling chat ──

    def chat_with_tools(self, messages, tools, system=None, max_tokens=4096):
        kw = dict(model=self._model, max_tokens=max_tokens,
                  messages=messages, tools=tools)
        if system:
            kw["system"] = system
        resp = self._client.messages.create(**kw)

        text_parts = []
        tool_calls = []
        for block in resp.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCall(id=block.id, name=block.name, input=block.input))

        return LLMResponse(
            text="\n".join(text_parts) if text_parts else None,
            tool_calls=tool_calls,
            stop_reason="tool_use" if resp.stop_reason == "tool_use"
                        else "end_turn",
            _raw=resp,
        )

    # ── message helpers (Anthropic format) ──

    def make_user_msg(self, content):
        return {"role": "user", "content": content}

    def make_assistant_msgs(self, response):
        return [{"role": "assistant", "content": response._raw.content}]

    def make_tool_result_msgs(self, results):
        return [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": tid, "content": content}
            for tid, content in results
        ]}]

    def is_available(self):
        return bool(os.getenv("ANTHROPIC_API_KEY"))


# ── Ollama ────────────────────────────────────────────────────

class OllamaProvider(LLMProvider):

    def __init__(self):
        import requests as _req
        self._requests = _req
        self._url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self._model = os.getenv("OLLAMA_MODEL", "mistral")

    @property
    def name(self):
        return "ollama"

    # ── simple chat ──

    def chat(self, prompt, system=None, max_tokens=1024):
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})

        resp = self._requests.post(
            f"{self._url}/api/chat",
            json={"model": self._model, "messages": msgs, "stream": False,
                  "options": {"num_predict": max_tokens}},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    # ── tool-calling chat ──

    def chat_with_tools(self, messages, tools, system=None, max_tokens=4096):
        ollama_msgs = list(messages)
        if system:
            ollama_msgs.insert(0, {"role": "system", "content": system})

        payload = {
            "model": self._model,
            "messages": ollama_msgs,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }
        ollama_tools = self._convert_tools(tools)
        if ollama_tools:
            payload["tools"] = ollama_tools

        resp = self._requests.post(
            f"{self._url}/api/chat", json=payload, timeout=180)
        resp.raise_for_status()
        data = resp.json()
        msg = data.get("message", {})

        tool_calls = []
        for tc in (msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            tool_calls.append(ToolCall(
                id=tc.get("id", f"call_{len(tool_calls)}"),
                name=fn.get("name", ""),
                input=args,
            ))

        return LLMResponse(
            text=msg.get("content") or None,
            tool_calls=tool_calls,
            stop_reason="tool_use" if tool_calls else "end_turn",
            _raw=data,
        )

    # ── message helpers (OpenAI / Ollama format) ──

    def make_user_msg(self, content):
        return {"role": "user", "content": content}

    def make_assistant_msgs(self, response):
        msg = {"role": "assistant", "content": response.text or ""}
        if response.tool_calls:
            msg["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.name,
                              "arguments": json.dumps(tc.input)}}
                for tc in response.tool_calls
            ]
        return [msg]

    def make_tool_result_msgs(self, results):
        # Ollama/OpenAI: each tool result is a separate message
        return [
            {"role": "tool", "content": content, "tool_call_id": tid}
            for tid, content in results
        ]

    def is_available(self):
        try:
            resp = self._requests.get(
                f"{self._url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    # ── internal helpers ──

    @staticmethod
    def _convert_tools(anthropic_tools):
        """Anthropic tool schema → OpenAI/Ollama tool schema."""
        return [
            {"type": "function", "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {}),
            }}
            for t in anthropic_tools
        ]


# ── Factory ───────────────────────────────────────────────────

_provider_cache: dict[str, LLMProvider] = {}


def get_provider(force: str | None = None, task: str | None = None) -> LLMProvider:
    """Return the configured LLM provider.

    force: override provider type ("claude" or "ollama") — bypasses cache.
    task:  task identifier for model routing via config/models.yaml.
           Different tasks can use different Claude models.
    """
    choice = (force or os.getenv("LLM_PROVIDER", "claude")).lower().strip()

    # Ollama: force always bypasses cache (keeps existing behavior)
    if choice == "ollama":
        prov = OllamaProvider()
        log.info("LLM provider: %s (force=%s)", prov.name, force)
        return prov

    # Claude: per-task model routing with cache
    cache_key = f"claude:{task}" if task else "claude:_default_"

    if force is None and cache_key in _provider_cache:
        return _provider_cache[cache_key]

    model = _resolve_model_for_task(task)
    prov = ClaudeProvider(model=model)

    log.info("LLM provider: %s model=%s task=%s", prov.name, model, task)

    if force is None:
        _provider_cache[cache_key] = prov

    return prov
