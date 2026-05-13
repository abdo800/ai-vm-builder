"""
LLM Provider Manager
Centralizes all provider/proxy configuration for AI VM Builder.

Supports:
  Direct providers:  OpenRouter, Anthropic, OpenAI, Groq, Ollama, Together AI
  Proxy gateways:   LiteLLM, Cloudflare AI Gateway, Portkey, custom OpenAI-compatible

Config is loaded from:
  1. Runtime (set via web UI /api/llm/config  → stored in llm_config.json)
  2. .env file fallback
  3. Built-in defaults

Usage:
    from llm_manager import LLMManager
    mgr = LLMManager()
    response = mgr.call(prompt, system_prompt, purpose="provisioning")
"""

import os
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

CONFIG_FILE = Path(__file__).parent / "llm_config.json"

# ── Known providers and proxies ───────────────────────────────────────────────

PROVIDERS = {
    # ── Direct LLM providers ──────────────────────────────────────────────────
    "openrouter": {
        "label":       "OpenRouter",
        "base_url":    "https://openrouter.ai/api/v1",
        "key_env":     "OPENROUTER_API_KEY",
        "key_header":  "Authorization",
        "default_model":"mistralai/mistral-7b-instruct",
        "free_tier":   True,
        "description": "Access 200+ models with one key. Free tier: 50 req/day.",
        "model_examples": [
            "mistralai/mistral-7b-instruct",
            "meta-llama/llama-3-70b-instruct",
            "google/gemini-flash-1.5",
            "openai/gpt-4o-mini",
            "anthropic/claude-sonnet-4-5",
            "mistralai/mixtral-8x7b-instruct",
        ],
        "extra_headers": {"X-Title": "AI VM Builder"},
        "type": "openai_compatible",
    },
    "anthropic": {
        "label":       "Anthropic (Claude)",
        "base_url":    None,  # uses native SDK
        "key_env":     "ANTHROPIC_API_KEY",
        "default_model":"claude-sonnet-4-20250514",
        "free_tier":   False,
        "description": "Native Claude API. Best reasoning quality.",
        "model_examples": [
            "claude-sonnet-4-20250514",
            "claude-opus-4-5",
            "claude-haiku-4-5-20251001",
        ],
        "type": "anthropic",
    },
    "openai": {
        "label":       "OpenAI",
        "base_url":    "https://api.openai.com/v1",
        "key_env":     "OPENAI_API_KEY",
        "default_model":"gpt-4o-mini",
        "free_tier":   False,
        "description": "GPT-4o, GPT-4o-mini. No free tier.",
        "model_examples": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
        "type": "openai_compatible",
    },
    "groq": {
        "label":       "Groq",
        "base_url":    "https://api.groq.com/openai/v1",
        "key_env":     "GROQ_API_KEY",
        "default_model":"llama3-70b-8192",
        "free_tier":   True,
        "description": "Ultra-fast inference. Free tier: 14,400 req/day. Recommended.",
        "model_examples": [
            "llama3-70b-8192",
            "llama3-8b-8192",
            "mixtral-8x7b-32768",
            "gemma-7b-it",
        ],
        "type": "openai_compatible",
    },
    "together": {
        "label":       "Together AI",
        "base_url":    "https://api.together.xyz/v1",
        "key_env":     "TOGETHER_API_KEY",
        "default_model":"meta-llama/Llama-3-70b-chat-hf",
        "free_tier":   True,
        "description": "Open-source models. Free $25 credit on signup.",
        "model_examples": [
            "meta-llama/Llama-3-70b-chat-hf",
            "mistralai/Mixtral-8x7B-Instruct-v0.1",
            "togethercomputer/falcon-40b-instruct",
        ],
        "type": "openai_compatible",
    },
    "ollama": {
        "label":       "Ollama (local)",
        "base_url":    "http://localhost:11434/v1",
        "key_env":     None,
        "default_model":"llama3",
        "free_tier":   True,
        "description": "Run models locally. No API key needed. Requires Ollama installed.",
        "model_examples": ["llama3", "mistral", "phi3", "gemma", "codellama"],
        "type": "openai_compatible",
    },
    # ── Proxy gateways ────────────────────────────────────────────────────────
    "litellm": {
        "label":       "LiteLLM Proxy",
        "base_url":    "http://localhost:4000",  # user can change
        "key_env":     "LITELLM_API_KEY",
        "default_model":"gpt-3.5-turbo",
        "free_tier":   True,
        "description": "Self-hosted proxy. Routes to any backend. OpenAI-compatible.",
        "model_examples": ["gpt-4o", "claude-3", "gemini-pro", "ollama/llama3"],
        "type": "openai_compatible",
        "is_proxy": True,
        "setup_hint": "Run: litellm --model ollama/llama3  or  docker run -p 4000:4000 ghcr.io/berriai/litellm",
    },
    "cloudflare": {
        "label":       "Cloudflare AI Gateway",
        "base_url":    "",  # user must provide: https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/openai
        "key_env":     "CLOUDFLARE_API_KEY",
        "default_model":"@cf/meta/llama-3-8b-instruct",
        "free_tier":   True,
        "description": "Cloudflare's AI Gateway — caching, rate limiting, analytics.",
        "model_examples": [
            "@cf/meta/llama-3-8b-instruct",
            "@cf/mistral/mistral-7b-instruct-v0.1",
            "@cf/google/gemma-7b-it",
        ],
        "type": "openai_compatible",
        "is_proxy": True,
        "setup_hint": "Base URL format: https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/openai",
    },
    "portkey": {
        "label":       "Portkey",
        "base_url":    "https://api.portkey.ai/v1",
        "key_env":     "PORTKEY_API_KEY",
        "default_model":"gpt-4o-mini",
        "free_tier":   True,
        "description": "AI gateway with observability, fallbacks, and load balancing.",
        "model_examples": ["gpt-4o-mini", "gpt-4o", "claude-3-haiku", "llama3-70b"],
        "type": "openai_compatible",
        "is_proxy": True,
        "extra_headers": {"x-portkey-provider": "openai"},
        "setup_hint": "Add x-portkey-provider header to route to specific backend.",
    },
    "custom": {
        "label":       "Custom / Self-hosted",
        "base_url":    "",  # user sets this
        "key_env":     "CUSTOM_API_KEY",
        "default_model":"",
        "free_tier":   True,
        "description": "Any OpenAI-compatible endpoint. vLLM, TGI, LocalAI, etc.",
        "model_examples": [],
        "type": "openai_compatible",
        "is_proxy": True,
        "setup_hint": "Set the Base URL to your OpenAI-compatible endpoint.",
    },
}

# ── Per-purpose config (provisioning vs security vs battle) ───────────────────

PURPOSES = ["provisioning", "security", "battle"]


class LLMManager:
    """
    Central LLM configuration manager.
    Loads config from llm_config.json (set by UI) with .env fallback.
    Supports per-purpose provider selection.
    """

    def __init__(self):
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Load from llm_config.json, fall back to .env."""
        base = {
            "provisioning": {
                "provider": os.getenv("LLM_PROVIDER", "openrouter"),
                "model":    os.getenv("LLM_MODEL", ""),
                "api_key":  "",
                "base_url": "",
                "extra_headers": "",
            },
            "security": {
                "provider": os.getenv("LLM_PROVIDER", "openrouter"),
                "model":    os.getenv("SECURITY_MODEL", os.getenv("LLM_MODEL", "")),
                "api_key":  "",
                "base_url": "",
                "extra_headers": "",
            },
            "battle": {
                "provider": os.getenv("LLM_PROVIDER", "openrouter"),
                "model":    os.getenv("LLM_MODEL", ""),
                "api_key":  "",
                "base_url": "",
                "extra_headers": "",
            },
        }
        if CONFIG_FILE.exists():
            try:
                saved = json.loads(CONFIG_FILE.read_text())
                for purpose in PURPOSES:
                    if purpose in saved:
                        base[purpose].update(saved[purpose])
            except Exception:
                pass
        return base

    def save_config(self, new_config: dict) -> bool:
        """Save config to llm_config.json."""
        try:
            # Merge with existing
            current = self._load_config()
            for purpose in PURPOSES:
                if purpose in new_config:
                    current[purpose].update(new_config[purpose])
            CONFIG_FILE.write_text(json.dumps(current, indent=2))
            self.config = current
            return True
        except Exception:
            return False

    def get_purpose_config(self, purpose: str = "provisioning") -> dict:
        """Return resolved config for a given purpose."""
        cfg      = self.config.get(purpose, self.config["provisioning"])
        provider = cfg.get("provider", "openrouter")
        pdef     = PROVIDERS.get(provider, PROVIDERS["custom"])

        # Resolve API key: UI-set > env var > empty
        api_key = (
            cfg.get("api_key") or
            (os.getenv(pdef.get("key_env", "")) if pdef.get("key_env") else "") or
            ""
        )
        # Resolve base URL: UI-set > provider default
        base_url = cfg.get("base_url") or pdef.get("base_url") or ""

        # Resolve model: UI-set > provider default
        model = cfg.get("model") or pdef.get("default_model") or ""

        # Resolve extra headers
        extra_headers = dict(pdef.get("extra_headers", {}))
        if cfg.get("extra_headers"):
            try:
                user_headers = json.loads(cfg["extra_headers"])
                extra_headers.update(user_headers)
            except Exception:
                pass

        return {
            "provider":      provider,
            "model":         model,
            "api_key":       api_key,
            "base_url":      base_url,
            "extra_headers": extra_headers,
            "type":          pdef.get("type", "openai_compatible"),
            "label":         pdef.get("label", provider),
        }

    def call(self, user_prompt: str, system_prompt: str = "",
             purpose: str = "provisioning", max_tokens: int = 800) -> str:
        """
        Universal LLM call routing through any configured provider/proxy.
        """
        cfg      = self.get_purpose_config(purpose)
        provider = cfg["provider"]
        model    = cfg["model"]
        api_key  = cfg["api_key"]
        base_url = cfg["base_url"]
        headers  = cfg["extra_headers"]
        ptype    = cfg["type"]

        if ptype == "anthropic" and provider == "anthropic":
            return self._call_anthropic(user_prompt, system_prompt, model, api_key, max_tokens)
        else:
            return self._call_openai_compatible(
                user_prompt, system_prompt, model, api_key, base_url, headers, max_tokens
            )

    def _call_anthropic(self, user_prompt, system_prompt, model, api_key, max_tokens):
        from anthropic import Anthropic
        key    = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        client = Anthropic(api_key=key)
        r = client.messages.create(
            model=model or "claude-sonnet-4-20250514",
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return r.content[0].text.strip()

    def _call_openai_compatible(self, user_prompt, system_prompt, model,
                                 api_key, base_url, extra_headers, max_tokens):
        from openai import OpenAI
        # Ollama doesn't need a key
        key = api_key or "no-key-needed"
        client = OpenAI(
            api_key=key,
            base_url=base_url,
            default_headers=extra_headers,
        )
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        r = client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            temperature=0.1,
            messages=messages,
        )
        return r.choices[0].message.content.strip()

    def test_connection(self, purpose: str = "provisioning") -> dict:
        """Test connectivity to configured provider. Returns status dict."""
        cfg = self.get_purpose_config(purpose)
        try:
            result = self.call(
                "Reply with exactly: OK",
                "You are a test. Reply with exactly: OK",
                purpose=purpose,
                max_tokens=10,
            )
            return {
                "success":  True,
                "provider": cfg["label"],
                "model":    cfg["model"],
                "response": result.strip(),
            }
        except Exception as e:
            return {
                "success":  False,
                "provider": cfg["label"],
                "model":    cfg["model"],
                "error":    str(e),
            }

    @staticmethod
    def get_providers_info() -> dict:
        """Return provider catalog for the UI."""
        return {
            k: {
                "label":        v["label"],
                "description":  v["description"],
                "default_model":v["default_model"],
                "model_examples":v.get("model_examples", []),
                "free_tier":    v["free_tier"],
                "is_proxy":     v.get("is_proxy", False),
                "setup_hint":   v.get("setup_hint", ""),
                "needs_base_url":v.get("is_proxy", False) or k == "cloudflare",
                "key_required": v.get("key_env") is not None and k != "ollama",
            }
            for k, v in PROVIDERS.items()
        }


# ── Singleton ─────────────────────────────────────────────────────────────────
_manager = None

def get_manager() -> LLMManager:
    global _manager
    if _manager is None:
        _manager = LLMManager()
    return _manager
