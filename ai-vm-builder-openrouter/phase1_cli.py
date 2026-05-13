"""
AI VM Builder — Phase 1: CLI + Multi-Provider LLM
Uses LLMManager for all provider/proxy routing.
"""
import os, json, argparse
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()

from llm_manager import get_manager, LLMManager, PROVIDERS

PROMPT_FILE   = Path(__file__).parent / "system_prompt.txt"
SYSTEM_PROMPT = PROMPT_FILE.read_text(encoding="utf-8")
VALID_OS      = {"ubuntu-22.04", "debian-12", "alpine"}
VALID_SECURITY= {"minimal", "standard", "hardened", "paranoid"}

# Keep OPENROUTER_MODELS for backwards compat with UI dropdowns
OPENROUTER_MODELS = {
    "mistral-7b":    "mistralai/mistral-7b-instruct",
    "llama3-8b":     "meta-llama/llama-3-8b-instruct",
    "llama3-70b":    "meta-llama/llama-3-70b-instruct",
    "mixtral-8x7b":  "mistralai/mixtral-8x7b-instruct",
    "gemini-flash":  "google/gemini-flash-1.5",
    "gemini-pro":    "google/gemini-pro-1.5",
    "gpt4o":         "openai/gpt-4o",
    "gpt4o-mini":    "openai/gpt-4o-mini",
    "claude-sonnet": "anthropic/claude-sonnet-4-5",
    "phi3-mini":     "microsoft/phi-3-mini-128k-instruct",
}
PROVIDER_DEFAULTS = {p: v["default_model"] for p, v in PROVIDERS.items()}


def analyze_request(user_input: str, provider: str = None, model: str = None,
                    api_key: str = None, base_url: str = None,
                    extra_headers: str = None) -> dict:
    """
    Send plain-English description to LLM, return structured VM config dict.
    Uses LLMManager — supports all providers and proxy gateways.
    """
    mgr = get_manager()

    # Override config if caller provides explicit values (from UI or CLI args)
    if any([provider, model, api_key, base_url]):
        override = {}
        if provider:     override["provider"]  = provider
        if model:        override["model"]      = model
        if api_key:      override["api_key"]    = api_key
        if base_url:     override["base_url"]   = base_url
        if extra_headers:override["extra_headers"] = extra_headers
        mgr.save_config({"provisioning": override})

    # Resolve short model alias → full name
    cfg = mgr.get_purpose_config("provisioning")
    if cfg["model"] in OPENROUTER_MODELS:
        resolved = OPENROUTER_MODELS[cfg["model"]]
        mgr.save_config({"provisioning": {"model": resolved}})

    print(f"  Provider : {cfg['provider']} ({cfg['label']})")
    print(f"  Model    : {cfg['model']}")

    raw = mgr.call(user_input, SYSTEM_PROMPT, purpose="provisioning", max_tokens=800)

    # Strip accidental markdown fences
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1]) if len(lines) > 2 else raw
    raw = raw.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned non-JSON output:\n{raw}\n\nError: {e}")


def validate_config(config: dict) -> tuple:
    errors = []
    required = ["os","cpu","ram_gb","disk_gb","packages","pip_packages",
                "npm_packages","ports","env_vars","purpose","security_profile"]
    for k in required:
        if k not in config: errors.append(f"Missing field: '{k}'")
    if "os" in config and config["os"] not in VALID_OS:
        errors.append(f"Invalid os '{config['os']}'")
    if "security_profile" in config and config["security_profile"] not in VALID_SECURITY:
        config["security_profile"] = "standard"
    for field, lo, hi in [("cpu",1,8),("ram_gb",1,16),("disk_gb",5,100)]:
        if field in config:
            try:
                if not (lo <= int(config[field]) <= hi):
                    errors.append(f"{field} must be {lo}-{hi}")
            except (ValueError, TypeError):
                errors.append(f"{field} must be integer")
    for lst in ["packages","pip_packages","npm_packages","ports"]:
        if lst in config and not isinstance(config[lst], list):
            errors.append(f"'{lst}' must be a list")
    if "env_vars" in config and not isinstance(config["env_vars"], dict):
        errors.append("'env_vars' must be a dict")
    return len(errors) == 0, errors


def print_config_summary(config: dict):
    os_labels = {"ubuntu-22.04":"Ubuntu 22.04","debian-12":"Debian 12","alpine":"Alpine"}
    print("\n" + "-"*54)
    print(f"  OS              : {os_labels.get(config.get('os',''), config.get('os',''))}")
    print(f"  CPU             : {config.get('cpu')} core(s)")
    print(f"  RAM             : {config.get('ram_gb')} GB")
    print(f"  Disk            : {config.get('disk_gb')} GB")
    pkgs = config.get('packages',[])
    print(f"  APT packages    : {', '.join(pkgs) if pkgs else '(none)'}")
    pip  = config.get('pip_packages',[])
    print(f"  Pip packages    : {', '.join(pip) if pip else '(none)'}")
    npm  = config.get('npm_packages',[])
    print(f"  NPM packages    : {', '.join(npm) if npm else '(none)'}")
    ports= config.get('ports',[])
    print(f"  Ports           : {', '.join(str(p) for p in ports) if ports else '(none)'}")
    print(f"  Security profile: {config.get('security_profile','standard')}")
    print(f"  Purpose         : {config.get('purpose','')}")
    print("-"*54)


def main():
    parser = argparse.ArgumentParser(description="AI VM Builder — Phase 1 CLI")
    parser.add_argument("--provider",  default=None)
    parser.add_argument("--model",     default=None)
    parser.add_argument("--api-key",   default=None)
    parser.add_argument("--base-url",  default=None)
    parser.add_argument("--list-models", action="store_true")
    parser.add_argument("--list-providers", action="store_true")
    args = parser.parse_args()

    if args.list_models:
        print("\nOpenRouter model aliases:")
        for alias, full in OPENROUTER_MODELS.items():
            print(f"  {alias:<16} -> {full}")
        return

    if args.list_providers:
        print("\nSupported providers:")
        for pid, info in LLMManager.get_providers_info().items():
            tier = "FREE" if info["free_tier"] else "PAID"
            proxy = " [PROXY]" if info["is_proxy"] else ""
            print(f"  {pid:<14} [{tier}]{proxy} — {info['description'][:60]}")
        return

    print("\nAI VM Builder — Phase 1 CLI")
    print("="*54)
    user_input = input("Describe your VM > ").strip()
    if not user_input: return

    print("\nCalling LLM...")
    try:
        config = analyze_request(user_input,
                                 provider=args.provider,
                                 model=args.model,
                                 api_key=args.api_key,
                                 base_url=args.base_url)
    except (ValueError, EnvironmentError) as e:
        print(f"\nError: {e}"); return

    is_valid, errors = validate_config(config)
    if not is_valid:
        print("\nValidation failed:")
        for err in errors: print(f"  - {err}")
        return

    print("\nConfig generated!")
    print_config_summary(config)
    print("\nFull JSON:")
    print(json.dumps(config, indent=2))

    output_path = Path(__file__).parent / "last_config.json"
    output_path.write_text(json.dumps(config, indent=2))
    print(f"\nSaved to: {output_path}")

if __name__ == "__main__":
    main()
