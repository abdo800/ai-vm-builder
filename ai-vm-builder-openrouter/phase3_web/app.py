"""
AI VM Builder — Phase 3: Flask Web Backend
All routes in one clean file — no appended blocks, no duplicates.
"""
import sys, os, json, threading, datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, request, jsonify, render_template
from phase1_cli import analyze_request, validate_config, OPENROUTER_MODELS, PROVIDER_DEFAULTS
from phase2_docker import (build_and_run, get_docker_client, OS_IMAGES,
                            install_system_packages, install_pip_packages, install_npm_packages)
from security.ai_defense import (run_scan, collect_snapshot, apply_patch,
                                  LOG_FILE, BATTLE_LOG,
                                  _battles, _get_detector,
                                  _detectors, _ebpf, _frida, _honeypots)
from security.adversarial.red_blue_engine import AdversarialEngine
from llm_manager import get_manager, LLMManager
import docker

app = Flask(__name__)

defense_threads = {}
defense_status  = {}


# ── Core routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/models")
def list_models():
    return jsonify({"aliases": OPENROUTER_MODELS, "provider_defaults": PROVIDER_DEFAULTS,
                    "providers": ["openrouter","anthropic","openai","groq","ollama"]})

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)
    if not data or not data.get("prompt","").strip():
        return jsonify({"error": "Non-empty 'prompt' required."}), 400
    provider = data.get("provider") or os.getenv("LLM_PROVIDER","openrouter")
    model    = data.get("model")    or os.getenv("LLM_MODEL") or None
    try:
        config = analyze_request(data["prompt"].strip(), provider=provider, model=model)
    except (ValueError, EnvironmentError) as e:
        return jsonify({"error": str(e)}), 500
    is_valid, errors = validate_config(config)
    if not is_valid:
        return jsonify({"error": "Validation: " + "; ".join(errors)}), 400
    return jsonify({"config": config, "provider": provider, "model": model})

@app.route("/create", methods=["POST"])
def create():
    data = request.get_json(silent=True)
    if not data or "config" not in data:
        return jsonify({"error": "'config' field required."}), 400
    config = data["config"]
    is_valid, errors = validate_config(config)
    if not is_valid:
        return jsonify({"error": "Invalid config: " + "; ".join(errors)}), 400
    try:
        container = build_and_run(config)
        if not container:
            return jsonify({"error": "Container creation failed."}), 500
        shell = "/bin/sh" if config["os"] == "alpine" else "/bin/bash"
        return jsonify({
            "success": True,
            "container_id":   container.short_id,
            "container_name": container.name,
            "connect_cmd":    f"docker exec -it {container.short_id} {shell}",
            "stop_cmd":       f"docker stop {container.short_id}",
            "image":          OS_IMAGES.get(config["os"],"unknown"),
            "security_profile": config.get("security_profile","standard"),
        })
    except SystemExit:
        return jsonify({"error": "Docker not running. Start Docker Desktop."}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/containers")
def list_containers():
    try:
        client     = get_docker_client()
        containers = client.containers.list(all=True, filters={"label":"ai-vm-builder=true"})
        return jsonify({"containers": [{
            "id":             c.short_id,
            "name":           c.name,
            "status":         c.status,
            "image":          c.image.tags[0] if c.image.tags else "unknown",
            "purpose":        c.labels.get("purpose",""),
            "security":       c.labels.get("security_profile","standard"),
            "defense_active": c.short_id in defense_threads,
            "battle_active":  (c.short_id in _battles and
                               _battles[c.short_id].get("engine") is not None and
                               _battles[c.short_id]["engine"]._running),
        } for c in containers]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/containers/<cid>/stop", methods=["POST"])
def stop_container(cid):
    try:
        get_docker_client().containers.get(cid).stop()
        return jsonify({"success": True})
    except docker.errors.NotFound:
        return jsonify({"error": "Not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/containers/<cid>/remove", methods=["DELETE"])
def remove_container(cid):
    try:
        get_docker_client().containers.get(cid).remove(force=True)
        defense_threads.pop(cid, None)
        defense_status.pop(cid, None)
        _battles.pop(cid, None)
        return jsonify({"success": True})
    except docker.errors.NotFound:
        return jsonify({"error": "Not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Security / defense routes ─────────────────────────────────────────────────

@app.route("/security/scan/<cid>", methods=["POST"])
def security_scan(cid):
    data       = request.get_json(silent=True) or {}
    dry_run    = data.get("dry_run", True)
    auto_patch = data.get("auto_patch", False)
    try:
        container = get_docker_client().containers.get(cid)
        result    = run_scan(container, dry_run=dry_run, auto_patch=auto_patch)
        defense_status[cid] = {
            "last_scan":    datetime.datetime.utcnow().isoformat(),
            "threat_level": result.get("threat_level","none"),
            "threats":      result.get("threats",[]),
            "patches":      result.get("patches",[]),
            "summary":      result.get("summary",""),
            "ml_scores":    result.get("ml_scores",{}),
        }
        return jsonify({"success": True, "assessment": result})
    except docker.errors.NotFound:
        return jsonify({"error": f"Container '{cid}' not found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/security/monitor/<cid>", methods=["POST"])
def start_monitor(cid):
    if cid in defense_threads and defense_threads[cid].is_alive():
        return jsonify({"message": "Already monitoring.", "container_id": cid})
    data       = request.get_json(silent=True) or {}
    interval   = int(data.get("interval", 60))
    dry_run    = data.get("dry_run", False)
    auto_patch = data.get("auto_patch", True)

    def _worker():
        import time
        try:
            container = get_docker_client().containers.get(cid)
            while cid in defense_threads:
                container.reload()
                if container.status != "running": break
                result = run_scan(container, dry_run=dry_run, auto_patch=auto_patch)
                defense_status[cid] = {
                    "last_scan":    datetime.datetime.utcnow().isoformat(),
                    "threat_level": result.get("threat_level","none"),
                    "threats":      result.get("threats",[]),
                    "patches":      result.get("patches",[]),
                    "summary":      result.get("summary",""),
                    "ml_scores":    result.get("ml_scores",{}),
                }
                time.sleep(interval)
        except Exception as e:
            defense_status[cid] = {"error": str(e)}
        finally:
            defense_threads.pop(cid, None)

    t = threading.Thread(target=_worker, daemon=True)
    defense_threads[cid] = t
    t.start()
    return jsonify({"success": True, "message": f"Monitoring started (every {interval}s)", "container_id": cid})

@app.route("/security/monitor/<cid>", methods=["DELETE"])
def stop_monitor(cid):
    defense_threads.pop(cid, None)
    return jsonify({"success": True, "message": "Monitoring stopped."})

@app.route("/security/status/<cid>")
def defense_status_route(cid):
    status = defense_status.get(cid)
    if not status:
        return jsonify({"message": "No scan data yet.", "container_id": cid})
    return jsonify({"container_id": cid, "monitoring": cid in defense_threads, **status})

@app.route("/security/log")
def get_defense_log():
    n = int(request.args.get("n", 20))
    entries = []
    if LOG_FILE.exists():
        lines = LOG_FILE.read_text().strip().split("\n")
        for line in lines[-n:]:
            try: entries.append(json.loads(line))
            except Exception: pass
    return jsonify({"entries": entries})

@app.route("/security/patch/<cid>", methods=["POST"])
def apply_manual_patch(cid):
    data = request.get_json(silent=True)
    if not data or not data.get("command"):
        return jsonify({"error": "'command' required."}), 400
    try:
        container = get_docker_client().containers.get(cid)
        patch  = {"id":"manual","command":data["command"],
                  "description":data.get("description","Manual patch")}
        result = apply_patch(container, patch, dry_run=data.get("dry_run",False))
        return jsonify(result)
    except docker.errors.NotFound:
        return jsonify({"error": "Container not found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/security/ml_status/<cid>")
def ml_status(cid):
    detector = _detectors.get(cid)
    if not detector:
        return jsonify({"message": "No ML baseline yet — run a scan first."})
    return jsonify({
        "container_id":         cid,
        "snapshots_seen":       detector.snapshot_count,
        "baseline_established": detector.baseline_established,
        "zscore_features":      list(detector.zscore.history.keys()),
        "iforest_trained":      detector.iforest.trained,
        "autoencoder_samples":  detector.autoencoder.samples_seen,
    })

@app.route("/security/ebpf_status/<cid>")
def ebpf_status(cid):
    ebpf     = _ebpf.get(cid)
    frida    = _frida.get(cid)
    honeypot = _honeypots.get(cid)
    return jsonify({
        "container_id": cid,
        "ebpf":     {"active": ebpf is not None,
                     "available": ebpf.available if ebpf else False,
                     "type": type(ebpf).__name__ if ebpf else "not_started"},
        "frida":    {"active": frida is not None,
                     "available": frida.available if frida else False,
                     "sessions": len(frida._sessions) if frida else 0},
        "honeypot": {"active": honeypot is not None,
                     "active_pots": honeypot.active_pots if honeypot else {}},
    })


# ── Red vs Blue battle routes ─────────────────────────────────────────────────

@app.route("/battle/start/<cid>", methods=["POST"])
def start_battle(cid):
    entry = _battles.get(cid)
    if entry and entry.get("engine") and entry["engine"]._running:
        return jsonify({"message": "Battle already running.", "container_id": cid})
    data     = request.get_json(silent=True) or {}
    rounds   = int(data.get("rounds", 20))
    interval = float(data.get("interval", 20.0))
    try:
        container = get_docker_client().containers.get(cid)
        detector  = _get_detector(cid)
        engine    = AdversarialEngine(container, detector)
        engine.start_background(rounds=rounds, interval=interval)
        _battles[cid] = {"engine": engine, "started": datetime.datetime.utcnow().isoformat()}
        return jsonify({"success": True,
                        "message": f"Battle started — {rounds} rounds, {interval}s interval",
                        "container_id": cid})
    except docker.errors.NotFound:
        return jsonify({"error": f"Container '{cid}' not found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/battle/stop/<cid>", methods=["POST"])
def stop_battle(cid):
    entry = _battles.get(cid)
    if not entry or not entry.get("engine"):
        return jsonify({"message": "No battle running for this container."})
    entry["engine"].stop()
    return jsonify({"success": True, "message": "Battle stopped."})

@app.route("/battle/status/<cid>")
def battle_status(cid):
    entry = _battles.get(cid)
    if not entry or not entry.get("engine"):
        return jsonify({"message": "No battle for this container.", "container_id": cid})
    return jsonify(entry["engine"].get_status())

@app.route("/battle/log")
def battle_log():
    n = int(request.args.get("n", 30))
    entries = []
    if BATTLE_LOG.exists():
        lines = BATTLE_LOG.read_text().strip().split("\n")
        for line in lines[-n:]:
            try: entries.append(json.loads(line))
            except Exception: pass
    return jsonify({"entries": entries})

@app.route("/battle/run_round/<cid>", methods=["POST"])
def run_single_round(cid):
    try:
        container = get_docker_client().containers.get(cid)
        detector  = _get_detector(cid)
        engine    = AdversarialEngine(container, detector)
        result    = engine.run_round()
        return jsonify({"success": True, "round": result})
    except docker.errors.NotFound:
        return jsonify({"error": "Container not found."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Entry point ───────────────────────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════
# LLM PROVIDER / PROXY CONFIGURATION ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route("/api/llm/providers")
def llm_providers():
    """Return full provider catalog for the settings UI."""
    return jsonify(LLMManager.get_providers_info())

@app.route("/api/llm/config", methods=["GET"])
def get_llm_config():
    """Return current LLM config (API keys masked)."""
    mgr    = get_manager()
    config = mgr.config.copy()
    # Mask API keys for security
    masked = {}
    for purpose, cfg in config.items():
        masked[purpose] = dict(cfg)
        key = masked[purpose].get("api_key","")
        if key:
            masked[purpose]["api_key"] = key[:8] + "••••••••" + key[-4:] if len(key) > 12 else "••••••••"
    return jsonify({"config": masked})

@app.route("/api/llm/config", methods=["POST"])
def set_llm_config():
    """Save LLM provider config for one or more purposes."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    mgr     = get_manager()
    success = mgr.save_config(data)
    if success:
        return jsonify({"success": True, "message": "Configuration saved."})
    return jsonify({"error": "Failed to save config."}), 500

@app.route("/api/llm/test", methods=["POST"])
def test_llm_connection():
    """Test connectivity to configured LLM for a given purpose."""
    data    = request.get_json(silent=True) or {}
    purpose = data.get("purpose", "provisioning")

    # If config values are provided inline, apply them temporarily
    if data.get("provider") or data.get("model") or data.get("api_key"):
        mgr = get_manager()
        override = {}
        for field in ["provider","model","api_key","base_url","extra_headers"]:
            if data.get(field): override[field] = data[field]
        mgr.save_config({purpose: override})

    mgr    = get_manager()
    result = mgr.test_connection(purpose=purpose)
    return jsonify(result)

@app.route("/api/llm/current/<purpose>")
def get_current_llm(purpose):
    """Return resolved (non-masked) config for a purpose — for display."""
    if purpose not in ["provisioning","security","battle"]:
        return jsonify({"error": "Invalid purpose"}), 400
    mgr = get_manager()
    cfg = mgr.get_purpose_config(purpose)
    # Mask key for response
    key = cfg.get("api_key","")
    cfg["api_key_masked"] = (key[:8] + "••••" + key[-4:]) if len(key) > 12 else ("••••" if key else "")
    cfg.pop("api_key", None)
    return jsonify(cfg)


if __name__ == "__main__":
    print("\nAI VM Builder — http://localhost:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
