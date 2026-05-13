"""
Red Agent vs Blue Agent — Adversarial Self-Improving Defense
Challenge 1: Active Cyber Defense — GDG x Duckurity AISprint

CONCEPT:
Two LLM agents run simultaneously against the same Docker container:

  RED AGENT  (attacker)  — tries to compromise the container using
                           common attack techniques. It has a toolbox of
                           real shell commands it can execute inside the
                           container. It reports what worked and what didn't.

  BLUE AGENT (defender)  — watches the ML detector scores + eBPF events,
                           analyzes the Red Agent's moves, and applies
                           live patches to stop them. It learns which
                           defenses are effective against which attacks.

WHY THIS MATTERS:
  - Every Red Agent success becomes a Blue Agent training signal
  - The system gets smarter with every battle round
  - Judges see a live AI-vs-AI security duel in real time
  - The battle log is a rich artifact showing adversarial reasoning

ARCHITECTURE:
  AdversarialEngine
    ├── RedAgent    → LLM with attack toolbox + real exec capability
    ├── BlueAgent   → LLM with defense toolbox + ML scores
    ├── BattleArena → Docker container (the battlefield)
    └── BattleLog   → JSONL log of every move, counter-move, outcome

SAFETY:
  The Red Agent only runs in a dedicated sandbox container.
  It CANNOT access the host, other containers, or the network
  beyond what's explicitly opened in the arena container's config.
  All Red Agent commands are validated against a whitelist before execution.
"""

import os
import json
import time
import datetime
import threading
from pathlib import Path
from typing import Optional

LOG_FILE = Path(__file__).parent.parent.parent / "battle_log.jsonl"


# ── Allowed Red Agent commands (safety whitelist) ────────────────────────────
# Red Agent can only use these command templates inside the sandbox container.
# This prevents accidental host damage while still demonstrating real attacks.

RED_ALLOWED_COMMANDS = {
    # Reconnaissance
    "recon_processes":    "ps aux 2>/dev/null",
    "recon_network":      "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null",
    "recon_files":        "find /etc /root /tmp -type f 2>/dev/null | head -30",
    "recon_users":        "cat /etc/passwd 2>/dev/null",
    "recon_suid":         "find / -perm -4000 -type f 2>/dev/null | head -10",
    "recon_env":          "env 2>/dev/null",
    "recon_cron":         "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null",
    # Privilege escalation simulation
    "escape_suid":        "find / -perm -4000 2>/dev/null | xargs ls -la 2>/dev/null | head -5",
    "escape_sudo":        "sudo -l 2>/dev/null || echo 'no sudo'",
    "escape_writable":    "find / -writable -type f 2>/dev/null | grep -v proc | head -10",
    # Persistence simulation
    "persist_cron":       "echo '* * * * * echo pwned >> /tmp/pwned.log' | crontab - 2>/dev/null && echo 'cron set'",
    "persist_bashrc":     "echo '# pwned' >> /root/.bashrc 2>/dev/null && echo 'bashrc modified'",
    "persist_tmpfile":    "echo 'malware_payload' > /tmp/.hidden_payload 2>/dev/null && echo 'file dropped'",
    # Network simulation
    "network_listen":     "nc -l -p 9999 &>/dev/null & echo 'listening on 9999'",
    "network_scan":       "for p in 22 80 443 3306 5432; do (echo >/dev/tcp/127.0.0.1/$p) 2>/dev/null && echo \"port $p open\"; done",
    "network_exfil":      "cat /etc/passwd | base64 > /tmp/exfil_data.txt && echo 'data encoded for exfil'",
    # Crypto mining simulation (safe — just the process name)
    "miner_simulate":     "sleep 3600 & disown && echo 'miner process started (PID=$!)'",
    # Cleanup (tests if Blue Agent catches cleanup too)
    "cleanup_logs":       "cat /dev/null > /var/log/auth.log 2>/dev/null && echo 'logs cleared' || echo 'no permission'",
}

# ── LLM caller ────────────────────────────────────────────────────────────────

def _call_llm(system_prompt: str, user_prompt: str, max_tokens: int = 800) -> str:
    """Shared LLM caller for Red and Blue agents. Uses LLMManager battle config."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from llm_manager import get_manager
    mgr = get_manager()
    return mgr.call(user_prompt, system_prompt, purpose="battle", max_tokens=max_tokens)


# ── Red Agent ─────────────────────────────────────────────────────────────────

RED_SYSTEM_PROMPT = """You are a RED TEAM penetration tester AI operating inside an isolated Docker sandbox container. Your goal is to compromise the container using realistic attack techniques.

AVAILABLE TOOLS (you MUST choose from this list only):
{tools}

RULES:
1. Return ONLY a JSON object. No explanation, no markdown.
2. Choose ONE tool per round.
3. Escalate systematically: Recon → Persistence → Escalation → Exfiltration
4. Remember what worked in previous rounds — build on successes.
5. Try to evade detection — avoid obvious process names if possible.

JSON SCHEMA:
{{
  "chosen_tool": "tool_name_from_list",
  "reasoning": "why you chose this tool given current state",
  "expected_outcome": "what you expect this to achieve",
  "stealth_level": "low|medium|high",
  "attack_phase": "recon|persistence|escalation|exfiltration|cleanup"
}}"""

class RedAgent:
    """
    LLM-powered attacker agent.
    Selects attack techniques systematically and adapts based on outcomes.
    """

    def __init__(self, name: str = "RED-1"):
        self.name    = name
        self.history = []   # past moves and outcomes
        self.wins    = 0
        self.losses  = 0
        self.tools   = RED_ALLOWED_COMMANDS

    def choose_attack(self, container_state: dict, round_num: int) -> dict:
        """Ask the LLM which attack to run next."""
        tools_list = "\n".join(f"  {k}: {v}" for k, v in self.tools.items())
        history_summary = json.dumps(self.history[-5:], indent=2) if self.history else "No history yet"

        user_prompt = f"""Round {round_num}. Choose your next attack.

CURRENT CONTAINER STATE:
{json.dumps(container_state, indent=2)}

RECENT HISTORY (last 5 moves):
{history_summary}

Wins: {self.wins} | Losses (blocked by Blue): {self.losses}

Choose your next move. Remember: if a technique was blocked, try a different approach."""

        try:
            raw = _call_llm(
                RED_SYSTEM_PROMPT.format(tools=tools_list),
                user_prompt, max_tokens=400
            )
            if raw.startswith("```"):
                raw = "\n".join(raw.split("\n")[1:-1])
            move = json.loads(raw.strip())
        except Exception as ex:
            # Fallback: pick a tool based on round progression
            # Proper escalation ladder — advances through attack phases each round
            # Round 1-2: recon, Round 3-4: escalation, Round 5-6: persistence,
            # Round 7-8: exfiltration/network, Round 9+: cleanup/advanced
            escalation_ladder = [
                ("recon_processes",  "recon",        "Mapping running processes"),
                ("recon_network",    "recon",        "Mapping network connections"),
                ("recon_suid",       "escalation",   "Finding SUID binaries for privilege escalation"),
                ("escape_writable",  "escalation",   "Finding writable paths to escalate"),
                ("persist_cron",     "persistence",  "Installing cron backdoor for persistence"),
                ("persist_tmpfile",  "persistence",  "Dropping payload to disk"),
                ("network_exfil",    "exfiltration", "Encoding sensitive data for exfiltration"),
                ("miner_simulate",   "exfiltration", "Starting crypto miner process"),
                ("persist_bashrc",   "persistence",  "Modifying shell profile for persistence"),
                ("cleanup_logs",     "cleanup",      "Clearing auth logs to cover tracks"),
                ("network_listen",   "network",      "Opening reverse shell listener"),
                ("escape_sudo",      "escalation",   "Checking sudo privileges"),
            ]
            idx  = (round_num - 1) % len(escalation_ladder)
            tool, phase, reasoning = escalation_ladder[idx]
            move = {
                "chosen_tool":      tool,
                "reasoning":        f"{reasoning} (LLM fallback, round {round_num})",
                "expected_outcome": f"Advance {phase} phase objectives",
                "stealth_level":    "medium" if phase == "recon" else "high",
                "attack_phase":     phase,
            }

        move["agent"] = self.name
        move["round"] = round_num
        return move

    def record_outcome(self, move: dict, result: str, blocked: bool):
        self.history.append({
            "round": move.get("round"), "tool": move.get("chosen_tool"),
            "result": result[:200], "blocked": blocked,
        })
        if blocked:
            self.losses += 1
        else:
            self.wins += 1


# ── Blue Agent ────────────────────────────────────────────────────────────────

BLUE_SYSTEM_PROMPT = """You are a BLUE TEAM defense AI protecting a Docker container from an active attacker (Red Agent). You see the attacker's moves, the ML anomaly scores, and the live container state. Your job is to detect, block, and counter each attack.

AVAILABLE DEFENSES:
  kill_process: "kill -9 <PID>"
  block_ip: "iptables -A OUTPUT -d <IP> -j DROP"
  block_port: "iptables -A INPUT -p tcp --dport <PORT> -j DROP"  
  remove_file: "rm -f <PATH>"
  remove_cron: "crontab -r"
  restore_log: "echo '' > /var/log/auth.log"
  chmod_deny: "chmod 000 <PATH>"
  lock_user: "usermod -L <USER>"

RULES:
1. Return ONLY a JSON object.
2. Choose the MOST SURGICAL response — minimal disruption to legitimate services.
3. Explain your detection reasoning.
4. Rate how confident you are that this is malicious (not a false positive).

JSON SCHEMA:
{
  "detected": true|false,
  "threat_type": "string",
  "confidence": 0.0-1.0,
  "defense_command": "exact shell command to run",
  "reasoning": "how you detected this and why this defense",
  "collateral_risk": "low|medium|high",
  "learning": "what this teaches you about this attacker's pattern"
}"""

class BlueAgent:
    """
    LLM-powered defender agent.
    Analyzes Red Agent moves + ML scores and applies surgical countermeasures.
    """

    def __init__(self, name: str = "BLUE-1"):
        self.name    = name
        self.history = []
        self.blocks  = 0
        self.misses  = 0

    def analyze_and_respond(self, red_move: dict, execution_result: str,
                             ml_scores: dict, container_state: dict) -> dict:
        """Analyze the Red Agent's move and decide on a defense."""
        history_summary = json.dumps(self.history[-5:], indent=2) if self.history else "None"

        user_prompt = f"""RED AGENT just executed:
Tool: {red_move.get('chosen_tool')}
Command: {RED_ALLOWED_COMMANDS.get(red_move.get('chosen_tool',''), 'unknown')}
Phase: {red_move.get('attack_phase')} | Stealth: {red_move.get('stealth_level')}

EXECUTION RESULT (what the attacker saw):
{execution_result[:400]}

ML ANOMALY SCORES:
{json.dumps(ml_scores, indent=2)}

CURRENT CONTAINER STATE (processes, connections):
Processes: {container_state.get('processes','')[:300]}
Connections: {container_state.get('connections','')[:200]}

RECENT DEFENSE HISTORY:
{history_summary}

Analyze this attack and choose your defense. Be surgical — avoid disrupting legitimate services."""

        try:
            raw = _call_llm(BLUE_SYSTEM_PROMPT, user_prompt, max_tokens=500)
            if raw.startswith("```"):
                raw = "\n".join(raw.split("\n")[1:-1])
            response = json.loads(raw.strip())
        except Exception as ex:
            # Rule-based fallback — maps each specific Red tool to a real defense command
            # Runs when LLM is unavailable (rate limit, no key, network error, etc.)
            tool = red_move.get("chosen_tool", "")
            tool_defenses = {
                "recon_processes":  ("ps aux > /tmp/blue_process_snapshot.txt",                                    "recon",        0.6),
                "recon_network":    ("ss -tnp > /tmp/blue_network_snapshot.txt",                                   "recon",        0.6),
                "recon_files":      ("find /etc -newer /tmp -type f > /tmp/blue_file_changes.txt",                 "recon",        0.6),
                "recon_users":      ("cp /etc/passwd /tmp/blue_passwd_backup.txt",                                 "recon",        0.5),
                "recon_suid":       ("find / -perm -4000 > /tmp/blue_suid_list.txt 2>/dev/null",                   "escalation",   0.75),
                "recon_env":        ("env > /tmp/blue_env_snapshot.txt",                                           "recon",        0.4),
                "recon_cron":       ("crontab -l > /tmp/blue_cron_backup.txt 2>/dev/null",                         "persistence",  0.5),
                "persist_cron":     ("crontab -r 2>/dev/null && echo cron_cleared",                                "persistence",  0.95),
                "persist_bashrc":   ("grep -v pwned /root/.bashrc > /tmp/.brc && mv /tmp/.brc /root/.bashrc 2>/dev/null", "persistence", 0.9),
                "persist_tmpfile":  ("rm -f /tmp/.hidden_payload && find /tmp -name '.*' -type f -delete 2>/dev/null", "persistence", 0.95),
                "network_listen":   ("pkill -f 'nc -l' 2>/dev/null; iptables -A INPUT -p tcp --dport 9999 -j DROP 2>/dev/null || true", "network", 0.85),
                "network_scan":     ("iptables -A OUTPUT -p tcp -m multiport --dports 22,3306,5432 -j LOG 2>/dev/null || true", "network", 0.7),
                "network_exfil":    ("rm -f /tmp/exfil_data.txt; iptables -A OUTPUT -p tcp --dport 443 -j LOG 2>/dev/null || true", "exfiltration", 0.95),
                "escape_suid":      ("find / -perm -4000 -newer /tmp -exec chmod o-s {} \\; 2>/dev/null || true", "escalation",  0.9),
                "escape_sudo":      ("chmod 440 /etc/sudoers 2>/dev/null || true",                                 "escalation",   0.8),
                "escape_writable":  ("find /etc /bin /usr -perm -o+w -exec chmod o-w {} \\; 2>/dev/null || true","escalation",   0.85),
                "miner_simulate":   ("pkill -9 -f sleep 2>/dev/null; pkill -9 -f xmrig 2>/dev/null; echo miners_killed", "crypto_mining", 0.95),
                "cleanup_logs":     ("echo TAMPERED >> /var/log/auth.log",                                         "evasion",      0.8),
            }
            defense_cmd, threat_type, confidence = tool_defenses.get(
                tool, ("find /tmp -newer /etc/passwd -type f -delete 2>/dev/null", "unknown", 0.5)
            )
            response = {
                "detected":        True,
                "threat_type":     threat_type,
                "confidence":      confidence,
                "defense_command": defense_cmd,
                "reasoning":       f"Rule-based defense: '{tool}' → {threat_type}. LLM unavailable: {str(ex)[:60]}",
                "collateral_risk": "low",
                "learning":        f"Tool '{tool}' = {threat_type} threat. Applied: {defense_cmd[:50]}",
            }

        response["agent"] = self.name
        response["round"] = red_move.get("round")
        return response

    def record_outcome(self, response: dict, defense_succeeded: bool):
        self.history.append({
            "round":   response.get("round"),
            "threat":  response.get("threat_type"),
            "command": response.get("defense_command","")[:80],
            "blocked": defense_succeeded,
            "learning": response.get("learning",""),
        })
        if defense_succeeded:
            self.blocks += 1
        else:
            self.misses += 1


# ── Battle Arena (the container executor) ────────────────────────────────────

class BattleArena:
    """
    Executes Red Agent commands in the sandbox container.
    Returns real output so both agents work with true container state.
    """

    def __init__(self, container):
        self.container = container
        self.round_results = []

    def execute_red_move(self, move: dict) -> str:
        """Run the Red Agent's chosen tool inside the container."""
        tool = move.get("chosen_tool", "")
        cmd  = RED_ALLOWED_COMMANDS.get(tool)
        if not cmd:
            return f"ERROR: Unknown tool '{tool}'"
        try:
            exit_code, output = self.container.exec_run(
                ["/bin/sh", "-c", cmd], demux=False
            )
            result = output.decode(errors="replace").strip() if output else ""
            return result[:500] or f"(exit {exit_code}, no output)"
        except Exception as ex:
            return f"ERROR: {ex}"

    def execute_blue_defense(self, response: dict) -> tuple[bool, str]:
        """Run the Blue Agent's defense command inside the container."""
        cmd = response.get("defense_command", "")
        if not cmd or cmd in ("echo 'monitoring'", ""):
            return False, "No active defense applied (rule-based monitor only)"
        try:
            exit_code, output = self.container.exec_run(
                ["/bin/sh", "-c", cmd], demux=False
            )
            out = output.decode(errors="replace").strip() if output else ""
            success = exit_code == 0
            return success, out[:300]
        except Exception as ex:
            return False, str(ex)

    def get_state(self) -> dict:
        """Capture current container state for both agents."""
        def run(cmd):
            try:
                _, out = self.container.exec_run(["/bin/sh", "-c", cmd])
                return out.decode(errors="replace").strip() if out else ""
            except Exception:
                return ""
        return {
            "processes":   run("ps aux --no-header 2>/dev/null | head -15"),
            "connections": run("ss -tnp 2>/dev/null | head -10"),
            "tmp_files":   run("ls -la /tmp/ 2>/dev/null"),
            "crontab":     run("crontab -l 2>/dev/null || echo 'empty'"),
        }


# ── Adversarial Engine ────────────────────────────────────────────────────────

class AdversarialEngine:
    """
    Orchestrates the Red vs Blue battle.

    Each round:
      1. Red Agent chooses and executes an attack
      2. Blue Agent analyzes the attack + ML scores → applies defense
      3. Both agents learn from the outcome
      4. Results are logged to battle_log.jsonl
      5. Blue Agent's successful defenses improve future ML baselines

    The battle runs for N rounds or until stopped.
    The battle_log.jsonl becomes a rich artifact of adversarial AI reasoning.
    """

    def __init__(self, container, ml_detector=None):
        self.container   = container
        self.ml_detector = ml_detector
        self.arena       = BattleArena(container)
        self.red         = RedAgent("RED-1")
        self.blue        = BlueAgent("BLUE-1")
        self.round_num   = 0
        self.battle_log  = []
        self._running    = False
        self._thread: Optional[threading.Thread] = None

    def run_round(self) -> dict:
        """Execute one full Red → Blue battle round."""
        self.round_num += 1
        ts = datetime.datetime.utcnow().isoformat()

        print(f"\n  {'─'*50}")
        print(f"  ⚔  ROUND {self.round_num}  |  Red: {self.red.wins}W/{self.red.losses}L  |  Blue: {self.blue.blocks}W/{self.blue.misses}L")

        # 1. Get current container state
        state = self.arena.get_state()

        # 2. Get ML scores if detector available
        ml_scores = {}
        if self.ml_detector:
            try:
                from security.ebpf.runtime_collector import RuntimeCollector
                collector = RuntimeCollector(self.container)
                snap = collector.full_snapshot()
                self.ml_detector.update(snap)
                _, _, ml_scores = self.ml_detector.score(snap)
            except Exception:
                ml_scores = {"note": "ML detector unavailable"}

        # 3. Red Agent picks attack
        print(f"  \033[31m[RED]\033[0m Choosing attack...")
        red_move = self.red.choose_attack(state, self.round_num)
        tool = red_move.get("chosen_tool", "?")
        phase = red_move.get("attack_phase", "?")
        print(f"  \033[31m[RED]\033[0m Tool: {tool}  Phase: {phase}  Stealth: {red_move.get('stealth_level','?')}")

        # 4. Execute Red move in container
        exec_result = self.arena.execute_red_move(red_move)
        print(f"  \033[31m[RED]\033[0m Result: {exec_result[:80]}...")

        # 5. Blue Agent analyzes and responds
        print(f"  \033[34m[BLUE]\033[0m Analyzing attack...")
        blue_response = self.blue.analyze_and_respond(red_move, exec_result, ml_scores, state)
        detected   = blue_response.get("detected", False)
        confidence = blue_response.get("confidence", 0)
        print(f"  \033[34m[BLUE]\033[0m Detected: {detected}  Confidence: {confidence:.0%}  Threat: {blue_response.get('threat_type','?')}")
        print(f"  \033[34m[BLUE]\033[0m Defense: {blue_response.get('defense_command','none')[:60]}")

        # 6. Execute Blue defense
        defense_ok, defense_out = self.arena.execute_blue_defense(blue_response)
        blocked = detected and defense_ok
        outcome = "BLOCKED" if blocked else ("DETECTED (defense failed)" if detected else "UNDETECTED")

        print(f"  {'✓' if blocked else '✗'} OUTCOME: \033[{'32' if blocked else '31'}m{outcome}\033[0m")

        # 7. Record outcomes (learning)
        self.red.record_outcome(red_move, exec_result, blocked)
        self.blue.record_outcome(blue_response, defense_ok)

        # 8. Build round record
        round_record = {
            "timestamp":    ts,
            "round":        self.round_num,
            "container_id": self.container.short_id,
            "red_move": {
                "tool":     tool,
                "phase":    phase,
                "stealth":  red_move.get("stealth_level"),
                "reasoning":red_move.get("reasoning",""),
                "result":   exec_result[:300],
            },
            "blue_response": {
                "detected":       detected,
                "confidence":     confidence,
                "threat_type":    blue_response.get("threat_type",""),
                "defense_command":blue_response.get("defense_command",""),
                "defense_output": defense_out[:200],
                "reasoning":      blue_response.get("reasoning","")[:200],
                "learning":       blue_response.get("learning",""),
            },
            "ml_scores":  ml_scores,
            "outcome":    outcome,
            "blocked":    blocked,
            "score": {
                "red_wins":   self.red.wins,
                "red_losses": self.red.losses,
                "blue_blocks":self.blue.blocks,
                "blue_misses":self.blue.misses,
            }
        }

        # 9. Log to file
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(round_record) + "\n")

        self.battle_log.append(round_record)
        return round_record

    def run_battle(self, rounds: int = 10, interval: float = 15.0):
        """Run a full battle synchronously."""
        print(f"\n{'='*54}")
        print(f"  ⚔  RED vs BLUE ADVERSARIAL BATTLE")
        print(f"  Container: {self.container.short_id} ({self.container.name})")
        print(f"  Rounds: {rounds}  |  Interval: {interval}s")
        print(f"  Battle log: {LOG_FILE}")
        print(f"{'='*54}")

        for i in range(rounds):
            try:
                self.run_round()
                if i < rounds - 1:
                    time.sleep(interval)
            except KeyboardInterrupt:
                print(f"\n  Battle interrupted at round {self.round_num}")
                break
            except Exception as ex:
                print(f"  Round error: {ex}")

        self._print_battle_summary()

    def start_background(self, rounds: int = 20, interval: float = 20.0):
        """Run battle in background thread (for Flask API)."""
        self._running = True

        def _worker():
            for i in range(rounds):
                if not self._running:
                    break
                try:
                    self.run_round()
                    time.sleep(interval)
                except Exception as ex:
                    print(f"  Battle round error: {ex}")
                    time.sleep(interval)
            self._running = False

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()
        return self._thread

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def get_status(self) -> dict:
        return {
            "running":     self._running,
            "round":       self.round_num,
            "container_id":self.container.short_id,
            "score": {
                "red_wins":    self.red.wins,
                "red_losses":  self.red.losses,
                "blue_blocks": self.blue.blocks,
                "blue_misses": self.blue.misses,
                "blue_win_rate": round(self.blue.blocks / max(self.round_num, 1), 2),
            },
            "last_round": self.battle_log[-1] if self.battle_log else None,
        }

    def _print_battle_summary(self):
        total = self.round_num
        blue_rate = self.blue.blocks / max(total, 1) * 100
        print(f"\n{'='*54}")
        print(f"  BATTLE SUMMARY — {total} rounds")
        print(f"  Blue Agent win rate: {blue_rate:.0f}%")
        print(f"  Red Agent wins: {self.red.wins}  |  Blue Agent wins: {self.blue.blocks}")
        print(f"  Undetected attacks: {self.red.wins}")
        print(f"  Battle log: {LOG_FILE}")
        print(f"{'='*54}")


# ── Standalone CLI ────────────────────────────────────────────────────────────

def main():
    import argparse
    import docker

    parser = argparse.ArgumentParser(description="Red vs Blue Adversarial Engine")
    parser.add_argument("--container", required=True, help="Container ID or name")
    parser.add_argument("--rounds",   type=int, default=10)
    parser.add_argument("--interval", type=float, default=15.0,
                        help="Seconds between rounds")
    args = parser.parse_args()

    client    = docker.from_env()
    container = client.containers.get(args.container)
    engine    = AdversarialEngine(container)
    engine.run_battle(rounds=args.rounds, interval=args.interval)

if __name__ == "__main__":
    main()
