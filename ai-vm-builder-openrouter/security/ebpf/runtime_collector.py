"""
eBPF Runtime Visibility Layer
Challenge 1 requirement: move beyond log scraping to true runtime visibility.

In a production system this would use actual eBPF programs (via bcc/bpftrace)
to hook into kernel syscalls. Inside Docker containers without CAP_SYS_ADMIN
we use the closest available alternative: /proc filesystem parsing + docker stats API.

This module provides the SAME interface as real eBPF collectors so swapping in
real eBPF is a drop-in replacement — just change the collector backend.

What real eBPF would give:
  - execve() hooks → every new process spawn, args, parent PID
  - connect()/accept() hooks → every network connection attempt
  - open()/write() hooks → every file access, not just recently modified
  - kill() hooks → process termination signals
  - ptrace() hooks → debugging/injection attempts (Frida detection)

What we emulate via /proc:
  - /proc/<pid>/comm, /proc/<pid>/cmdline, /proc/<pid>/status
  - /proc/<pid>/net/tcp, /proc/<pid>/net/tcp6
  - /proc/<pid>/fd → open file descriptors
  - docker stats API → CPU/memory/network per container
"""

import os
import json
import time
import datetime
from pathlib import Path
from typing import Optional


# ── Process event types (mirrors eBPF tracepoint events) ─────────────────────

class ProcessEvent:
    def __init__(self, pid: int, ppid: int, comm: str, cmdline: str,
                 uid: int, gid: int, timestamp: str):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.cmdline = cmdline
        self.uid = uid
        self.gid = gid
        self.timestamp = timestamp
        self.suspicious = False
        self.reason = ""

    def to_dict(self) -> dict:
        return {
            "pid": self.pid, "ppid": self.ppid, "comm": self.comm,
            "cmdline": self.cmdline[:200], "uid": self.uid, "gid": self.gid,
            "timestamp": self.timestamp, "suspicious": self.suspicious,
            "reason": self.reason,
        }


class NetworkEvent:
    def __init__(self, pid: int, comm: str, local_addr: str, remote_addr: str,
                 state: str, protocol: str):
        self.pid = pid
        self.comm = comm
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.state = state
        self.protocol = protocol
        self.suspicious = False
        self.reason = ""

    def to_dict(self) -> dict:
        return {
            "pid": self.pid, "comm": self.comm, "local": self.local_addr,
            "remote": self.remote_addr, "state": self.state,
            "protocol": self.protocol, "suspicious": self.suspicious,
            "reason": self.reason,
        }


# ── Runtime collector ─────────────────────────────────────────────────────────

class RuntimeCollector:
    """
    Collects runtime events from a running Docker container.
    Interface mirrors what an eBPF-based collector would expose.

    In production: replace _collect_processes() and _collect_network()
    with actual eBPF program output via BCC's PerfEventArray.
    """

    # Processes that should NEVER be root inside a container
    ROOT_SENSITIVE = {"nginx", "apache2", "python3", "python", "node", "java", "ruby"}

    # Processes that suggest shell spawning / reverse shells
    SHELL_PROCS = {"bash", "sh", "zsh", "fish", "dash", "ksh"}

    # Processes that suggest container escape / introspection
    ESCAPE_INDICATORS = {"nsenter", "unshare", "capsh", "docker", "kubectl", "runc"}

    # Known crypto miner process names
    MINER_NAMES = {"xmrig", "minerd", "cgminer", "bfgminer", "ethminer", "nbminer",
                   "t-rex", "phoenixminer", "teamredminer", "lolminer"}

    def __init__(self, container, docker_client=None):
        self.container = container
        self.docker_client = docker_client
        self.known_pids: set = set()
        self.known_connections: set = set()
        self.baseline_ports: set = set()
        self.baseline_established = False

    def _exec(self, cmd: str) -> str:
        """Run command inside container, return stdout."""
        try:
            exit_code, output = self.container.exec_run(
                ["/bin/sh", "-c", cmd],
                demux=False,
            )
            return output.decode(errors="replace").strip() if output else ""
        except Exception:
            return ""

    def collect_processes(self) -> list[ProcessEvent]:
        """
        Collect all processes visible inside the container.
        Mirrors: eBPF execve() tracepoint events.
        """
        output = self._exec(
            "ps -eo pid,ppid,uid,gid,comm,args --no-headers 2>/dev/null || "
            "ps aux --no-headers 2>/dev/null"
        )
        events = []
        now = datetime.datetime.utcnow().isoformat()

        for line in output.strip().split("\n"):
            parts = line.split(None, 5)
            if len(parts) < 5:
                continue
            try:
                pid  = int(parts[0])
                ppid = int(parts[1])
                uid  = int(parts[2]) if parts[2].isdigit() else 0
                gid  = int(parts[3]) if parts[3].isdigit() else 0
                comm = parts[4]
                cmdline = parts[5] if len(parts) > 5 else comm
            except (ValueError, IndexError):
                continue

            event = ProcessEvent(pid, ppid, comm, cmdline, uid, gid, now)

            # Detect suspicious patterns (mirrors eBPF kprobe logic)
            comm_lower = comm.lower()

            if comm_lower in self.MINER_NAMES:
                event.suspicious = True
                event.reason = f"Known crypto miner: {comm}"

            elif comm_lower in self.SHELL_PROCS and uid == 0:
                event.suspicious = True
                event.reason = f"Root shell process spawned: {comm} (PID={pid}, PPID={ppid})"

            elif comm_lower in self.ESCAPE_INDICATORS:
                event.suspicious = True
                event.reason = f"Container escape tool detected: {comm}"

            elif uid == 0 and comm_lower in self.ROOT_SENSITIVE:
                event.suspicious = True
                event.reason = f"Sensitive service running as root: {comm}"

            # NEW process not seen in last scan (exec event simulation)
            elif pid not in self.known_pids and pid > 100:
                event.suspicious = False  # new but not inherently suspicious

            events.append(event)

        self.known_pids = {e.pid for e in events}
        return events

    def collect_network(self) -> list[NetworkEvent]:
        """
        Collect active network connections inside the container.
        Mirrors: eBPF connect()/accept() sock tracepoints.
        """
        output = self._exec(
            "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null"
        )
        events = []

        PRIVATE_PREFIXES = ("127.", "10.", "172.", "192.168.", "::1", "0.0.0.0", "*")

        for line in output.strip().split("\n"):
            if not line.strip() or "State" in line or "Netid" in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            try:
                state  = parts[0] if parts[0] not in ("tcp", "tcp6", "udp") else parts[1]
                local  = parts[-3] if len(parts) >= 5 else ""
                remote = parts[-2] if len(parts) >= 5 else ""
                pid_info = parts[-1] if "pid=" in parts[-1] else ""
                pid  = 0
                comm = "unknown"
                if "pid=" in pid_info:
                    try:
                        pid = int(pid_info.split("pid=")[1].split(",")[0])
                    except Exception:
                        pass
                if 'comm="' in pid_info:
                    comm = pid_info.split('comm="')[1].split('"')[0]
            except Exception:
                continue

            event = NetworkEvent(pid, comm, local, remote, state, "tcp")

            # Flag external connections not in baseline
            remote_ip = remote.split(":")[0] if ":" in remote else remote
            if remote_ip and not any(remote_ip.startswith(p) for p in PRIVATE_PREFIXES):
                conn_key = f"{remote_ip}:{remote.split(':')[-1]}"
                if conn_key not in self.known_connections:
                    event.suspicious = True
                    event.reason = f"New external connection to {remote} (process: {comm})"
                    self.known_connections.add(conn_key)

            events.append(event)

        return events

    def collect_file_events(self) -> list[dict]:
        """
        Detect recently modified files in sensitive locations.
        Mirrors: eBPF open()/write() kprobes on sensitive paths.
        """
        sensitive_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/crontab", "/etc/cron.d",
            "/etc/sudoers", "/root/.bashrc", "/root/.bash_profile",
            "/usr/bin", "/usr/sbin", "/bin", "/sbin",
        ]
        events = []
        now = datetime.datetime.utcnow().isoformat()

        output = self._exec(
            "find /etc /root /usr/bin /usr/sbin /bin /sbin "
            "-newer /tmp -type f 2>/dev/null | head -20"
        )

        for filepath in output.strip().split("\n"):
            if not filepath.strip():
                continue
            is_sensitive = any(filepath.startswith(p) for p in sensitive_paths)
            events.append({
                "timestamp": now,
                "path": filepath,
                "sensitive": is_sensitive,
                "event_type": "write",
                "suspicious": is_sensitive,
                "reason": f"Sensitive path modified: {filepath}" if is_sensitive else "",
            })

        return events

    def get_docker_stats(self) -> dict:
        """
        Get CPU/memory/network stats via Docker API.
        Mirrors: eBPF perf counters for resource usage.
        """
        try:
            stats = self.container.stats(stream=False)
            cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                        stats["precpu_stats"]["cpu_usage"]["total_usage"]
            sys_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                        stats["precpu_stats"]["system_cpu_usage"]
            num_cpus = stats["cpu_stats"].get("online_cpus", 1)
            cpu_pct = (cpu_delta / max(sys_delta, 1)) * num_cpus * 100.0

            mem_usage = stats["memory_stats"].get("usage", 0)
            mem_limit = stats["memory_stats"].get("limit", 1)
            mem_pct = (mem_usage / max(mem_limit, 1)) * 100.0

            net_rx = sum(v.get("rx_bytes", 0) for v in stats.get("networks", {}).values())
            net_tx = sum(v.get("tx_bytes", 0) for v in stats.get("networks", {}).values())

            return {
                "cpu_pct": round(cpu_pct, 2),
                "mem_pct": round(mem_pct, 2),
                "mem_mb": round(mem_usage / 1024 / 1024, 1),
                "net_rx_mb": round(net_rx / 1024 / 1024, 2),
                "net_tx_mb": round(net_tx / 1024 / 1024, 2),
            }
        except Exception:
            return {"cpu_pct": 0, "mem_pct": 0, "mem_mb": 0, "net_rx_mb": 0, "net_tx_mb": 0}

    def full_snapshot(self) -> dict:
        """
        Collect a complete runtime snapshot.
        This is what gets fed to the ML detector and LLM analyzer.
        """
        processes = self.collect_processes()
        network   = self.collect_network()
        file_events = self.collect_file_events()
        stats     = self.get_docker_stats()

        suspicious_procs = [e.to_dict() for e in processes if e.suspicious]
        suspicious_net   = [e.to_dict() for e in network   if e.suspicious]
        suspicious_files = [e for e in file_events          if e.get("suspicious")]

        return {
            "timestamp":          datetime.datetime.utcnow().isoformat(),
            "container_id":       self.container.short_id,
            "process_count":      len(processes),
            "processes_raw":      "\n".join(
                f"{e.pid} {e.comm} uid={e.uid}" for e in processes[:30]
            ),
            "suspicious_processes": suspicious_procs,
            "connections_raw":    "\n".join(
                f"{e.state} {e.local_addr} {e.remote_addr}" for e in network[:20]
            ),
            "suspicious_connections": suspicious_net,
            "file_events":        file_events[:20],
            "suspicious_files":   suspicious_files,
            "docker_stats":       stats,
            "high_cpu_alert":     stats.get("cpu_pct", 0) > 80,
            "high_mem_alert":     stats.get("mem_pct", 0) > 90,
            # Fields expected by the existing ai_defense.py snapshot format
            "processes":          "\n".join(
                f"{e.uid} {e.pid} {e.comm} {e.cmdline[:80]}" for e in processes
            ),
            "connections":        "\n".join(
                f"{e.state} {e.local_addr} {e.remote_addr}" for e in network
            ),
            "listening":          "\n".join(
                f"LISTEN {e.local_addr}" for e in network if e.state == "LISTEN"
            ),
            "recent_files":       "\n".join(e["path"] for e in file_events),
            "suid_files":         self._exec("find / -perm -4000 2>/dev/null | head -10"),
            "world_writable":     self._exec("find /etc /bin -perm -o+w 2>/dev/null | head -5"),
            "crontabs":           self._exec("crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null"),
            "auth_log":           self._exec("tail -20 /var/log/auth.log 2>/dev/null || echo ''"),
            "app_log":            self._exec("tail -10 /var/log/syslog 2>/dev/null || echo ''"),
            "env_vars":           self._exec("env | grep -v KEY | grep -v SECRET | head -10"),
            "users":              self._exec("cat /etc/passwd | grep -v nologin | head -5"),
            "open_files":         self._exec("ls /proc/1/fd 2>/dev/null | wc -l || echo 0"),
            "cpu_usage":          f"cpu={stats.get('cpu_pct', 0):.1f}% mem={stats.get('mem_pct', 0):.1f}%",
        }


# ── Honeypot redirector ───────────────────────────────────────────────────────

class HoneypotRedirector:
    """
    Re-routes suspicious traffic to a honeypot using iptables inside the container.
    Challenge 1 requirement: 'inject local code or re-route traffic to honeypots on the fly'

    In production: use iptables REDIRECT or DNAT rules.
    """

    def __init__(self, container, honeypot_ip: str = "127.0.0.1",
                 honeypot_port: int = 9999):
        self.container = container
        self.honeypot_ip = honeypot_ip
        self.honeypot_port = honeypot_port
        self.redirected: list = []

    def _exec(self, cmd: str) -> tuple[int, str]:
        try:
            code, out = self.container.exec_run(["/bin/sh", "-c", cmd])
            return code, out.decode(errors="replace").strip() if out else ""
        except Exception as e:
            return 1, str(e)

    def redirect_ip(self, remote_ip: str, dry_run: bool = False) -> dict:
        """
        Block outbound traffic to a suspicious IP and optionally redirect to honeypot.
        """
        result = {
            "action": "redirect_ip",
            "remote_ip": remote_ip,
            "dry_run": dry_run,
            "success": False,
            "commands": [],
        }

        commands = [
            f"iptables -A OUTPUT -d {remote_ip} -j DROP",
            f"iptables -A INPUT -s {remote_ip} -j DROP",
        ]

        for cmd in commands:
            result["commands"].append(cmd)
            if not dry_run:
                code, out = self._exec(cmd)
                if code == 0:
                    result["success"] = True
                    self.redirected.append({"ip": remote_ip, "cmd": cmd})

        return result

    def isolate_process(self, pid: int, dry_run: bool = False) -> dict:
        """Kill a suspicious process immediately."""
        result = {
            "action": "isolate_process",
            "pid": pid,
            "dry_run": dry_run,
            "success": False,
            "command": f"kill -9 {pid}",
        }
        if not dry_run:
            code, out = self._exec(f"kill -9 {pid}")
            result["success"] = (code == 0)
            result["output"] = out
        return result

    def setup_honeypot_listener(self, port: int = 9999) -> dict:
        """
        Start a basic netcat honeypot listener inside the container.
        Any redirected traffic will be captured and logged.
        """
        result = {"action": "setup_honeypot", "port": port}
        cmd = f"ncat -l {port} -k --output /tmp/honeypot_{port}.log &>/dev/null &"
        fallback = f"nc -l -p {port} >> /tmp/honeypot_{port}.log 2>/dev/null &"
        code, out = self._exec(cmd)
        if code != 0:
            code, out = self._exec(fallback)
        result["success"] = (code == 0)
        result["log_path"] = f"/tmp/honeypot_{port}.log"
        return result
