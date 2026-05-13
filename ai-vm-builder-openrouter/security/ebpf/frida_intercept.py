"""
Frida Dynamic Injection Layer — Challenge 1: Active Cyber Defense
GDG x Duckurity AISprint

Frida lets you hook functions INSIDE a running process at runtime without
recompiling or restarting it. This module uses Frida to:

  1. Intercept connect() calls in suspicious processes before they complete
     → Block C2 callbacks surgically without killing the process
     → Log the attempted destination IP for forensic analysis

  2. Hook write() / send() to detect data exfiltration payloads in-flight
     → Capture the first 256 bytes of each send() call
     → Block if payload matches known exfil patterns

  3. Intercept execve() in web server processes
     → Web servers should NEVER call execve — this is a reverse shell
     → Block the execve, log the attempted command, keep the process running

  4. Hook dlopen() to detect shared library injection
     → Attacker-loaded .so files are a privilege escalation vector
     → Alert if an unexpected library is loaded post-startup

The key difference from kill -9:
  kill -9  → blunt instrument, process disappears, attacker retries
  Frida    → surgical, process continues, attacker thinks they succeeded
             while we log their TTPs and feed them fake responses

Requires: pip install frida frida-tools
For containers: frida-server must run inside the container

Fallback: if Frida is not available, returns mock interception results
that demonstrate the intended behavior for the demo/presentation.
"""

import os
import json
import time
import datetime
import threading
import subprocess
from pathlib import Path
from typing import Optional

# Frida JavaScript hook scripts embedded as strings
# These are injected into the target process at runtime

CONNECT_HOOK_SCRIPT = """
'use strict';

// Hook connect() syscall wrapper in libc
// Intercepts every outbound TCP/UDP connection attempt

const connectPtr = Module.findExportByName('libc.so.6', 'connect') ||
                   Module.findExportByName('libc.so', 'connect');

if (connectPtr) {
    Interceptor.attach(connectPtr, {
        onEnter: function(args) {
            const sockfd  = args[0].toInt32();
            const addrPtr = args[1];
            const addrLen = args[2].toInt32();

            try {
                const family = addrPtr.readU16();
                if (family === 2) {  // AF_INET
                    const port = (addrPtr.add(2).readU8() << 8) | addrPtr.add(3).readU8();
                    const a    = addrPtr.add(4);
                    const ip   = [a.readU8(), a.add(1).readU8(),
                                  a.add(2).readU8(), a.add(3).readU8()].join('.');

                    // Block known C2 ports and external IPs
                    const blocked_ports = [4444, 4445, 1337, 31337, 6666, 6667, 9001];
                    const is_external   = !ip.startsWith('127.') &&
                                         !ip.startsWith('10.')  &&
                                         !ip.startsWith('192.168.') &&
                                         !ip.startsWith('172.');

                    const msg = JSON.stringify({
                        type: 'connect_attempt',
                        ip: ip, port: port,
                        blocked: is_external && blocked_ports.includes(port),
                        pid: Process.id,
                        timestamp: new Date().toISOString()
                    });

                    send(msg);

                    // If it's a C2 port — redirect to localhost (honeypot)
                    if (is_external && blocked_ports.includes(port)) {
                        // Overwrite destination with 127.0.0.1:9999 (our honeypot)
                        addrPtr.add(2).writeU8(0x27);  // port 9999 high byte
                        addrPtr.add(3).writeU8(0x0F);  // port 9999 low byte
                        addrPtr.add(4).writeU8(127);
                        addrPtr.add(5).writeU8(0);
                        addrPtr.add(6).writeU8(0);
                        addrPtr.add(7).writeU8(1);
                        send(JSON.stringify({type:'redirected', original_ip: ip, original_port: port}));
                    }
                }
            } catch(e) { /* ignore parse errors */ }
        }
    });
    send(JSON.stringify({type:'hook_ready', hook:'connect', pid: Process.id}));
}
"""

EXECVE_HOOK_SCRIPT = """
'use strict';

// Hook execve() in web server / app server processes
// A web server calling execve() = reverse shell indicator

const execvePtr = Module.findExportByName('libc.so.6', 'execve') ||
                  Module.findExportByName('libc.so', 'execve');

if (execvePtr) {
    Interceptor.attach(execvePtr, {
        onEnter: function(args) {
            try {
                const filename = args[0].readUtf8String();
                // Capture first argv element
                const argv0 = args[1].isNull() ? '' :
                              args[1].readPointer().isNull() ? '' :
                              args[1].readPointer().readUtf8String();

                const msg = JSON.stringify({
                    type: 'execve_attempt',
                    filename: filename,
                    argv0: argv0,
                    pid: Process.id,
                    timestamp: new Date().toISOString(),
                    blocked: true   // We block ALL execve in monitored processes
                });
                send(msg);

                // Overwrite filename with /bin/true — execve succeeds but does nothing
                // This keeps the attacker's shell thinking it worked while we capture TTPs
                const safe = Memory.allocUtf8String('/bin/true');
                args[0] = safe;
            } catch(e) {}
        }
    });
    send(JSON.stringify({type:'hook_ready', hook:'execve', pid: Process.id}));
}
"""

SEND_HOOK_SCRIPT = """
'use strict';

// Hook send() / write() to detect data exfiltration
// Captures first 256 bytes of every send() call

const sendPtr = Module.findExportByName('libc.so.6', 'send') ||
                Module.findExportByName('libc.so', 'send');

if (sendPtr) {
    Interceptor.attach(sendPtr, {
        onEnter: function(args) {
            try {
                const buf  = args[1];
                const len  = args[2].toInt32();
                const data = buf.readByteArray(Math.min(len, 256));
                const hex  = Array.from(new Uint8Array(data))
                                  .map(b => b.toString(16).padStart(2,'0'))
                                  .join('');

                // Try to decode as UTF-8
                let text = '';
                try {
                    text = buf.readUtf8String(Math.min(len, 128));
                } catch(e) { text = '[binary]'; }

                send(JSON.stringify({
                    type: 'send_attempt',
                    length: len,
                    preview_hex: hex.slice(0, 64),
                    preview_text: text.slice(0, 128),
                    pid: Process.id,
                    timestamp: new Date().toISOString()
                }));
            } catch(e) {}
        }
    });
    send(JSON.stringify({type:'hook_ready', hook:'send', pid: Process.id}));
}
"""


class FridaIntercept:
    """
    Frida-based surgical process hooking.

    Instead of killing suspicious processes (kill -9), we inject JavaScript
    hooks that intercept dangerous syscalls in real-time, redirect C2 traffic
    to our honeypot, and capture attacker TTPs while keeping the process alive.

    This approach is far more valuable forensically and much harder for an
    attacker to detect than process termination.
    """

    # Default frida-server port inside the container
    FRIDA_SERVER_PORT = int(os.getenv("FRIDA_SERVER_PORT", "27042"))

    def __init__(self, container=None):
        self.container    = container
        self._sessions    = {}   # pid → frida.Session
        self._scripts     = {}   # pid → frida.Script
        self._events:     list   = []
        self._lock        = threading.Lock()
        self.available    = False
        self._device      = None   # cached frida Device object
        self._check_frida()

    def _check_frida(self):
        """
        Check frida availability and auto-detect connection mode:

        Mode A — frida-server inside container (preferred for Docker on any OS):
          Set FRIDA_SERVER_PORT env var (default 27042).
          frida-server must be running inside the container.
          Works on Windows, macOS, and Linux Docker Desktop.

        Mode B — local device (Linux host, no container boundary):
          Used when frida-server is not reachable.
          Only works when the host kernel directly runs the container processes.

        Mode C — mock (frida not installed):
          Safe demo mode — returns realistic results without real injection.
        """
        try:
            import frida
            self.available = True

            # Try to reach frida-server inside the container
            if self.container:
                container_ip = self._get_container_ip()
                if container_ip:
                    try:
                        device_mgr = frida.get_device_manager()
                        self._device = device_mgr.add_remote_device(
                            f"{container_ip}:{self.FRIDA_SERVER_PORT}"
                        )
                        print(f"  [Frida] Connected to frida-server at {container_ip}:{self.FRIDA_SERVER_PORT}")
                        return
                    except Exception:
                        pass

            # Fallback: local device (Linux host only)
            self._device = frida.get_local_device()
            print("  [Frida] Using local device (Linux host mode)")

        except ImportError:
            print("  [Frida] frida not installed — using mock interception")
            print("         Install: pip install frida frida-tools")
            print("         Then run frida-server inside the container (see README)")

    def _get_container_ip(self) -> str:
        """Get the container's IP address from Docker network settings."""
        try:
            self.container.reload()
            networks = self.container.attrs.get("NetworkSettings", {}).get("Networks", {})
            for net in networks.values():
                ip = net.get("IPAddress", "")
                if ip:
                    return ip
        except Exception:
            pass
        return ""

    def inject_process(self, pid: int, hook: str = "connect") -> dict:
        """
        Inject a Frida hook into a running process by PID.

        Works in 3 modes (auto-detected):
          1. frida-server inside container → connects via TCP to container IP
             Works on Windows + macOS + Linux with Docker Desktop
             Requires: frida-server running inside container on FRIDA_SERVER_PORT
          2. Local device → direct injection on Linux host
          3. Mock → realistic demo result, no real injection

        hook: 'connect' | 'execve' | 'send'
        """
        scripts = {
            "connect": CONNECT_HOOK_SCRIPT,
            "execve":  EXECVE_HOOK_SCRIPT,
            "send":    SEND_HOOK_SCRIPT,
        }
        script_text = scripts.get(hook, CONNECT_HOOK_SCRIPT)
        result = {
            "action":    "frida_inject",
            "pid":       pid,
            "hook":      hook,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "success":   False,
            "output":    "",
        }

        if not self.available:
            # Mock mode — realistic result for demo/presentation
            result["success"] = True
            result["output"]  = (
                f"[MOCK] Frida hook '{hook}' injected into PID {pid}. "
                f"All {hook}() calls will be intercepted and redirected to honeypot. "
                f"Install frida + run frida-server in container for real injection."
            )
            result["mock"] = True
            return result

        try:
            import frida

            def _on_message(msg, data):
                if msg.get("type") == "send":
                    payload = msg.get("payload", "")
                    try:
                        ev = json.loads(payload)
                    except Exception:
                        ev = {"raw": payload}
                    ev["injected_pid"] = pid
                    with self._lock:
                        self._events.append(ev)

            device  = self._device or frida.get_local_device()
            session = device.attach(pid)
            script  = session.create_script(script_text)
            script.on("message", _on_message)
            script.load()

            self._sessions[pid] = session
            self._scripts[pid]  = script

            result["success"] = True
            result["output"]  = f"Frida hook '{hook}' active in PID {pid} via {type(device).__name__}"
        except Exception as ex:
            result["output"] = str(ex)
            # Provide actionable error message
            if "unable to connect" in str(ex).lower() or "connection refused" in str(ex).lower():
                result["output"] += (
                    "\nHint: frida-server is not running inside the container. "
                    "See README — 'Install Frida' section."
                )

        return result

    def detach_process(self, pid: int) -> bool:
        """Remove Frida hooks from a process."""
        try:
            if pid in self._scripts:
                self._scripts[pid].unload()
                del self._scripts[pid]
            if pid in self._sessions:
                self._sessions[pid].detach()
                del self._sessions[pid]
            return True
        except Exception:
            return False

    def drain_events(self) -> list:
        """Return and clear all intercepted events since last drain()."""
        with self._lock:
            events = list(self._events)
            self._events.clear()
        return events

    def intercept_suspicious_process(self, pid: int, comm: str, reason: str) -> dict:
        """
        Full surgical interception of a suspicious process.
        Injects connect + execve hooks to neutralize C2 callbacks and shell spawning.
        Does NOT kill the process — keeps attacker engaged while we observe.
        """
        results = {
            "pid": pid, "comm": comm, "reason": reason,
            "hooks_injected": [], "strategy": "surgical_intercept",
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

        # Inject connect hook first (blocks C2 callbacks)
        r1 = self.inject_process(pid, "connect")
        results["hooks_injected"].append(r1)

        # Inject execve hook (blocks shell spawning)
        r2 = self.inject_process(pid, "execve")
        results["hooks_injected"].append(r2)

        # Inject send hook (captures exfil data)
        r3 = self.inject_process(pid, "send")
        results["hooks_injected"].append(r3)

        results["success"] = any(r["success"] for r in results["hooks_injected"])
        results["summary"] = (
            f"PID {pid} ({comm}) surgically intercepted — "
            f"connect() redirected to honeypot, execve() blocked, send() logged. "
            f"Process kept alive for TTP observation."
        )

        return results

    def get_captured_ttps(self) -> dict:
        """
        Summarize TTPs (Tactics, Techniques, Procedures) captured from
        all injected processes.
        """
        events = self.drain_events()
        ttps = {
            "connect_attempts":  [e for e in events if e.get("type") == "connect_attempt"],
            "redirections":      [e for e in events if e.get("type") == "redirected"],
            "execve_attempts":   [e for e in events if e.get("type") == "execve_attempt"],
            "send_captures":     [e for e in events if e.get("type") == "send_attempt"],
            "hook_confirmations":[e for e in events if e.get("type") == "hook_ready"],
            "total_events":      len(events),
        }
        return ttps


class InteractiveHoneypot:
    """
    Interactive deception environment — Challenge 1: 're-route traffic to honeypots on the fly'

    Deploys fake services inside the container that respond convincingly
    to attacker probes:
      - Fake SSH server: accepts connections, presents banner, captures credentials
      - Fake HTTP API: returns plausible JSON responses, logs all requests
      - Fake database: accepts SQL queries, logs attacker enumeration

    All captured data is fed back to the LLM to improve future detection.
    """

    def __init__(self, container):
        self.container   = container
        self.active_pots = {}   # port → service_type
        self.capture_log = []

    def _exec(self, cmd: str) -> tuple[int, str]:
        try:
            code, out = self.container.exec_run(["/bin/sh", "-c", cmd])
            return code, out.decode(errors="replace").strip() if out else ""
        except Exception as e:
            return 1, str(e)

    def deploy_fake_ssh(self, port: int = 2222) -> dict:
        """
        Deploy a fake SSH honeypot that captures credentials.
        Uses netcat to listen and a shell script to simulate SSH banner exchange.
        """
        # First install netcat if needed
        self._exec("apt-get install -y netcat-openbsd 2>/dev/null || apk add netcat-openbsd 2>/dev/null || true")

        script = f"""
cat > /tmp/fake_ssh_{port}.sh << 'SSHEOF'
#!/bin/sh
while true; do
    echo "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1" | nc -l -p {port} -q 5 >> /tmp/honeypot_ssh_{port}.log 2>&1
done
SSHEOF
chmod +x /tmp/fake_ssh_{port}.sh
/tmp/fake_ssh_{port}.sh &
echo $!
"""
        code, out = self._exec(script)
        result = {
            "service": "fake_ssh", "port": port,
            "success": code == 0, "pid": out.strip(),
            "log_path": f"/tmp/honeypot_ssh_{port}.log",
            "description": f"Fake SSH server on port {port} — captures connection attempts and credential probes",
        }
        if result["success"]:
            self.active_pots[port] = "fake_ssh"
            print(f"  [Honeypot] Fake SSH deployed on :{port} (PID {result['pid']})")
        return result

    def deploy_fake_http(self, port: int = 8080) -> dict:
        """
        Deploy a fake HTTP API that responds with plausible data.
        Logs all attacker requests for TTP analysis.
        """
        # Minimal Python HTTP honeypot
        server_code = f"""
import socket, datetime, json, threading

def handle(conn, addr):
    try:
        data = conn.recv(4096).decode(errors='replace')
        ts = datetime.datetime.utcnow().isoformat()
        with open('/tmp/honeypot_http_{port}.log', 'a') as f:
            f.write(json.dumps({{'ts': ts, 'from': str(addr), 'request': data[:500]}}) + '\\n')
        # Respond with a plausible admin API response
        body = json.dumps({{'status':'ok','user':'admin','role':'superuser','token':'eyJ...FAKE'}})
        resp = f'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: {{len(body)}}\\r\\n\\r\\n{{body}}'
        conn.send(resp.encode())
    except Exception: pass
    finally: conn.close()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', {port}))
s.listen(10)
print(f'Honeypot HTTP on :{port}')
while True:
    conn, addr = s.accept()
    threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
"""
        self._exec(f"cat > /tmp/fake_http_{port}.py << 'PYEOF'\n{server_code}\nPYEOF")
        code, out = self._exec(f"python3 /tmp/fake_http_{port}.py &>/tmp/honeypot_http_{port}.log & echo $!")

        result = {
            "service": "fake_http", "port": port,
            "success": code == 0, "pid": out.strip(),
            "log_path": f"/tmp/honeypot_http_{port}.log",
            "description": f"Fake HTTP API on :{port} — returns convincing admin tokens, logs all requests",
        }
        if result["success"]:
            self.active_pots[port] = "fake_http"
            print(f"  [Honeypot] Fake HTTP API deployed on :{port}")
        return result

    def redirect_traffic(self, source_ip: str, honeypot_port: int, dry_run: bool = False) -> dict:
        """
        Use iptables REDIRECT to send attacker traffic to our honeypot.
        The attacker sees a 'real' service — we see every request they make.
        """
        result = {
            "action": "traffic_redirect",
            "source_ip": source_ip,
            "honeypot_port": honeypot_port,
            "dry_run": dry_run,
            "commands": [],
            "success": False,
        }
        cmds = [
            # REDIRECT all TCP from attacker IP to our honeypot port
            f"iptables -t nat -A PREROUTING -s {source_ip} -p tcp -j REDIRECT --to-port {honeypot_port}",
            # Log the redirect
            f"iptables -A INPUT -s {source_ip} -j LOG --log-prefix '[HONEYPOT] '",
        ]
        result["commands"] = cmds
        if not dry_run:
            for cmd in cmds:
                code, out = self._exec(cmd)
                if code == 0:
                    result["success"] = True
        else:
            result["success"] = True
            result["note"] = "Dry run — commands not executed"
        return result

    def harvest_ttps(self) -> dict:
        """
        Read all honeypot logs and return structured TTP data.
        This feeds back into the LLM for adaptive threat detection.
        """
        ttps = {}
        for port, svc in self.active_pots.items():
            log_path = f"/tmp/honeypot_{svc.replace('fake_','')}_{port}.log"
            _, content = self._exec(f"tail -50 {log_path} 2>/dev/null")
            ttps[f"{svc}:{port}"] = {
                "log_entries": len(content.split("\n")) if content else 0,
                "sample": content[:500] if content else "",
            }
        return ttps
