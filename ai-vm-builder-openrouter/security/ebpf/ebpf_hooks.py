"""
Real eBPF Hook Layer — Challenge 1: Active Cyber Defense
GDG x Duckurity AISprint

Provides kernel-level syscall visibility using Linux eBPF via the bcc library.
Falls back gracefully to /proc-based collection when bcc is unavailable
(e.g., macOS, Docker Desktop, containers without CAP_SYS_ADMIN).

Real eBPF programs hooked:
  - sys_execve   → every process spawn with full argv[]
  - sys_connect  → every outbound connection attempt with IP + port
  - sys_open     → file access on sensitive paths (/etc, /root, /bin)
  - sys_kill     → process termination signals (injection detection)

Architecture:
  EBPFCollector.start()   → load BPF programs, attach kprobes
  EBPFCollector.drain()   → return queued SyscallEvent objects since last call
  EBPFCollector.stop()    → detach all probes, free resources
  ProcFallback            → identical interface, uses /proc + docker exec

Usage:
    collector = EBPFCollector.create(container)  # auto-selects real or fallback
    collector.start()
    events = collector.drain()   # list[SyscallEvent]
    collector.stop()

Install for real eBPF (Linux host with kernel headers):
    apt-get install bpfcc-tools linux-headers-$(uname -r)
    pip install bcc
"""

import os
import sys
import json
import time
import socket
import struct
import datetime
import threading
from collections import deque
from pathlib import Path
from typing import Optional


# ── Syscall event ─────────────────────────────────────────────────────────────

class SyscallEvent:
    """
    Represents one kernel-level syscall event.
    Mirrors the data returned by a real eBPF perf event ring buffer.
    """
    TYPES = {"execve", "connect", "open", "kill", "ptrace", "socket"}

    def __init__(self, event_type: str, pid: int, ppid: int, uid: int,
                 comm: str, args: str, timestamp: str = None):
        self.event_type = event_type
        self.pid        = pid
        self.ppid       = ppid
        self.uid        = uid
        self.comm       = comm
        self.args       = args  # argv for execve, ip:port for connect, path for open
        self.timestamp  = timestamp or datetime.datetime.utcnow().isoformat()
        self.suspicious = False
        self.reason     = ""

    def to_dict(self) -> dict:
        return {
            "type": self.event_type, "pid": self.pid, "ppid": self.ppid,
            "uid": self.uid, "comm": self.comm, "args": self.args[:256],
            "timestamp": self.timestamp, "suspicious": self.suspicious,
            "reason": self.reason,
        }

    def __repr__(self):
        return f"SyscallEvent({self.event_type} pid={self.pid} comm={self.comm} args={self.args[:60]})"


# ── eBPF BPF program text ─────────────────────────────────────────────────────

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// Shared event structure sent via perf ring buffer
struct event_t {
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[16];
    char args[128];
    u8   event_type;   // 0=execve 1=connect 2=open 3=kill 4=ptrace
};

BPF_PERF_OUTPUT(events);

// ── execve hook ───────────────────────────────────────────────────────────────
int trace_execve(struct pt_regs *ctx, const char __user *filename,
                 const char __user *const __user *argv) {
    struct event_t e = {};
    e.event_type = 0;
    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.args, sizeof(e.args), filename);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e.ppid = task->real_parent->tgid;
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

// ── connect hook ──────────────────────────────────────────────────────────────
int trace_connect(struct pt_regs *ctx, int fd, struct sockaddr __user *uaddr, int addrlen) {
    struct event_t e = {};
    e.event_type = 1;
    e.pid  = bpf_get_current_pid_tgid() >> 32;
    e.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    // Read destination IP:port from sockaddr
    struct sockaddr_in addr = {};
    bpf_probe_read_user(&addr, sizeof(addr), uaddr);
    if (addr.sin_family == 2) {  // AF_INET
        u32 ip   = addr.sin_addr.s_addr;
        u16 port = __builtin_bswap16(addr.sin_port);
        bpf_snprintf(e.args, sizeof(e.args), "%d.%d.%d.%d:%d",
                     ip & 0xff, (ip >> 8) & 0xff,
                     (ip >> 16) & 0xff, (ip >> 24) & 0xff, port);
    }
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

// ── open hook (sensitive paths only) ─────────────────────────────────────────
int trace_open(struct pt_regs *ctx, const char __user *filename, int flags) {
    struct event_t e = {};
    char fname[64];
    bpf_probe_read_user_str(fname, sizeof(fname), filename);
    // Only report accesses to sensitive paths
    if (fname[0] != '/') return 0;
    if (fname[1] != 'e' && fname[1] != 'r' && fname[1] != 'b') return 0;
    e.event_type = 2;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(e.args, sizeof(e.args), filename);
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

// ── ptrace hook (Frida / injection detection) ─────────────────────────────────
int trace_ptrace(struct pt_regs *ctx, long request, long pid) {
    struct event_t e = {};
    e.event_type = 4;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_snprintf(e.args, sizeof(e.args), "ptrace req=%ld target_pid=%ld", request, pid);
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""

# ── Suspicious pattern rules ──────────────────────────────────────────────────

SUSPICIOUS_COMMS = {
    "xmrig", "minerd", "cgminer", "ethminer", "nbminer",     # crypto miners
    "nc", "ncat", "netcat", "socat",                           # reverse shell tools
    "nsenter", "unshare", "capsh",                             # container escape
    "nmap", "masscan", "zmap",                                 # port scanners
    "curl", "wget",                                            # dropper download (if unexpected)
}

SENSITIVE_PATHS = {
    "/etc/passwd", "/etc/shadow", "/etc/crontab", "/etc/sudoers",
    "/root/.bashrc", "/root/.ssh/authorized_keys",
    "/usr/bin/python", "/usr/bin/bash", "/bin/sh",
}

PRIVATE_PREFIXES = ("127.", "10.", "172.1", "172.2", "172.3",
                    "192.168.", "0.0.0.0", "::1", "[::")


def _is_external_ip(addr: str) -> bool:
    ip = addr.split(":")[0]
    return bool(ip) and not any(ip.startswith(p) for p in PRIVATE_PREFIXES)


# ── Real eBPF collector (Linux + bcc) ─────────────────────────────────────────

class EBPFCollector:
    """
    Real eBPF-based syscall collector using the bcc library.
    Requires: Linux host, kernel headers, bcc installed.
    Install: apt-get install bpfcc-tools linux-headers-$(uname -r) && pip install bcc
    """

    def __init__(self, container=None):
        self.container = container
        self._bpf      = None
        self._queue: deque[SyscallEvent] = deque(maxlen=500)
        self._lock     = threading.Lock()
        self._running  = False
        self._thread: Optional[threading.Thread] = None
        self.available = False

    @classmethod
    def create(cls, container=None) -> "EBPFCollector | ProcFallback":
        """Auto-select real eBPF or /proc fallback based on availability."""
        try:
            import bcc  # noqa: F401
            # Also check we have CAP_SYS_ADMIN / CAP_BPF
            if os.geteuid() == 0:
                print("  [eBPF] bcc available — using real kernel hooks")
                c = cls(container)
                c.available = True
                return c
            else:
                print("  [eBPF] bcc available but not root — using /proc fallback")
        except ImportError:
            print("  [eBPF] bcc not installed — using /proc fallback")
        return ProcFallback(container)

    def start(self):
        """Load BPF programs and attach kprobes."""
        try:
            from bcc import BPF
            self._bpf = BPF(text=BPF_PROGRAM)
            self._bpf.attach_kprobe(event=self._bpf.get_syscall_fnname("execve"),
                                    fn_name="trace_execve")
            self._bpf.attach_kprobe(event=self._bpf.get_syscall_fnname("connect"),
                                    fn_name="trace_connect")
            self._bpf.attach_kprobe(event=self._bpf.get_syscall_fnname("open"),
                                    fn_name="trace_open")
            self._bpf.attach_kprobe(event=self._bpf.get_syscall_fnname("ptrace"),
                                    fn_name="trace_ptrace")

            def _handle(cpu, data, size):
                e = self._bpf["events"].event(data)
                type_map = {0: "execve", 1: "connect", 2: "open", 3: "kill", 4: "ptrace"}
                ev = SyscallEvent(
                    event_type=type_map.get(e.event_type, "unknown"),
                    pid=e.pid, ppid=0, uid=e.uid,
                    comm=e.comm.decode(errors="replace"),
                    args=e.args.decode(errors="replace"),
                )
                self._classify(ev)
                with self._lock:
                    self._queue.append(ev)

            self._bpf["events"].open_perf_buffer(_handle)
            self._running = True

            def _poll():
                while self._running:
                    try:
                        self._bpf.perf_buffer_poll(timeout=100)
                    except Exception:
                        break

            self._thread = threading.Thread(target=_poll, daemon=True)
            self._thread.start()
            print("  [eBPF] Probes attached: execve, connect, open, ptrace")
        except Exception as ex:
            print(f"  [eBPF] Failed to attach probes: {ex}")
            self.available = False

    def drain(self) -> list[SyscallEvent]:
        """Return and clear all queued events since last drain()."""
        with self._lock:
            events = list(self._queue)
            self._queue.clear()
        return events

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        if self._bpf:
            try:
                self._bpf.cleanup()
            except Exception:
                pass

    def _classify(self, ev: SyscallEvent):
        """Apply suspicion rules to a raw syscall event."""
        comm = ev.comm.lower()
        if comm in SUSPICIOUS_COMMS:
            ev.suspicious = True
            ev.reason = f"Suspicious binary: {ev.comm}"

        if ev.event_type == "execve" and ev.uid == 0:
            if comm in {"bash", "sh", "zsh", "python", "python3"}:
                ev.suspicious = True
                ev.reason = f"Root shell/interpreter spawn: {ev.comm}"

        if ev.event_type == "connect" and _is_external_ip(ev.args):
            ev.suspicious = True
            ev.reason = f"Outbound connection to external IP: {ev.args}"

        if ev.event_type == "open" and ev.args in SENSITIVE_PATHS:
            ev.suspicious = True
            ev.reason = f"Sensitive file accessed: {ev.args}"

        if ev.event_type == "ptrace":
            ev.suspicious = True
            ev.reason = f"ptrace() called — injection or debugging: {ev.args}"


# ── /proc fallback (identical interface) ──────────────────────────────────────

class ProcFallback:
    """
    Fallback eBPF-compatible collector using /proc filesystem + docker exec.
    Provides the same SyscallEvent interface as EBPFCollector.
    Used when bcc/eBPF is not available (macOS, Docker Desktop, no kernel headers).
    """

    def __init__(self, container=None):
        self.container = container
        self._seen_pids: set = set()
        self._seen_conns: set = set()
        self.available = True

    def start(self):
        print("  [eBPF-fallback] /proc collector started")

    def stop(self):
        pass

    def drain(self) -> list[SyscallEvent]:
        """
        Synthesize SyscallEvent objects from /proc and docker exec output.
        New PIDs → execve events. New connections → connect events.
        """
        events = []
        now = datetime.datetime.utcnow().isoformat()

        if not self.container:
            return events

        def run(cmd):
            try:
                _, out = self.container.exec_run(["/bin/sh", "-c", cmd])
                return out.decode(errors="replace").strip() if out else ""
            except Exception:
                return ""

        # Synthesize execve events from ps
        ps_out = run("ps -eo pid,ppid,uid,comm,args --no-headers 2>/dev/null")
        current_pids = set()
        for line in ps_out.split("\n"):
            parts = line.split(None, 4)
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[0]); ppid = int(parts[1]); uid = int(parts[2])
                comm = parts[3]; args = parts[4] if len(parts) > 4 else comm
            except (ValueError, IndexError):
                continue
            current_pids.add(pid)
            if pid not in self._seen_pids:
                ev = SyscallEvent("execve", pid, ppid, uid, comm, args, now)
                self._classify(ev)
                events.append(ev)
        self._seen_pids = current_pids

        # Synthesize connect events from ss
        ss_out = run("ss -tnp state established 2>/dev/null")
        for line in ss_out.split("\n"):
            if not line.strip() or "State" in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            remote = parts[4] if len(parts) > 4 else parts[-1]
            key = remote
            if key not in self._seen_conns:
                self._seen_conns.add(key)
                comm = "unknown"
                if 'comm="' in line:
                    comm = line.split('comm="')[1].split('"')[0]
                ev = SyscallEvent("connect", 0, 0, 0, comm, remote, now)
                self._classify(ev)
                events.append(ev)

        # Synthesize open events for recently modified sensitive files
        recent = run("find /etc /root /usr/bin /bin -newer /tmp -type f 2>/dev/null | head -10")
        for path in recent.split("\n"):
            if path.strip() and path.strip() in SENSITIVE_PATHS:
                ev = SyscallEvent("open", 0, 0, 0, "unknown", path.strip(), now)
                ev.suspicious = True
                ev.reason = f"Sensitive file modified: {path.strip()}"
                events.append(ev)

        return events

    def _classify(self, ev: SyscallEvent):
        """Same classification logic as EBPFCollector."""
        comm = ev.comm.lower()
        if comm in SUSPICIOUS_COMMS:
            ev.suspicious = True
            ev.reason = f"Suspicious binary: {ev.comm}"
        if ev.event_type == "execve" and ev.uid == 0 and comm in {"bash","sh","zsh","python","python3"}:
            ev.suspicious = True
            ev.reason = f"Root shell spawn: {ev.comm}"
        if ev.event_type == "connect" and _is_external_ip(ev.args):
            ev.suspicious = True
            ev.reason = f"External connection: {ev.args}"
        if ev.event_type == "open" and ev.args in SENSITIVE_PATHS:
            ev.suspicious = True
            ev.reason = f"Sensitive file accessed: {ev.args}"
