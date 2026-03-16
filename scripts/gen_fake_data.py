#!/usr/bin/env python3
"""Generate rich fake dashboard data for screenshots."""

import json, random, os, sys
from datetime import datetime, timedelta, timezone

TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")
DATA_DIR = sys.argv[1] if len(sys.argv) > 1 else "./data"
HOST = "prod-server-01"

# Fake attackers
ATTACKERS = [
    {"ip": "185.220.101.47", "country": "RU", "city": "Moscow",    "abuse": 98},
    {"ip": "45.142.212.100", "country": "CN", "city": "Shanghai",  "abuse": 87},
    {"ip": "194.165.16.11",  "country": "NL", "city": "Amsterdam", "abuse": 72},
    {"ip": "91.108.4.200",   "country": "IR", "city": "Tehran",    "abuse": 91},
    {"ip": "23.94.49.211",   "country": "US", "city": "Los Angeles","abuse": 45},
    {"ip": "103.27.108.55",  "country": "HK", "city": "Hong Kong", "abuse": 63},
    {"ip": "5.188.87.33",    "country": "DE", "city": "Frankfurt",  "abuse": 55},
]

USERS = ["root", "admin", "ubuntu", "deploy", "git", "postgres", "maicon"]

DETECTORS = [
    "ssh_bruteforce", "credential_stuffing", "port_scan",
    "web_scan", "user_agent_scanner", "sudo_abuse", "execution_guard",
]

SKILLS = ["block-ip-ufw", "block-ip-iptables", "suspend-user-sudo"]
AI_PROVIDERS = ["openai:gpt-4o-mini", "anthropic:claude-haiku-4-5-20251001", "fail2ban:sshd", "crowdsec"]

def ts(minutes_ago=0, jitter=0):
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago + random.uniform(0, jitter))
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def write_jsonl(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"  wrote {len(records)} records → {path}")

# ── EVENTS ────────────────────────────────────────────────────────────────────
events = []

# SSH brute force waves from multiple IPs
for atk in ATTACKERS[:5]:
    ip = atk["ip"]
    wave_start = random.randint(20, 400)
    for i in range(random.randint(12, 35)):
        user = random.choice(["root", "admin", "ubuntu", "pi", "test", "deploy"])
        events.append({
            "ts": ts(wave_start - i * 0.8, 0.3),
            "host": HOST, "source": "auth.log", "kind": "ssh.login_failed",
            "severity": "info",
            "summary": f"Invalid user {user} from {ip}",
            "details": {"ip": ip, "user": user, "reason": "invalid_user", "port": 22},
            "tags": ["auth", "ssh"],
            "entities": [{"type": "ip", "value": ip}, {"type": "user", "value": user}],
        })

# Successful SSH login (legitimate)
events.append({
    "ts": ts(180), "host": HOST, "source": "auth.log", "kind": "ssh.login_success",
    "severity": "low", "summary": f"Accepted publickey for maicon from 177.92.10.5",
    "details": {"ip": "177.92.10.5", "user": "maicon", "method": "publickey"},
    "tags": ["auth", "ssh"], "entities": [{"type": "ip", "value": "177.92.10.5"}, {"type": "user", "value": "maicon"}],
})

# Sudo commands
sudo_cmds = ["apt upgrade -y", "systemctl restart nginx", "tail -f /var/log/auth.log", "cat /etc/shadow", "id", "whoami"]
for i, cmd in enumerate(sudo_cmds):
    severity = "high" if cmd in ["cat /etc/shadow"] else "low"
    events.append({
        "ts": ts(60 + i * 8), "host": HOST, "source": "journald", "kind": "sudo.command",
        "severity": severity, "summary": f"maicon ran sudo: {cmd}",
        "details": {"user": "maicon", "command": cmd, "tty": "pts/0"},
        "tags": ["sudo", "auth"], "entities": [{"type": "user", "value": "maicon"}],
    })

# Nginx access log — scan attempts
scan_uas = [
    ("Nikto/2.1.6", "nikto"), ("sqlmap/1.7 (https://sqlmap.org)", "sqlmap"),
    ("Mozilla/5.0 Nuclei", "nuclei"), ("masscan/1.0", "masscan"),
]
scan_paths = ["/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/api/v1/users", "/../../../etc/passwd"]
for atk in ATTACKERS[:3]:
    for j in range(random.randint(5, 15)):
        ua_label, ua_str = random.choice(scan_uas)
        path = random.choice(scan_paths)
        events.append({
            "ts": ts(random.randint(10, 300), 5),
            "host": HOST, "source": "nginx_access", "kind": "http.request",
            "severity": "medium",
            "summary": f"GET {path} from {atk['ip']} [{ua_label}]",
            "details": {"ip": atk["ip"], "method": "GET", "path": path, "status": random.choice([404, 403, 200, 401]),
                        "user_agent": ua_str, "bytes": random.randint(200, 4096)},
            "tags": ["http", "nginx"],
            "entities": [{"type": "ip", "value": atk["ip"]}],
        })

# Nginx error — scanner probes
for atk in ATTACKERS[1:4]:
    for j in range(random.randint(3, 8)):
        path = random.choice(scan_paths)
        events.append({
            "ts": ts(random.randint(5, 200), 5),
            "host": HOST, "source": "nginx_error", "kind": "http.error",
            "severity": random.choice(["medium", "high"]),
            "summary": f"[error] open() \"{path}\" failed, client: {atk['ip']}",
            "details": {"ip": atk["ip"], "level": "error", "path": path,
                        "message": f"open() \"{path}\" failed (2: No such file or directory)"},
            "tags": ["http", "nginx"], "entities": [{"type": "ip", "value": atk["ip"]}],
        })

# Docker events — privilege escalation attempt
events.append({
    "ts": ts(90), "host": HOST, "source": "docker", "kind": "container.privileged",
    "severity": "high", "summary": "Privileged container started: exploit-test",
    "details": {"container_id": "a3f7b2e1c9d0", "image": "ubuntu:22.04", "name": "exploit-test",
                "privileged": True, "caps": ["SYS_ADMIN", "NET_ADMIN"]},
    "tags": ["docker", "container", "privilege-escalation"],
    "entities": [{"type": "container", "value": "exploit-test"}],
})

# File integrity changes
events.append({
    "ts": ts(30), "host": HOST, "source": "integrity", "kind": "ssh.authorized_keys_changed",
    "severity": "high", "summary": "authorized_keys modified for user deploy",
    "details": {"path": "/home/deploy/.ssh/authorized_keys", "user": "deploy",
                "old_hash": "sha256:abc123", "new_hash": "sha256:def456",
                "mitre_technique": "T1098.004"},
    "tags": ["integrity", "persistence", "T1098.004"],
    "entities": [{"type": "user", "value": "deploy"}, {"type": "path", "value": "/home/deploy/.ssh/authorized_keys"}],
})

# Falco alert
events.append({
    "ts": ts(15), "host": HOST, "source": "falco_log", "kind": "falco.terminal_shell_in_container",
    "severity": "critical", "summary": "Terminal shell opened in container nginx-prod",
    "details": {"rule": "Terminal shell in container", "priority": "CRITICAL",
                "container": "nginx-prod", "user": "root", "proc": "/bin/bash",
                "output_fields": {"container.name": "nginx-prod", "user.name": "root"}},
    "tags": ["falco", "container", "shell"],
    "entities": [{"type": "container", "value": "nginx-prod"}],
})

# Suricata alert
events.append({
    "ts": ts(45), "host": HOST, "source": "suricata_eve", "kind": "suricata.alert",
    "severity": "critical",
    "summary": f"ET SCAN Potential SSH Scan from {ATTACKERS[0]['ip']}",
    "details": {"alert": {"signature": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak", "severity": 2},
                "src_ip": ATTACKERS[0]["ip"], "dest_port": 22},
    "tags": ["suricata", "network", "scan"],
    "entities": [{"type": "ip", "value": ATTACKERS[0]["ip"]}],
})

# Network firewall drops (port scan)
scan_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 27017, 9200, 11211]
for port in scan_ports:
    events.append({
        "ts": ts(random.randint(50, 120), 3),
        "host": HOST, "source": "syslog_firewall", "kind": "network.connection_blocked",
        "severity": "low", "summary": f"[UFW BLOCK] {ATTACKERS[3]['ip']} → port {port}",
        "details": {"src_ip": ATTACKERS[3]["ip"], "dst_port": port, "proto": "TCP", "interface": "eth0"},
        "tags": ["firewall", "network"], "entities": [{"type": "ip", "value": ATTACKERS[3]["ip"]}],
    })

events.sort(key=lambda e: e["ts"])
write_jsonl(f"{DATA_DIR}/events-{TODAY}.jsonl", events)

# ── INCIDENTS ────────────────────────────────────────────────────────────────
incidents = []

# SSH bruteforce incidents
for atk in ATTACKERS[:4]:
    ip = atk["ip"]
    count = random.randint(8, 40)
    incidents.append({
        "ts": ts(random.randint(10, 350), 5),
        "host": HOST,
        "incident_id": f"ssh_bruteforce:{ip}:{TODAY}T{random.randint(0,23):02d}:{random.randint(0,59):02d}Z",
        "severity": "high",
        "title": f"SSH brute force from {ip}",
        "summary": f"{count} failed SSH login attempts from {ip} in 300s — {atk['city']}, {atk['country']} (AbuseIPDB: {atk['abuse']}%)",
        "evidence": [{"count": count, "ip": ip, "kind": "ssh.login_failed", "window_seconds": 300}],
        "recommended_checks": [f"Check auth.log for successful logins from {ip}", "Block with ufw deny from " + ip],
        "tags": ["auth", "ssh", "bruteforce"],
        "entities": [{"type": "ip", "value": ip}],
    })

# Credential stuffing
incidents.append({
    "ts": ts(120), "host": HOST,
    "incident_id": f"credential_stuffing:{ATTACKERS[1]['ip']}:{TODAY}",
    "severity": "high",
    "title": f"Credential stuffing from {ATTACKERS[1]['ip']}",
    "summary": f"7 distinct usernames tried from {ATTACKERS[1]['ip']} in 300s (root, admin, ubuntu, git, postgres, deploy, test)",
    "evidence": [{"users": ["root","admin","ubuntu","git","postgres","deploy","test"], "ip": ATTACKERS[1]["ip"]}],
    "recommended_checks": ["Review all targeted accounts for compromise"],
    "tags": ["auth", "ssh", "credential_stuffing"],
    "entities": [{"type": "ip", "value": ATTACKERS[1]["ip"]}],
})

# Port scan
incidents.append({
    "ts": ts(55), "host": HOST,
    "incident_id": f"port_scan:{ATTACKERS[3]['ip']}:{TODAY}",
    "severity": "high",
    "title": f"Port scan from {ATTACKERS[3]['ip']}",
    "summary": f"10 distinct ports probed by {ATTACKERS[3]['ip']} in 60s (22, 80, 443, 3306, 5432, 6379, 8080, 27017, 9200, 11211)",
    "evidence": [{"ports": [22,80,443,3306,5432,6379,8080,27017,9200,11211], "ip": ATTACKERS[3]["ip"], "window_seconds": 60}],
    "recommended_checks": ["Block IP immediately", "Review firewall rules"],
    "tags": ["network", "port_scan"],
    "entities": [{"type": "ip", "value": ATTACKERS[3]["ip"]}],
})

# Web scanner
incidents.append({
    "ts": ts(40), "host": HOST,
    "incident_id": f"user_agent_scanner:{ATTACKERS[0]['ip']}:{TODAY}",
    "severity": "high",
    "title": f"Security scanner detected: {ATTACKERS[0]['ip']}",
    "summary": f"Nikto/2.1.6 scanner identified from {ATTACKERS[0]['ip']} — active vulnerability scanning in progress",
    "evidence": [{"scanner": "Nikto", "ip": ATTACKERS[0]["ip"], "paths_probed": 23}],
    "recommended_checks": ["Block scanner IP", "Review nginx access log for successful probes"],
    "tags": ["http", "scanner", "T1595", "T1595.002"],
    "entities": [{"type": "ip", "value": ATTACKERS[0]["ip"]}],
})

# Web scan (error-based)
incidents.append({
    "ts": ts(25), "host": HOST,
    "incident_id": f"web_scan:{ATTACKERS[2]['ip']}:{TODAY}",
    "severity": "high",
    "title": f"Web scan detected from {ATTACKERS[2]['ip']}",
    "summary": f"16 error responses (404/403) in 60s from {ATTACKERS[2]['ip']} — path traversal and admin panel probing",
    "evidence": [{"count": 16, "ip": ATTACKERS[2]["ip"], "window_seconds": 60}],
    "recommended_checks": ["Block IP at edge (Cloudflare)", "Enable WAF rules for path traversal"],
    "tags": ["http", "web_scan", "nginx"],
    "entities": [{"type": "ip", "value": ATTACKERS[2]["ip"]}],
})

# Docker privilege escalation
incidents.append({
    "ts": ts(90), "host": HOST,
    "incident_id": f"container.privileged:exploit-test:{TODAY}",
    "severity": "critical",
    "title": "Privileged Docker container started",
    "summary": "Container 'exploit-test' (ubuntu:22.04) started with --privileged + SYS_ADMIN + NET_ADMIN caps — potential container escape",
    "evidence": [{"container": "exploit-test", "caps": ["SYS_ADMIN", "NET_ADMIN"], "privileged": True}],
    "recommended_checks": ["Stop container immediately", "Audit who ran this image", "Check for host filesystem mounts"],
    "tags": ["docker", "container", "privilege-escalation", "T1611"],
    "entities": [{"type": "container", "value": "exploit-test"}],
})

# Falco critical
incidents.append({
    "ts": ts(15), "host": HOST,
    "incident_id": f"falco.terminal_shell_in_container:nginx-prod:{TODAY}",
    "severity": "critical",
    "title": "Shell opened inside production container",
    "summary": "Falco detected /bin/bash spawned in nginx-prod container as root — active intrusion indicator",
    "evidence": [{"rule": "Terminal shell in container", "container": "nginx-prod", "user": "root"}],
    "recommended_checks": ["Isolate container immediately", "Capture memory dump", "Review container logs"],
    "tags": ["falco", "container", "intrusion", "T1059"],
    "entities": [{"type": "container", "value": "nginx-prod"}],
})

# SSH key tampering
incidents.append({
    "ts": ts(30), "host": HOST,
    "incident_id": f"ssh.authorized_keys_changed:deploy:{TODAY}",
    "severity": "high",
    "title": "SSH authorized_keys modified for user deploy",
    "summary": "Persistence technique detected: /home/deploy/.ssh/authorized_keys changed — possible unauthorized key injection (MITRE T1098.004)",
    "evidence": [{"path": "/home/deploy/.ssh/authorized_keys", "user": "deploy", "technique": "T1098.004"}],
    "recommended_checks": ["Review new keys in authorized_keys", "Check who last logged in as deploy", "Audit recent sudo commands"],
    "tags": ["integrity", "persistence", "T1098.004"],
    "entities": [{"type": "user", "value": "deploy"}, {"type": "path", "value": "/home/deploy/.ssh/authorized_keys"}],
})

incidents.sort(key=lambda e: e["ts"])
write_jsonl(f"{DATA_DIR}/incidents-{TODAY}.jsonl", incidents)

# ── DECISIONS ────────────────────────────────────────────────────────────────
decisions = []

action_map = [
    (ATTACKERS[0]["ip"], "block_ip", "block-ip-ufw", 0.96, True, False, "openai:gpt-4o-mini",
     "High confidence SSH brute force + Nikto scanner. AbuseIPDB: 98%. Blocking immediately."),
    (ATTACKERS[1]["ip"], "block_ip", "block-ip-ufw", 0.91, True, False, "anthropic:claude-haiku-4-5-20251001",
     "Credential stuffing attack with 7 distinct users. High abuse score. Block recommended."),
    (ATTACKERS[2]["ip"], "block_ip", "block-ip-ufw", 0.84, True, True,  "openai:gpt-4o-mini",
     "Web scanning detected. Confidence sufficient but dry-run mode active."),
    (ATTACKERS[3]["ip"], "block_ip", "block-ip-ufw", 0.95, True, False, "fail2ban:sshd",
     "fail2ban ban in jail 'sshd'"),
    ("exploit-test",     "ignore",   None,           0.62, False, False, "openai:gpt-4o-mini",
     "Privileged container flagged but confidence below threshold. Manual review required."),
    ("deploy",           "suspend_user_sudo", "suspend-user-sudo", 0.78, True, False, "anthropic:claude-haiku-4-5-20251001",
     "SSH key tampering detected for deploy user. Suspending sudo access for 1h pending investigation."),
    (ATTACKERS[4]["ip"], "ignore",   None,           0.55, False, False, "openai:gpt-4o-mini",
     "Scan activity detected but confidence below 0.8 threshold. Monitor only."),
    (ATTACKERS[0]["ip"], "block_ip", "block-ip-ufw", 0.98, True, False, "crowdsec",
     "CrowdSec community ban — origin: crowdsec, duration: 86399s"),
]

for i, (target, action, skill, conf, executed, dry, provider, reason) in enumerate(action_map):
    is_ip = action == "block_ip"
    is_user = action == "suspend_user_sudo"
    inc_id = f"{random.choice(DETECTORS)}:{target}:{TODAY}"
    decisions.append({
        "ts": ts(random.randint(5, 300), 10),
        "host": HOST,
        "incident_id": inc_id,
        "ai_provider": provider,
        "action_type": action,
        "target_ip":   target if is_ip else None,
        "target_user": target if is_user else None,
        "skill_id":    skill,
        "confidence":  conf,
        "auto_executed": executed,
        "dry_run":     dry,
        "reason":      reason,
        "estimated_threat": "high" if conf > 0.8 else "medium",
        "execution_result": (
            f"DRY RUN: would execute: sudo ufw deny from {target}" if dry and is_ip else
            f"Blocked {target} via ufw" if executed and is_ip and not dry else
            f"Suspended sudo for {target} (1h)" if executed and is_user else
            "Skipped — confidence below threshold"
        ),
    })

decisions.sort(key=lambda e: e["ts"])
write_jsonl(f"{DATA_DIR}/decisions-{TODAY}.jsonl", decisions)

print(f"\nDone! {len(events)} events, {len(incidents)} incidents, {len(decisions)} decisions for {TODAY}")
print(f"Open http://127.0.0.1:8787 to see the dashboard.")
