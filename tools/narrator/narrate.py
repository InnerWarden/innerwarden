#!/usr/bin/env python3
import argparse, json, os, re
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc)


def parse_ts(s: str):
    try:
        # tolerate trailing Z
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        return datetime.fromisoformat(s)
    except Exception:
        return None


def load_jsonl(path: Path):
    if not path.exists():
        return []
    out = []
    with path.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def entity_map(entities):
    m = {}
    for e in entities or []:
        t = e.get('type')
        v = e.get('value')
        if not t or v is None:
            continue
        m.setdefault(t, set()).add(str(v))
    return {k: sorted(list(v)) for k, v in m.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data-dir', default=os.path.expanduser('~/.local/share/innerwarden'))
    ap.add_argument('--host', default=None)
    ap.add_argument('--window-min', type=int, default=30)
    ap.add_argument('--max-incidents', type=int, default=50)
    args = ap.parse_args()

    data_dir = Path(args.data_dir)
    today = utc_now().strftime('%Y-%m-%d')

    incidents_path = data_dir / f'incidents-{today}.jsonl'
    events_path = data_dir / f'events-{today}.jsonl'

    incidents = load_jsonl(incidents_path)
    events = load_jsonl(events_path)

    now = utc_now()
    window_s = args.window_min * 60

    def in_window(item):
        ts = parse_ts(item.get('ts', ''))
        if not ts:
            return False
        return (now - ts).total_seconds() <= window_s

    recent_incidents = [i for i in incidents if in_window(i)]
    recent_incidents = recent_incidents[-args.max_incidents :]

    recent_events = [e for e in events if in_window(e)]

    # Simple aggregation
    by_sev = {}
    by_kind = {}
    by_ip = {}

    for i in recent_incidents:
        sev = (i.get('severity') or 'unknown').lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        # infer kind from tags/title
        title = (i.get('title') or '').strip()
        by_kind[title] = by_kind.get(title, 0) + 1

        em = entity_map(i.get('entities'))
        for ip in em.get('ip', []):
            by_ip[ip] = by_ip.get(ip, 0) + 1

    top_ips = sorted(by_ip.items(), key=lambda x: (-x[1], x[0]))[:8]
    top_kinds = sorted(by_kind.items(), key=lambda x: (-x[1], x[0]))[:6]

    # Compose markdown
    lines = []
    lines.append(f"# Inner Warden Summary")
    lines.append("")
    lines.append(f"Window: last {args.window_min} min")
    lines.append(f"GeneratedAt: {now.isoformat().replace('+00:00','Z')}")
    lines.append("")

    lines.append("## Quick counts")
    lines.append(f"- Incidents: {len(recent_incidents)}")
    if by_sev:
        sev_bits = ', '.join([f"{k}:{v}" for k, v in sorted(by_sev.items(), key=lambda x: x[0])])
        lines.append(f"- Severity: {sev_bits}")
    lines.append(f"- Events: {len(recent_events)}")

    if top_kinds:
        lines.append("")
        lines.append("## Top incident types")
        for k, v in top_kinds:
            lines.append(f"- {v}x {k}")

    if top_ips:
        lines.append("")
        lines.append("## Top IPs")
        for ip, c in top_ips:
            lines.append(f"- {c} incidents: {ip}")

    lines.append("")
    lines.append("## Recent incidents")
    if not recent_incidents:
        lines.append("- (none)")
    else:
        for i in recent_incidents[-12:]:
            ts = i.get('ts','')
            sev = (i.get('severity') or '').upper()
            title = (i.get('title') or '').strip() or (i.get('summary') or '').strip()
            summary = (i.get('summary') or '').strip()
            em = entity_map(i.get('entities'))
            ip = em.get('ip',[None])[0]
            tail = f" (ip {ip})" if ip else ""
            lines.append(f"- [{sev}] {ts} {title}{tail}")
            if summary and summary != title:
                lines.append(f"  - {summary}")

    out_dir = data_dir / 'summary'
    out_dir.mkdir(parents=True, exist_ok=True)

    latest = out_dir / 'latest.md'
    latest.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    # also keep history
    hist = out_dir / f'summary-{today}-{now.strftime('%H%M%S')}.md'
    hist.write_text('\n'.join(lines) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
