# Inner Warden Narrator (MVP)

This is a lightweight summarizer that reads the daily JSONL outputs and produces:
- `~/.local/share/innerwarden/summary/latest.md`
- a timestamped history file in the same folder

It does not require OpenClaw.

Usage:
```bash
python3 tools/narrator/narrate.py --window-min 30
```
