"""
DFITS - Digital Forensic Intelligence & Timeline System
Phase 1: Multi-Source Parser
Supports: .log files, WhatsApp .txt exports
Output:   unified_events.json  (list of event dicts)
"""

import re
import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime


# ──────────────────────────────────────────────
#  UNIFIED EVENT SCHEMA
# ──────────────────────────────────────────────
def make_event(timestamp: datetime, source_file: str,
               source_type: str, event_type: str,
               description: str, raw_line: str = "") -> dict:
    """
    Every parser must return events in this exact shape.
    Adding a SHA-256 hash of the raw line preserves evidence integrity.
    """
    return {
        "timestamp":   timestamp.isoformat(),
        "source_file": source_file,
        "source_type": source_type,       # "log" | "whatsapp" | "browser" | ...
        "event_type":  event_type,        # "login_failed" | "chat_message" | ...
        "description": description,
        "raw_hash":    hashlib.sha256(raw_line.encode()).hexdigest()[:16]
    }


# ──────────────────────────────────────────────
#  LOG FILE PARSER
# ──────────────────────────────────────────────

# Patterns ordered from most-specific to least-specific.
# Each tuple: (regex, event_type, description_template)
LOG_PATTERNS = [
    # Windows-style: 2024-05-01 10:45:23
    (r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", "%Y-%m-%d %H:%M:%S"),
    # Syslog-style:  May  1 10:45:23  (no year — we inject current year)
    (r"([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",         "%b %d %H:%M:%S"),
    # ISO 8601 with T:  2024-05-01T10:45:23
    (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",                "%Y-%m-%dT%H:%M:%S"),
]

# Keywords → event type mapping (checked on lower-cased line)
KEYWORD_MAP = [
    (["failed password", "authentication failure", "login failed",
      "invalid user", "failed login"],                          "login_failed"),
    (["accepted password", "session opened", "logged in",
      "login successful"],                                      "login_success"),
    (["usb", "removable", "mass storage", "usbstor"],          "usb_event"),
    (["deleted", "removed file", "unlinked"],                  "file_deleted"),
    (["created", "new file", "touch"],                         "file_created"),
    (["sudo", "privilege", "escalat", "root"],                 "privilege_change"),
    (["error", "err ", "critical", "fatal"],                   "error"),
    (["warning", "warn "],                                     "warning"),
    (["shutdown", "reboot", "restart", "halt"],                "system_event"),
    (["connection", "connect", "ssh", "rdp", "telnet"],        "network_event"),
]


def classify_log_line(line: str) -> str:
    """Return the best-matching event_type for a log line."""
    low = line.lower()
    for keywords, event_type in KEYWORD_MAP:
        if any(kw in low for kw in keywords):
            return event_type
    return "generic_log"


def parse_log_timestamp(line: str):
    """Try each timestamp pattern; return (datetime, matched_string) or None."""
    current_year = datetime.now().year
    for pattern, fmt in LOG_PATTERNS:
        m = re.search(pattern, line)
        if m:
            ts_str = m.group(1)
            try:
                # Syslog has no year — prepend it
                if "%Y" not in fmt:
                    ts_str = f"{current_year} {ts_str}"
                    fmt     = f"%Y {fmt}"
                dt = datetime.strptime(ts_str, fmt)
                return dt
            except ValueError:
                continue
    return None


def parse_log_file(filepath: str) -> list[dict]:
    """Parse a generic .log file into events."""
    events = []
    path   = Path(filepath)

    with open(filepath, "r", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue

            dt = parse_log_timestamp(line)
            if dt is None:
                continue                        # skip lines with no timestamp

            event_type  = classify_log_line(line)
            description = line[:200]            # cap at 200 chars for readability

            events.append(make_event(
                timestamp   = dt,
                source_file = path.name,
                source_type = "log",
                event_type  = event_type,
                description = description,
                raw_line    = raw_line,
            ))

    print(f"  [log]       {path.name}  →  {len(events)} events extracted")
    return events


# ──────────────────────────────────────────────
#  WHATSAPP CHAT PARSER
# ──────────────────────────────────────────────

# WhatsApp exports two common date formats:
#   [01/05/2024, 10:45:23] Sender: message
#   01/05/2024, 10:45 - Sender: message   (Android, no seconds)
WA_PATTERNS = [
    # iOS format:     [DD/MM/YYYY, HH:MM:SS]
    (r"\[(\d{2}/\d{2}/\d{4}),\s*(\d{2}:\d{2}:\d{2})\]\s*([^:]+):\s*(.*)",
     "%d/%m/%Y %H:%M:%S"),
    # Android format: DD/MM/YYYY, HH:MM -
    (r"(\d{2}/\d{2}/\d{4}),\s*(\d{1,2}:\d{2})\s*-\s*([^:]+):\s*(.*)",
     "%d/%m/%Y %H:%M"),
    # US date format: MM/DD/YYYY
    (r"\[(\d{2}/\d{2}/\d{4}),\s*(\d{2}:\d{2}:\d{2})\]\s*([^:]+):\s*(.*)",
     "%m/%d/%Y %H:%M:%S"),
]

# WhatsApp system messages (no sender)
WA_SYSTEM_RE = re.compile(
    r"(added|removed|left|changed|created|deleted|joined|end-to-end)", re.I
)


def classify_wa_message(text: str, sender: str) -> tuple[str, str]:
    """Return (event_type, description) for a WhatsApp line."""
    low = text.lower()

    # Attachments
    if "<media omitted>" in low or "image omitted" in low:
        return "media_shared", f"{sender} shared media"
    if "document omitted" in low:
        return "document_shared", f"{sender} shared a document"
    if "audio omitted" in low or "voice message" in low:
        return "voice_message", f"{sender} sent a voice message"
    if "location" in low and ("http" in low or "maps" in low):
        return "location_shared", f"{sender} shared a location"

    # Suspicious keywords (basic intelligence)
    suspicious = ["meet me", "delete this", "don't tell", "burner", "cash",
                  "untraceable", "no record", "secret", "destroy"]
    if any(kw in low for kw in suspicious):
        return "suspicious_chat", f"{sender}: {text[:150]}"

    return "chat_message", f"{sender}: {text[:150]}"


def parse_whatsapp_file(filepath: str) -> list[dict]:
    """Parse a WhatsApp .txt export into events."""
    events = []
    path   = Path(filepath)

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue

            matched = False
            for pattern, fmt in WA_PATTERNS:
                m = re.match(pattern, line)
                if m:
                    date_str, time_str, sender, message = m.groups()
                    try:
                        dt = datetime.strptime(f"{date_str} {time_str}", fmt)
                    except ValueError:
                        continue

                    event_type, description = classify_wa_message(message, sender.strip())

                    events.append(make_event(
                        timestamp   = dt,
                        source_file = path.name,
                        source_type = "whatsapp",
                        event_type  = event_type,
                        description = description,
                        raw_line    = raw_line,
                    ))
                    matched = True
                    break

            # System messages (no sender colon)
            if not matched and WA_SYSTEM_RE.search(line):
                # Try to extract any timestamp
                for pattern, fmt in WA_PATTERNS:
                    m2 = re.search(r"(\d{2}/\d{2}/\d{4}),\s*(\d{1,2}:\d{2})", line)
                    if m2:
                        try:
                            dt = datetime.strptime(
                                f"{m2.group(1)} {m2.group(2)}", "%d/%m/%Y %H:%M"
                            )
                            events.append(make_event(
                                timestamp   = dt,
                                source_file = path.name,
                                source_type = "whatsapp",
                                event_type  = "system_message",
                                description = line[:200],
                                raw_line    = raw_line,
                            ))
                        except ValueError:
                            pass
                        break

    print(f"  [whatsapp]  {path.name}  →  {len(events)} events extracted")
    return events


# ──────────────────────────────────────────────
#  DISPATCHER — auto-detect file type
# ──────────────────────────────────────────────

def parse_file(filepath: str) -> list[dict]:
    """Route a file to the correct parser based on extension and content sniff."""
    path = Path(filepath)
    ext  = path.suffix.lower()

    if ext in (".txt",):
        # Peek at first line to distinguish WhatsApp from plain text logs
        with open(filepath, "r", errors="replace") as fh:
            first = fh.readline()
        # WhatsApp always starts with a date in brackets or DD/MM/YYYY
        if re.match(r"[\[\d]", first.strip()):
            return parse_whatsapp_file(filepath)
        return parse_log_file(filepath)

    elif ext in (".log", ".syslog", ".evtx_txt", ".auth"):
        return parse_log_file(filepath)

    else:
        # Try log parser as fallback
        print(f"  [?]  Unknown extension '{ext}' for {path.name} — trying log parser")
        return parse_log_file(filepath)


# ──────────────────────────────────────────────
#  TIMELINE MERGE + OUTPUT
# ──────────────────────────────────────────────

def build_timeline(all_events: list[dict]) -> list[dict]:
    """Sort all events chronologically across all sources."""
    return sorted(all_events, key=lambda e: e["timestamp"])


def save_json(events: list[dict], output_path: str):
    """Write events to JSON with metadata header."""
    output = {
        "case_metadata": {
            "generated_at": datetime.now().isoformat(),
            "total_events": len(events),
            "sources":      list({e["source_file"] for e in events}),
            "event_types":  list({e["event_type"]  for e in events}),
        },
        "events": events
    }
    with open(output_path, "w") as fh:
        json.dump(output, fh, indent=2)
    print(f"\n  Saved {len(events)} events → {output_path}")


def print_summary(events: list[dict]):
    """Print a quick terminal summary after parsing."""
    from collections import Counter
    print("\n── Event type breakdown ──────────────────────")
    counts = Counter(e["event_type"] for e in events)
    for etype, count in counts.most_common():
        bar = "█" * min(count, 40)
        print(f"  {etype:<22} {count:>4}  {bar}")
    print("──────────────────────────────────────────────")

    # Show first 5 events as a preview
    print("\n── Timeline preview (first 5 events) ────────")
    for e in events[:5]:
        print(f"  {e['timestamp']}  [{e['event_type']}]  {e['description'][:60]}")
    print("──────────────────────────────────────────────\n")


# ──────────────────────────────────────────────
#  CLI ENTRYPOINT
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DFITS Phase 1 — parse evidence files into unified JSON timeline"
    )
    parser.add_argument(
        "files", nargs="+",
        help="Evidence files to parse (.log, .txt WhatsApp exports)"
    )
    parser.add_argument(
        "-o", "--output", default="unified_events.json",
        help="Output JSON file (default: unified_events.json)"
    )
    args = parser.parse_args()

    print("\n══ DFITS Phase 1 Parser ══════════════════════")
    all_events = []

    for filepath in args.files:
        p = Path(filepath)
        if not p.exists():
            print(f"  [!] File not found: {filepath}")
            continue
        events = parse_file(filepath)
        all_events.extend(events)

    if not all_events:
        print("  No events extracted. Check file formats.")
        return

    timeline = build_timeline(all_events)
    print_summary(timeline)
    save_json(timeline, args.output)
    print("══ Done ══════════════════════════════════════\n")


if __name__ == "__main__":
    main()