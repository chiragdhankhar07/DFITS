"""
DFITS - Digital Forensic Intelligence & Timeline System
Phase 3: Rule-Based Detection Engine

Consumes the Phase 2 TimelineEngine → runs forensic detection rules →
writes flags back to SQLite → outputs a structured alert report JSON.

Rules are pure Python logic — no ML, no black boxes.
Every flag includes: rule name, evidence, confidence score, severity.
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

# Import Phase 2 engine
import sys
sys.path.insert(0, str(Path(__file__).parent))
from phase2_timeline import init_db, ingest_json, TimelineEngine


# ──────────────────────────────────────────────
#  ALERT SCHEMA
# ──────────────────────────────────────────────

SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def make_alert(rule_id: str, rule_name: str, severity: str,
               confidence: int, description: str,
               evidence_ids: list[int], evidence_snippets: list[str],
               recommendation: str = "") -> dict:
    """
    Every detection rule must return alerts in this exact shape.
    confidence: 0-100 integer
    severity:   LOW | MEDIUM | HIGH | CRITICAL
    """
    return {
        "rule_id":           rule_id,
        "rule_name":         rule_name,
        "severity":          severity,
        "severity_rank":     SEVERITY.get(severity, 0),
        "confidence":        confidence,
        "description":       description,
        "evidence_ids":      evidence_ids,
        "evidence_snippets": evidence_snippets,
        "recommendation":    recommendation,
        "detected_at":       datetime.now().isoformat(),
    }


# ──────────────────────────────────────────────
#  DETECTION RULES
# ──────────────────────────────────────────────

class DetectionEngine:
    """
    Each method named run_* is a detection rule.
    Rules are auto-discovered and executed by run_all().
    """

    def __init__(self, engine: TimelineEngine):
        self.engine = engine
        self.df     = engine.full_timeline()
        self.alerts = []

    # ── RULE 01: Brute-force login attempt ────────────────────────────────────

    def run_brute_force_login(self) -> list[dict]:
        """
        3+ failed logins within 60 seconds → brute-force attempt.
        If followed by a success → successful intrusion.
        """
        alerts = []
        fails  = self.df[self.df["event_type"] == "login_failed"].sort_values("timestamp")
        if fails.empty:
            return alerts

        # Sliding 60-second window
        for i, row in fails.iterrows():
            window_end  = row["timestamp"] + timedelta(seconds=60)
            burst       = fails[
                (fails["timestamp"] >= row["timestamp"]) &
                (fails["timestamp"] <= window_end)
            ]
            if len(burst) >= 3:
                ids      = list(burst["id"])
                snippets = list(burst["description"].str[:80])

                # Check if succeeded after last failure
                last_fail = burst["timestamp"].max()
                success   = self.df[
                    (self.df["event_type"] == "login_success") &
                    (self.df["timestamp"]  >  last_fail) &
                    (self.df["timestamp"]  <= last_fail + timedelta(seconds=120))
                ]

                if not success.empty:
                    ids      += list(success["id"])
                    snippets += list(success["description"].str[:80])
                    alerts.append(make_alert(
                        rule_id   = "RULE-01a",
                        rule_name = "Brute-force login — SUCCEEDED",
                        severity  = "CRITICAL",
                        confidence= 95,
                        description=(
                            f"{len(burst)} failed logins in {int((burst['timestamp'].max() - burst['timestamp'].min()).total_seconds())}s "
                            f"followed by successful login at {success['timestamp'].iloc[0].strftime('%H:%M:%S')}"
                        ),
                        evidence_ids     = ids,
                        evidence_snippets= snippets,
                        recommendation   = "Investigate the source IP. Review what the account accessed post-login. Consider account suspension.",
                    ))
                else:
                    alerts.append(make_alert(
                        rule_id   = "RULE-01b",
                        rule_name = "Brute-force login — blocked",
                        severity  = "HIGH",
                        confidence= 85,
                        description=(
                            f"{len(burst)} failed logins within 60 seconds — attack blocked"
                        ),
                        evidence_ids     = ids,
                        evidence_snippets= snippets,
                        recommendation   = "Block source IP. Enable account lockout policy.",
                    ))
                break   # one alert per burst cluster

        return alerts

    # ── RULE 02: USB insertion → file deletion chain ──────────────────────────

    def run_usb_then_deletion(self) -> list[dict]:
        """
        USB device inserted AND file(s) deleted within 10 minutes →
        possible data exfiltration or evidence destruction.
        """
        alerts  = []
        usb_evs = self.df[self.df["event_type"] == "usb_event"].sort_values("timestamp")
        del_evs = self.df[self.df["event_type"] == "file_deleted"]

        for _, usb in usb_evs.iterrows():
            window_end = usb["timestamp"] + timedelta(minutes=10)
            deletions  = del_evs[
                (del_evs["timestamp"] > usb["timestamp"]) &
                (del_evs["timestamp"] <= window_end)
            ]
            if deletions.empty:
                continue

            gap_secs = int(
                (deletions["timestamp"].min() - usb["timestamp"]).total_seconds()
            )
            ids      = [usb["id"]] + list(deletions["id"])
            snippets = [usb["description"][:80]] + list(deletions["description"].str[:80])

            alerts.append(make_alert(
                rule_id   = "RULE-02",
                rule_name = "USB insertion followed by file deletion",
                severity  = "CRITICAL",
                confidence= 90,
                description=(
                    f"USB device detected at {usb['timestamp'].strftime('%H:%M:%S')}, "
                    f"then {len(deletions)} file(s) deleted {gap_secs}s later — "
                    f"possible data theft or evidence destruction"
                ),
                evidence_ids     = ids,
                evidence_snippets= snippets,
                recommendation   = (
                    "Immediately image the USB device. Attempt file recovery. "
                    "Cross-reference deleted filenames with sensitive data inventory."
                ),
            ))

        return alerts

    # ── RULE 03: Privilege escalation after unauthorised access ───────────────

    def run_privilege_escalation(self) -> list[dict]:
        """
        Login success followed by privilege escalation (sudo/root) within 10 min.
        Severity elevated if brute-force preceded the login.
        """
        alerts   = []
        priv_evs = self.df[self.df["event_type"] == "privilege_change"].sort_values("timestamp")

        for _, priv in priv_evs.iterrows():
            lookback = priv["timestamp"] - timedelta(minutes=10)

            # Was there a login in the 10 min before?
            logins = self.df[
                (self.df["event_type"] == "login_success") &
                (self.df["timestamp"]  >= lookback) &
                (self.df["timestamp"]  <  priv["timestamp"])
            ]
            if logins.empty:
                continue

            # Was there a brute-force before that login?
            earliest_login = logins["timestamp"].min()
            brute = self.df[
                (self.df["event_type"] == "login_failed") &
                (self.df["timestamp"]  <  earliest_login)
            ]

            ids      = list(logins["id"]) + [priv["id"]]
            snippets = list(logins["description"].str[:80]) + [priv["description"][:80]]

            if not brute.empty:
                severity   = "CRITICAL"
                confidence = 95
                desc = (
                    f"Brute-force ({len(brute)} attempts) → login success → "
                    f"privilege escalation at {priv['timestamp'].strftime('%H:%M:%S')}"
                )
                ids      = list(brute["id"]) + ids
                snippets = list(brute["description"].str[:80]) + snippets
            else:
                severity   = "HIGH"
                confidence = 75
                desc = (
                    f"Login success followed by privilege escalation "
                    f"{int((priv['timestamp'] - logins['timestamp'].min()).total_seconds())}s later"
                )

            alerts.append(make_alert(
                rule_id   = "RULE-03",
                rule_name = "Privilege escalation after login",
                severity  = severity,
                confidence= confidence,
                description      = desc,
                evidence_ids     = ids,
                evidence_snippets= snippets,
                recommendation   = (
                    "Review all commands run as root. Check /var/log/auth.log. "
                    "Audit files accessed or modified with elevated privileges."
                ),
            ))

        return alerts

    # ── RULE 04: Suspicious chat coordination with system events ─────────────

    def run_chat_system_correlation(self) -> list[dict]:
        """
        Suspicious chat messages occurring within 30 minutes of
        system-level events (login, USB, file deletion).
        Indicates coordinated activity.
        """
        alerts  = []
        sus_chats = self.df[self.df["event_type"] == "suspicious_chat"].sort_values("timestamp")
        sys_events = self.df[
            self.df["event_type"].isin(["login_success","usb_event","file_deleted","privilege_change"])
        ]

        if sus_chats.empty or sys_events.empty:
            return alerts

        for _, chat in sus_chats.iterrows():
            nearby_sys = sys_events[
                (sys_events["timestamp"] >= chat["timestamp"] - timedelta(minutes=30)) &
                (sys_events["timestamp"] <= chat["timestamp"] + timedelta(minutes=30))
            ]
            if nearby_sys.empty:
                continue

            ids      = [chat["id"]] + list(nearby_sys["id"])
            snippets = [chat["description"][:80]] + list(nearby_sys["description"].str[:80])
            gap_min  = abs(
                (nearby_sys["timestamp"].min() - chat["timestamp"]).total_seconds() / 60
            )

            alerts.append(make_alert(
                rule_id   = "RULE-04",
                rule_name = "Suspicious chat correlated with system events",
                severity  = "HIGH",
                confidence= 80,
                description=(
                    f"Suspicious message from {chat['source_file']} at "
                    f"{chat['timestamp'].strftime('%H:%M:%S')} is within "
                    f"{gap_min:.0f} min of {len(nearby_sys)} system event(s): "
                    f"{list(nearby_sys['event_type'].unique())}"
                ),
                evidence_ids     = ids,
                evidence_snippets= snippets,
                recommendation   = (
                    "Correlate chat participants with system account names. "
                    "Request operator data for message metadata."
                ),
            ))
            break  # one summary alert for this rule

        return alerts

    # ── RULE 05: Activity outside business hours ──────────────────────────────

    def run_off_hours_activity(self,
                               business_start: int = 8,
                               business_end:   int = 18) -> list[dict]:
        """
        Significant activity (3+ events) between midnight and business_start,
        or after business_end — could indicate unauthorised after-hours access.
        """
        alerts = []
        if self.df.empty:
            return alerts

        hour_col = self.df["timestamp"].dt.hour
        off_hours = self.df[
            (hour_col < business_start) | (hour_col >= business_end)
        ]
        if len(off_hours) < 3:
            return alerts

        ids      = list(off_hours["id"])
        snippets = list(off_hours["description"].str[:60])
        hours    = sorted(off_hours["timestamp"].dt.hour.unique())

        alerts.append(make_alert(
            rule_id   = "RULE-05",
            rule_name = "Significant off-hours system activity",
            severity  = "MEDIUM",
            confidence= 65,
            description=(
                f"{len(off_hours)} events outside business hours "
                f"({business_start}:00–{business_end}:00), "
                f"at hours: {hours}"
            ),
            evidence_ids     = ids[:10],
            evidence_snippets= snippets[:10],
            recommendation   = (
                "Verify if after-hours access was authorised. "
                "Check badge/CCTV records for physical presence."
            ),
        ))

        return alerts

    # ── RULE 06: Rapid file deletion burst ────────────────────────────────────

    def run_mass_deletion(self, threshold: int = 2,
                          window_seconds: int = 120) -> list[dict]:
        """
        threshold+ file deletions within window_seconds →
        possible evidence destruction or ransomware staging.
        """
        alerts  = []
        del_evs = self.df[self.df["event_type"] == "file_deleted"].sort_values("timestamp")
        if len(del_evs) < threshold:
            return alerts

        for i, row in del_evs.iterrows():
            window_end = row["timestamp"] + timedelta(seconds=window_seconds)
            burst      = del_evs[
                (del_evs["timestamp"] >= row["timestamp"]) &
                (del_evs["timestamp"] <= window_end)
            ]
            if len(burst) >= threshold:
                duration = int(
                    (burst["timestamp"].max() - burst["timestamp"].min()).total_seconds()
                )
                alerts.append(make_alert(
                    rule_id   = "RULE-06",
                    rule_name = "Mass file deletion detected",
                    severity  = "HIGH",
                    confidence= 88,
                    description=(
                        f"{len(burst)} files deleted within {duration}s — "
                        f"possible evidence destruction or ransomware staging"
                    ),
                    evidence_ids     = list(burst["id"]),
                    evidence_snippets= list(burst["description"].str[:80]),
                    recommendation   = (
                        "Run file-carving on the disk immediately (e.g. Photorec). "
                        "Preserve disk image before further access."
                    ),
                ))
                break

        return alerts

    # ── RULE 07: Location data shared in suspicious context ───────────────────

    def run_location_in_suspicious_context(self) -> list[dict]:
        """
        Location shared within 15 minutes of suspicious chat messages →
        possible meetup coordination.
        """
        alerts  = []
        locs    = self.df[self.df["event_type"] == "location_shared"]
        sus     = self.df[self.df["event_type"] == "suspicious_chat"]

        if locs.empty or sus.empty:
            return alerts

        for _, loc in locs.iterrows():
            nearby_sus = sus[
                (sus["timestamp"] >= loc["timestamp"] - timedelta(minutes=15)) &
                (sus["timestamp"] <= loc["timestamp"] + timedelta(minutes=15))
            ]
            if nearby_sus.empty:
                continue

            ids      = [loc["id"]] + list(nearby_sus["id"])
            snippets = [loc["description"][:80]] + list(nearby_sus["description"].str[:80])

            alerts.append(make_alert(
                rule_id   = "RULE-07",
                rule_name = "Location shared near suspicious messages",
                severity  = "MEDIUM",
                confidence= 72,
                description=(
                    f"Location shared at {loc['timestamp'].strftime('%H:%M:%S')} "
                    f"within 15 min of {len(nearby_sus)} suspicious message(s)"
                ),
                evidence_ids     = ids,
                evidence_snippets= snippets,
                recommendation   = (
                    "Preserve location URL for geolocation analysis. "
                    "Cross-reference with CCTV or cell tower data."
                ),
            ))

        return alerts

    # ── RULE 08: Statistical activity spike ───────────────────────────────────

    def run_activity_spike(self) -> list[dict]:
        """
        Wraps Phase 2 spike detection — any z>2.5 minute gets an alert.
        """
        alerts = []
        spikes = self.engine.activity_spikes("min", threshold_multiplier=2.5)
        if spikes.empty:
            return alerts

        for _, spike in spikes.iterrows():
            bucket     = pd.Timestamp(spike["bucket"])
            bucket_end = bucket + timedelta(minutes=1)
            evs        = self.df[
                (self.df["timestamp"] >= bucket) &
                (self.df["timestamp"] <  bucket_end)
            ]
            alerts.append(make_alert(
                rule_id   = "RULE-08",
                rule_name = "Statistical activity spike",
                severity  = "MEDIUM",
                confidence= min(int(spike["z_score"] * 25), 95),
                description=(
                    f"{int(spike['count'])} events at "
                    f"{bucket.strftime('%H:%M')} "
                    f"(z={spike['z_score']:.1f} σ above mean) — "
                    f"types: {spike['event_types']}"
                ),
                evidence_ids     = list(evs["id"]),
                evidence_snippets= list(evs["description"].str[:60]),
                recommendation   = "Manually review all events in this minute window.",
            ))

        return alerts

    # ──────────────────────────────────────────────
    #  RULE RUNNER
    # ──────────────────────────────────────────────

    def run_all(self) -> list[dict]:
        """
        Auto-discover and execute every method named run_*.
        Deduplicates alerts with identical evidence_ids.
        Sorts by severity desc, confidence desc.
        """
        rule_methods = [
            getattr(self, m) for m in sorted(dir(self))
            if m.startswith("run_") and callable(getattr(self, m))
            and m != "run_all"
        ]

        all_alerts = []
        for method in rule_methods:
            try:
                results = method()
                all_alerts.extend(results)
                if results:
                    print(f"  [✓] {method.__name__:<40} → {len(results)} alert(s)")
                else:
                    print(f"  [ ] {method.__name__:<40} → clean")
            except Exception as ex:
                print(f"  [!] {method.__name__} ERROR: {ex}")

        # Deduplicate: drop alerts whose evidence_ids are a subset of a higher-severity alert
        unique = []
        seen_ids = set()
        for alert in sorted(all_alerts,
                            key=lambda a: (a["severity_rank"], a["confidence"]),
                            reverse=True):
            key = frozenset(alert["evidence_ids"])
            if key not in seen_ids:
                unique.append(alert)
                seen_ids.add(key)

        self.alerts = unique

        # Write flags back to the database
        self._write_flags()

        return self.alerts

    def _write_flags(self):
        """Persist all flagged event IDs back to SQLite via Phase 2 engine."""
        for alert in self.alerts:
            if alert["evidence_ids"]:
                self.engine.flag_bulk(
                    alert["evidence_ids"],
                    f"[{alert['rule_id']}] {alert['rule_name']} (conf={alert['confidence']}%)"
                )


# ──────────────────────────────────────────────
#  SCORING — CASE RISK SCORE
# ──────────────────────────────────────────────

def compute_case_score(alerts: list[dict]) -> dict:
    """
    Aggregate a single 0-100 case risk score from all alerts.
    Weights: CRITICAL=40, HIGH=20, MEDIUM=10, LOW=5
    Capped at 100.
    """
    weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    raw     = sum(weights.get(a["severity"], 0) * (a["confidence"] / 100)
                  for a in alerts)
    score   = min(int(raw), 100)

    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "alert_breakdown": {
            sev: sum(1 for a in alerts if a["severity"] == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        },
        "total_alerts":    len(alerts),
        "flagged_events":  sum(len(a["evidence_ids"]) for a in alerts),
    }


# ──────────────────────────────────────────────
#  TERMINAL REPORT
# ──────────────────────────────────────────────

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

def print_detection_report(alerts: list[dict], score: dict):
    print("\n\n══ DFITS Phase 3 — Detection Report ═════════════════")

    # Risk score banner
    icon = SEV_ICON.get(score["risk_level"], "⚪")
    print(f"\n  {icon}  CASE RISK SCORE: {score['risk_score']}/100  [{score['risk_level']}]")
    print(f"      {score['total_alerts']} alert(s) | "
          f"{score['flagged_events']} evidence event(s) flagged")
    bd = score["alert_breakdown"]
    print(f"      CRITICAL:{bd['CRITICAL']}  HIGH:{bd['HIGH']}  "
          f"MEDIUM:{bd['MEDIUM']}  LOW:{bd['LOW']}")

    print("\n──────────────────────────────────────────────────────")

    for i, alert in enumerate(alerts, 1):
        icon = SEV_ICON.get(alert["severity"], "⚪")
        print(f"\n  {icon}  ALERT {i} of {len(alerts)}")
        print(f"      Rule:        {alert['rule_id']} — {alert['rule_name']}")
        print(f"      Severity:    {alert['severity']}")
        print(f"      Confidence:  {alert['confidence']}%")
        print(f"      Finding:     {alert['description']}")
        if alert["recommendation"]:
            print(f"      Action:      {alert['recommendation']}")
        print(f"      Evidence IDs: {alert['evidence_ids']}")
        print("      Evidence:")
        for snip in alert["evidence_snippets"][:4]:
            print(f"        · {snip[:75]}")

    print("\n══ End of Detection Report ═══════════════════════════\n")


# ──────────────────────────────────────────────
#  EXPORT
# ──────────────────────────────────────────────

def export_detection_json(alerts: list[dict], score: dict, output_path: str):
    output = {
        "generated_at": datetime.now().isoformat(),
        "case_score":   score,
        "alerts":       alerts,
    }
    with open(output_path, "w") as fh:
        json.dump(output, fh, indent=2, default=str)
    print(f"  Detection report saved → {output_path}")


# ──────────────────────────────────────────────
#  CLI ENTRYPOINT
# ──────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="DFITS Phase 3 — Rule-Based Detection Engine"
    )
    parser.add_argument("--db",     default="dfits_evidence.db",
                        help="SQLite DB from Phase 2")
    parser.add_argument("--json",   default=None,
                        help="Optional: re-ingest a Phase 1 JSON before detecting")
    parser.add_argument("--export", default="detection_report.json",
                        help="Output detection report JSON")
    args = parser.parse_args()

    print(f"\n══ DFITS Phase 3 — Detection Engine ═════════════════")

    # Connect to Phase 2 DB
    conn   = init_db(args.db)
    if args.json:
        n = ingest_json(conn, args.json)
        print(f"  Re-ingested {n} new events from {args.json}")

    engine = TimelineEngine(conn)
    total  = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"  Loaded {total} events from {args.db}")
    print(f"\n  Running detection rules...\n")

    # Run all rules
    detector = DetectionEngine(engine)
    alerts   = detector.run_all()
    score    = compute_case_score(alerts)

    # Report
    print_detection_report(alerts, score)
    export_detection_json(alerts, score, args.export)

    conn.close()
    print("  Done.\n")


if __name__ == "__main__":
    main()