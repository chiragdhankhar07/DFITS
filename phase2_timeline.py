"""
DFITS - Digital Forensic Intelligence & Timeline System
Phase 2: Unified Event Database + Timeline Engine

Loads Phase 1 JSON  →  SQLite database  →  pandas timeline
Queries:
  - full chronological timeline
  - filter by source / event_type / time window
  - activity density (events per minute)
  - cross-source event correlation
  - suspicious pattern seeds (for Phase 3 detection engine)
"""

import json
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd
from tabulate import tabulate


# ──────────────────────────────────────────────
#  DATABASE LAYER
# ──────────────────────────────────────────────

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    source_file  TEXT    NOT NULL,
    source_type  TEXT    NOT NULL,
    event_type   TEXT    NOT NULL,
    description  TEXT,
    raw_hash     TEXT,
    flagged      INTEGER DEFAULT 0,   -- 1 = suspicious (set by Phase 3)
    flag_reason  TEXT    DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_timestamp   ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_event_type  ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_source_type ON events(source_type);
CREATE INDEX IF NOT EXISTS idx_flagged     ON events(flagged);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    """Create or open the SQLite evidence database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row          # dict-like rows
    conn.executescript(DB_SCHEMA)
    conn.commit()
    return conn


def ingest_json(conn: sqlite3.Connection, json_path: str) -> int:
    """
    Load Phase 1 JSON into the database.
    Skips duplicates based on (timestamp + raw_hash).
    Returns number of NEW rows inserted.
    """
    with open(json_path) as fh:
        data = json.load(fh)

    events = data.get("events", data) if isinstance(data, dict) else data

    inserted = 0
    for e in events:
        # Duplicate check
        exists = conn.execute(
            "SELECT 1 FROM events WHERE timestamp=? AND raw_hash=?",
            (e["timestamp"], e.get("raw_hash", ""))
        ).fetchone()

        if not exists:
            conn.execute(
                """INSERT INTO events
                   (timestamp, source_file, source_type, event_type, description, raw_hash)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    e["timestamp"],
                    e.get("source_file", "unknown"),
                    e.get("source_type", "unknown"),
                    e.get("event_type",  "generic"),
                    e.get("description", ""),
                    e.get("raw_hash",    ""),
                )
            )
            inserted += 1

    conn.commit()
    return inserted


# ──────────────────────────────────────────────
#  DATAFRAME LOADER
# ──────────────────────────────────────────────

def load_dataframe(conn: sqlite3.Connection,
                   source_type: str = None,
                   event_type:  str = None,
                   start_time:  str = None,
                   end_time:    str = None,
                   flagged_only: bool = False) -> pd.DataFrame:
    """
    Pull events from SQLite into a pandas DataFrame.
    All filters are optional — omit any to get everything.
    """
    query  = "SELECT * FROM events WHERE 1=1"
    params = []

    if source_type:
        query  += " AND source_type = ?"
        params.append(source_type)
    if event_type:
        query  += " AND event_type = ?"
        params.append(event_type)
    if start_time:
        query  += " AND timestamp >= ?"
        params.append(start_time)
    if end_time:
        query  += " AND timestamp <= ?"
        params.append(end_time)
    if flagged_only:
        query  += " AND flagged = 1"

    query += " ORDER BY timestamp ASC"

    df = pd.read_sql_query(query, conn, params=params)

    if df.empty:
        return df

    # Parse timestamp column into proper datetime
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Convenience columns used by the timeline engine
    df["minute"]  = df["timestamp"].dt.floor("min")
    df["hour"]    = df["timestamp"].dt.floor("h")
    df["date"]    = df["timestamp"].dt.date

    return df


# ──────────────────────────────────────────────
#  TIMELINE ENGINE
# ──────────────────────────────────────────────

class TimelineEngine:
    """
    Core forensic intelligence layer.
    All methods return DataFrames or dicts — clean input for Phase 3 + dashboard.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.df   = load_dataframe(conn)          # full dataset cached

    def reload(self):
        """Refresh after new data is ingested or flags are written."""
        self.df = load_dataframe(self.conn)

    # ── 1. Full chronological timeline ────────────────────────────────────────

    def full_timeline(self) -> pd.DataFrame:
        """All events sorted by time — the master forensic timeline."""
        return self.df.sort_values("timestamp").reset_index(drop=True)

    # ── 2. Timeline slice by time window ──────────────────────────────────────

    def time_slice(self, start: str, end: str) -> pd.DataFrame:
        """
        Return events between two ISO timestamps.
        e.g. engine.time_slice("2024-05-01T10:40", "2024-05-01T10:55")
        """
        mask = (self.df["timestamp"] >= pd.Timestamp(start)) & \
               (self.df["timestamp"] <= pd.Timestamp(end))
        return self.df[mask].reset_index(drop=True)

    # ── 3. Activity density ────────────────────────────────────────────────────

    def activity_density(self, resolution: str = "min") -> pd.DataFrame:
        """
        Count events per time bucket across ALL sources.
        resolution: 'min' | 'h' | 'D'
        Returns a DataFrame with columns: bucket, count, sources_active
        """
        col = {"min": "minute", "h": "hour", "D": "date"}.get(resolution, "minute")
        density = (
            self.df.groupby(col)
            .agg(
                count          = ("id",          "count"),
                sources_active = ("source_type", "nunique"),
                event_types    = ("event_type",  lambda x: list(x.unique())),
            )
            .reset_index()
            .rename(columns={col: "bucket"})
            .sort_values("bucket")
        )
        return density

    # ── 4. Spike detection ─────────────────────────────────────────────────────

    def activity_spikes(self, resolution: str = "min",
                        threshold_multiplier: float = 2.5) -> pd.DataFrame:
        """
        Identify time buckets where event count exceeds
        (mean + threshold_multiplier × std).
        These are high-interest investigation windows.
        """
        density = self.activity_density(resolution)
        if density.empty or len(density) < 3:
            return density

        mean = density["count"].mean()
        std  = density["count"].std()
        cutoff = mean + threshold_multiplier * std

        spikes = density[density["count"] >= cutoff].copy()
        spikes["z_score"] = ((spikes["count"] - mean) / std).round(2)
        return spikes.reset_index(drop=True)

    # ── 5. Cross-source correlation ────────────────────────────────────────────

    def cross_source_events(self, window_seconds: int = 300) -> pd.DataFrame:
        """
        Find time windows where events from MULTIPLE sources overlap.
        window_seconds: how wide a window to look (default 5 min)
        Returns windows with 2+ source_types active simultaneously.
        """
        if self.df.empty:
            return pd.DataFrame()

        results = []
        events  = self.df.sort_values("timestamp").reset_index(drop=True)

        for i, anchor in events.iterrows():
            window_end  = anchor["timestamp"] + timedelta(seconds=window_seconds)
            window_mask = (
                (events["timestamp"] >= anchor["timestamp"]) &
                (events["timestamp"] <= window_end)
            )
            window_events = events[window_mask]
            sources = window_events["source_type"].unique()

            if len(sources) >= 2:
                results.append({
                    "window_start":   anchor["timestamp"],
                    "window_end":     window_end,
                    "event_count":    len(window_events),
                    "sources":        list(sources),
                    "event_types":    list(window_events["event_type"].unique()),
                    "source_count":   len(sources),
                })

        if not results:
            return pd.DataFrame()

        correlations = pd.DataFrame(results).drop_duplicates("window_start")
        return correlations.reset_index(drop=True)

    # ── 6. Per-source breakdown ────────────────────────────────────────────────

    def source_summary(self) -> pd.DataFrame:
        """Count events per source_file, with earliest/latest timestamps."""
        if self.df.empty:
            return pd.DataFrame()
        return (
            self.df.groupby(["source_file", "source_type"])
            .agg(
                event_count = ("id",        "count"),
                first_event = ("timestamp", "min"),
                last_event  = ("timestamp", "max"),
                event_types = ("event_type","nunique"),
            )
            .reset_index()
            .sort_values("event_count", ascending=False)
        )

    # ── 7. Event-type frequency table ─────────────────────────────────────────

    def event_type_frequency(self) -> pd.DataFrame:
        """Count + percentage breakdown of event types."""
        if self.df.empty:
            return pd.DataFrame()
        counts = self.df["event_type"].value_counts().reset_index()
        counts.columns = ["event_type", "count"]
        counts["pct"] = (counts["count"] / counts["count"].sum() * 100).round(1)
        return counts

    # ── 8. Neighbour lookup ────────────────────────────────────────────────────

    def events_near(self, timestamp: str,
                    before_sec: int = 120,
                    after_sec:  int = 120) -> pd.DataFrame:
        """
        Retrieve events within a time radius around a specific moment.
        Useful for investigating a known event of interest.
        """
        ts    = pd.Timestamp(timestamp)
        start = ts - timedelta(seconds=before_sec)
        end   = ts + timedelta(seconds=after_sec)
        mask  = (self.df["timestamp"] >= start) & (self.df["timestamp"] <= end)
        return self.df[mask].sort_values("timestamp").reset_index(drop=True)

    # ── 9. Flag writer (used by Phase 3 detection engine) ─────────────────────

    def flag_event(self, event_id: int, reason: str):
        """Mark an event as suspicious in the database."""
        self.conn.execute(
            "UPDATE events SET flagged=1, flag_reason=? WHERE id=?",
            (reason, event_id)
        )
        self.conn.commit()

    def flag_bulk(self, event_ids: list[int], reason: str):
        """Flag multiple events at once."""
        self.conn.executemany(
            "UPDATE events SET flagged=1, flag_reason=? WHERE id=?",
            [(reason, eid) for eid in event_ids]
        )
        self.conn.commit()


# ──────────────────────────────────────────────
#  PRETTY PRINT HELPERS
# ──────────────────────────────────────────────

def print_df(df: pd.DataFrame, title: str, max_rows: int = 15):
    print(f"\n{'═'*60}")
    print(f"  {title}")
    print(f"{'═'*60}")
    if df.empty:
        print("  (no results)")
        return
    # Truncate description for display
    display = df.copy()
    if "description" in display.columns:
        display["description"] = display["description"].str[:55]
    if "timestamp" in display.columns:
        display["timestamp"] = display["timestamp"].astype(str).str[:19]
    print(tabulate(
        display.head(max_rows),
        headers="keys",
        tablefmt="simple",
        showindex=False
    ))
    if len(df) > max_rows:
        print(f"  … and {len(df) - max_rows} more rows")


# ──────────────────────────────────────────────
#  EXPORT HELPERS
# ──────────────────────────────────────────────

def export_timeline_json(engine: TimelineEngine, output_path: str):
    """Export enriched timeline to JSON for Phase 3 / dashboard."""
    tl  = engine.full_timeline()
    spk = engine.activity_spikes()
    src = engine.source_summary()
    frq = engine.event_type_frequency()
    cor = engine.cross_source_events()

    def df_to_list(df):
        if df.empty:
            return []
        return json.loads(df.to_json(orient="records", date_format="iso"))

    output = {
        "generated_at":        datetime.now().isoformat(),
        "total_events":        len(tl),
        "source_summary":      df_to_list(src),
        "event_type_frequency":df_to_list(frq),
        "activity_spikes":     df_to_list(spk),
        "cross_source_windows":df_to_list(cor),
        "timeline":            df_to_list(
            tl[["id","timestamp","source_file","source_type",
                "event_type","description","flagged","flag_reason"]]
        ),
    }

    with open(output_path, "w") as fh:
        json.dump(output, fh, indent=2, default=str)

    print(f"\n  Enriched timeline saved → {output_path}")


# ──────────────────────────────────────────────
#  CLI DEMO
# ──────────────────────────────────────────────

def run_demo(engine: TimelineEngine):
    """Print a full terminal report of all timeline analyses."""

    print("\n\n══ DFITS Phase 2 — Timeline Engine Report ═══")

    # 1. Source summary
    print_df(engine.source_summary(), "Evidence sources")

    # 2. Event type frequency
    print_df(engine.event_type_frequency(), "Event type frequency")

    # 3. Activity density (per minute)
    print_df(engine.activity_density("min"), "Activity density (per minute)")

    # 4. Spike windows
    spikes = engine.activity_spikes("min")
    print_df(spikes, "Activity spikes (high-interest windows)")

    # 5. Cross-source correlations
    cors = engine.cross_source_events(window_seconds=300)
    if not cors.empty:
        print_df(
            cors[["window_start","event_count","sources","event_types"]],
            "Cross-source correlations (events from 2+ sources within 5 min)"
        )

    # 6. Timeline slice — the active period
    sliced = engine.time_slice("2024-05-01T10:30", "2024-05-01T10:55")
    print_df(
        sliced[["timestamp","source_type","event_type","description"]],
        "Timeline slice  10:30–10:55  (key investigation window)"
    )

    # 7. Neighbour lookup around the USB event
    near = engine.events_near("2024-05-01T10:45:02", before_sec=180, after_sec=180)
    print_df(
        near[["timestamp","source_type","event_type","description"]],
        "Events ±3 min around USB insertion (10:45:02)"
    )

    print("\n══ End of report ═══════════════════════════\n")


def main():
    parser = argparse.ArgumentParser(
        description="DFITS Phase 2 — Unified Event Database + Timeline Engine"
    )
    parser.add_argument(
        "json_file",
        help="Phase 1 output JSON (unified_events.json)"
    )
    parser.add_argument(
        "--db", default="dfits_evidence.db",
        help="SQLite database path (default: dfits_evidence.db)"
    )
    parser.add_argument(
        "--export", default="timeline_enriched.json",
        help="Enriched output JSON for Phase 3 / dashboard"
    )
    parser.add_argument(
        "--demo", action="store_true", default=True,
        help="Print full terminal analysis report (default: on)"
    )
    args = parser.parse_args()

    # 1. Init DB
    print(f"\n  Opening database  →  {args.db}")
    conn = init_db(args.db)

    # 2. Ingest Phase 1 JSON
    inserted = ingest_json(conn, args.json_file)
    total    = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"  Ingested {inserted} new events  |  {total} total in database")

    # 3. Build engine
    engine = TimelineEngine(conn)

    # 4. Demo report
    if args.demo:
        run_demo(engine)

    # 5. Export enriched JSON
    export_timeline_json(engine, args.export)

    conn.close()
    print("  Done.\n")


if __name__ == "__main__":
    main()