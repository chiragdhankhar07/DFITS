# DFITS — Digital Forensic Intelligence & Timeline System

A prototype tool for cybercrime investigation workflow automation.
Mimics real forensic platforms like Autopsy and Plaso.

## What it does
- Parses .log files and WhatsApp exports into a unified evidence timeline
- Stores all events in a SQLite database
- Runs 8 rule-based detection rules (brute-force login, USB + file deletion, privilege escalation, suspicious chat correlation and more)
- Displays a live Streamlit dashboard with Plotly charts

## Tech stack
Python · pandas · SQLite · Streamlit · Plotly

## How to run
pip install pandas streamlit plotly tabulate

python3 phase1_parser.py sample_system.log sample_whatsapp.txt -o unified_events.json
python3 phase2_timeline.py unified_events.json --db dfits_evidence.db
python3 phase3_detection.py --db dfits_evidence.db
streamlit run phase4_dashboard.py -- --db dfits_evidence.db

## Built by
Chirag — Digital Forensics Specialist & Assistant Professor
