from log_extractor import extract_windows_logs
from forensic_tool import (
    generate_timeline,
    generate_evidence_table,
    detect_attack_patterns,
    reconstruct_attack,
    generate_html_report
)
from attack_simulator import simulate_attack
from datetime import datetime

# ── MODE SELECTION ─────────────────────────────────────────────────────────────
print("=" * 50)
print("    DIGITAL FORENSIC ANALYSIS TOOL")
print("=" * 50)
mode = input("\nChoose mode (live / demo): ").strip().lower()

logs = []
integrity_results = []
tampered = False

# ── DEMO MODE ──────────────────────────────────────────────────────────────────
if mode == "demo":
    logs = simulate_attack()
    print("\n[Demo] Simulated attack logs loaded.")

# ── LIVE MODE ──────────────────────────────────────────────────────────────────
else:
    print("\n--- LOG EXTRACTION ---")
    start_input = input("Enter Start Date (YYYY-MM-DD) or press Enter for all: ").strip()
    end_input   = input("Enter End Date   (YYYY-MM-DD) or press Enter for all: ").strip()

    if start_input == "" or end_input == "":
        start = None
        end   = None
    else:
        start = datetime.strptime(start_input, "%Y-%m-%d")
        end   = datetime.strptime(end_input,   "%Y-%m-%d")

    logs = extract_windows_logs(start, end)

    if not logs:
        print("\n No relevant logs found for the given date range.")
        exit()

# ── ANALYSIS ───────────────────────────────────────────────────────────────────
if logs:
    generate_timeline(logs)
    generate_evidence_table(logs)
    attack = detect_attack_patterns(logs)
    generate_html_report(logs)

    if attack:
        reconstruct_attack(logs)

    # ── SUMMARY ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 50)
    print("FINAL SUMMARY")
    print("=" * 50)

    if attack:
        print("  Threat detected in system logs")
    else:
        print("  System appears normal — no attack patterns found")

    print("\nForensic Report -> forensic_report.html")
else:
    print("No logs to analyse!")