from log_extractor import extract_windows_logs
from forensic_tool import generate_timeline, generate_evidence_table
from forensic_tool import detect_attack_patterns, reconstruct_attack, generate_html_report
from attack_simulator import simulate_attack

from datetime import datetime

# --- MODE SELECTION ---
mode = input("Choose mode (live/demo): ")

# --- DEMO MODE ---
if mode == "demo":
    logs = simulate_attack()

# --- LIVE MODE ---
else:
    start_input = input("Enter Start Date (YYYY-MM-DD) or press Enter: ")
    end_input = input("Enter End Date (YYYY-MM-DD) or press Enter: ")

    if start_input == "" or end_input == "":
        start = None
        end = None
    else:
        start = datetime.strptime(start_input, "%Y-%m-%d")
        end = datetime.strptime(end_input, "%Y-%m-%d")

    logs = extract_windows_logs(start, end)
    if not logs:
        print("\n⚠ No relevant logs found for given date range")

# --- ANALYSIS ---
generate_timeline(logs)
generate_evidence_table(logs)

attack = detect_attack_patterns(logs)

generate_html_report(logs)

if attack:
    reconstruct_attack(logs)

print("\n===== SUMMARY =====")

if attack:
    print("⚠ Threat detected in system logs")
else:
    print("✔ System appears normal")