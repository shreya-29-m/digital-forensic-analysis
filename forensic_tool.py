import win32evtlog
import sys
from datetime import datetime
from log_extractor import extract_windows_logs

server = 'localhost'
log_type = 'Security'

important_events = {
    4624: "LOGIN SUCCESS",
    4625: "LOGIN FAILED",
    4672: "ADMIN PRIVILEGE",
    4720: "USER CREATED",
    4726: "USER DELETED",
    4688: "PROCESS CREATED"
}


def generate_html_report(logs):
    # ===== ANALYSIS =====
    failed = sum(1 for log in logs if log["event"] == "LOGIN FAILED")
    success = any(log["event"] == "LOGIN SUCCESS" for log in logs)
    admin = any(log["event"] == "ADMIN PRIVILEGE" for log in logs)

    attacker_ip = "UNKNOWN"

    for log in logs:
        if log["event"] == "LOGIN FAILED":
            attacker_ip = log["ip"]

    # ===== STATUS =====
    if failed >= 5 and success and admin:
        status = "CRITICAL"
        message = "Potential attack detected: brute force + privilege escalation"
        summary = "Multiple failed logins followed by success and admin access."
    else:
        status = "SAFE"
        message = "No major suspicious activity detected"
        summary = "System logs appear normal."

    # ===== HTML START =====
    html = f"""
    <html>
    <head>
    <title>Forensic Report</title>

    <style>
    body {{
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: Consolas, monospace;
        padding: 20px;
    }}

    h1 {{
        text-align: center;
        color: #58a6ff;
    }}

    .card {{
        background: #161b22;
        padding: 15px;
        margin: 20px 0;
        border-radius: 10px;
        border: 1px solid #30363d;
    }}

    .safe {{ color: #3fb950; }}
    .critical {{ color: #f85149; }}

    button {{
        background: #21262d;
        color: #58a6ff;
        border: none;
        padding: 8px;
        cursor: pointer;
        margin-top: 10px;
    }}

    .dropdown {{
        display: none;
        margin-top: 10px;
        padding: 10px;
        background: #0d1117;
        border-left: 3px solid #58a6ff;
    }}

    table {{
        width: 100%;
        border-collapse: collapse;
    }}

    th, td {{
        padding: 10px;
        border-bottom: 1px solid #30363d;
    }}

    th {{
        color: #58a6ff;
    }}
    </style>

    <script>
    function toggle(id) {{
        var x = document.getElementById(id);
        if (x.style.display === "none") {{
            x.style.display = "block";
        }} else {{
            x.style.display = "none";
        }}
    }}
    </script>

    </head>

    <body>

    <h1> DIGITAL FORENSIC REPORT</h1>

    <div style="text-align:center; font-size: 24px; margin-top:10px;">
        <span class="{ 'critical' if status=='CRITICAL' else 'safe' }">
            THREAT LEVEL: {status}
        </span>
    </div>
    
    <div class="card">
    <h2>🛡 SYSTEM STATUS</h2>
    <p class="{ 'critical' if status=='CRITICAL' else 'safe' }">{status}</p>
    <p>{message}</p>

    <button onclick="toggle('status_explain')">Explain</button>
    <div id="status_explain" class="dropdown">
    SAFE means no suspicious behavior detected.
    CRITICAL indicates a potential attack pattern.
    </div>
    </div>

    <div class="card">
    <h2>⚠ ATTACK SUMMARY</h2>
    <p>{summary}</p>

    <button onclick="toggle('summary_explain')">Explain</button>
    <div id="summary_explain" class="dropdown">
    This summarizes brute force attempts, suspicious logins, and privilege escalation.
    </div>
    </div>

    <div class="card">
    <h2>🕵️ ATTACKER INFO</h2>
    <p><b>IP:</b> <span class="critical">{attacker_ip}</span></p>

    <button onclick="toggle('attacker_explain')">Explain</button>
    <div id="attacker_explain" class="dropdown">
    This IP is suspected due to repeated failed login attempts.
    </div>
    </div>

    <div class="card">
    <h2>📊 EVIDENCE TABLE</h2>

    <table>
    <tr>
        <th>User</th>
        <th>IP</th>
        <th>Event</th>
        <th>Time</th>
    </tr>
    """

    # ===== TABLE DATA =====
    for log in logs:
        html += f"""
        <tr>
            <td>{log['user']}</td>
            <td>{log['ip']}</td>
            <td>{log['event']}</td>
            <td>{log['time']}</td>
        </tr>
        """

    # ===== HTML END =====
    html += """
    </table>
    </div>

    </body>
    </html>
    """

    # ===== SAVE FILE =====
    with open("forensic_report.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("✔ Forensic report generated: forensic_report.html")


def generate_timeline(logs):

    print("\n===== FORENSIC EVENT TIMELINE =====\n")

    logs = sorted(logs, key=lambda x: x["time"])

    last_user = "UNKNOWN"
    last_ip = "UNKNOWN"
    logs = sorted(logs, key=lambda x: x["time"])
    for log in logs:

        event_type = log.get("event", "UNKNOWN")

        user = log.get("user", "UNKNOWN")
        ip = log.get("ip", "UNKNOWN")

        # Update only if real user exists
        if event_type == "LOGIN SUCCESS" and user != "UNKNOWN":
            last_user = user
            last_ip = ip

        # Attach only if missing
        if event_type == "ADMIN PRIVILEGE":
            if user == "UNKNOWN":
                log["user"] = last_user
            if ip == "UNKNOWN":
                log["ip"] = last_ip

        print(f"{log['time']} | {event_type} | User: {log.get('user')} | IP: {log.get('ip')}")

def detect_threats(logs):

    failed_count = 0

    for log in logs:
        if log["id"] == 4625:
            failed_count += 1

    return failed_count


def detect_attack_patterns(logs):
    from collections import defaultdict

    ip_fail_count = defaultdict(int)
    ip_success_after_fail = {}

    print("\n===== ATTACK PATTERN ANALYSIS =====")

    # Step 1: count failed attempts per IP
    for log in logs:
        if log["event"] == "LOGIN FAILED":
            ip_fail_count[log["ip"]] += 1

    # Step 2: check success after fail per IP
    for log in logs:
        if log["event"] == "LOGIN SUCCESS":
            if ip_fail_count[log["ip"]] >= 5:
                ip_success_after_fail[log["ip"]] = True

    attack_detected = False

    # Step 3: print brute force
    for ip, count in ip_fail_count.items():
        if count >= 5:
            print(f"⚠ [WARNING] Possible Brute Force Attack from {ip}")
            print(f"{count} failed login attempts detected\n")
            attack_detected = True

    # Step 4: suspicious login after fail
    for ip in ip_success_after_fail:
        print(f"[HIGH] Suspicious Login After Failures from {ip}")
        print("Failed logins followed by a successful login\n")
        attack_detected = True

    # Step 5: privilege escalation detection
    for i in range(len(logs) - 1):
        if logs[i]["event"] == "LOGIN SUCCESS":
            ip = logs[i]["ip"]
            if logs[i + 1]["event"] == "ADMIN PRIVILEGE":
                if ip_fail_count[ip] >= 5:
                    print(f"[HIGH] Possible Privilege Escalation from {ip}")
                    print("Admin privileges assigned after suspicious login\n")
                    attack_detected = True

    # Step 6: full attack chain
    for ip in ip_success_after_fail:
        if ip_fail_count[ip] >= 5:
            print(f"[CRITICAL] Attack Chain Detected from {ip}")
            print("Brute Force → Account Compromise → Privilege Escalation\n")
            attack_detected = True

    # Step 7: no attack
    if not attack_detected:
        print("✔ No suspicious activity detected")

    return attack_detected

def reconstruct_attack(logs):
    print("\n===== ATTACK RECONSTRUCTION =====")

    attack_steps = []

    for i in range(len(logs)):

        if logs[i]["event"] == "LOGIN FAILED":
            attack_steps.append((
                logs[i]["time"],
                f"Failed login attempt from {logs[i]['ip']} (User: {logs[i]['user']})"
            ))

        if logs[i]["event"] == "LOGIN SUCCESS":
            attack_steps.append((
                logs[i]["time"],
                f"Successful login from {logs[i]['ip']} (User: {logs[i]['user']})"
            ))

        if logs[i]["event"] == "ADMIN PRIVILEGE":
            attack_steps.append((
                logs[i]["time"],
                f"Privilege escalation for {logs[i]['user']} from {logs[i]['ip']}"
            ))

    # Sort by time (very important)
    attack_steps.sort(key=lambda x: x[0])

    for step in attack_steps:
        print(f"{step[0]} → {step[1]}")

def generate_evidence_table(logs):

    print("\n===== FORENSIC EVIDENCE =====\n")
    print("USER\tIP\t\tEVENT\t\tTIME")
    print("-" * 55)

    for log in logs:
        time = log["time"].strftime("%H:%M:%S")
        user = log.get("user", "UNKNOWN")
        ip = log.get("ip", "UNKNOWN")
        event = log.get("event", "UNKNOWN")

        print(f"{user}\t{ip}\t{event}\t{time}")

if __name__ == "__main__":

    start = datetime.strptime(sys.argv[1], "%Y-%m-%d")
    end = datetime.strptime(sys.argv[2], "%Y-%m-%d")

    logs = extract_logs(start, end)

    generate_timeline(logs)

    detect_threats(logs)

    detect_attack_patterns(logs)

    reconstruct_attack(logs)

    generate_html_report(logs)