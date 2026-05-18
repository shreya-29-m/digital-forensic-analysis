import os
from datetime import datetime
import sys


def generate_html_report(logs):
    """
    Updated version — now accepts integrity_results from log_integrity.py
    and adds a LOG INTEGRITY section to the forensic report.

    Args:
        logs              : list of log event dicts (same as before)
        integrity_results : list of dicts from verify_integrity()
                            Each dict has: path, status, expected_hash, actual_hash, note
        tampered          : bool — True if any integrity violation found
    """
    if integrity_results is None:
        integrity_results = []

    # ===== ANALYSIS =====
    failed  = sum(1 for log in logs if log["event"] == "LOGIN FAILED")
    success = any(log["event"] == "LOGIN SUCCESS" for log in logs)
    admin   = any(log["event"] in ("ADMIN PRIVILEGE", "GROUP MEMBERSHIP CHANGE", "DOMAIN GROUP CHANGE") for log in logs)

    attacker_ip = "UNKNOWN"
    for log in logs:
        if log["event"] == "LOGIN FAILED":
            attacker_ip = log["ip"]

    # ===== THREAT STATUS =====
    if failed >= 5 and success :
        status       = "CRITICAL"
        message      = "Potential attack detected: brute force + privilege escalation"
        summary      = "Multiple failed logins followed by success and admin access."
    else:
        status       = "SAFE"
        message      = "No major suspicious activity detected"
        summary      = "System logs appear normal."

    if tampered:
        status  = "CRITICAL"
        message = message + " | Log tampering detected — attacker covered tracks"

    status_class = "critical" if status == "CRITICAL" else "safe"

    # ===== BUILD HTML =====
    html = """
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
    h1  {{ text-align: center; color: #58a6ff; }}
    h2  {{ color: #58a6ff; }}
    .card {{
      background: #161b22;
      padding: 15px;
      margin: 20px 0;
      border-radius: 10px;
      border: 1px solid #30363d;
    }}
    .safe     {{ color: #3fb950; }}
    .critical {{ color: #f85149; }}
    .warning  {{ color: #d29922; }}
    .ok       {{ color: #3fb950; }}
    button {{
      background: #21262d;
      color: #58a6ff;
      border: none;
      padding: 8px 12px;
      cursor: pointer;
      margin-top: 10px;
      border-radius: 4px;
    }}
    .dropdown {{
      display: none;
      margin-top: 10px;
      padding: 10px;
      background: #0d1117;
      border-left: 3px solid #58a6ff;
    }}
    table  {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #30363d; text-align: left; }}
    th     {{ color: #58a6ff; }}
    .tampered {{ color: #f85149; font-weight: bold; }}
    .deleted  {{ color: #f85149; font-weight: bold; }}
    .intact   {{ color: #3fb950; }}
    .new-file {{ color: #d29922; }}
  </style>
  <script>
    function toggle(id) {{
      var x = document.getElementById(id);
      x.style.display = (x.style.display === "none") ? "block" : "none";
    }}
  </script>
</head>
<body>

<h1>DIGITAL FORENSIC REPORT</h1>
<p style="text-align:center; color:#8b949e;">Generated: {timestamp}</p>

<div style="text-align:center; font-size:24px; margin:10px 0;">
  <span class="{status_class}">THREAT LEVEL: {status}</span>
</div>

<!-- SYSTEM STATUS -->
<div class="card">
  <h2>SYSTEM STATUS</h2>
  <p class="{status_class}">{status}</p>
  <p>{message}</p>
  <button onclick="toggle('status_explain')">Explain</button>
  <div id="status_explain" class="dropdown">
    SAFE means no suspicious behaviour was detected.<br>
    CRITICAL indicates a confirmed or likely attack pattern (brute force, privilege
    escalation, or log tampering).
  </div>
</div>

<!-- ATTACK SUMMARY -->
<div class="card">
  <h2>ATTACK SUMMARY</h2>
  <p>{summary}</p>
  <button onclick="toggle('summary_explain')">Explain</button>
  <div id="summary_explain" class="dropdown">
    This summarises brute force attempts, suspicious logins, privilege escalation
    events, and whether log files were tampered with after the breach.
  </div>
</div>

<!-- ATTACKER INFO -->
<div class="card">
  <h2>ATTACKER INFO</h2>
  <p><b>Suspected IP:</b> <span class="critical">{attacker_ip}</span></p>
  <button onclick="toggle('attacker_explain')">Explain</button>
  <div id="attacker_explain" class="dropdown">
    This IP address is flagged due to repeated failed login attempts followed
    by a successful login — a classic brute-force pattern.
  </div>
</div>
""".format(
        timestamp    = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        status_class = status_class,
        status       = status,
        message      = message,
        summary      = summary,
        attacker_ip  = attacker_ip
    )

    # ===== PRIVILEGE ESCALATION SECTION (NEW) =====
    priv_events = [
        log for log in logs
        if log["event"] in ("ADMIN PRIVILEGE", "GROUP MEMBERSHIP CHANGE", "DOMAIN GROUP CHANGE")
    ]

    if priv_events:
        html += """
<!-- PRIVILEGE ESCALATION -->
<div class="card">
  <h2>PRIVILEGE ESCALATION EVENTS</h2>
  <p class="critical">
    {count} privilege escalation event(s) detected. The attacker gained
    elevated access after the initial compromise.
  </p>
  <button onclick="toggle('priv_explain')">Explain</button>
  <div id="priv_explain" class="dropdown">
    <b>Event 4672</b> — Special privileges (SeDebugPrivilege etc.) assigned at logon.<br>
    <b>Event 4732</b> — User added to local Administrators group.<br>
    <b>Event 4728</b> — User added to Domain Admins (full domain takeover).<br><br>
    Finding all three in sequence is the forensic signature of a complete
    privilege escalation attack chain.
  </div>
  <table>
    <tr><th>Time</th><th>Event</th><th>User</th><th>IP</th><th>Event ID</th><th>Detail</th></tr>
""".format(count=len(priv_events))

        for log in priv_events:
            time_str = log["time"].strftime("%H:%M:%S") if hasattr(log["time"], "strftime") else str(log["time"])
            detail   = log.get("detail", "")
            html += """
    <tr>
      <td>{time}</td>
      <td class="critical">{event}</td>
      <td>{user}</td>
      <td>{ip}</td>
      <td>{eid}</td>
      <td style="font-size:11px;">{detail}</td>
    </tr>
""".format(
                time   = time_str,
                event  = log["event"],
                user   = log.get("user", "UNKNOWN"),
                ip     = log.get("ip",   "UNKNOWN"),
                eid    = log.get("id",   ""),
                detail = detail
            )

        html += "</table></div>\n"

    # ===== FULL EVIDENCE TABLE =====
    html += """
<!-- EVIDENCE TABLE -->
<div class="card">
  <h2>FULL EVIDENCE TABLE</h2>
  <table>
    <tr><th>User</th><th>IP</th><th>Event</th><th>Event ID</th><th>Time</th><th>Detail</th></tr>
"""
    for log in logs:
        time_str = log["time"].strftime("%H:%M:%S") if hasattr(log["time"], "strftime") else str(log["time"])
        html += """
    <tr>
      <td>{user}</td>
      <td>{ip}</td>
      <td>{event}</td>
      <td>{eid}</td>
      <td>{time}</td>
      <td style="font-size:11px;">{detail}</td>
    </tr>
""".format(
            user   = log.get("user",   "UNKNOWN"),
            ip     = log.get("ip",     "UNKNOWN"),
            event  = log.get("event",  "UNKNOWN"),
            eid    = log.get("id",     ""),
            time   = time_str,
            detail = log.get("detail", "")
        )

    html += """
  </table>
</div>

</body>
</html>
"""

    with open("forensic_report.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("Forensic report generated: forensic_report.html")



def generate_timeline(logs):
    print("\n===== FORENSIC EVENT TIMELINE =====\n")

    logs = sorted(logs, key=lambda x: x["time"])

    last_user = "UNKNOWN"
    last_ip = "UNKNOWN"

    for log in logs:
        event_type = log.get("event", "UNKNOWN")
        user = log.get("user", "UNKNOWN")
        ip = log.get("ip", "UNKNOWN")

        if event_type == "LOGIN SUCCESS" and user != "UNKNOWN":
            last_user = user
            last_ip = ip

        if event_type == "ADMIN PRIVILEGE":
            if user == "UNKNOWN":
                log["user"] = last_user
            if ip == "UNKNOWN":
                log["ip"] = last_ip

        print("{time} | {event} | User: {user} | IP: {ip}".format(
            time=log['time'],
            event=event_type,
            user=log.get('user'),
            ip=log.get('ip')
        ))


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

    for log in logs:
        if log["event"] == "LOGIN FAILED":
            ip_fail_count[log["ip"]] += 1

    for log in logs:
        if log["event"] == "LOGIN SUCCESS":
            if ip_fail_count[log["ip"]] >= 5:
                ip_success_after_fail[log["ip"]] = True

    attack_detected = False

    for ip, count in ip_fail_count.items():
        if count >= 5:
            print("[WARNING] Possible Brute Force Attack from {ip}".format(ip=ip))
            print("{count} failed login attempts detected\n".format(count=count))
            attack_detected = True

    for ip in ip_success_after_fail:
        print("[HIGH] Suspicious Login After Failures from {ip}".format(ip=ip))
        print("Failed logins followed by a successful login\n")
        attack_detected = True

    for i in range(len(logs) - 1):
        if logs[i]["event"] == "LOGIN SUCCESS":
            ip = logs[i]["ip"]
            if logs[i + 1]["event"] == "ADMIN PRIVILEGE":
                if ip_fail_count[ip] >= 5:
                    print("[HIGH] Possible Privilege Escalation from {ip}".format(ip=ip))
                    print("Admin privileges assigned after suspicious login\n")
                    attack_detected = True

    for ip in ip_success_after_fail:
        if ip_fail_count[ip] >= 5:
            print("[CRITICAL] Attack Chain Detected from {ip}".format(ip=ip))
            print("Brute Force -> Account Compromise -> Privilege Escalation\n")
            attack_detected = True

    if not attack_detected:
        print("No suspicious activity detected")

    for log in logs:
        if log["event"] == "LOG CLEARED":
            print("[CRITICAL] Security Log was CLEARED by {user} at {time}".format(
                user=log["user"], time=log["time"]))
            print("This is direct evidence of post-breach cover-up!\n")
            attack_detected = True

        if log["event"] == "AUDIT POLICY CHANGED":
            print("[HIGH] Audit Policy was CHANGED by {user} at {time}".format(
                user=log["user"], time=log["time"]))
            print("Attacker may have disabled logging to hide activity!\n")
            attack_detected = True

    return attack_detected


def reconstruct_attack(logs):
    print("\n===== ATTACK RECONSTRUCTION =====")

    attack_steps = []

    for i in range(len(logs)):
        if logs[i]["event"] == "LOGIN FAILED":
            attack_steps.append((
                logs[i]["time"],
                "Failed login attempt from {ip} (User: {user})".format(
                    ip=logs[i]['ip'], user=logs[i]['user'])
            ))

        if logs[i]["event"] == "LOGIN SUCCESS":
            attack_steps.append((
                logs[i]["time"],
                "Successful login from {ip} (User: {user})".format(
                    ip=logs[i]['ip'], user=logs[i]['user'])
            ))

        if logs[i]["event"] == "ADMIN PRIVILEGE":
            attack_steps.append((
                logs[i]["time"],
                "Privilege escalation for {user} from {ip}".format(
                    user=logs[i]['user'], ip=logs[i]['ip'])
            ))

    attack_steps.sort(key=lambda x: x[0])

    for step in attack_steps:
        print("{time} -> {desc}".format(time=step[0], desc=step[1]))


def generate_evidence_table(logs):
    print("\n===== FORENSIC EVIDENCE =====\n")
    print("USER\tIP\t\tEVENT\t\tTIME")
    print("-" * 55)

    for log in logs:
        time = log["time"].strftime("%H:%M:%S")
        user = log.get("user", "UNKNOWN")
        ip = log.get("ip", "UNKNOWN")
        event = log.get("event", "UNKNOWN")

        print("{user}\t{ip}\t{event}\t{time}".format(
            user=user, ip=ip, event=event, time=time))
