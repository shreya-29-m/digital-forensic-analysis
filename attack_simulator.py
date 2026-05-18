"""
attack_simulator.py  (updated)
------------------------------
Simulates a full attack chain for demo mode:
  Brute Force → Account Compromise → Privilege Escalation

Privilege escalation now includes three realistic Windows Event IDs:
  4672 — Special privileges assigned to new logon (token elevation)
  4728 — User added to a security-enabled global group (e.g. Domain Admins)
  4732 — User added to a security-enabled local group  (e.g. Administrators)

These are the three events a real forensic analyst looks for to prove
privilege escalation happened.
"""

from datetime import datetime, timedelta


def simulate_attack():
    logs = []
    base_time = datetime.now()

    # ── Normal baseline activity ───────────────────────────────────────────────
    logs.append({
        "time":  base_time,
        "event": "LOGIN SUCCESS",
        "user":  "user1",
        "ip":    "192.168.1.10",
        "id":    4624,
        "detail": "Normal user login"
    })
    logs.append({
        "time":  base_time + timedelta(seconds=10),
        "event": "LOGIN SUCCESS",
        "user":  "user1",
        "ip":    "192.168.1.10",
        "id":    4624,
        "detail": "Normal user login"
    })

    # ── Brute force: 6 failed attempts against admin ───────────────────────────
    for i in range(6):
        logs.append({
            "time":  base_time + timedelta(seconds=20 + i),
            "event": "LOGIN FAILED",
            "user":  "admin",
            "ip":    "192.168.1.50",
            "id":    4625,
            "detail": f"Failed login attempt #{i+1} — wrong password"
        })

    # ── Successful login after brute force ────────────────────────────────────
    logs.append({
        "time":  base_time + timedelta(seconds=40),
        "event": "LOGIN SUCCESS",
        "user":  "admin",
        "ip":    "192.168.1.50",
        "id":    4624,
        "detail": "Login succeeded after multiple failures — possible compromise"
    })

    # ── Privilege Escalation Step 1: Special privileges on logon ──────────────
    # Event 4672: Fired when an account logs on with admin/special privileges.
    # This is the FIRST sign of escalation — the attacker's token has elevated rights.
    logs.append({
        "time":  base_time + timedelta(seconds=45),
        "event": "ADMIN PRIVILEGE",
        "user":  "admin",
        "ip":    "192.168.1.50",
        "id":    4672,
        "detail": (
            "Special privileges assigned to new logon. "
            "Privileges: SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege. "
            "This indicates the account now has elevated token rights."
        )
    })

    # ── Privilege Escalation Step 2: Added to local Administrators group ───────
    # Event 4732: Fired when a user is added to a local security group.
    # Attacker adds their compromised account to the local Administrators group.
    logs.append({
        "time":  base_time + timedelta(seconds=55),
        "event": "GROUP MEMBERSHIP CHANGE",
        "user":  "admin",
        "ip":    "192.168.1.50",
        "id":    4732,
        "detail": (
            "A member was added to a security-enabled local group. "
            "Group: Administrators. "
            "Member added: admin. "
            "This grants full local system control."
        )
    })

    # ── Privilege Escalation Step 3: Added to Domain Admins (if domain joined) ─
    # Event 4728: Fired when a user is added to a global security group.
    # This is the highest escalation — full domain control.
    logs.append({
        "time":  base_time + timedelta(seconds=65),
        "event": "DOMAIN GROUP CHANGE",
        "user":  "admin",
        "ip":    "192.168.1.50",
        "id":    4728,
        "detail": (
            "A member was added to a security-enabled global group. "
            "Group: Domain Admins. "
            "Member added: admin. "
            "CRITICAL: This account now has domain-wide administrator access."
        )
    })

    return logs
