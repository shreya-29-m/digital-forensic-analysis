from datetime import datetime

def extract_windows_logs(start_date=None, end_date=None):
    try:
        import win32evtlog

        print("Scanning Windows Security Logs...\n")
        server = 'localhost'
        logtype = 'Security'
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        logs = []
        events = win32evtlog.ReadEventLog(hand, flags, 0)

        while events:
            for event in events:
                event_id = event.EventID & 0xFFFF

                if event_id not in [4624, 4625, 4672, 1102, 4719]:
                    continue

                # ── event type ──
                if event_id == 4624:
                    event_type = "LOGIN SUCCESS"
                elif event_id == 4625:
                    event_type = "LOGIN FAILED"
                elif event_id == 4672:
                    event_type = "ADMIN PRIVILEGE"
                elif event_id == 1102:
                    event_type = "LOG CLEARED"
                elif event_id == 4719:
                    event_type = "AUDIT POLICY CHANGED"
                else:
                    event_type = "UNKNOWN"

                # ── time ──
                log_time = event.TimeGenerated

                if start_date and log_time < start_date:
                    continue
                if end_date and log_time > end_date:
                    continue

                # ── user and ip ──
                user = "UNKNOWN"
                ip = "UNKNOWN"

                try:
                    if event.StringInserts:
                        if len(event.StringInserts) > 5:
                            user = event.StringInserts[5] or "UNKNOWN"
                        if len(event.StringInserts) > 18:
                            ip = event.StringInserts[18] or "UNKNOWN"
                except:
                    user = "UNKNOWN"
                    ip = "UNKNOWN"

                # ── filters ──
                if user in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "UMFD-0", "UMFD-1"]:
                    continue

                if ip == "127.0.0.1":
                    ip = "LOCAL"

                if user == "UNKNOWN":
                    continue

                if logs and logs[-1]["time"] == log_time and logs[-1]["event"] == event_type:
                    continue

                logs.append({
                    "time": log_time,
                    "event": event_type,
                    "user": user,
                    "ip": ip,
                    "id": event_id
                })

            events = win32evtlog.ReadEventLog(hand, flags, 0)

        return logs

    except ImportError:
        print("win32evtlog not available - using subprocess fallback...\n")
        return extract_logs_subprocess(start_date, end_date)


def extract_logs_subprocess(start_date=None, end_date=None):
    import subprocess

    print("Scanning Windows Security Logs via wevtutil...\n")

    important_events = {
        4624: "LOGIN SUCCESS",
        4625: "LOGIN FAILED",
        4672: "ADMIN PRIVILEGE",
        1102: "LOG CLEARED",
        4719: "AUDIT POLICY CHANGED"
    }

    logs = []

    try:
        cmd = ["wevtutil", "qe", "Security", "/f:text", "/c:200"]
        result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = result.communicate()
        output = output.decode("utf-8", errors="ignore")

        current = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Date:"):
                try:
                    time_str = line.replace("Date:", "").strip()
                    current["time"] = datetime.strptime(time_str[:19], "%Y-%m-%dT%H:%M:%S")
                except:
                    pass
            elif line.startswith("Event ID:"):
                try:
                    eid = int(line.replace("Event ID:", "").strip())
                    current["id"] = eid
                    current["event"] = important_events.get(eid, "UNKNOWN")
                except:
                    pass
            elif line == "" and "time" in current and "event" in current:
                if current.get("event") != "UNKNOWN":
                    current.setdefault("user", "UNKNOWN")
                    current.setdefault("ip", "UNKNOWN")
                    logs.append(current)
                current = {}

    except Exception as e:
        print("Error reading logs: {err}".format(err=e))

    return logs