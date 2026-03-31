import win32evtlog
from datetime import datetime


def extract_windows_logs(start_date=None, end_date=None):

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

            # STEP 3 FILTER (important security events only)
            if event_id not in [4624, 4625, 4672]:
                continue

            time = event.TimeGenerated
            # Convert to datetime
            log_time = datetime.strptime(str(time), "%Y-%m-%d %H:%M:%S")

            # Apply date filter early
            if start_date and log_time < start_date:
                continue

            if end_date and log_time > end_date:
                continue

            if event_id == 4624:
                event_type = "LOGIN SUCCESS"
            elif event_id == 4625:
                event_type = "LOGIN FAILED"
            elif event_id == 4672:
                event_type = "ADMIN PRIVILEGE"
            else:
                event_type = "UNKNOWN"

            user = "UNKNOWN"
            ip = "UNKNOWN"

            if event.StringInserts:

                try:
                    if len(event.StringInserts) > 5:
                        user = event.StringInserts[5]

                    if len(event.StringInserts) > 18:
                        ip = event.StringInserts[18]

                except:
                    pass
                    
            # Remove noisy system logins
            if user in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "UMFD-0", "UMFD-1"]:
                continue

            # Fix empty or local IP values
            if ip == "127.0.0.1":
                ip = "LOCAL"
            if user == "UNKNOWN":
                continue

            if logs and logs[-1]["time"] == time and logs[-1]["event"] == event_type:
                continue

            logs.append({
                "time": time,
                "event": event_type,
                "user": user,
                "ip": ip,
                "id": event_id
            })

        events = win32evtlog.ReadEventLog(hand, flags, 0)
    return logs