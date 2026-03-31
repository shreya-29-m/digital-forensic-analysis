from datetime import datetime, timedelta

def simulate_attack():
    logs = []

    base_time = datetime.now()

    # Normal activity
    logs.append({
        "time": base_time,
        "event": "LOGIN SUCCESS",
        "user": "user1",
        "ip": "192.168.1.10",
        "id": 4624
    })

    logs.append({
        "time": base_time + timedelta(seconds=10),
        "event": "LOGIN SUCCESS",
        "user": "user1",
        "ip": "192.168.1.10",
        "id": 4624
    })

    # Brute force attempts
    for i in range(6):
        logs.append({
            "time": base_time + timedelta(seconds=20+i),
            "event": "LOGIN FAILED",
            "user": "admin",
            "ip": "192.168.1.50",
            "id": 4625
        })

    # Successful login after attack
    logs.append({
        "time": base_time + timedelta(seconds=40),
        "event": "LOGIN SUCCESS",
        "user": "admin",
        "ip": "192.168.1.50",
        "id": 4624
    })

    # Privilege escalation
    logs.append({
        "time": base_time + timedelta(seconds=60),
        "event": "ADMIN PRIVILEGE",
        "user": "admin",
        "ip": "192.168.1.50",
        "id": 4672
    })

    return logs