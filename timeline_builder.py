def build_timeline(events):

    # Sort events by time
    timeline = sorted(events, key=lambda x: x["time"])

    return timeline


def print_timeline(timeline):

    print("\n===== FORENSIC EVENT TIMELINE =====\n")

    for event in timeline:

        event_id = event["event_id"]
        time = event["time"]
        source = event["source"]

        print(f"{log['time']} | {event_type} | User: {log['user']} | IP: {log['ip']}")