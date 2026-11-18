
import json
from datetime import datetime, timedelta

# Load CloudTrail events
with open("experiment3.json", "r", encoding="utf-8") as file:
    data = json.load(file)

records = data["Records"]

# Sort events by timestamp
records.sort(
    key=lambda event: datetime.fromisoformat(
        event["eventTime"].replace("Z", "+00:00")
    )
)

threshold = 3
time_window = timedelta(minutes=10)

print("=" * 60)
print("       LOGIN SEQUENCE DETECTION ENGINE")
print("=" * 60)

# Group login events by username
users = {}

for event in records:
    username = event.get("userIdentity", {}).get(
        "userName", "Unknown"
    )

    if event.get("eventName") != "ConsoleLogin":
        continue

    result = (
        event.get("responseElements") or {}
    ).get("ConsoleLogin")

    event_time = datetime.fromisoformat(
        event["eventTime"].replace("Z", "+00:00")
    )

    users.setdefault(username, []).append(
        (event_time, result)
    )

# Detect failures followed by success
for username, events in users.items():

    for index, (success_time, result) in enumerate(events):

        if result != "Success":
            continue

        # Count failures within the previous 10 minutes
        failures = [
            event_time
            for event_time, status in events[:index]
            if status == "Failure"
            and success_time - time_window <= event_time < success_time
        ]

        if len(failures) >= threshold:

            print("\n[!] SECURITY ALERT DETECTED")
            print("Alert: Suspicious Login Pattern")
            print("User:", username)
            print("Failed Attempts:", len(failures))
            print("Successful Login:", success_time)
            print("Time Window: 10 minutes")
            print("Status: Suspicious activity")

        else:
            print("\nNo suspicious login sequence for:", username)

print("\n" + "=" * 60)
print("LOGIN ANALYSIS COMPLETED")
print("=" * 60)
