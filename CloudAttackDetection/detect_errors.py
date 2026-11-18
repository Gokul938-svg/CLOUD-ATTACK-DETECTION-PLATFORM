
import json
from datetime import datetime

# Load CloudTrail event
with open("cloudtraillatest.json", "r", encoding="utf-8") as file:
    data = json.load(file)

# Handle both single events and CloudTrail Records
if isinstance(data, dict) and "Records" in data:
    records = data["Records"]
else:
    records = [data]

print("=" * 55)
print("       AWS SECURITY EVENT DETECTION ENGINE")
print("=" * 55)

total_events = len(records)
access_denied = 0
other_errors = 0

for event in records:

    username = event.get("userIdentity", {}).get("userName", "Unknown")
    event_name = event.get("eventName", "Unknown")
    service = event.get("eventSource", "Unknown")
    region = event.get("awsRegion", "Unknown")
    source_ip = event.get("sourceIPAddress", "Unknown")
    error = event.get("errorCode")

    print("\nUser:", username)
    print("Event:", event_name)
    print("Service:", service)
    print("Region:", region)
    print("Source IP:", source_ip)

    if error == "AccessDenied":
        access_denied += 1

        print("\n[!] SECURITY EVENT DETECTED")
        print("Alert: Unauthorized API Access")
        print("Error:", error)

    elif error:
        other_errors += 1

        print("\n[!] API ERROR DETECTED")
        print("Error:", error)

    else:
        print("\n[+] No API error recorded")

    print("-" * 55)

print("\nFINAL SECURITY REPORT")
print("=" * 55)
print("Total Events:", total_events)
print("Access Denied Events:", access_denied)
print("Other Error Events:", other_errors)
print("Events Without Errors:",
      total_events - access_denied - other_errors)
