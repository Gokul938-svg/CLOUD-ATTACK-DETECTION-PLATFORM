
import json

# Load CloudTrail JSON
with open("cloudtraillatest.json", "r", encoding="utf-8") as file:
    data = json.load(file)

# Support both CloudTrail Records and individual events
if isinstance(data, dict) and "Records" in data:
    records = data["Records"]
else:
    records = [data]

# Counters
total_events = 0
access_denied_count = 0
failed_login_count = 0
other_error_count = 0
events_without_errors = 0

print("=" * 55)
print("       AWS SECURITY EVENT DETECTION ENGINE")
print("=" * 55)

for event in records:

    total_events += 1

    identity = event.get("userIdentity") or {}
    response = event.get("responseElements") or {}

    username = identity.get("userName", "Unknown")
    event_name = event.get("eventName", "Unknown")
    service = event.get("eventSource", "Unknown")
    region = event.get("awsRegion", "Unknown")
    source_ip = event.get("sourceIPAddress", "Unknown")

    error_code = event.get("errorCode")
    error_message = event.get("errorMessage")

    # Detect failed console login
    if (
        event_name == "ConsoleLogin"
        and response.get("ConsoleLogin") == "Failure"
    ):
        failed_login_count += 1

        print("\nUser:", username)
        print("Event:", event_name)
        print("Service:", service)
        print("Region:", region)
        print("\n[!] SECURITY EVENT DETECTED")
        print("Alert: Failed Console Login")
        print("Error:", error_message or "Authentication failed")
        print("-" * 55)

    # Detect unauthorized API access
    elif error_code == "AccessDenied":
        access_denied_count += 1

        print("\nUser:", username)
        print("Event:", event_name)
        print("Service:", service)
        print("Region:", region)
        print("\n[!] SECURITY EVENT DETECTED")
        print("Alert: Unauthorized API Access")
        print("Error:", error_code)
        print("-" * 55)

    # Detect other API errors
    elif error_code:
        other_error_count += 1

        print("\nUser:", username)
        print("Event:", event_name)
        print("Service:", service)
        print("Region:", region)
        print("\n[!] API ERROR DETECTED")
        print("Error:", error_code)
        print("-" * 55)

    else:
        events_without_errors += 1

# Final report
print("\nFINAL SECURITY REPORT")
print("=" * 55)
print("Total Events:", total_events)
print("Access Denied Events:", access_denied_count)
print("Failed Console Login Events:", failed_login_count)
print("Other Error Events:", other_error_count)
print("Events Without Errors:", events_without_errors)
print("=" * 55)
