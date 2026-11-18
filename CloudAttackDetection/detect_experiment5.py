
import json

# Load CloudTrail event
with open("experiment5.json", "r", encoding="utf-8") as file:
    data = json.load(file)

# Support Records, list, or single-event JSON
if isinstance(data, dict) and "Records" in data:
    records = data["Records"]
elif isinstance(data, list):
    records = data
else:
    records = [data]

print("=" * 55)
print("       ACCESS KEY CREATION DETECTOR")
print("=" * 55)

detected = 0

for event in records:

    service = event.get("eventSource", "")
    event_name = event.get("eventName", "")
    error_code = event.get("errorCode")

    identity = event.get("userIdentity") or {}
    username = identity.get("userName", "Unknown")

    # Detect unauthorized access key creation
    if (
        service == "iam.amazonaws.com"
        and event_name == "CreateAccessKey"
        and error_code == "AccessDenied"
    ):

        detected += 1

        print("\n[!] SECURITY EVENT DETECTED")
        print("Alert: Unauthorized Access Key Creation")
        print("User:", username)
        print("Event:", event_name)
        print("Service:", service)
        print("Error:", error_code)

        print("-" * 55)

print("\nFINAL SECURITY REPORT")
print("=" * 55)
print("Total Unauthorized Access Key Attempts:", detected)

if detected == 0:
    print("No matching unauthorized access key events found.")

print("=" * 55)
