
import json

# Load CloudTrail event
with open("experiment4.json", "r", encoding="utf-8") as file:
    data = json.load(file)

# Support both single event and Records format
if isinstance(data, dict) and "Records" in data:
    records = data["Records"]
elif isinstance(data, list):
    records = data
else:
    records = [data]

print("=" * 55)
print("       IAM POLICY MODIFICATION DETECTOR")
print("=" * 55)

detected = 0

for event in records:

    service = event.get("eventSource", "")
    event_name = event.get("eventName", "")
    error_code = event.get("errorCode")
    identity = event.get("userIdentity") or {}
    username = identity.get("userName", "Unknown")

    # Detect unauthorized IAM operations
    if service == "iam.amazonaws.com" and error_code == "AccessDenied":

        detected += 1

        print("\n[!] SECURITY EVENT DETECTED")
        print("Alert: Unauthorized IAM Operation")
        print("User:", username)
        print("Event:", event_name)
        print("Service:", service)
        print("Error:", error_code)

        print("-" * 55)

print("\nFINAL SECURITY REPORT")
print("=" * 55)
print("Total IAM Unauthorized Events:", detected)

if detected == 0:
    print("No matching unauthorized IAM events found.")

print("=" * 55)
