
import json

with open("cloudtraillatest.json", "r", encoding="utf-8") as file:
    data = json.load(file)

records = data["Records"]

print("AWS CLOUDTRAIL DETAILED ANALYSIS")
print("=" * 40)

print("Total Events:", len(records))

for event in records:

    identity = event.get("userIdentity", {})

    print("\nEvent Name:", event.get("eventName"))
    print("Event Source:", event.get("eventSource"))
    print("Event Time:", event.get("eventTime"))

    print("Identity Type:", identity.get("type"))
    print("Username:", identity.get("userName"))
    print("Principal ID:", identity.get("principalId"))

    print("Source IP:", event.get("sourceIPAddress"))
    print("Error Code:", event.get("errorCode"))
    print("Read Only:", event.get("readOnly"))

    print("-" * 40)
