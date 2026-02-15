"""Batch scanning example — scan multiple items in one request."""

from shieldcortex import ShieldCortex, BatchItem, ScanConfig

client = ShieldCortex(api_key="sc_live_YOUR_KEY_HERE")

items = [
    BatchItem(content="User preference: dark mode enabled"),
    BatchItem(content="Meeting notes from Tuesday standup"),
    BatchItem(content="Password: hunter2"),  # This should be blocked
]

result = client.scan_batch(items, config=ScanConfig(mode="strict"))

print(f"Scanned: {result.total_scanned}")
print(f"Threats: {result.threats}")
print(f"Clean: {result.clean}")

for i, scan in enumerate(result.results):
    status = "SAFE" if scan.allowed else f"BLOCKED ({scan.firewall.reason})"
    print(f"  [{i}] {status}")
