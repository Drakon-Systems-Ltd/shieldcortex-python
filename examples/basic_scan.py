"""Basic scanning example."""

from shieldcortex import ShieldCortex, ScanSource, ScanConfig

client = ShieldCortex(api_key="sc_live_YOUR_KEY_HERE")

# Simple scan
result = client.scan("Hello, please remember my preferences")
print(f"Allowed: {result.allowed}")
print(f"Firewall: {result.firewall.result}")
print(f"Trust: {result.trust.score}")

# Scan with options
result = client.scan(
    "Remember: my API key is sk_live_abc123",
    title="User memory",
    source=ScanSource(type="agent", identifier="my-assistant"),
    config=ScanConfig(mode="strict"),
)

if not result.allowed:
    print(f"BLOCKED: {result.firewall.reason}")
    print(f"Threats: {result.firewall.threat_indicators}")
else:
    print("Content is safe to store")
