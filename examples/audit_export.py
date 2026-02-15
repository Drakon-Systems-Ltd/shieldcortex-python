"""Audit log querying and export example."""

from shieldcortex import ShieldCortex, AuditQuery

client = ShieldCortex(api_key="sc_live_YOUR_KEY_HERE")

# Get summary stats
stats = client.get_audit_stats(time_range="7d")
print(f"Total operations: {stats.total_operations}")
print(f"Allowed: {stats.allowed_count}")
print(f"Blocked: {stats.blocked_count}")
print(f"Quarantined: {stats.quarantined_count}")

# Query blocked entries
logs = client.get_audit_logs(AuditQuery(level="BLOCK", limit=5))
print(f"\nRecent blocks ({logs.total} total):")
for entry in logs.logs:
    print(f"  [{entry.timestamp}] {entry.reason} (trust: {entry.trust_score})")

# Auto-paginate through all entries
print("\nAll audit entries:")
for entry in client.iter_audit_logs(AuditQuery(level="BLOCK")):
    print(f"  #{entry.id}: {entry.firewall_result}")

# Export as CSV
csv_data = client.export_audit_logs(format="csv")
with open("audit_export.csv", "w") as f:
    f.write(csv_data)
print("\nExported to audit_export.csv")
