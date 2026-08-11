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

# Export as CSV — returns the raw body plus X-ShieldCortex-Export-* integrity headers
export = client.export_audit_logs(format="csv")
with open("audit_export.csv", "w") as f:
    f.write(export.content)
print("\nExported to audit_export.csv")

# Verify the export's integrity. sha256/signature/manifest_id are None when
# the server did not send them — the export is unverifiable, never "".
headers = export.headers
if headers.sha256 is None or headers.signature is None:
    print("Export is UNVERIFIABLE — integrity headers absent")
else:
    print(f"Entries: {headers.count}")
    print(f"SHA-256: {headers.sha256}")
    print(f"Signature ({headers.signature_algorithm}): {headers.signature}")
    if headers.manifest_id is not None:
        # Server-side check against the persisted, signed manifest
        response = client.verify_audit_export(
            headers.manifest_id, export_sha256=headers.sha256
        )
        result = response.verification
        print(f"Manifest {headers.manifest_id}:")
        print(f"  signature valid: {result.signature_valid}")
        print(f"  sha256 matches:  {result.sha256_matches}")
