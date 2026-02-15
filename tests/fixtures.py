"""Shared test response payloads."""

SCAN_ALLOWED_RESPONSE = {
    "allowed": True,
    "firewall": {
        "result": "ALLOW",
        "reason": "Content passed all checks",
        "threatIndicators": [],
        "anomalyScore": 0.02,
        "blockedPatterns": [],
    },
    "sensitivity": {"level": "PUBLIC", "redactionRequired": False},
    "trust": {"score": 0.95},
    "auditId": 42,
    "usage": {"scansUsed": 10, "scansLimit": 500},
}

SCAN_BLOCKED_RESPONSE = {
    "allowed": False,
    "firewall": {
        "result": "BLOCK",
        "reason": "SQL injection detected",
        "threatIndicators": ["sql_injection"],
        "anomalyScore": 0.95,
        "blockedPatterns": ["DROP TABLE"],
    },
    "sensitivity": {"level": "PUBLIC", "redactionRequired": False},
    "trust": {"score": 0.1},
    "auditId": 43,
}

AUDIT_RESPONSE = {
    "logs": [
        {
            "id": 1,
            "timestamp": "2026-02-15T10:00:00.000Z",
            "source_type": "user",
            "source_identifier": "alice@example.com",
            "trust_score": 0.95,
            "sensitivity_level": "PUBLIC",
            "firewall_result": "ALLOW",
            "anomaly_score": 0.02,
            "threat_indicators": [],
            "reason": "Content passed all checks",
            "pipeline_duration_ms": 45,
        },
        {
            "id": 2,
            "timestamp": "2026-02-15T10:05:00.000Z",
            "source_type": "agent",
            "source_identifier": "crewai:research",
            "trust_score": 0.3,
            "sensitivity_level": "CONFIDENTIAL",
            "firewall_result": "BLOCK",
            "anomaly_score": 0.88,
            "threat_indicators": ["credential_leak"],
            "reason": "Credential pattern detected",
            "pipeline_duration_ms": 67,
        },
    ],
    "total": 2,
    "pagination": {"limit": 100, "offset": 0, "hasMore": False},
}

AUDIT_STATS_RESPONSE = {
    "totalOperations": 1000,
    "allowedCount": 900,
    "blockedCount": 80,
    "quarantinedCount": 20,
    "topSources": [
        {"source": "user", "count": 600},
        {"source": "agent", "count": 400},
    ],
    "threatBreakdown": {"sql_injection": 40, "credential_leak": 30, "xss": 10},
}

QUARANTINE_RESPONSE = {
    "items": [
        {
            "id": 100,
            "status": "pending",
            "reason": "High anomaly score",
            "threat_indicators": ["credential_leak"],
            "anomaly_score": 0.92,
            "source_type": "agent",
            "source_identifier": "crewai:writer",
            "created_at": "2026-02-15T10:00:00.000Z",
            "content": "Suspicious text...",
            "title": "Memory entry",
        }
    ],
    "total": 1,
}
