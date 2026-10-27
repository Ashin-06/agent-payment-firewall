-- Held tool calls waiting for the customer. digest = SHA-256 of the exact tool and
-- arguments approved; args and reasons are JSON. created_at is epoch seconds.
CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    tool TEXT NOT NULL,
    args TEXT NOT NULL,
    reasons TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    status TEXT NOT NULL,
    decided_by TEXT
);
CREATE INDEX approvals_status ON approvals (status);

-- Hash-chained audit entries (JSON). seq is the chain position; the key stops two
-- writers from both appending after the same entry.
CREATE TABLE audit_log (
    seq BIGINT PRIMARY KEY,
    entry TEXT NOT NULL
);
