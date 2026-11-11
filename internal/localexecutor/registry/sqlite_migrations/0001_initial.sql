PRAGMA application_id = 0x41535633;
PRAGMA user_version = 1;

CREATE TABLE registry_meta (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    schema_name TEXT NOT NULL,
    journal_profile TEXT NOT NULL CHECK (journal_profile = 'delete'),
    codec TEXT NOT NULL
) STRICT;

CREATE TABLE resources (
    realm TEXT NOT NULL,
    host TEXT NOT NULL,
    resource TEXT NOT NULL,
    backend TEXT NOT NULL,
    active_knowledge TEXT NOT NULL CHECK (active_knowledge IN ('KNOWN', 'ABSENT', 'UNKNOWN', 'CONFLICT')),
    reference_json TEXT,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY (realm, host, resource, backend)
) STRICT;

CREATE TABLE executions (
    realm TEXT NOT NULL,
    host TEXT NOT NULL,
    resource TEXT NOT NULL,
    backend TEXT NOT NULL,
    execution_key TEXT NOT NULL,
    request_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    backend_knowledge TEXT NOT NULL CHECK (backend_knowledge IN ('KNOWN', 'ABSENT', 'UNKNOWN', 'CONFLICT')),
    receipt_json TEXT,
    PRIMARY KEY (realm, host, resource, backend, execution_key),
    UNIQUE (realm, host, resource, backend, request_id),
    UNIQUE (realm, host, resource, backend, operation_id, attempt_id, step_id),
    FOREIGN KEY (realm, host, resource, backend)
        REFERENCES resources (realm, host, resource, backend)
) STRICT;

CREATE TABLE projections (
    realm TEXT NOT NULL,
    host TEXT NOT NULL,
    resource TEXT NOT NULL,
    backend TEXT NOT NULL,
    execution_key TEXT NOT NULL,
    boundary TEXT NOT NULL CHECK (boundary IN ('executor_ledger', 'cp_report', 'cp_audit')),
    knowledge TEXT NOT NULL CHECK (knowledge IN ('KNOWN', 'ABSENT', 'UNKNOWN', 'CONFLICT')),
    record_json TEXT,
    PRIMARY KEY (realm, host, resource, backend, execution_key, boundary),
    FOREIGN KEY (realm, host, resource, backend, execution_key)
        REFERENCES executions (realm, host, resource, backend, execution_key)
) STRICT;

CREATE TABLE witnesses (
    realm TEXT NOT NULL,
    host TEXT NOT NULL,
    resource TEXT NOT NULL,
    backend TEXT NOT NULL,
    execution_key TEXT NOT NULL,
    outcome_json TEXT NOT NULL,
    PRIMARY KEY (realm, host, resource, backend, execution_key),
    FOREIGN KEY (realm, host, resource, backend, execution_key)
        REFERENCES executions (realm, host, resource, backend, execution_key)
) STRICT;

CREATE TABLE liabilities (
    realm TEXT NOT NULL,
    host TEXT NOT NULL,
    resource TEXT NOT NULL,
    backend TEXT NOT NULL,
    execution_key TEXT NOT NULL,
    liability_id TEXT NOT NULL,
    PRIMARY KEY (realm, host, resource, backend, execution_key, liability_id),
    FOREIGN KEY (realm, host, resource, backend, execution_key)
        REFERENCES executions (realm, host, resource, backend, execution_key)
) STRICT;

INSERT INTO registry_meta (singleton, schema_version, schema_name, journal_profile, codec)
VALUES (1, 1, 'autostream-v3-registry', 'delete', 'internal-json-v1');
