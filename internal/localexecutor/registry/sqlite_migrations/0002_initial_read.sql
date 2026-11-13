PRAGMA application_id = 0x41535633;
PRAGMA user_version = 2;

CREATE TABLE registry_meta (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
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
    reference_revision TEXT,
    reference_state_version TEXT,
    reference_json TEXT,
    backend_frame_json TEXT NOT NULL,
    PRIMARY KEY (realm, host, resource, backend),
    CHECK (
        (active_knowledge = 'KNOWN' AND reference_revision IS NOT NULL AND reference_json IS NOT NULL AND
            reference_state_version IS NOT NULL AND length(reference_state_version) = 20 AND
            reference_state_version NOT GLOB '*[^0-9]*' AND reference_state_version <= '18446744073709551615')
        OR
        (active_knowledge <> 'KNOWN' AND reference_revision IS NULL AND reference_state_version IS NULL AND reference_json IS NULL)
    )
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
    receipt_kind TEXT CHECK (receipt_kind IN ('positive', 'negative')),
    receipt_json TEXT,
    PRIMARY KEY (realm, host, resource, backend, execution_key),
    UNIQUE (realm, host, resource, backend, request_id),
    UNIQUE (realm, host, resource, backend, operation_id, attempt_id, step_id),
    FOREIGN KEY (realm, host, resource, backend)
        REFERENCES resources (realm, host, resource, backend),
    CHECK (
        (backend_knowledge = 'KNOWN' AND receipt_kind IS NOT NULL AND receipt_json IS NOT NULL)
        OR
        (backend_knowledge <> 'KNOWN' AND receipt_kind IS NULL AND receipt_json IS NULL)
    )
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

CREATE TABLE reference_transitions (
    realm TEXT NOT NULL,
    host TEXT NOT NULL,
    resource TEXT NOT NULL,
    backend TEXT NOT NULL,
    transition_id TEXT NOT NULL,
    execution_key TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    before_revision TEXT NOT NULL,
    before_state_version TEXT NOT NULL CHECK (
        length(before_state_version) = 20 AND before_state_version NOT GLOB '*[^0-9]*' AND
        before_state_version <= '18446744073709551615'
    ),
    after_revision TEXT NOT NULL,
    after_state_version TEXT NOT NULL CHECK (
        length(after_state_version) = 20 AND after_state_version NOT GLOB '*[^0-9]*' AND
        after_state_version <= '18446744073709551615'
    ),
    PRIMARY KEY (realm, host, resource, backend, transition_id),
    UNIQUE (realm, host, resource, backend, execution_key),
    UNIQUE (realm, host, resource, backend, receipt_id),
    UNIQUE (realm, host, resource, backend, after_state_version),
    FOREIGN KEY (realm, host, resource, backend, execution_key)
        REFERENCES executions (realm, host, resource, backend, execution_key),
    CHECK (before_revision <> after_revision AND after_state_version > before_state_version)
) STRICT;

INSERT INTO registry_meta (singleton, schema_version, schema_name, journal_profile, codec)
VALUES (1, 2, 'autostream-v3-registry', 'delete', 'internal-json-v2');
