package registry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"strings"
)

const (
	RegistrySchemaVersion    = 2
	RegistryMigrationVersion = 2
	RegistryApplicationID    = 0x41535633
)

// registryInitialMigration has no runtime call site. It is applied only by the
// explicit administration/test operation below, never while opening a ReadPort.
//
//go:embed sqlite_migrations/0002_initial_read.sql
var registryInitialMigration string

const registryMigrationLedgerDDL = `CREATE TABLE registry_migrations (
    version INTEGER NOT NULL PRIMARY KEY CHECK (version = 2),
    checksum TEXT NOT NULL CHECK (
        length(checksum) = 64 AND checksum NOT GLOB '*[^0-9a-f]*'
    ),
    dirty INTEGER NOT NULL CHECK (dirty IN (0, 1)),
    target_schema_version INTEGER NOT NULL CHECK (target_schema_version = 2)
) STRICT`

// RegistryMigrationChecksum binds the exact embedded v2 migration bytes and its
// durable migration-ledger definition. It is not a data or Continuity proof.
func RegistryMigrationChecksum() string {
	sum := sha256.Sum256([]byte(registryMigrationLedgerDDL + "\n" + registryInitialMigration))
	return hex.EncodeToString(sum[:])
}

type sqliteQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func sqliteSchemaFailure(ctx context.Context, field string) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return fault(CodeUnavailable, field)
}

func sqliteMigrationStatements() []string {
	var statements []string
	for _, statement := range strings.Split(registryInitialMigration, ";") {
		if statement = strings.TrimSpace(statement); statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}

func sqliteNormalizeDDL(statement string) string {
	return strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimSpace(statement), ";")), " ")
}

func sqliteExpectedTables() map[string]string {
	expected := map[string]string{"registry_migrations": sqliteNormalizeDDL(registryMigrationLedgerDDL)}
	for _, statement := range sqliteMigrationStatements() {
		words := strings.Fields(statement)
		if len(words) >= 3 && words[0] == "CREATE" && words[1] == "TABLE" {
			expected[words[2]] = sqliteNormalizeDDL(statement)
		}
	}
	return expected
}

// validateSQLiteSchema executes only metadata SELECTs and read PRAGMAs. Matching
// a version integer is insufficient: the complete fixed v2 schema is checked.
// This is not a sandbox for malicious SQLite files or privileged host actors.
func validateSQLiteSchema(ctx context.Context, query sqliteQueryer) error {
	if ctx == nil || query == nil {
		return invalid("sqlite.schema_context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var applicationID, version int64
	if err := query.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.application_id")
	}
	if err := query.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.user_version")
	}
	if applicationID != RegistryApplicationID || version != RegistrySchemaVersion {
		return invalid("sqlite.schema_version")
	}
	expected := sqliteExpectedTables()
	if len(expected) != 6 {
		return invalid("sqlite.schema_manifest")
	}
	rows, err := query.QueryContext(ctx, "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")
	if err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.schema_read")
	}
	seen := make(map[string]bool, len(expected))
	autoindexes := make(map[string]bool)
	for rows.Next() {
		var kind, name, table string
		var definition sql.NullString
		if err := rows.Scan(&kind, &name, &table, &definition); err != nil {
			rows.Close()
			return sqliteSchemaFailure(ctx, "sqlite.schema_scan")
		}
		if kind == "index" && strings.HasPrefix(name, "sqlite_autoindex_") && !definition.Valid {
			if _, exists := expected[table]; !exists || autoindexes[name] {
				rows.Close()
				return invalid("sqlite.schema_index")
			}
			autoindexes[name] = true
			continue
		}
		wanted, exists := expected[name]
		if kind != "table" || !exists || table != name || !definition.Valid ||
			seen[name] || sqliteNormalizeDDL(definition.String) != wanted {
			rows.Close()
			return invalid("sqlite.schema_manifest")
		}
		seen[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return sqliteSchemaFailure(ctx, "sqlite.schema_iteration")
	}
	if err := rows.Close(); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.schema_close")
	}
	if len(seen) != len(expected) {
		return invalid("sqlite.schema_missing")
	}
	// Each fixed composite PK/UNIQUE must have its expected SQLite autoindex.
	// registry_meta and registry_migrations use INTEGER PRIMARY KEY without autoindexes.
	counts := map[string]int{"resources": 1, "executions": 3, "projections": 1, "reference_transitions": 4}
	for table, count := range counts {
		for index := 1; index <= count; index++ {
			// index values are a small internal constant, never caller SQL.
			name := "sqlite_autoindex_" + table + "_" + string(rune('0'+index))
			if !autoindexes[name] {
				return invalid("sqlite.schema_index_missing")
			}
		}
	}
	if len(autoindexes) != 9 {
		return invalid("sqlite.schema_index_count")
	}
	meta, err := query.QueryContext(ctx, "SELECT singleton, schema_version, schema_name, journal_profile, codec FROM registry_meta")
	if err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.metadata_read")
	}
	count := 0
	for meta.Next() {
		var singleton, schemaVersion int64
		var name, profile, codec string
		if err := meta.Scan(&singleton, &schemaVersion, &name, &profile, &codec); err != nil {
			meta.Close()
			return sqliteSchemaFailure(ctx, "sqlite.metadata_scan")
		}
		count++
		if singleton != 1 || schemaVersion != RegistrySchemaVersion ||
			name != "autostream-v3-registry" || profile != "delete" || codec != "internal-json-v2" {
			meta.Close()
			return invalid("sqlite.metadata")
		}
	}
	if err := meta.Err(); err != nil {
		meta.Close()
		return sqliteSchemaFailure(ctx, "sqlite.metadata_iteration")
	}
	if err := meta.Close(); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.metadata_close")
	}
	if count != 1 {
		return invalid("sqlite.metadata_count")
	}
	return sqliteValidateMigration(ctx, query, 0)
}

// sqliteValidateMigration rejects missing, repeated, dirty or differently bound
// records. Absence is not treated as an unattempted or recoverable migration.
func sqliteValidateMigration(ctx context.Context, query sqliteQueryer, expectedDirty int64) error {
	rows, err := query.QueryContext(ctx, "SELECT version, checksum, dirty, target_schema_version FROM registry_migrations")
	if err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_record_read")
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var version, dirty, target int64
		var checksum string
		if err := rows.Scan(&version, &checksum, &dirty, &target); err != nil {
			return sqliteSchemaFailure(ctx, "sqlite.migration_record_scan")
		}
		count++
		if version != RegistryMigrationVersion || target != RegistrySchemaVersion {
			return invalid("sqlite.migration_record_version")
		}
		if checksum != RegistryMigrationChecksum() {
			return invalid("sqlite.migration_checksum")
		}
		if dirty != expectedDirty {
			return invalid("sqlite.migration_dirty")
		}
	}
	if err := rows.Err(); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_record_iteration")
	}
	if err := rows.Close(); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_record_close")
	}
	if count != 1 {
		return invalid("sqlite.migration_record_count")
	}
	return nil
}

// MigrateRegistrySchemaV2ForAdministration is an explicit, offline administration/
// test operation, never a ReadPort dependency. Fresh v2 baselines only: prior v1,
// nonempty, dirty and mismatched databases are preserved and rejected. No upgrade,
// repair, destructive cleanup, retry, VACUUM or checkpoint is implemented.
//
// First commit a dirty ledger on the empty database. Then apply the v2 schema and
// mark clean together in a second transaction. Failure after the first commit
// intentionally leaves durable dirty evidence; it must not be retried implicitly.
func MigrateRegistrySchemaV2ForAdministration(ctx context.Context, database *sql.DB) error {
	if ctx == nil || database == nil {
		return invalid("sqlite.migration_context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_begin")
	}
	defer tx.Rollback()
	var profile string
	if err := tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&profile); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_profile")
	}
	if profile != "delete" {
		return invalid("sqlite.migration_profile")
	}
	var applicationID, version, objects int64
	if err := tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_application_id")
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_user_version")
	}
	if applicationID == RegistryApplicationID && version == RegistrySchemaVersion {
		if err := validateSQLiteSchema(ctx, tx); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return sqliteSchemaFailure(ctx, "sqlite.migration_commit")
		}
		return nil
	}
	if applicationID != 0 || version != 0 {
		return invalid("sqlite.migration_version")
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&objects); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_existing_schema")
	}
	if objects != 0 {
		return invalid("sqlite.migration_nonempty_or_dirty")
	}
	if _, err := tx.ExecContext(ctx, registryMigrationLedgerDDL); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_ledger_create")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO registry_migrations(version, checksum, dirty, target_schema_version) VALUES(?, ?, 1, ?)", RegistryMigrationVersion, RegistryMigrationChecksum(), RegistrySchemaVersion); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_ledger_record")
	}
	if err := tx.Commit(); err != nil {
		// Commit uncertainty is not permission to start a second migration.
		return sqliteSchemaFailure(ctx, "sqlite.migration_dirty_commit")
	}
	return sqliteApplyFreshV2(ctx, database)
}

// sqliteApplyFreshV2 has no public resume entry. The only caller has just created
// the dirty ledger; all baseline conditions are checked again in this transaction.
func sqliteApplyFreshV2(ctx context.Context, database *sql.DB) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_apply_begin")
	}
	defer tx.Rollback()
	var applicationID, version, objects int64
	var profile, definition string
	for _, item := range []struct {
		query string
		value *int64
	}{
		{"PRAGMA application_id", &applicationID},
		{"PRAGMA user_version", &version},
		{"SELECT count(*) FROM sqlite_schema", &objects},
	} {
		if err := tx.QueryRowContext(ctx, item.query).Scan(item.value); err != nil {
			return sqliteSchemaFailure(ctx, "sqlite.migration_apply_baseline")
		}
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&profile); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_apply_profile")
	}
	if applicationID != 0 || version != 0 || objects != 1 || profile != "delete" {
		return invalid("sqlite.migration_apply_baseline")
	}
	if err := tx.QueryRowContext(ctx, "SELECT sql FROM sqlite_schema WHERE type='table' AND name='registry_migrations'").Scan(&definition); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_apply_manifest")
	}
	if sqliteNormalizeDDL(definition) != sqliteNormalizeDDL(registryMigrationLedgerDDL) {
		return invalid("sqlite.migration_apply_manifest")
	}
	if err := sqliteValidateMigration(ctx, tx, 1); err != nil {
		return err
	}
	for _, statement := range sqliteMigrationStatements() {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return sqliteSchemaFailure(ctx, "sqlite.migration_statement")
		}
	}
	result, err := tx.ExecContext(ctx, "UPDATE registry_migrations SET dirty=0 WHERE version=? AND checksum=? AND dirty=1 AND target_schema_version=?", RegistryMigrationVersion, RegistryMigrationChecksum(), RegistrySchemaVersion)
	if err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_clean_record")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return invalid("sqlite.migration_clean_record")
	}
	if err := validateSQLiteSchema(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_commit")
	}
	return nil
}
