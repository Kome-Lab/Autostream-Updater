package registry

import (
	"context"
	"database/sql"
	_ "embed"
	"strings"
)

const (
	RegistrySchemaVersion = 1
	RegistryApplicationID = 0x41535633
)

// registryInitialMigration has no runtime call site. It is applied only by the
// explicit administration/test operation below, never while opening a ReadPort.
//
//go:embed sqlite_migrations/0001_initial.sql
var registryInitialMigration string

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
	expected := make(map[string]string)
	for _, statement := range sqliteMigrationStatements() {
		words := strings.Fields(statement)
		if len(words) >= 3 && words[0] == "CREATE" && words[1] == "TABLE" {
			expected[words[2]] = sqliteNormalizeDDL(statement)
		}
	}
	return expected
}

// validateSQLiteSchema executes only metadata SELECTs and read PRAGMAs. Matching
// a version integer is insufficient: the complete fixed v1 schema is checked.
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
	// registry_meta uses INTEGER PRIMARY KEY and has no autoindex.
	counts := map[string]int{"resources": 1, "executions": 3, "projections": 1, "witnesses": 1, "liabilities": 1}
	for table, count := range counts {
		for index := 1; index <= count; index++ {
			// index values are a small internal constant, never caller SQL.
			name := "sqlite_autoindex_" + table + "_" + string(rune('0'+index))
			if !autoindexes[name] {
				return invalid("sqlite.schema_index_missing")
			}
		}
	}
	if len(autoindexes) != 7 {
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
			name != "autostream-v3-registry" || profile != "delete" || codec != "internal-json-v1" {
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
	return nil
}

// MigrateRegistrySchemaV1ForAdministration is an explicit management/test-only
// write operation. ReadPort opening never calls it. It accepts only an empty
// delete-journal database or the exact existing v1 schema. There is no repair,
// destructive migration, VACUUM, checkpoint, automatic retry or schema downgrade.
func MigrateRegistrySchemaV1ForAdministration(ctx context.Context, database *sql.DB) error {
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
		return invalid("sqlite.migration_nonempty")
	}
	for _, statement := range sqliteMigrationStatements() {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return sqliteSchemaFailure(ctx, "sqlite.migration_statement")
		}
	}
	if err := validateSQLiteSchema(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return sqliteSchemaFailure(ctx, "sqlite.migration_commit")
	}
	return nil
}
