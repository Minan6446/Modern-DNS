package db

import (
	"fmt"
	"strings"
)

// RunBootstrapSchema executes idempotent bootstrap SQL statements.
// It intentionally skips CREATE DATABASE / USE because the app should
// operate within the DSN-selected schema only.
func RunBootstrapSchema(schemaSQL string) error {
	if DB == nil {
		return fmt.Errorf("mysql is not initialized")
	}
	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("get sql db failed: %w", err)
	}

	statements := splitSQLStatements(schemaSQL)
	for _, stmt := range statements {
		normalized := strings.ToUpper(strings.TrimSpace(stmt))
		if strings.HasPrefix(normalized, "CREATE DATABASE") || strings.HasPrefix(normalized, "USE ") {
			continue
		}
		if _, err := sqlDB.Exec(stmt); err != nil {
			// MySQL 1061 = Duplicate key name — the index already exists.
			// This is expected for idempotent ADD INDEX statements run
			// against databases that already have the index (e.g. the
			// inline indexes in the CREATE TABLE IF NOT EXISTS above).
			if strings.Contains(err.Error(), "Error 1061") {
				continue
			}
			return fmt.Errorf("execute bootstrap schema failed: %w; sql=%q", err, truncateSQL(stmt, 160))
		}
	}
	return nil
}

func splitSQLStatements(sqlText string) []string {
	delimiter := ";"
	stmts := make([]string, 0, 256)
	var buf strings.Builder

	flush := func() {
		stmt := strings.TrimSpace(buf.String())
		if stmt == "" {
			buf.Reset()
			return
		}
		if strings.HasSuffix(stmt, delimiter) {
			stmt = strings.TrimSpace(stmt[:len(stmt)-len(delimiter)])
		}
		if stmt != "" {
			stmts = append(stmts, stmt)
		}
		buf.Reset()
	}

	for _, line := range strings.Split(sqlText, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}

		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "DELIMITER ") {
			newDelimiter := strings.TrimSpace(trimmed[len("DELIMITER "):])
			if newDelimiter != "" {
				delimiter = newDelimiter
			}
			continue
		}

		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(line)

		if strings.HasSuffix(strings.TrimSpace(buf.String()), delimiter) {
			flush()
		}
	}

	if strings.TrimSpace(buf.String()) != "" {
		flush()
	}

	return stmts
}

func truncateSQL(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
