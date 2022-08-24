package database

// The code below was generated by lxd-generate - DO NOT EDIT!

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	"github.com/lxc/lxd/lxd/db/query"
	"github.com/lxc/lxd/shared/api"

	"github.com/canonical/microcluster/cluster"
)

var _ = api.ServerEnvironment{}

var extendedTableObjects = cluster.RegisterStmt(`
SELECT extended_table.id, extended_table.key, extended_table.value
  FROM extended_table
  ORDER BY extended_table.key
`)

var extendedTableObjectsByKey = cluster.RegisterStmt(`
SELECT extended_table.id, extended_table.key, extended_table.value
  FROM extended_table
  WHERE extended_table.key = ? ORDER BY extended_table.key
`)

var extendedTableID = cluster.RegisterStmt(`
SELECT extended_table.id FROM extended_table
  WHERE extended_table.key = ?
`)

var extendedTableCreate = cluster.RegisterStmt(`
INSERT INTO extended_table (key, value)
  VALUES (?, ?)
`)

var extendedTableDeleteByKey = cluster.RegisterStmt(`
DELETE FROM extended_table WHERE key = ?
`)

var extendedTableUpdate = cluster.RegisterStmt(`
UPDATE extended_table
  SET key = ?, value = ?
 WHERE id = ?
`)

// GetExtendedTables returns all available extended_tables.
// generator: extended_table GetMany
func GetExtendedTables(ctx context.Context, tx *sql.Tx, filter ExtendedTableFilter) ([]ExtendedTable, error) {
	var err error

	// Result slice.
	objects := make([]ExtendedTable, 0)

	// Pick the prepared statement and arguments to use based on active criteria.
	var sqlStmt *sql.Stmt
	var args []any

	if filter.Key != nil {
		sqlStmt, err = cluster.Stmt(tx, extendedTableObjectsByKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to get \"extendedTableObjectsByKey\" prepared statement: %w", err)
		}

		args = []any{
			filter.Key,
		}
	} else if filter.Key == nil {
		sqlStmt, err = cluster.Stmt(tx, extendedTableObjects)
		if err != nil {
			return nil, fmt.Errorf("Failed to get \"extendedTableObjects\" prepared statement: %w", err)
		}

		args = []any{}
	} else {
		return nil, fmt.Errorf("No statement exists for the given Filter")
	}

	// Dest function for scanning a row.
	dest := func(scan func(dest ...any) error) error {
		e := ExtendedTable{}
		err := scan(&e.ID, &e.Key, &e.Value)
		if err != nil {
			return err
		}

		objects = append(objects, e)

		return nil
	}

	// Select.
	err = query.SelectObjects(sqlStmt, dest, args...)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch from \"extendeds_tables\" table: %w", err)
	}

	return objects, nil
}

// GetExtendedTable returns the extended_table with the given key.
// generator: extended_table GetOne
func GetExtendedTable(ctx context.Context, tx *sql.Tx, key string) (*ExtendedTable, error) {
	filter := ExtendedTableFilter{}
	filter.Key = &key

	objects, err := GetExtendedTables(ctx, tx, filter)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch from \"extendeds_tables\" table: %w", err)
	}

	switch len(objects) {
	case 0:
		return nil, api.StatusErrorf(http.StatusNotFound, "ExtendedTable not found")
	case 1:
		return &objects[0], nil
	default:
		return nil, fmt.Errorf("More than one \"extendeds_tables\" entry matches")
	}
}

// GetExtendedTableID return the ID of the extended_table with the given key.
// generator: extended_table ID
func GetExtendedTableID(ctx context.Context, tx *sql.Tx, key string) (int64, error) {
	stmt, err := cluster.Stmt(tx, extendedTableID)
	if err != nil {
		return -1, fmt.Errorf("Failed to get \"extendedTableID\" prepared statement: %w", err)
	}

	rows, err := stmt.Query(key)
	if err != nil {
		return -1, fmt.Errorf("Failed to get \"extendeds_tables\" ID: %w", err)
	}

	defer func() { _ = rows.Close() }()

	// Ensure we read one and only one row.
	if !rows.Next() {
		return -1, api.StatusErrorf(http.StatusNotFound, "ExtendedTable not found")
	}

	var id int64
	err = rows.Scan(&id)
	if err != nil {
		return -1, fmt.Errorf("Failed to scan ID: %w", err)
	}

	if rows.Next() {
		return -1, fmt.Errorf("More than one row returned")
	}

	err = rows.Err()
	if err != nil {
		return -1, fmt.Errorf("Result set failure: %w", err)
	}

	return id, nil
}

// ExtendedTableExists checks if a extended_table with the given key exists.
// generator: extended_table Exists
func ExtendedTableExists(ctx context.Context, tx *sql.Tx, key string) (bool, error) {
	_, err := GetExtendedTableID(ctx, tx, key)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

// CreateExtendedTable adds a new extended_table to the database.
// generator: extended_table Create
func CreateExtendedTable(ctx context.Context, tx *sql.Tx, object ExtendedTable) (int64, error) {
	// Check if a extended_table with the same key exists.
	exists, err := ExtendedTableExists(ctx, tx, object.Key)
	if err != nil {
		return -1, fmt.Errorf("Failed to check for duplicates: %w", err)
	}

	if exists {
		return -1, api.StatusErrorf(http.StatusConflict, "This \"extendeds_tables\" entry already exists")
	}

	args := make([]any, 2)

	// Populate the statement arguments.
	args[0] = object.Key
	args[1] = object.Value

	// Prepared statement to use.
	stmt, err := cluster.Stmt(tx, extendedTableCreate)
	if err != nil {
		return -1, fmt.Errorf("Failed to get \"extendedTableCreate\" prepared statement: %w", err)
	}

	// Execute the statement.
	result, err := stmt.Exec(args...)
	if err != nil {
		return -1, fmt.Errorf("Failed to create \"extendeds_tables\" entry: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return -1, fmt.Errorf("Failed to fetch \"extendeds_tables\" entry ID: %w", err)
	}

	return id, nil
}

// DeleteExtendedTable deletes the extended_table matching the given key parameters.
// generator: extended_table DeleteOne-by-Key
func DeleteExtendedTable(ctx context.Context, tx *sql.Tx, key string) error {
	stmt, err := cluster.Stmt(tx, extendedTableDeleteByKey)
	if err != nil {
		return fmt.Errorf("Failed to get \"extendedTableDeleteByKey\" prepared statement: %w", err)
	}

	result, err := stmt.Exec(key)
	if err != nil {
		return fmt.Errorf("Delete \"extendeds_tables\": %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("Fetch affected rows: %w", err)
	}

	if n == 0 {
		return api.StatusErrorf(http.StatusNotFound, "ExtendedTable not found")
	} else if n > 1 {
		return fmt.Errorf("Query deleted %d ExtendedTable rows instead of 1", n)
	}

	return nil
}

// UpdateExtendedTable updates the extended_table matching the given key parameters.
// generator: extended_table Update
func UpdateExtendedTable(ctx context.Context, tx *sql.Tx, key string, object ExtendedTable) error {
	id, err := GetExtendedTableID(ctx, tx, key)
	if err != nil {
		return err
	}

	stmt, err := cluster.Stmt(tx, extendedTableUpdate)
	if err != nil {
		return fmt.Errorf("Failed to get \"extendedTableUpdate\" prepared statement: %w", err)
	}

	result, err := stmt.Exec(object.Key, object.Value, id)
	if err != nil {
		return fmt.Errorf("Update \"extendeds_tables\" entry failed: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("Fetch affected rows: %w", err)
	}

	if n != 1 {
		return fmt.Errorf("Query updated %d rows instead of 1", n)
	}

	return nil
}