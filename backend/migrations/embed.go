package migrations

import _ "embed"

// SchemaSQL embeds the bootstrap schema so runtime can initialise
// MySQL without shelling into the DB container.
//go:embed schema.sql
var SchemaSQL string
