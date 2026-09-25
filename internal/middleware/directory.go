package middleware

// DirectoryKeyHeader carries a directory_reader project credential
// ("<public id>.<secret>") to LookupUsers, the one RPC it authorizes. It is
// deliberately not the Authorization header: the JWT layer never sees it,
// so the credential cannot be confused with a session on any other RPC, and
// the handler that verifies it is the only code that reads it.
const DirectoryKeyHeader = "X-Directory-Key"
