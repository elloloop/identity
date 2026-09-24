package middleware

// AdminAPISecretHeader carries the shared secret that authenticates the
// control-plane admin RPCs (AdminCreateProject and friends). A PLATFORM
// operator presents it to provision projects/tenants out-of-band; the value
// is compared in constant time against config.AdminAPISecret by the admin
// handler. It is intentionally distinct from the user-auth Authorization
// header and the X-Project-Key credential header: the admin RPCs are not
// user-authenticated, and the secret IS their authentication.
//
// There is no admin-secret middleware: the secret is checked in the handler
// (so an unset secret yields CodeUnimplemented and a wrong one yields a
// denial uniformly, without a chain-position dependency). The header name
// lives here so the middleware and handler packages share one source of
// truth and tests don't hardcode the literal.
const AdminAPISecretHeader = "X-Admin-Secret"

// DirectoryKeyHeader carries a directory_reader project credential
// ("<public id>.<secret>") to LookupUsers, the one RPC it authorizes. It is
// deliberately not the Authorization header: the JWT layer never sees it,
// so the credential cannot be confused with a session on any other RPC, and
// the handler that verifies it is the only code that reads it.
const DirectoryKeyHeader = "X-Directory-Key"
