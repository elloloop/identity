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

// TenantOperatorKeyHeader carries a tenant_operator project credential
// ("<public id>.<secret>"). It authorizes the tenant operations
// (AdminGetTenant, AdminListTenants, AdminSuspendTenant, AdminRestoreTenant,
// AdminRecoverTenantOwnership and GetLoginPolicy) on its own project in
// place of AdminAPISecretHeader; the admin service verifies it on every
// call. Like the secret it has no middleware, but the rate limit on those
// calls counts the requests that carry it (PathLimit.Header), so it lives
// here beside the secret's.
const TenantOperatorKeyHeader = "X-Tenant-Operator-Key"
