package service

// ProjectAnonymousConfig is a project's anonymous-sign-in policy.
//
// It is deliberately ORTHOGONAL to ProjectAccessConfig, matching Firebase:
// `access.mode` (open/allowlist/invite/closed) governs which EMAIL-IDENTIFIED
// humans may sign up and log in, and says nothing about anonymous sessions.
// A project may run mode:closed — admitting no new identified users at all —
// while still handing out anonymous sessions to its app, because the two
// answer different questions. Anonymous sign-in is instead gated by its own
// switch here (default OFF, so the capability never appears without an
// explicit decision) and, when configured, by the assurance layer.
type ProjectAnonymousConfig struct {
	// Enabled turns SignInAnonymously on for the project. Absent/false means
	// the RPC is refused with ErrAnonymousDisabled.
	Enabled bool `json:"enabled"`
}

// validate accepts any value: the block carries a single boolean and both
// states are meaningful. It exists so ProjectConfig.Validate has a uniform
// call for every block.
//
// There is deliberately NO per-project retention override. Retention is
// deployment-wide (GATEWAY_ANONYMOUS_RETENTION_DAYS) because the sweeper
// runs against the boot repo pinned to the default project — a per-project
// window would be config an operator could set and the server would ignore.
// See ADR-0013's "Not shipped" list.
func (a ProjectAnonymousConfig) validate() error { return nil }
