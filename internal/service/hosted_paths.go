package service

// Paths of the hosted pages an emailed link lands on (ADR-0014). The link
// builders mail them and the hosted UI serves them; both read them from
// here so a page cannot move without its links, its rate limit and its
// tests moving with it.
const (
	HostedVerifyEmailPath        = "/auth/verify-email"
	HostedResetPasswordPath      = "/auth/reset-password" //nolint:gosec // G101: a URL path, not a credential
	HostedConfirmEmailChangePath = "/auth/confirm-email-change"
	HostedMagicLinkPath          = "/auth/magic-link"
	HostedAcceptInvitationPath   = "/auth/accept-invitation"
	// HostedJoinTeamPath is where a tenant-membership invitation lands.
	// Accepting one needs a signed-in caller whose address matches, so the
	// page cannot complete it: it tells the invitee what the link is and
	// sends them to sign in. It is a different path from the admin
	// user-invitation page because the two invitations live in different
	// stores and complete through different RPCs.
	HostedJoinTeamPath = "/auth/join-team"
)
