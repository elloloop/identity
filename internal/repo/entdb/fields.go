package entdb

// EntDB field-id constants for every node type the repo package
// touches. Keys match proto/identity/schema/schema.proto field
// numbers. They are duplicated here (rather than re-exported from
// internal/service) so the repo package owns its persistence
// vocabulary and can grow independently as the schema evolves.

// ── Type IDs ───────────────────────────────────────────────────────

const (
	typeUser                   = 1
	typeRefreshToken           = 5
	typePasswordResetToken     = 19
	typePasskeyCredential      = 20
	typePasskeyChallenge       = 21
	typeQrLoginSession         = 22
	typeTotpCredential         = 23
	typeRecoveryCode           = 24
	typeLoginChallenge         = 25
	typeUserInvitation         = 27
	typeEmailVerificationToken = 29
)

// ── User (type 1) ─────────────────────────────────────────────────

const (
	ufEmail            = "1"
	ufName             = "2"
	ufRole             = "3"
	ufAvatarURL        = "4"
	ufCreatedAt        = "5"
	ufUpdatedAt        = "6"
	ufPasswordHash     = "7"
	ufTotpRequired     = "8"
	ufFailedLoginCount = "9"
	ufLockedUntil      = "10"
	ufStatus           = "11"
	ufRecoveryEmail    = "12"
	ufQuotaBytes       = "15"
	ufLastLoginAt      = "17"
	ufEmailVerified    = "18"
	ufEmailVerifiedAt  = "19"
)

// ── RefreshToken (type 5) ─────────────────────────────────────────

const (
	rfTokenHash  = "1"
	rfUserID     = "2"
	rfDeviceInfo = "3"
	rfExpiresAt  = "4"
	rfCreatedAt  = "5"
	rfDeviceName = "6"
	rfIPAddress  = "7"
	rfUserAgent  = "8"
	rfLastUsedAt = "9"
	rfConsumedAt = "10"
)

// ── PasswordResetToken (type 19) ──────────────────────────────────

const (
	prTokenHash  = "1"
	prUserID     = "2"
	prExpiresAt  = "3"
	prCreatedAt  = "4"
	prConsumedAt = "5"
)

// ── PasskeyCredential (type 20) ───────────────────────────────────

const (
	pkCredentialID = "1"
	pkUserID       = "2"
	pkPublicKey    = "3"
	pkSignCount    = "4"
	pkDeviceName   = "5"
	pkAAGUID       = "6"
	pkTransports   = "7"
	pkCreatedAt    = "8"
	pkLastUsedAt   = "9"
)

// ── PasskeyChallenge (type 21) ────────────────────────────────────

const (
	pcChallenge     = "1"
	pcUserID        = "2"
	pcChallengeType = "3"
	pcExpiresAt     = "4"
	pcCreatedAt     = "5"
)

// ── QrLoginSession (type 22) ──────────────────────────────────────

const (
	qrSessionID          = "1"
	qrStatus             = "2"
	qrUserID             = "3"
	qrNewDeviceInfo      = "4"
	qrNewDeviceIP        = "5"
	qrNewDeviceUserAgent = "6"
	qrApprovedDeviceInfo = "7"
	qrExpiresAt          = "8"
	qrCreatedAt          = "9"
	qrUpdatedAt          = "10"
)

// ── TotpCredential (type 23) ──────────────────────────────────────

const (
	tcUserID          = "1"
	tcSecretEncrypted = "2"
	tcVerified        = "3"
	tcCreatedAt       = "4"
	tcLastUsedAt      = "5"
)

// ── RecoveryCode (type 24) ────────────────────────────────────────

const (
	rcUserID    = "1"
	rcCodeHash  = "2"
	rcUsed      = "3"
	rcCreatedAt = "4"
	rcUsedAt    = "5"
)

// ── LoginChallenge (type 25) ──────────────────────────────────────

const (
	lcChallengeID = "1"
	lcUserID      = "2"
	lcExpiresAt   = "3"
	lcCreatedAt   = "4"
)

// ── UserInvitation (type 27) ──────────────────────────────────────

const (
	invTokenHash  = "1"
	invEmail      = "2"
	invUserID     = "3"
	invInvitedBy  = "4"
	invRole       = "5"
	invExpiresAt  = "6"
	invAcceptedAt = "7"
	invCreatedAt  = "8"
)

// ── OAuthIdentity (type 30 — chosen by linkage agent) ─────────────
// Note: type IDs are stable EntDB field IDs; if both EmailChangeToken
// and OAuthIdentity claim 30, the upstream schema migration must
// disambiguate one of them. We're carrying both as 30 here pending
// confirmation from the schema apply step.
const typeOAuthIdentity = 31

const (
	oiUserID         = "1"
	oiProvider       = "2"
	oiProviderUserID = "3"
	oiEmailAtLink    = "4"
	oiCreatedAt      = "5"
)

// ── EmailChangeToken (type 30) ────────────────────────────────────
const typeEmailChangeToken = 30

const (
	ecTokenHash  = "1"
	ecUserID     = "2"
	ecOldEmail   = "3"
	ecNewEmail   = "4"
	ecExpiresAt  = "5"
	ecCreatedAt  = "6"
	ecConsumedAt = "7"
)

// ── EmailVerificationToken (type 29) ──────────────────────────────

const (
	evTokenHash  = "1"
	evUserID     = "2"
	evEmail      = "3"
	evExpiresAt  = "4"
	evCreatedAt  = "5"
	evConsumedAt = "6"
)
