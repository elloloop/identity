package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/passwords"
)

// ── Managed child accounts (parent-creates-child) ──────────────────────
//
// CreateManagedChildAccount is the parent-creates-child flow: an
// authenticated adult creates a minor's account directly. The account is
// BORN ACTIVE under the caller's guardianship — it never passes through
// pending_parental_consent, because the consent evidence (a parental-consent
// record equivalent to a GrantParentalConsent grant, plus the guardian edge)
// is captured in the SAME atomic write as the account itself.
//
// The child is identified within the project by a parent-chosen username —
// children often have no email — and signs in with it via PasswordLogin, or
// via a passkey bootstrapped on the child's device with the enrolment ticket
// this call returns when no password is set.
//
// The same two server-enforced checks as GrantParentalConsent apply to the
// calling adult: a strong verified factor on the adult's account AND a
// step-up password re-entry. Both are mandatory; a modified client cannot
// bypass either (the caller's identity comes from the verified session,
// never from the request).

// usernamePattern is the managed-child username alphabet: lowercase
// alphanumerics plus `_`/`-`/`.`. Length is bounded separately (3..32) so the
// regexp stays a pure character-class check.
var usernamePattern = regexp.MustCompile(`^[a-z0-9._-]+$`)

const (
	usernameMinLen = 3
	usernameMaxLen = 32
)

// normalizeUsername canonicalizes a username for storage and lookup: trimmed
// and lower-cased, so uniqueness is effectively case-insensitive.
func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// validateUsernameFormat enforces the username shape. One rule, one
// implementation: every write path that accepts a username validates here.
func validateUsernameFormat(username string) error {
	if len(username) < usernameMinLen || len(username) > usernameMaxLen {
		return fmt.Errorf("%w: username must be %d-%d characters", ErrInvalidArgument, usernameMinLen, usernameMaxLen)
	}
	if !usernamePattern.MatchString(username) {
		return fmt.Errorf("%w: username may contain only lowercase letters, digits, '_', '-', and '.'", ErrInvalidArgument)
	}
	return nil
}

// ManagedChildAccountRequest carries the client-supplied fields of a
// CreateManagedChildAccount call. The calling adult's identity is NOT here —
// it is the authenticated session user, passed separately.
type ManagedChildAccountRequest struct {
	Username         string
	DisplayName      string
	DateOfBirthMs    int64
	Market           string
	AvatarURL        string
	Password         string // parent-chosen password credential
	PasskeyEnrolment bool   // bootstrap passkey enrolment instead of a password
	PolicyVersion    string // consent policy version, as in GrantParentalConsent
	StepUpPassword   string // the calling adult's password re-entry
}

// ManagedChildAccountResult is the outcome of a successful creation: the
// child account, the consent record written with it, and — only when
// passkey enrolment was requested — the enrolment ticket for the child's
// device.
type ManagedChildAccountResult struct {
	Child           *User
	Consent         *ParentalConsentRecord
	EnrolmentTicket string
}

// ErrManagedChildNotMinor is returned when the supplied date of birth
// classifies as ADULT under the thresholds the child's market resolves to —
// this RPC creates minor accounts only. Mapped to CodeInvalidArgument.
var ErrManagedChildNotMinor = errors.New("date of birth does not classify as a minor under the applicable jurisdiction")

// auditManagedChildFailure records a refused creation attempt so a spoofing
// or probing attempt is visible in the audit trail. step names which check
// failed.
func (s *AuthService) auditManagedChildFailure(ctx context.Context, actorID, step, ip, userAgent string) {
	s.audit.Log(
		ctx, audit.EventManagedChildAccountCreated,
		audit.WithActor(actorID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent), audit.WithSuccess(false),
		audit.WithDetails(map[string]any{"step": step}),
	)
}

// CreateManagedChildAccount creates a minor's account under the calling
// adult's guardianship. callerUserID is the authenticated adult (derived by
// the handler from the verified session, NEVER from the request body).
//
// The project access mode deliberately does NOT gate this call: it is not
// self-signup. The guard is the calling adult's standing — an active,
// authenticated, non-minor account in the project — so the call succeeds
// under invite and closed modes alike.
func (s *AuthService) CreateManagedChildAccount(
	ctx context.Context, callerUserID string, req ManagedChildAccountRequest, ip, userAgent string,
) (*ManagedChildAccountResult, error) {
	if callerUserID == "" {
		return nil, ErrUnauthenticated
	}

	// Request shape, checked before any lookup so every malformed call fails
	// identically.
	username := normalizeUsername(req.Username)
	if err := validateUsernameFormat(username); err != nil {
		return nil, err
	}
	if req.PolicyVersion = strings.TrimSpace(req.PolicyVersion); req.PolicyVersion == "" {
		return nil, fmt.Errorf("%w: policy_version is required", ErrInvalidArgument)
	}
	if (req.Password == "") == !req.PasskeyEnrolment {
		return nil, fmt.Errorf("%w: exactly one of password / passkey_enrolment must be set", ErrInvalidArgument)
	}
	// A managed child account without a date of birth is never valid — gate
	// on or off: the DOB is what makes the account a *child* account. The
	// future/absurd checks are the same SubmitDateOfBirth applies.
	if err := validateCompletionDOB(req.DateOfBirthMs, s.nowFunc()); err != nil {
		return nil, err
	}
	market := normalizeJurisdictionCode(req.Market)
	if err := s.validateAccountMarket(ctx, market); err != nil {
		return nil, err
	}

	repo := s.repo(ctx)

	// 1. The caller must exist, be an active account, and — when the age gate
	// is on — not be a minor: a child cannot create managed children. An
	// unknown caller band (no DOB on file) is not known-minor, so it passes.
	caller, err := repo.GetUser(ctx, callerUserID)
	if err != nil {
		return nil, fmt.Errorf("fetch calling user: %w", err)
	}
	if caller == nil {
		return nil, fmt.Errorf("%w: calling user not found", ErrNotFound)
	}
	if !isActiveConsentingAccount(caller.Status) {
		s.auditManagedChildFailure(ctx, callerUserID, "caller_inactive", ip, userAgent)
		return nil, ErrAccountNotActive
	}
	if dec := s.determinerForUser(ctx, caller).Determine(caller.DateOfBirthMs, s.nowFunc()); dec.IsMinor {
		s.auditManagedChildFailure(ctx, callerUserID, "caller_minor", ip, userAgent)
		return nil, fmt.Errorf("%w: a minor cannot create managed child accounts", ErrPermissionDenied)
	}

	// 2. Step-up re-authentication + strong verified factor — the same two
	// mandatory checks as GrantParentalConsent, verified before any state
	// change so a caller holding only a session token cannot create accounts.
	admitted, reauthenticated := s.stepUp(caller, req.StepUpPassword)
	if !admitted {
		s.auditManagedChildFailure(ctx, callerUserID, "step_up", ip, userAgent)
		return nil, ErrParentalConsentStepUpFailed
	}
	factors, err := s.strongVerifiedFactors(ctx, caller)
	if err != nil {
		return nil, fmt.Errorf("check verified factors: %w", err)
	}
	if len(factors) == 0 {
		s.auditManagedChildFailure(ctx, callerUserID, "verified_factor", ip, userAgent)
		return nil, ErrParentalConsentFactorMissing
	}

	// 3. Band check: the child's DOB must classify as a MINOR (CHILD or TEEN)
	// under the thresholds its market resolves to. An adult-band DOB means the
	// caller reached for the wrong RPC. The check runs only when the age gate
	// is on; with the gate off the DOB is still required (validated above) and
	// the band fields stay unknown.
	gate := s.determinerForUser(ctx, &User{Market: market})
	var band agegate.AgeBand
	if gate.Enabled() {
		dec := gate.Determine(req.DateOfBirthMs, s.nowFunc())
		band = dec.Band
		if band != agegate.BandChild && band != agegate.BandTeen {
			s.auditManagedChildFailure(ctx, callerUserID, "band", ip, userAgent)
			return nil, ErrManagedChildNotMinor
		}
	}

	// 4. Credential: hash the parent-chosen password with the deployment's
	// password policy applied (the username stands in for the email in the
	// policy's identifier-similarity check).
	var passwordHash string
	if !req.PasskeyEnrolment {
		if err := s.validatePasswordStrengthForEmail(ctx, username, req.Password); err != nil {
			return nil, err
		}
		passwordHash, err = passwords.Hash(req.Password)
		if err != nil {
			return nil, fmt.Errorf("hashing password: %w", err)
		}
	}

	// 5. Username uniqueness within the project, pre-checked so the refusal is
	// clean; the repository's transaction enforces it atomically regardless
	// (a racing create hits the unique index), and both paths return the same
	// ErrAlreadyExists — the refusal discloses nothing beyond the act of
	// creation itself.
	existing, err := repo.FindUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("check username: %w", err)
	}
	if existing != nil {
		s.auditManagedChildFailure(ctx, callerUserID, "duplicate_username", ip, userAgent)
		return nil, fmt.Errorf("%w: username %q is already taken", ErrAlreadyExists, username)
	}

	// 6. Atomically create the child (born ACTIVE under guardianship — never
	// pending_parental_consent), the guardian edge, and the consent record.
	now := s.nowMs()
	// COPPA data-minimization applies to THIS write too. An avatar is
	// non-essential PII the server declines to persist for a child, and the
	// parent creating the account is not an exemption — otherwise this path
	// would store what UpdateProfile refuses to store for the same account a
	// second later, and the minimization control would be bypassable by
	// choosing the other door.
	avatarURL := strings.TrimSpace(req.AvatarURL)
	if avatarURL != "" && s.minorData.BlocksChildFor(ctx, &User{DateOfBirthMs: req.DateOfBirthMs, Market: market}) {
		s.logger.Info("managed_child_avatar_dropped_minor", zap.String("username", username))
		avatarURL = ""
	}
	child := &User{
		Username:      username,
		Name:          strings.TrimSpace(req.DisplayName),
		AvatarURL:     avatarURL,
		Role:          "member",
		Status:        StatusActive,
		PasswordHash:  passwordHash,
		DateOfBirthMs: req.DateOfBirthMs,
		Market:        market,
		CreatedAt:     msToTime(now),
		UpdatedAt:     msToTime(now),
	}
	edge := &GuardianEdge{
		GuardianUserID: callerUserID,
		CreatedAtMs:    now,
	}
	consent := &ParentalConsentRecord{
		ConsentID:        "pconsent_" + randomToken(16),
		ProjectID:        s.projectID(ctx),
		ConsentingUserID: callerUserID,
		PolicyVersion:    req.PolicyVersion,
		Factors:          encodeConsentFactors(factors),
		SteppedUp:        reauthenticated,
		ConsentIP:        ip,
		ConsentUserAgent: userAgent,
		GrantedAt:        now,
		// Snapshot the market the child's classification resolved under, so the
		// record says WHICH jurisdiction's thresholds it proves consent against.
		Market: s.resolvedMarketFor(ctx, child),
	}
	// The enrolment ticket is minted BEFORE the commit. Its subject is the
	// child id, so the id is generated here rather than by the driver: if
	// signing failed after the commit, the account would exist with no
	// password and no ticket, a retry would answer ALREADY_EXISTS, and there
	// is no RPC to mint a replacement — an unreachable account. Failing
	// before the write leaves nothing behind and the retry simply works.
	credential := "password"
	var ticket string
	if req.PasskeyEnrolment {
		credential = "passkey_enrolment" // #nosec G101 -- an audit-detail label naming the credential shape.
		child.ID = "usr_" + randomToken(16)
		ticket, err = s.mintPurposeTicket(ctx, child.ID, tokenPurposePasskeyEnrolment, passkeyEnrolmentTicketTTL)
		if err != nil {
			return nil, err
		}
	}

	if err := repo.CreateManagedChildAccount(ctx, child, edge, consent); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			s.auditManagedChildFailure(ctx, callerUserID, "duplicate_username", ip, userAgent)
			return nil, fmt.Errorf("%w: username %q is already taken", ErrAlreadyExists, username)
		}
		return nil, fmt.Errorf("creating managed child account: %w", err)
	}
	s.stampAgeBand(ctx, child)

	s.audit.Log(
		ctx, audit.EventManagedChildAccountCreated,
		audit.WithActor(callerUserID), audit.WithTarget(child.ID),
		audit.WithIP(ip), audit.WithUserAgent(userAgent), audit.WithSuccess(true),
		audit.WithDetails(map[string]any{
			"username":   username,
			"market":     market,
			"age_band":   child.AgeBand,
			"credential": credential,
			"stepped_up": consent.SteppedUp,
		}),
	)
	return &ManagedChildAccountResult{Child: child, Consent: consent, EnrolmentTicket: ticket}, nil
}
