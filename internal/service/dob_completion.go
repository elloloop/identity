package service

import (
	"context"
	"fmt"
	"time"

	"github.com/elloloop/identity/pkg/agegate"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/jwt"
)

// tokenPurposeDOBCompletion is the JWT `purpose` claim value marking a
// required-DOB completion ticket. A ticket is a bearer credential whose
// only use is one SubmitDateOfBirth call; the auth middleware refuses to
// authenticate any request with a non-empty purpose claim.
const tokenPurposeDOBCompletion = "dob_completion"

// tokenPurposePasskeyEnrolment is the JWT `purpose` claim value marking a
// managed-child passkey-enrolment ticket (minted by
// CreateManagedChildAccount). Its only use is the passkey registration
// ceremony (Begin/CompletePasskeyRegistration) for the ticket's subject; like
// every purpose token it never authenticates a request.
const tokenPurposePasskeyEnrolment = "passkey_enrolment" // #nosec G101 -- a claim value naming the ticket's purpose, not a credential.

// dobCompletionTicketTTL bounds the completion step: long enough for a
// user to type a date, short enough that a leaked ticket is useless
// within minutes.
const dobCompletionTicketTTL = 10 * time.Minute

// passkeyEnrolmentTicketTTL bounds the enrolment step: long enough for a
// parent to hand the ticket to the child's device and complete the WebAuthn
// ceremony — on two devices, legitimately (the ticket is single-purpose but
// NOT single-use within its window) — short enough that a leaked ticket
// expires quickly.
const passkeyEnrolmentTicketTTL = 15 * time.Minute

// maxRecordedAgeYears bounds a submitted date of birth: no living user is
// older, and an implausibly old DOB would classify ADULT under any
// threshold, defeating the gate it was submitted to satisfy.
const maxRecordedAgeYears = 150

// DOBRequiredError is the typed form of ErrDOBRequired: the refusal every
// session-issuing path returns when GATEWAY_AGEGATE_REQUIRE_DOB is on and
// the account has no date of birth. Ticket is the completion credential
// the Connect layer hands to the client as an error detail.
type DOBRequiredError struct {
	Ticket string
}

func (e *DOBRequiredError) Error() string { return ErrDOBRequired.Error() }
func (e *DOBRequiredError) Unwrap() error { return ErrDOBRequired }

// enforceDOBRequired refuses to issue a session when the deployment
// requires a known age (GATEWAY_AGEGATE_REQUIRE_DOB under an enabled age
// gate) and the authenticated account has no date of birth on file. It
// runs at the token chokepoint so every session-issuing path — and every
// account created before the flag was enabled, at its next issuance or
// refresh — is covered by construction.
//
// Anonymous accounts are exempt: they structurally carry no date of birth
// (their age guardrail is the product minimum-age gate), and a CHILD-band
// result would strand an email-less account in PENDING_PARENTAL_CONSENT
// with no channel to reach a parent. The moment an anonymous account is
// promoted to an identified one, the exemption ends and this gate applies.
func (s *AuthService) enforceDOBRequired(ctx context.Context, user *User, ipAddr, userAgent string) error {
	if !s.ageGate.Enabled() || !s.cfg.AgeGateRequireDOB || user == nil {
		return nil
	}
	if user.IsAnonymous || user.DateOfBirthMs != 0 {
		return nil
	}
	ticket, err := s.mintDOBCompletionTicket(ctx, user)
	if err != nil {
		return err
	}
	s.audit.Log(
		ctx, audit.EventLoginFailure,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(false),
		audit.WithDetails(map[string]any{"reason": "dob_required"}),
	)
	return &DOBRequiredError{Ticket: ticket}
}

// mintPurposeTicket signs a short-lived bearer credential whose only use is
// the flow named by purpose, for the account named by userID. It is signed by
// the same key as access tokens but carries a purpose claim, so it can never
// authenticate a request.
func (s *AuthService) mintPurposeTicket(ctx context.Context, userID, purpose string, ttl time.Duration) (string, error) {
	claims := jwt.Claims{
		Sub:     userID,
		Tenant:  s.tenantID(ctx),
		Project: s.projectID(ctx),
		Purpose: purpose,
	}
	if s.cfg.JWTAudience != "" {
		claims.Audience = []string{s.cfg.JWTAudience}
	}
	ticket, err := s.signer.SignAccessToken(ctx, claims, ttl)
	if err != nil {
		return "", fmt.Errorf("minting %s ticket: %w", purpose, err)
	}
	return ticket, nil
}

// verifyPurposeTicket is the verification half of mintPurposeTicket: the
// ticket must verify against the access-token key, carry exactly the expected
// purpose, and name this request's project. Every failure returns the same
// ErrUnauthenticated so the refusal discloses nothing about which check
// failed.
func (s *AuthService) verifyPurposeTicket(ctx context.Context, ticket, purpose string) (*jwt.Claims, error) {
	claims, err := jwt.VerifyPurposeToken(ticket, s.signer, s.tenantID(ctx), s.cfg.JWTAudience, s.cfg.JWTRequireAudience, purpose)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid or expired %s ticket", ErrUnauthenticated, purpose)
	}
	if claims.Project != s.projectID(ctx) {
		return nil, fmt.Errorf("%w: invalid or expired %s ticket", ErrUnauthenticated, purpose)
	}
	return claims, nil
}

// mintDOBCompletionTicket signs the short-lived bearer credential that
// authorizes exactly one thing: a SubmitDateOfBirth call for the account
// named by sub.
func (s *AuthService) mintDOBCompletionTicket(ctx context.Context, user *User) (string, error) {
	return s.mintPurposeTicket(ctx, user.ID, tokenPurposeDOBCompletion, dobCompletionTicketTTL)
}

// validateCompletionDOB rejects a missing, future, or implausibly old
// date of birth. The future check is load-bearing: agegate.Determine
// classifies a future DOB as unknown-but-stored, which would otherwise
// satisfy the "DOB on file" condition while resolving to no band at all.
func validateCompletionDOB(dobMs int64, now time.Time) error {
	if dobMs <= 0 {
		return fmt.Errorf("%w: date of birth is required", ErrInvalidArgument)
	}
	dob := time.UnixMilli(dobMs).UTC()
	if dob.After(now.UTC()) {
		return fmt.Errorf("%w: date of birth cannot be in the future", ErrInvalidArgument)
	}
	if dob.Before(now.UTC().AddDate(-maxRecordedAgeYears, 0, 0)) {
		return fmt.Errorf("%w: date of birth is implausibly old", ErrInvalidArgument)
	}
	return nil
}

// SubmitDateOfBirth completes the required-DOB step: it verifies the
// completion ticket, stores the date of birth on the ticket's account,
// derives the age band under the account's jurisdiction, and only then
// issues a session. It is unauthenticated — the ticket is the credential
// — and needs no flag check of its own: only a deployment that requires a
// DOB ever mints a ticket, so every other presentation fails verification.
//
// A CHILD-band result lands in PENDING_PARENTAL_CONSENT and mints no
// tokens: the correct dead end on a self-signup path, where a child was
// never supposed to arrive unaccompanied. TEEN and ADULT complete the
// sign-in with a normal token pair.
func (s *AuthService) SubmitDateOfBirth(ctx context.Context, completionToken string, dobMs int64, ipAddr, userAgent string) (*LoginResult, error) {
	claims, err := s.verifyPurposeTicket(ctx, completionToken, tokenPurposeDOBCompletion)
	if err != nil {
		return nil, err
	}
	if err := validateCompletionDOB(dobMs, s.nowFunc()); err != nil {
		return nil, err
	}

	user, err := s.repo(ctx).GetUser(ctx, claims.Sub)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("%w: invalid or expired completion token", ErrUnauthenticated)
	}
	if user.DateOfBirthMs != 0 {
		return nil, ErrDOBAlreadySet
	}
	// The ticket was minted after this same check passed on the login path,
	// but up to dobCompletionTicketTTL may have elapsed since — a status
	// change in that window must still win over the ticket.
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent); err != nil {
		return nil, err
	}

	gate := s.determinerForUser(ctx, user)
	dec := gate.Determine(dobMs, s.nowFunc())
	now := s.nowMs()
	regate := ""
	if gate.Enabled() && dec.Band == agegate.BandChild {
		regate = StatusPendingParentalConsent
	}
	// SET-ONCE. The ticket is reusable within its TTL, so two calls can both
	// pass the read above; an unconditional write would let an adult-band
	// submission mint a session while a concurrent child-band one gates the
	// account — a valid non-minor session on a consent-gated child. The
	// compare-and-set picks exactly one winner, and only the winner gets
	// past here to issue tokens. The loser is told the date is already set,
	// which it now is.
	won, err := s.repo(ctx).SetDateOfBirthOnce(ctx, user.ID, dobMs, regate, now)
	if err != nil {
		return nil, fmt.Errorf("storing date of birth: %w", err)
	}
	if !won {
		return nil, ErrDOBAlreadySet
	}
	user.DateOfBirthMs = dobMs
	user.UpdatedAt = msToTime(now)
	s.stampAgeBand(ctx, user)

	if gate.Enabled() && dec.Band == agegate.BandChild {
		user.Status = StatusPendingParentalConsent
		s.audit.Log(
			ctx, audit.EventLoginSuccess,
			audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
			audit.WithSuccess(true),
			audit.WithDetails(map[string]any{"method": "dob_completion", "pending_parental_consent": true, "age_band": user.AgeBand}),
		)
		return &LoginResult{User: user}, nil
	}

	s.updateLastLogin(ctx, user.ID)
	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "dob_completion", "age_band": user.AgeBand}),
	)
	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}
