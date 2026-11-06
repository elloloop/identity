package service

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/origin"
	"github.com/elloloop/identity/pkg/audit"
	"github.com/elloloop/identity/pkg/emailaddr"
	"github.com/elloloop/identity/pkg/passkeys"
)

// ── BeginPasskeyRegistration ───────────────────────────────────────────

// BeginPasskeyRegistration generates WebAuthn registration options for the
// authenticated user. Returns (optionsJSON, challengeID, error).
func (s *AuthService) BeginPasskeyRegistration(ctx context.Context, userID, deviceName string) (string, string, error) {
	// Refused at BEGIN, not only at completion: this call persists a
	// challenge row, and the anonymous retention sweep does not reach the
	// challenge tables (no FK to users), so an anonymous caller could
	// accumulate rows the sweep never reclaims. Completion is guarded too.
	if err := s.refuseCredentialAttach(ctx, userID); err != nil {
		return "", "", err
	}
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if user == nil {
		return "", "", fmt.Errorf("%w: user not found", ErrNotFound)
	}

	existing, err := s.repo(ctx).ListPasskeyCredentials(ctx, userID)
	if err != nil {
		return "", "", err
	}
	existingIDs := make([]string, 0, len(existing))
	for _, c := range existing {
		if c.CredentialID != "" {
			existingIDs = append(existingIDs, c.CredentialID)
		}
	}

	// The WebAuthn user entity labels the credential in the platform's passkey
	// manager. A managed child has no email and may have no display name, so
	// fall back to its project-unique username — otherwise the credential is
	// stored unlabelled and the child cannot tell it apart from any other.
	entityName := coalesce(user.Email, user.Username)
	relyingParty, err := s.passkeysFor(ctx)
	if err != nil {
		return "", "", err
	}
	optionsJSON, challengeB64, err := relyingParty.BeginRegistration(
		userID, entityName, coalesce(user.Name, entityName), existingIDs,
	)
	if err != nil {
		return "", "", fmt.Errorf("building registration options: %w", err)
	}

	now := s.nowMs()
	nodeID, err := s.repo(ctx).CreatePasskeyChallenge(ctx, &PasskeyChallengeRecord{
		Challenge:     challengeB64,
		UserID:        userID,
		ChallengeType: "registration",
		ExpiresAt:     now + int64(s.cfg.PasskeyChallengeExpirySeconds)*1000,
		CreatedAt:     now,
	})
	if err != nil {
		return "", "", fmt.Errorf("storing challenge: %w", err)
	}

	s.logger.Info(
		"passkey_registration_begin",
		zap.String("user_id", userID),
		zap.String("challenge_id", nodeID),
		zap.Int("existing_credentials", len(existingIDs)),
	)
	return optionsJSON, nodeID, nil
}

// ── CompletePasskeyRegistration ────────────────────────────────────────

// VerifyPasskeyEnrolmentTicket verifies a managed-child passkey-enrolment
// ticket (purpose `passkey_enrolment`, minted by CreateManagedChildAccount)
// and returns the child account id the ceremony enrols. The Connect layer
// calls it to resolve the account a session-less ceremony runs for; the
// ticket rides in the request BODY because a purpose JWT is never a session
// credential (the auth middleware refuses to authenticate one).
//
// The ticket is single-purpose but NOT single-use within its TTL: enrolling
// passkeys on two of the child's devices inside the window is legitimate.
func (s *AuthService) VerifyPasskeyEnrolmentTicket(ctx context.Context, ticket string) (string, error) {
	if ticket == "" {
		return "", fmt.Errorf("%w: enrolment ticket is required", ErrInvalidArgument)
	}
	claims, err := s.verifyPurposeTicket(ctx, ticket, tokenPurposePasskeyEnrolment)
	if err != nil {
		return "", err
	}
	return claims.Sub, nil
}

// CompletePasskeyRegistration verifies the attestation response and stores the
// new credential. When issueSession is true — the managed-child enrolment
// path, where the ceremony redeemed an enrolment ticket and the child has no
// session yet — it also issues the account's first token pair through the
// normal issuance chokepoint; the returned LoginResult is nil otherwise and
// the response shape is exactly what a session-authenticated completion
// returns today.
func (s *AuthService) CompletePasskeyRegistration(ctx context.Context, userID, challengeID, credentialJSON, deviceName string, issueSession bool, ipAddr, userAgent string) (*PasskeyInfo, *LoginResult, error) {
	if challengeID == "" || credentialJSON == "" {
		return nil, nil, fmt.Errorf("%w: challenge_id and credential_json are required", ErrInvalidArgument)
	}
	// A passkey is a permanent credential; an anonymous caller must go
	// through UpgradeAnonymousAccount so the flag is cleared with it.
	if err := s.refuseCredentialAttach(ctx, userID); err != nil {
		return nil, nil, err
	}

	// On the managed-child enrolment path the ticket stood in for a session,
	// and up to its TTL may have passed since it was minted. Re-check the
	// account status BEFORE the credential is persisted, not only before the
	// session is issued: a guardian who deactivates a child mid-ceremony must
	// not end up with a permanent passkey attached to that account, ready to
	// authenticate the moment it is reactivated.
	if issueSession {
		enrolmentUser, statusErr := s.repo(ctx).GetUser(ctx, userID)
		if statusErr != nil {
			return nil, nil, statusErr
		}
		if enrolmentUser == nil {
			return nil, nil, fmt.Errorf("%w: user not found", ErrNotFound)
		}
		if statusErr := s.checkAccountStatus(ctx, enrolmentUser, ipAddr, userAgent, sessionGateSignIn); statusErr != nil {
			return nil, nil, statusErr
		}
	}

	challenge, err := s.repo(ctx).GetPasskeyChallenge(ctx, challengeID)
	if err != nil {
		return nil, nil, err
	}
	if challenge == nil {
		return nil, nil, fmt.Errorf("%w: challenge not found or already consumed", ErrNotFound)
	}
	if challenge.ChallengeType != "registration" {
		return nil, nil, fmt.Errorf("%w: challenge is not a registration challenge", ErrInvalidArgument)
	}
	if challenge.UserID != userID {
		return nil, nil, fmt.Errorf("%w: challenge does not belong to this user", ErrPermissionDenied)
	}
	if challenge.ExpiresAt < s.nowMs() {
		_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)
		return nil, nil, fmt.Errorf("%w: challenge expired", ErrTokenExpired)
	}

	relyingParty, err := s.passkeysFor(ctx)
	if err != nil {
		return nil, nil, err
	}
	result, err := relyingParty.CompleteRegistration(credentialJSON, challenge.Challenge)
	if err != nil {
		s.logger.Warn(
			"passkey_registration_verify_failed",
			zap.String("user_id", userID), zap.Error(err),
		)
		return nil, nil, fmt.Errorf("%w: attestation verification failed", ErrInvalidArgument)
	}

	// Read before the insert: see withdrawPasskeyIfAddressProven.
	holder, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if holder == nil {
		return nil, nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	now := s.nowMs()
	_, err = s.repo(ctx).CreatePasskeyCredential(ctx, &PasskeyCredRecord{
		CredentialID:   result.CredentialID,
		UserID:         userID,
		PublicKey:      result.PublicKey,
		SignCount:      int64(result.SignCount),
		DeviceName:     deviceName,
		AAGUID:         result.AAGUID,
		Transports:     result.Transports,
		BackupEligible: result.BackupEligible,
		BackupState:    result.BackupState,
		CreatedAt:      now,
		LastUsedAt:     now,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("storing credential: %w", err)
	}

	// Single-use challenge -- delete it.
	_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)
	if !holder.EmailVerified {
		if err := s.withdrawPasskeyIfAddressProven(ctx, userID, result.CredentialID); err != nil {
			return nil, nil, err
		}
	}

	s.logger.Info(
		"passkey_registered",
		zap.String("user_id", userID),
		zap.String("credential_id", result.CredentialID),
		zap.String("device_name", deviceName),
	)

	s.audit.Log(
		ctx, audit.EventPasskeyAdded,
		audit.WithActor(userID),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"credential_id": result.CredentialID}),
	)

	info := &PasskeyInfo{
		CredentialID: result.CredentialID,
		DeviceName:   deviceName,
		CreatedAt:    msToTime(now),
		LastUsedAt:   msToTime(now),
	}
	if !issueSession {
		return info, nil, nil
	}

	// Managed-child enrolment path: the ticket took the place of a session,
	// so completion issues the account's first one. The status was already
	// checked before the credential was written (above); re-read it here so
	// the session is issued from the committed row rather than a stale copy.
	// Token issuance goes through the normal chokepoint (issueTokens), so the
	// product age gate and the required-DOB gate apply exactly as on a login.
	user, err := s.repo(ctx).GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent, sessionGateSignIn); err != nil {
		return nil, nil, err
	}
	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, nil, err
	}
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(userID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "passkey_enrolment"}),
	)
	return info, &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// ── BeginPasskeyLogin ──────────────────────────────────────────────────

// BeginPasskeyLogin generates WebAuthn authentication options.
// If email is provided, scopes to that user's credentials. Otherwise allows
// discoverable credentials (usernameless flow).
func (s *AuthService) BeginPasskeyLogin(ctx context.Context, email string) (string, string, error) {
	relyingParty, err := s.passkeysFor(ctx)
	if err != nil {
		return "", "", err
	}

	var allowedIDs []string
	// Looked up by the canonical form accounts are stored under. An address
	// with no mailbox once canonical names nobody, so it takes the same path
	// as an unknown one: an empty allow list.
	if canonical, usable := emailaddr.Mailbox(email); usable {
		user, err := s.repo(ctx).FindUserByEmail(ctx, canonical)
		if err != nil {
			return "", "", err
		}
		if user != nil {
			creds, err := s.repo(ctx).ListPasskeyCredentials(ctx, user.ID)
			if err != nil {
				return "", "", err
			}
			for _, c := range creds {
				if c.CredentialID != "" {
					allowedIDs = append(allowedIDs, c.CredentialID)
				}
			}
		}
		// If user doesn't exist or has no passkeys, fall through with empty
		// allow list to prevent email enumeration.
	}

	optionsJSON, challengeB64, err := relyingParty.BeginAuthentication(allowedIDs)
	if err != nil {
		return "", "", fmt.Errorf("building authentication options: %w", err)
	}

	now := s.nowMs()
	nodeID, err := s.repo(ctx).CreatePasskeyChallenge(ctx, &PasskeyChallengeRecord{
		Challenge:     challengeB64,
		ChallengeType: "authentication",
		ExpiresAt:     now + int64(s.cfg.PasskeyChallengeExpirySeconds)*1000,
		CreatedAt:     now,
	})
	if err != nil {
		return "", "", fmt.Errorf("storing challenge: %w", err)
	}

	s.logger.Info(
		"passkey_login_begin",
		zap.String("challenge_id", nodeID),
		zap.Int("allowed_credentials", len(allowedIDs)),
	)
	return optionsJSON, nodeID, nil
}

// ── CompletePasskeyLogin ───────────────────────────────────────────────

// CompletePasskeyLogin verifies the assertion response and issues tokens.
func (s *AuthService) CompletePasskeyLogin(ctx context.Context, challengeID, credentialJSON, ipAddr, userAgent string) (*LoginResult, error) {
	if challengeID == "" || credentialJSON == "" {
		return nil, fmt.Errorf("%w: challenge_id and credential_json are required", ErrInvalidArgument)
	}

	relyingParty, err := s.passkeysFor(ctx)
	if err != nil {
		return nil, err
	}

	challenge, err := s.repo(ctx).GetPasskeyChallenge(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if challenge == nil {
		return nil, fmt.Errorf("%w: invalid or expired challenge", ErrUnauthenticated)
	}
	if challenge.ChallengeType != "authentication" {
		return nil, fmt.Errorf("%w: challenge is not an authentication challenge", ErrInvalidArgument)
	}
	if challenge.ExpiresAt < s.nowMs() {
		_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)
		return nil, fmt.Errorf("%w: challenge expired", ErrUnauthenticated)
	}

	credID, err := passkeys.ExtractCredentialID(credentialJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid credential_json: %w", ErrInvalidArgument, err)
	}

	cred, err := s.repo(ctx).GetPasskeyCredentialByCredID(ctx, credID)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, fmt.Errorf("%w: unknown credential", ErrUnauthenticated)
	}
	if cred.UserID == "" {
		return nil, errors.New("credential missing user_id")
	}
	if cred.SignCount > int64(math.MaxUint32) {
		return nil, errors.New("credential sign_count overflows WebAuthn counter")
	}

	newSignCount, err := relyingParty.CompleteAuthentication(
		credentialJSON,
		challenge.Challenge,
		cred.PublicKey,
		uint32(cred.SignCount), // #nosec G115 -- bounds checked above.
		cred.CredentialID,
		cred.UserID,
		cred.BackupEligible,
		cred.BackupState,
	)
	if err != nil {
		s.logger.Warn(
			"passkey_login_verify_failed",
			zap.String("user_id", cred.UserID),
			zap.String("credential_id", credID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("%w: passkey verification failed", ErrUnauthenticated)
	}

	// Update sign count.
	now := s.nowMs()
	_ = s.repo(ctx).UpdatePasskeyCredential(ctx, cred.NodeID, map[string]any{
		"sign_count":   int64(newSignCount),
		"last_used_at": now,
	})

	// Single-use challenge.
	_ = s.repo(ctx).DeletePasskeyChallenge(ctx, challenge.NodeID)

	user, err := s.repo(ctx).GetUser(ctx, cred.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	// Enforce account status + lockout before issuing tokens. Without
	// this, an account locked by failed-password attempts would still
	// be loginable via passkey, defeating the lockout entirely.
	if err := s.checkAccountStatus(ctx, user, ipAddr, userAgent, sessionGateSignIn); err != nil {
		return nil, err
	}

	// A valid assertion proves credential possession, but a closed/allowlist
	// project must still refuse a non-member — otherwise a passkey enrolled
	// before the project was restricted would keep working. user.Email is the
	// DB-persisted (canonical) account email; wrap once (idempotent, self-heals).
	if err := s.enforceAccountAccessLogin(ctx, user); err != nil {
		return nil, err
	}

	// Consult the tenant's LoginPolicy before issuing tokens. A passkey is a
	// distinct authentication method, so a tenant that disallows it via its
	// AllowedMethods allow-list — or one that requires SSO — must be honoured
	// here too, otherwise the policy could be bypassed by enrolling and using
	// a passkey. A passkey is itself a strong factor, so it satisfies a
	// Require2FA policy on its own and never yields a second-factor decision.
	if _, err := s.enforceLoginPolicy(ctx, user.Email, LoginMethodPasskey); err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, ipAddr, userAgent)
	if err != nil {
		return nil, err
	}

	s.logger.Info(
		"passkey_login_success",
		zap.String("user_id", user.ID),
		zap.String("credential_id", credID),
	)

	s.audit.Log(
		ctx, audit.EventPasskeyUsed,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"credential_id": credID}),
	)
	s.audit.Log(
		ctx, audit.EventLoginSuccess,
		audit.WithActor(user.ID), audit.WithIP(ipAddr), audit.WithUserAgent(userAgent),
		audit.WithSuccess(true),
		audit.WithDetails(map[string]any{"method": "passkey"}),
	)

	return &LoginResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    secondsToInt32(s.cfg.JWTExpirySeconds),
	}, nil
}

// ���─ helpers ────────────────────────────────────────────────────────────

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// withdrawPasskeyIfAddressProven deletes the passkey this registration just
// stored when the account's address, unproven when the registration began,
// is proven now: see withdrawIfAddressProven. Only that credential goes; the
// passkeys registered before it are the proof's to void or keep, and a
// verification link keeps them.
func (s *AuthService) withdrawPasskeyIfAddressProven(ctx context.Context, userID, credentialID string) error {
	withdrawn, err := s.withdrawIfAddressProven(ctx, userID, attachedCredential{
		kind:    "passkey",
		refusal: "the passkey could not be registered",
		fields:  []zap.Field{zap.String("credential_id", credentialID)},
		withdraw: func(ctx context.Context) error {
			return s.repo(ctx).DeletePasskeyCredential(ctx, userID, credentialID)
		},
	})
	if err != nil || !withdrawn {
		return err
	}
	s.audit.Log(
		ctx, audit.EventPasskeyAdded,
		audit.WithActor(userID),
		audit.WithSuccess(false),
		audit.WithDetails(map[string]any{
			"credential_id": credentialID,
			"reason":        "address_proven_while_registering",
		}),
	)
	return fmt.Errorf("%w: the account's address was proven while registering; sign in again", ErrUnauthenticated)
}

// passkeysFor returns the WebAuthn relying-party instance for the request in
// ctx. The first that applies decides:
//
//  1. the GATEWAY_PASSKEY_RELYING_PARTIES entry for the request's host, since
//     one project may serve several products, each on its own domain;
//  2. the passkey block of the resolved project's config_json, which inherits
//     a field it leaves out from the global GATEWAY_PASSKEY_* values;
//  3. the global s.passkeys.
//
// An operator who sets GATEWAY_PASSKEY_RELYING_PARTIES has said the global RP-ID
// is some other host's, so 3 no longer applies and a block must name its own
// rp_id and origin (rp_name, a display name, is still inherited). Anything else
// gets ErrPasskeysUnavailable: an unconfigured host never receives another
// product's RP-ID.
//
// With neither setting in play s.passkeys is returned unchanged.
func (s *AuthService) passkeysFor(ctx context.Context) (*passkeys.WebAuthnService, error) {
	perHost := s.cfg.PasskeyRelyingPartiesConfigured()
	if perHost {
		if party, ok := s.cfg.PasskeyRelyingPartyForHost(RequestHostFromContext(ctx)); ok {
			return s.relyingParty(passkeys.Config{
				RPID:              party.RPID,
				RPName:            coalesce(party.RPName, s.cfg.PasskeyRPName),
				Origin:            party.Origins[0],
				AdditionalOrigins: party.Origins[1:],
			})
		}
	}
	scope := ProjectScopeFromContext(ctx)
	if scope != nil && scope.Passkey != (ProjectPasskeyConfig{}) {
		block := scope.Passkey
		if !perHost || (block.RPID != "" && block.Origin != "") {
			built, err := s.relyingParty(passkeys.Config{
				RPID:   coalesce(block.RPID, s.cfg.PasskeyRPID),
				RPName: coalesce(block.RPName, s.cfg.PasskeyRPName),
				Origin: coalesce(block.Origin, s.cfg.PasskeyOrigin),
			})
			if err == nil {
				return built, nil
			}
			// A block can pass the write path's checks and still not build: an
			// rp_id alone, with no global origin to inherit.
			s.logger.Warn("passkey_rp_override_invalid",
				zap.String("project_id", scope.ProjectID), zap.Error(err))
		}
	}
	if perHost {
		s.logPasskeysUnavailable(ctx, scope)
		return nil, ErrPasskeysUnavailable
	}
	return s.passkeys, nil
}

// logPasskeysUnavailable tells the operator which host lost passkeys, since only
// the client sees the refusal. The host is client-supplied, so it is bounded.
func (s *AuthService) logPasskeysUnavailable(ctx context.Context, scope *ProjectScope) {
	projectID := ""
	if scope != nil {
		projectID = scope.ProjectID
	}
	host := RequestHostFromContext(ctx)
	if len(host) > origin.MaxDNSNameLen {
		host = host[:origin.MaxDNSNameLen]
	}
	s.logger.Warn("passkey_relying_party_unavailable",
		zap.String("host", host),
		zap.String("project_id", projectID),
		zap.String("hint", "add the host to GATEWAY_PASSKEY_RELYING_PARTIES, or give its project a passkey block with rp_id and origin"))
}

// relyingParty returns the memoised WebAuthn instance for cfg.
func (s *AuthService) relyingParty(cfg passkeys.Config) (*passkeys.WebAuthnService, error) {
	key := strings.Join(append([]string{cfg.RPID, cfg.RPName, cfg.Origin}, cfg.AdditionalOrigins...), "\x00")

	s.passkeyRPCacheMu.RLock()
	wa := s.passkeyRPCache[key]
	s.passkeyRPCacheMu.RUnlock()
	if wa != nil {
		return wa, nil
	}

	built, err := passkeys.NewWebAuthnService(cfg)
	if err != nil {
		return nil, err
	}

	s.passkeyRPCacheMu.Lock()
	defer s.passkeyRPCacheMu.Unlock()
	if s.passkeyRPCache == nil {
		s.passkeyRPCache = map[string]*passkeys.WebAuthnService{}
	}
	if existing := s.passkeyRPCache[key]; existing != nil {
		return existing, nil
	}
	s.passkeyRPCache[key] = built
	return built, nil
}
