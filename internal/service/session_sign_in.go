package service

import "slices"

// AMRRecoveryEmail is the amr value (RFC 8176 lets a server define its own)
// of a session a recovery email opened. Its access tokens carry it in the
// amr claim, with the address's RecoveryEmail.ID in the recovery_email_id
// claim, and its refresh token keeps that id across rotations, so the
// session says how it was opened for as long as it lasts, and ends when the
// address is removed. The address may be the weakest mailbox the person has,
// so such a session makes no account security change while a recovery hold
// is in force or once its address is gone, never approves another device's
// QR sign-in, and acts in a tenant only through an explicit membership,
// never through the domain of the account's email.
const AMRRecoveryEmail = "recovery_email"

// recoverySessionAMR is the amr claim of a session's access tokens:
// AMRRecoveryEmail when the recovery email recoveryEmailID opened it, none
// when it was opened another way.
func recoverySessionAMR(recoveryEmailID string) []string {
	if recoveryEmailID == "" {
		return nil
	}
	return []string{AMRRecoveryEmail}
}

// AMRUnvouched marks a session whose amr no one vouched for: the native-gRPC
// bridge sets it unless the host said its interceptor forwards the verified
// token's amr and recovery_email_id. No token carries it. Such a session may
// be one a recovery email opened, and cannot say which address, so it is
// held during a recovery hold and approves no QR sign-in while one is in
// force; and in a project whose recovery emails sign in it is treated as a
// recovery session (treatedAsRecoverySession).
const AMRUnvouched = "unvouched"

// SessionSignIn is what the caller's verified access token says about the
// session it belongs to and the sign-in that opened it.
type SessionSignIn struct {
	// AuthTimeSec is the token's auth_time (epoch seconds); 0 when no
	// sign-in opened the session.
	AuthTimeSec int64
	// AMR is the token's amr claim.
	AMR []string
	// RecoveryEmailID is the token's recovery_email_id: the RecoveryEmail.ID
	// of the recovery email that opened the session, empty when none did.
	RecoveryEmailID string
	// SessionID is the token's sid: the session's id under
	// GATEWAY_REVOCATION_MODE=session, and empty otherwise.
	SessionID string
}

// openedByRecoveryEmail reports whether a recovery email opened the session.
func (s SessionSignIn) openedByRecoveryEmail() bool {
	return slices.Contains(s.AMR, AMRRecoveryEmail)
}

// unvouched reports whether no one vouched for how the session was opened.
func (s SessionSignIn) unvouched() bool {
	return slices.Contains(s.AMR, AMRUnvouched)
}

// mayBeRecoverySession reports whether the session may have been opened by
// a recovery email: it says it was, or no one vouched for how it was opened.
func (s SessionSignIn) mayBeRecoverySession() bool {
	return s.openedByRecoveryEmail() || s.unvouched()
}

// treatedAsRecoverySession reports whether the session is treated as one a
// recovery email opened, in a project whose recovery emails are configured
// as cfg: it says it was, or no one vouched for how it was opened where
// recovery emails sign in. Only there could an unvouched session be one, and
// there it must be taken for one, since it cannot name the address behind it.
func (s SessionSignIn) treatedAsRecoverySession(cfg ProjectRecoveryEmailsConfig) bool {
	return s.openedByRecoveryEmail() || s.unvouched() && cfg.SignIn
}
