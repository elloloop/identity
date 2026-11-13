package service

import "slices"

// AMRRecoveryEmail is the amr value (RFC 8176 lets a server define its own)
// of a session a recovery email opened. Its access tokens carry it in the
// amr claim, and its refresh token keeps the address across rotations, so the
// session says how it was opened for as long as it lasts, and ends when the
// address is removed. The address may be the weakest mailbox the person has,
// so such a session makes no account security change while a recovery hold
// is in force, never approves another device's QR sign-in, and acts in a
// tenant only through an explicit membership, never through the domain of
// the account's email.
const AMRRecoveryEmail = "recovery_email"

// recoverySessionAMR is the amr claim of a session's access tokens:
// AMRRecoveryEmail when the recovery email recoveryEmail opened it, none
// when it was opened another way.
func recoverySessionAMR(recoveryEmail string) []string {
	if recoveryEmail == "" {
		return nil
	}
	return []string{AMRRecoveryEmail}
}

// AMRUnvouched marks a session whose amr no one vouched for: the native-gRPC
// bridge sets it when the host's interceptor does not own the sign-in
// metadata. No token carries it. During a recovery hold such a session is
// held like one a recovery email opened.
const AMRUnvouched = "unvouched"

// SessionSignIn is what the caller's verified access token says about the
// session it belongs to and the sign-in that opened it.
type SessionSignIn struct {
	// AuthTimeSec is the token's auth_time (epoch seconds); 0 when no
	// sign-in opened the session.
	AuthTimeSec int64
	// AMR is the token's amr claim.
	AMR []string
	// SessionID is the token's sid: the session's id under
	// GATEWAY_REVOCATION_MODE=session, and empty otherwise.
	SessionID string
}

// openedByRecoveryEmail reports whether a recovery email opened the session.
func (s SessionSignIn) openedByRecoveryEmail() bool {
	return slices.Contains(s.AMR, AMRRecoveryEmail)
}

// mayBeRecoverySession reports whether the session may have been opened by
// a recovery email: it says it was, or no one vouched for how it was opened.
func (s SessionSignIn) mayBeRecoverySession() bool {
	return s.openedByRecoveryEmail() || slices.Contains(s.AMR, AMRUnvouched)
}
