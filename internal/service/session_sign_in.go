package service

import "slices"

// AMRRecoveryEmail is the amr value (RFC 8176 lets a server define its own)
// of a session a recovery email opened. Its access tokens carry it in the
// amr claim, and its refresh token keeps it across rotations, so the session
// says how it was opened for as long as it lasts. The address may be the
// weakest mailbox the person has, so such a session is held from changing
// the account's sign-in and recovery settings while a recovery hold is in
// force, and acts in a tenant only through an explicit membership, never
// through the domain of the account's email.
const AMRRecoveryEmail = "recovery_email"

// AMRUnvouched marks a session whose amr no one vouched for: the native-gRPC
// bridge sets it when the host's interceptor does not own the sign-in
// metadata. No token carries it. During a recovery hold such a session is
// held like one a recovery email opened.
const AMRUnvouched = "unvouched"

// SessionSignIn is what the caller's verified access token says about the
// sign-in that opened its session.
type SessionSignIn struct {
	// AuthTimeSec is the token's auth_time (epoch seconds); 0 when no
	// sign-in opened the session.
	AuthTimeSec int64
	// AMR is the token's amr claim.
	AMR []string
}

// openedByRecoveryEmail reports whether a recovery email opened the session.
func (s SessionSignIn) openedByRecoveryEmail() bool {
	return slices.Contains(s.AMR, AMRRecoveryEmail)
}

// heldByRecoveryHold reports whether a recovery hold binds the session: one
// a recovery email opened, or one whose opening no one vouched for.
func (s SessionSignIn) heldByRecoveryHold() bool {
	return s.openedByRecoveryEmail() || slices.Contains(s.AMR, AMRUnvouched)
}
