package conformance

import (
	"context"
	"fmt"
	"testing"

	"github.com/elloloop/identity/internal/service"
)

// readYourWritesIterations is the per-entity loop count for the
// read-your-writes subtests. The bug these target — a create whose
// secondary index (unique-key or filter) has not caught up by the time
// the very next read runs — is probabilistic: on entdb the IDV
// user_id filter missed ~50% of immediate reads, but a less-loaded
// index might miss only occasionally. Looping makes a low per-iteration
// miss rate p detectable: P(detect) = 1 - (1-p)^N, so N=50 catches even
// a 5% lag with ~92% probability per run and a 50% lag with certainty.
const readYourWritesIterations = 50

// runReadYourWritesConformance asserts the Repository contract that a
// successful write is visible to the very next read through EVERY access
// path the service uses to fetch it — not just by node id, but through
// the secondary unique-key and filter indexes too.
//
// This is the generalization of the IDV read-after-write flake
// (TestIDV_StubProvider_LatestForUser): sdkScope.create waits for
// node-id visibility, but secondary indexes on entdb are applied
// asynchronously, a beat behind. Any repo method that reads back a
// just-written row through a secondary index can therefore race the
// index apply. Each subtest creates a fresh row and immediately reads
// it back through one secondary path, looped, so a backend that lets
// the index lag fails loudly and attributably
// (e.g. TestConformance/entdb/ReadYourWrites_OAuthIdentity_ByProviderID).
//
// Memory and postgres are synchronous, so they pass on the first
// iteration; the value is the cross-backend guard against entdb (and
// any future driver) regressing read-your-writes.
func runReadYourWritesConformance(t *testing.T, driver Driver) {
	t.Helper()

	t.Run(driver.Name+"/ReadYourWrites", func(t *testing.T) {
		t.Run("User_ByEmail", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			for i := 0; i < readYourWritesIterations; i++ {
				email := fmt.Sprintf("ryw-user-%d@example.com", i)
				id, err := r.CreateUser(ctx, &service.User{Email: email, Status: "active", Role: "member"})
				if err != nil {
					t.Fatalf("iter %d: CreateUser: %v", i, err)
				}
				got, err := r.FindUserByEmail(ctx, email)
				if err != nil {
					t.Fatalf("iter %d: FindUserByEmail: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: user %q not found by email immediately after create", i, email)
				}
				if got.ID != id {
					t.Fatalf("iter %d: FindUserByEmail id = %q, want %q", i, got.ID, id)
				}
			}
		})

		t.Run("RefreshToken_ByHash", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "ryw-rt@example.com")
			for i := 0; i < readYourWritesIterations; i++ {
				h := fmt.Sprintf("ryw-rt-%d", i)
				if _, err := r.CreateRefreshToken(ctx, &service.RefreshTokenRecord{
					TokenHash: h, UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100, LastUsedAt: 100,
				}); err != nil {
					t.Fatalf("iter %d: CreateRefreshToken: %v", i, err)
				}
				got, err := r.FindRefreshTokenByHash(ctx, h)
				if err != nil {
					t.Fatalf("iter %d: FindRefreshTokenByHash: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: refresh token %q not found immediately after create", i, h)
				}
			}
		})

		t.Run("PasswordResetToken_ByHash", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "ryw-prt@example.com")
			for i := 0; i < readYourWritesIterations; i++ {
				h := fmt.Sprintf("ryw-prt-%d", i)
				if err := r.CreatePasswordResetToken(ctx, &service.PasswordResetToken{
					TokenHash: h, UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
				}); err != nil {
					t.Fatalf("iter %d: CreatePasswordResetToken: %v", i, err)
				}
				got, err := r.FindPasswordResetTokenByHash(ctx, h)
				if err != nil {
					t.Fatalf("iter %d: FindPasswordResetTokenByHash: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: reset token %q not found immediately after create", i, h)
				}
			}
		})

		t.Run("EmailVerificationToken_ByHash", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "ryw-evt@example.com")
			for i := 0; i < readYourWritesIterations; i++ {
				h := fmt.Sprintf("ryw-evt-%d", i)
				if err := r.CreateEmailVerificationToken(ctx, &service.EmailVerificationToken{
					TokenHash: h, UserID: uid, Email: "e@example.com", ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
				}); err != nil {
					t.Fatalf("iter %d: CreateEmailVerificationToken: %v", i, err)
				}
				got, err := r.FindEmailVerificationTokenByHash(ctx, h)
				if err != nil {
					t.Fatalf("iter %d: FindEmailVerificationTokenByHash: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: email-verification token %q not found immediately after create", i, h)
				}
			}
		})

		t.Run("EmailChangeToken_ByHash", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "ryw-ect@example.com")
			for i := 0; i < readYourWritesIterations; i++ {
				h := fmt.Sprintf("ryw-ect-%d", i)
				if err := r.CreateEmailChangeToken(ctx, &service.EmailChangeToken{
					TokenHash: h, UserID: uid, OldEmail: "old@x", NewEmail: "new@x", ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
				}); err != nil {
					t.Fatalf("iter %d: CreateEmailChangeToken: %v", i, err)
				}
				got, err := r.FindEmailChangeTokenByHash(ctx, h)
				if err != nil {
					t.Fatalf("iter %d: FindEmailChangeTokenByHash: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: email-change token %q not found immediately after create", i, h)
				}
			}
		})

		t.Run("PasskeyCredential_ByCredID_AndList", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "ryw-pk@example.com")
			for i := 0; i < readYourWritesIterations; i++ {
				cred := fmt.Sprintf("ryw-cred-%d", i)
				if _, err := r.CreatePasskeyCredential(ctx, &service.PasskeyCredRecord{
					CredentialID: cred, UserID: uid, PublicKey: "pk", SignCount: 1,
				}); err != nil {
					t.Fatalf("iter %d: CreatePasskeyCredential: %v", i, err)
				}
				got, err := r.GetPasskeyCredentialByCredID(ctx, cred)
				if err != nil {
					t.Fatalf("iter %d: GetPasskeyCredentialByCredID: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: passkey %q not found by cred id immediately after create", i, cred)
				}
				list, err := r.ListPasskeyCredentials(ctx, uid)
				if err != nil {
					t.Fatalf("iter %d: ListPasskeyCredentials: %v", i, err)
				}
				if !containsPasskeyCred(list, cred) {
					t.Fatalf("iter %d: read-after-write miss: passkey %q absent from List immediately after create (len=%d)", i, cred, len(list))
				}
			}
		})

		t.Run("QrLoginSession_BySid", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			for i := 0; i < readYourWritesIterations; i++ {
				sid := fmt.Sprintf("ryw-qr-%d", i)
				if _, err := r.CreateQrLoginSession(ctx, &service.QrLoginSessionRecord{
					SessionID: sid, Status: "pending", ExpiresAt: 9_000_000_000_000, CreatedAt: 100, UpdatedAt: 100,
				}); err != nil {
					t.Fatalf("iter %d: CreateQrLoginSession: %v", i, err)
				}
				got, err := r.FindQrLoginSession(ctx, sid)
				if err != nil {
					t.Fatalf("iter %d: FindQrLoginSession: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: qr session %q not found immediately after create", i, sid)
				}
			}
		})

		t.Run("RecoveryCode_ByHash", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "ryw-rc@example.com")
			for i := 0; i < readYourWritesIterations; i++ {
				h := fmt.Sprintf("ryw-rc-%d", i)
				if _, err := r.CreateRecoveryCode(ctx, &service.RecoveryCodeRecord{
					UserID: uid, CodeHash: h, CreatedAt: 100,
				}); err != nil {
					t.Fatalf("iter %d: CreateRecoveryCode: %v", i, err)
				}
				got, err := r.FindRecoveryCodeByHash(ctx, uid, h)
				if err != nil {
					t.Fatalf("iter %d: FindRecoveryCodeByHash: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: recovery code %q not found immediately after create", i, h)
				}
			}
		})

		t.Run("LoginChallenge_ByChallengeID", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "ryw-lc@example.com")
			for i := 0; i < readYourWritesIterations; i++ {
				cid := fmt.Sprintf("ryw-lc-%d", i)
				if _, err := r.CreateLoginChallenge(ctx, &service.LoginChallengeRecord{
					ChallengeID: cid, UserID: uid, ExpiresAt: 9_000_000_000_000, CreatedAt: 100,
				}); err != nil {
					t.Fatalf("iter %d: CreateLoginChallenge: %v", i, err)
				}
				got, err := r.GetLoginChallengeByChallengeID(ctx, cid)
				if err != nil {
					t.Fatalf("iter %d: GetLoginChallengeByChallengeID: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: login challenge %q not found immediately after create", i, cid)
				}
			}
		})

		t.Run("OAuthIdentity_ByProviderID_AndList", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			for i := 0; i < readYourWritesIterations; i++ {
				// Fresh user per iteration so each link targets a distinct
				// user and the List assertion is exactly 1.
				uid := createTestUser(t, r, fmt.Sprintf("ryw-oa-%d@example.com", i))
				sub := fmt.Sprintf("ryw-sub-%d", i)
				if err := r.CreateOAuthIdentity(ctx, &service.OAuthIdentity{
					UserID: uid, Provider: "google", ProviderUserID: sub, EmailAtLinkTime: "x@y.com", CreatedAt: 100,
				}); err != nil {
					t.Fatalf("iter %d: CreateOAuthIdentity: %v", i, err)
				}
				got, err := r.FindUserByProviderID(ctx, "google", sub)
				if err != nil {
					t.Fatalf("iter %d: FindUserByProviderID: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: oauth link (google,%s) not found immediately after create", i, sub)
				}
				if got.ID != uid {
					t.Fatalf("iter %d: FindUserByProviderID id = %q, want %q", i, got.ID, uid)
				}
				list, err := r.ListOAuthIdentitiesForUser(ctx, uid)
				if err != nil {
					t.Fatalf("iter %d: ListOAuthIdentitiesForUser: %v", i, err)
				}
				if len(list) != 1 {
					t.Fatalf("iter %d: read-after-write miss: ListOAuthIdentitiesForUser len = %d, want 1 immediately after create", i, len(list))
				}
			}
		})

		t.Run("Session_BySid", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			uid := createTestUser(t, r, "ryw-sess@example.com")
			for i := 0; i < readYourWritesIterations; i++ {
				sid := fmt.Sprintf("ryw-sess-%d", i)
				if _, err := r.CreateSession(ctx, &service.SessionRecord{SID: sid, UserID: uid, CreatedAtMs: 100}); err != nil {
					t.Fatalf("iter %d: CreateSession: %v", i, err)
				}
				got, err := r.GetSessionBySid(ctx, sid)
				if err != nil {
					t.Fatalf("iter %d: GetSessionBySid: %v", i, err)
				}
				if got == nil {
					t.Fatalf("iter %d: read-after-write miss: session %q not found immediately after create", i, sid)
				}
			}
		})

		t.Run("IdentityVerification_ByID_AndLatest", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			for i := 0; i < readYourWritesIterations; i++ {
				uid := createTestUser(t, r, fmt.Sprintf("ryw-idv-%d@example.com", i))
				verID := fmt.Sprintf("ryw-idv-%d", i)
				if err := r.CreateIdentityVerification(ctx, &service.IdentityVerificationRecord{
					VerificationID: verID, UserID: uid, Provider: "stub",
					Status: service.IDVStatusPending, CreatedAt: int64(100 + i), UpdatedAt: int64(100 + i),
				}); err != nil {
					t.Fatalf("iter %d: CreateIdentityVerification: %v", i, err)
				}
				byID, err := r.GetIdentityVerification(ctx, verID)
				if err != nil {
					t.Fatalf("iter %d: GetIdentityVerification: %v", i, err)
				}
				if byID == nil {
					t.Fatalf("iter %d: read-after-write miss: idv %q not found by id immediately after create", i, verID)
				}
				latest, err := r.GetLatestIdentityVerificationForUser(ctx, uid)
				if err != nil {
					t.Fatalf("iter %d: GetLatestIdentityVerificationForUser: %v", i, err)
				}
				if latest == nil || latest.VerificationID != verID {
					t.Fatalf("iter %d: read-after-write miss: GetLatest returned %#v, want verification %q immediately after create", i, latest, verID)
				}
			}
		})

		t.Run("Organization_BySlug_AndListForUser", func(t *testing.T) {
			ctx := context.Background()
			r := driver.NewRepo(t)
			for i := 0; i < readYourWritesIterations; i++ {
				owner := createTestUser(t, r, fmt.Sprintf("ryw-org-%d@example.com", i))
				slug := fmt.Sprintf("ryw-org-%d", i)
				orgID, err := r.CreateOrganization(ctx, &service.Organization{
					Slug: slug, DisplayName: "Org", OwnerUserID: owner, CreatedAtMs: 100, UpdatedAtMs: 100,
				})
				if err != nil {
					t.Fatalf("iter %d: CreateOrganization: %v", i, err)
				}
				bySlug, err := r.GetOrganizationBySlug(ctx, slug)
				if err != nil {
					t.Fatalf("iter %d: GetOrganizationBySlug: %v", i, err)
				}
				if bySlug == nil {
					t.Fatalf("iter %d: read-after-write miss: org %q not found by slug immediately after create", i, slug)
				}
				if _, err := r.AddOrganizationMember(ctx, &service.OrganizationMembership{
					OrganizationID: orgID, UserID: owner, Role: "admin", CreatedAtMs: 100,
				}); err != nil {
					t.Fatalf("iter %d: AddOrganizationMember: %v", i, err)
				}
				orgs, err := r.ListOrganizationsForUser(ctx, owner)
				if err != nil {
					t.Fatalf("iter %d: ListOrganizationsForUser: %v", i, err)
				}
				if len(orgs) != 1 {
					t.Fatalf("iter %d: read-after-write miss: ListOrganizationsForUser len = %d, want 1 immediately after AddMember", i, len(orgs))
				}
			}
		})
	})
}

func containsPasskeyCred(list []*service.PasskeyCredRecord, credID string) bool {
	for _, c := range list {
		if c.CredentialID == credID {
			return true
		}
	}
	return false
}
