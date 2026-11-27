package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/email"
)

func TestNormalizeInvitationNote_Accepted(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, in, want string }{
		{"empty", "", ""},
		{"only whitespace", "  \n\t \r\n ", ""},
		{"plain email address", "Your mail address will be jane@example.com", "Your mail address will be jane@example.com"},
		{"email address ending a sentence", "Write to jane.doe+team@example.com.", "Write to jane.doe+team@example.com."},
		{"email address in brackets", "(ask jane@example.com)", "(ask jane@example.com)"},
		{"uppercase email address", "Mail JANE@EXAMPLE.COM", "Mail JANE@EXAMPLE.COM"},
		{"fullwidth email address", "Mail ｊａｎｅ＠ｅｘａｍｐｌｅ．ｃｏｍ", "Mail ｊａｎｅ＠ｅｘａｍｐｌｅ．ｃｏｍ"},
		{"abbreviations", "Bring e.g. a laptop, i.e. yours. Dr. Smith says hi.", "Bring e.g. a laptop, i.e. yours. Dr. Smith says hi."},
		{"version and decimal", "v1.2 ships at 3.14 pm", "v1.2 ships at 3.14 pm"},
		{"three dotted numbers", "release 1.2.3", "release 1.2.3"},
		{"colon after a scheme word with a space", "Data: the shared folder. Tel: ask reception.", "Data: the shared folder. Tel: ask reception."},
		{"time", "Stand-up at 10:30", "Stand-up at 10:30"},
		{"ellipsis and dashes", "Welcome… see you Monday — Acme team", "Welcome… see you Monday — Acme team"},
		{"japanese sentences", "ようこそ。明日から始めましょう。", "ようこそ。明日から始めましょう。"},
		{"cyrillic sentence", "Привет, команда.", "Привет, команда."},
		{"emoji joined by ZWJ", "Welcome 👩\u200D💻", "Welcome 👩\u200D💻"},
		{"persian with ZWNJ", "می\u200Cخواهم", "می\u200Cخواهم"},
		{"lines trimmed and CRLF read as LF", "  Hi Jane, \r\n  welcome aboard.  ", "Hi Jane,\nwelcome aboard."},
		{"four lines", "a\nb\nc\nd", "a\nb\nc\nd"},
		{"at the length cap", strings.Repeat("é", maxInvitationNoteRunes), strings.Repeat("é", maxInvitationNoteRunes)},
		{"at the length cap counting line breaks", strings.Repeat("a", 139) + "\n" + strings.Repeat("b", 140), strings.Repeat("a", 139) + "\n" + strings.Repeat("b", 140)},
		{"surrounding space past the cap", "  " + strings.Repeat("a", maxInvitationNoteRunes) + "  ", strings.Repeat("a", maxInvitationNoteRunes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeInvitationNote(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestNormalizeInvitationNote_Refused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, in, reason string }{
		{"one past the length cap", strings.Repeat("é", maxInvitationNoteRunes+1), "longer than 280"},
		{"five lines", "a\nb\nc\nd\ne", "more than 4 lines"},
		{"blank line", "Hi\n\nwelcome", "blank line"},
		{"line of spaces", "Hi\n   \nwelcome", "blank line"},
		{"invalid UTF-8", "Hi \xff", "UTF-8"},
		{"NUL", "Hi\x00there", "control"},
		{"tab", "Hi\tthere", "control"},
		{"lone carriage return", "Hi\rthere", "control"},
		{"escape", "Hi\x1b[31mthere", "control"},
		{"next line", "Hi\u0085there", "control"},
		{"right-to-left override", "Hi \u202Emoc.elpmaxe", "invisible"},
		{"left-to-right isolate", "Hi \u2066there\u2069", "invisible"},
		{"left-to-right mark", "Hi\u200Ethere", "invisible"},
		{"arabic letter mark", "Hi\u061Cthere", "invisible"},
		{"byte order mark", "Hi\uFEFFthere", "invisible"},
		{"soft hyphen", "Hi\u00ADthere", "invisible"},
		{"zero-width space", "Hi\u200Bthere", "invisible"},
		{"line separator", "Hi\u2028there", "invisible"},
		{"paragraph separator", "Hi\u2029there", "invisible"},

		{"https URL", "Sign in at https://example.com", "link"},
		{"scheme without a known name", "go to hxxp://example", "link"},
		{"bare domain", "Sign in at example.com", "link"},
		{"www host", "Visit www.example now", "link"},
		{"uppercase domain", "Visit WWW.EXAMPLE.COM", "link"},
		{"domain and path", "see example.com/login", "link"},
		{"domain in brackets", "(acme.example)", "link"},
		{"domain with a port", "example.com:8443", "link"},
		{"subdomain", "auth.acme.example", "link"},
		{"punycode domain", "xn--80ak6aa92e.xn--p1ai", "link"},
		{"punycode top-level label", "acme.xn--p1ai", "link"},
		{"IPv4 address", "use 192.168.0.1", "link"},
		{"cyrillic lookalike letter", "Sign in at exаmple.com", "link"},
		{"cyrillic domain", "пример.рф", "link"},
		{"fullwidth domain", "ｅｘａｍｐｌｅ．ｃｏｍ", "link"},
		{"mathematical bold domain", "𝐞𝐱𝐚𝐦𝐩𝐥𝐞.𝐜𝐨𝐦", "link"},
		{"ideographic full stop for a dot", "example。com", "link"},
		{"halfwidth ideographic full stop for a dot", "example｡com", "link"},
		{"one dot leader for a dot", "example․com", "link"},
		{"ZWJ hiding a domain", "exa\u200Dmple.com", "link"},
		{"ZWNJ before the dot", "example\u200C.com", "link"},
		{"missing space after a full stop", "We are done.See you", "link"},
		{"mailto", "mailto:jane@example.com", "link"},
		{"tel", "Call tel:+15550100", "link"},
		{"sms", "sms:+15550100", "link"},
		{"javascript", "javascript:alert(1)", "link"},
		{"data", "data:text/html,hi", "link"},
		{"uppercase scheme", "MAILTO:jane", "link"},
		{"fullwidth scheme", "ｍａｉｌｔｏ：jane", "link"},
		{"HTML anchor", `<a href="x">here</a>`, "markup"},
		{"angle bracket", "a > b", "markup"},
		{"fullwidth angle bracket", "＜b＞hi", "markup"},
		{"markdown link", "[click](x)", "markup"},
		{"handle with no local part", "ping @jane", "email address is allowed"},
		{"address with no local part", "@example.com", "email address is allowed"},
		{"two at signs", "jane@@example.com", "email address is allowed"},
		{"address with two at signs", "jane@bob@example.com", "email address is allowed"},
		{"address with no domain dot", "jane@localhost", "email address is allowed"},
		{"address with a lookalike domain", "jane@exаmple.com", "email address is allowed"},
		{"address with a non-ASCII local part", "jäne@example.com", "email address is allowed"},
		{"address whose local part ends in a dot", "jane.@example.com", "email address is allowed"},
		{"address with a one-letter top-level label", "jane@example.x", "email address is allowed"},
		{"address with two dots in a row", "ja..ne@example.com", "email address is allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeInvitationNote(tc.in)
			require.ErrorIs(t, err, ErrInvalidArgument)
			require.Contains(t, err.Error(), tc.reason)
			require.Empty(t, got)
			require.NotContains(t, err.Error(), tc.in, "the refusal does not repeat the note")
		})
	}
}

const noteLabel = "A note from the administrator who invited you:"

// withNotesProject is withProject for a project whose tenant policy allows
// invitation notes or not.
func withNotesProject(allowed bool) context.Context {
	return withTenantsPolicy(ProjectTenantsConfig{InvitationNotes: allowed})
}

// withTenantsPolicy is withProject for a project with the tenant policy
// tenants, taken as given, unvalidated.
func withTenantsPolicy(tenants ProjectTenantsConfig) context.Context {
	return WithProjectScope(context.Background(), &ProjectScope{
		ProjectID: mTestProject,
		Access:    ProjectAccessConfig{Mode: AccessModeOpen},
		Tenants:   tenants,
	})
}

// A note on an invitation to an operator's tenant, where the project allows
// notes, is in both parts of the email: quoted line by line in the text part,
// and escaped, its lines kept apart, in the HTML part.
func TestCreateTenantInvitation_NoteInTheEmail(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)

	out, err := f.svc.CreateTenantInvitation(withNotesProject(true), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember,
		" Your mail address will be jane@example.com \r\nTom & Jerry's \"team\" says hi")
	require.NoError(t, err)
	require.Equal(t, EmailSent, out.EmailStatus)
	require.Equal(t, 1, f.mailer.count())
	msg := f.mailer.last()

	require.Contains(t, msg.Text, "become a member.\n\n"+noteLabel+"\n> Your mail address will be jane@example.com\n> Tom & Jerry's \"team\" says hi\n\nhttp")
	require.Contains(t, msg.HTML, noteLabel)
	require.Contains(t, msg.HTML, ">Your mail address will be jane@example.com<br>Tom &amp; Jerry&#39;s &#34;team&#34; says hi</blockquote>")
}

// With no note, or one that is only whitespace, the email carries no note
// section, whether or not the project allows notes.
func TestCreateTenantInvitation_NoNoteNoNoteSection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allowed bool
		note    string
	}{
		{"none, notes allowed", true, ""},
		{"none, notes not allowed", false, ""},
		{"whitespace, notes not allowed", false, " \r\n\t "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMembershipFixture()
			f.seedAdmin(mTestProject, mTestTenant, mAdminID)

			_, err := f.svc.CreateTenantInvitation(withNotesProject(tc.allowed), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember, tc.note)
			require.NoError(t, err)
			msg := f.mailer.last()
			for part, body := range map[string]string{"text": msg.Text, "html": msg.HTML} {
				require.NotContains(t, body, "A note from", part)
				require.NotContains(t, body, "blockquote", part)
			}
		})
	}
}

// A note is refused before anything is stored or sent: where the project does
// not allow notes, even if it allows them on self-service tenants; on a tenant
// a user created unless the project allows notes there too; and when it reads
// as a link, on any tenant. A caller who is not an owner or admin is refused
// as one, so a note never tells them whether the tenant is one a user created.
func TestCreateTenantInvitation_NoteRefused(t *testing.T) {
	off := ProjectTenantsConfig{}
	notes := ProjectTenantsConfig{InvitationNotes: true}
	both := ProjectTenantsConfig{InvitationNotes: true, InvitationNotesSelfService: true}
	selfServiceOnly := ProjectTenantsConfig{InvitationNotesSelfService: true}
	for _, tc := range []struct {
		name      string
		policy    ProjectTenantsConfig
		createdBy string
		role      string
		note      string
		want      error
	}{
		{"project does not allow notes", off, "", RoleOwner, "Welcome aboard", ErrInvitationNoteNotAllowed},
		{"self-service tenant, notes allowed only elsewhere", notes, "user-creator", RoleOwner, "Welcome aboard", ErrInvitationNoteNotAllowed},
		{"self-service setting without notes, self-service tenant", selfServiceOnly, "user-creator", RoleOwner, "Welcome aboard", ErrInvitationNoteNotAllowed},
		{"self-service setting without notes, operator tenant", selfServiceOnly, "", RoleOwner, "Welcome aboard", ErrInvitationNoteNotAllowed},
		{"link", notes, "", RoleOwner, "Sign in at example.com", ErrInvalidArgument},
		{"link where notes are not allowed", off, "", RoleOwner, "Sign in at example.com", ErrInvalidArgument},
		{"link on a self-service tenant allowed notes", both, "user-creator", RoleOwner, "Sign in at example.com", ErrInvalidArgument},
		{"lookalike domain on a self-service tenant allowed notes", both, "user-creator", RoleOwner, "Sign in at exаmple.com", ErrInvalidArgument},
		{"bidirectional override", notes, "", RoleOwner, "Hi \u202Emoc.elpmaxe", ErrInvalidArgument},
		{"over the cap on a self-service tenant allowed notes", both, "user-creator", RoleOwner, strings.Repeat("a", maxInvitationNoteRunes+1), ErrInvalidArgument},
		{"plain member of a self-service tenant", notes, "user-creator", RoleMember, "Welcome aboard", ErrPermissionDenied},
		{"plain member where self-service tenants allow notes", both, "user-creator", RoleMember, "Welcome aboard", ErrPermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMembershipFixture()
			f.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Status: TenantStatusClaimed, CreatedBy: tc.createdBy})
			f.seedMember(mTestProject, mTestTenant, mAdminID, tc.role)

			_, err := f.svc.CreateTenantInvitation(withTenantsPolicy(tc.policy), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember, tc.note)
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, f.invitations.byID, "a refused invitation is not stored")
			require.Zero(t, f.mailer.count(), "a refused invitation sends no email")
		})
	}
}

// With notes allowed, and on self-service tenants too, an owner or admin of
// either kind of tenant sends a note, normalized as anywhere else, and the
// self-service tenant's name still stays out of the email.
func TestCreateTenantInvitation_NoteOnSelfServiceTenantWhereAllowed(t *testing.T) {
	const crafted = "Payroll update"
	for _, tc := range []struct {
		name      string
		createdBy string
		role      string
	}{
		{"self-service tenant, owner", "user-creator", RoleOwner},
		{"self-service tenant, admin", "user-creator", RoleAdmin},
		{"operator tenant", "", RoleOwner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMembershipFixture()
			f.tenants.put(&Tenant{ID: mTestTenant, ProjectID: mTestProject, Name: crafted, Status: TenantStatusClaimed, CreatedBy: tc.createdBy})
			f.seedMember(mTestProject, mTestTenant, mAdminID, tc.role)
			policy := ProjectTenantsConfig{InvitationNotes: true, InvitationNotesSelfService: true}

			_, err := f.svc.CreateTenantInvitation(withTenantsPolicy(policy), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember,
				"  Your mail address will be jane@example.com  \r\nSee you Monday.")
			require.NoError(t, err)
			msg := f.mailer.last()
			require.Contains(t, msg.Text, noteLabel+"\n> Your mail address will be jane@example.com\n> See you Monday.\n")
			require.Contains(t, msg.HTML, ">Your mail address will be jane@example.com<br>See you Monday.</blockquote>")
			if tc.createdBy != "" {
				require.NotContains(t, msg.Text, crafted, "a self-service tenant's name stays out")
				require.NotContains(t, msg.HTML, crafted, "a self-service tenant's name stays out")
			}
		})
	}
}

// The note is not stored with the invitation: a resend is a new call, and its
// email carries the note that call passes, the same note when it passes it
// again and none when it passes none.
func TestCreateTenantInvitation_ResendCarriesItsOwnNote(t *testing.T) {
	f := newMembershipFixture()
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	ctx := withNotesProject(true)
	start := time.Now()
	cooldown := config.DefaultTenantInvitationResendCooldownSeconds*time.Second + time.Second
	const note = "Your mail address will be jane@example.com"

	for i, sent := range []string{note, note, ""} {
		f.svc.nowFunc = func() time.Time { return start.Add(time.Duration(i) * cooldown) }
		out, err := f.svc.CreateTenantInvitation(ctx, mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember, sent)
		require.NoError(t, err, "send %d", i)
		msg := f.mailer.last()
		if sent == "" {
			require.NotContains(t, msg.Text, note, "send %d", i)
			require.NotContains(t, msg.HTML, note, "send %d", i)
		} else {
			require.Contains(t, msg.Text, "> "+note, "send %d", i)
			require.Contains(t, msg.HTML, note, "send %d", i)
		}
		open := 0
		for _, inv := range f.invitations.byID {
			if inv.Status == InvitationStatusPending {
				open++
				require.Equal(t, out.Invitation.ID, inv.ID, "the resend revoked the earlier invitation")
			}
		}
		require.Equal(t, 1, open)
	}
	require.Equal(t, 3, f.mailer.count())
}

// No log line carries the note, including those of a send that fails.
func TestCreateTenantInvitation_NoteIsNotLogged(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	f := newMembershipFixture()
	f.svc = NewMembershipService(f.invitations, f.memberships, f.tenants, f.users,
		email.NewChain(logger, &recordingMailer{sendErr: email.ErrTransport}), true, &config.Config{}, logger)
	f.seedAdmin(mTestProject, mTestTenant, mAdminID)
	const note = "Your mail address will be jane@example.com"

	out, err := f.svc.CreateTenantInvitation(withNotesProject(true), mAdminID, SessionSignIn{}, mTestTenant, mInvitee, RoleMember, note)
	require.NoError(t, err)
	require.Equal(t, EmailSendFailed, out.EmailStatus)
	require.NotZero(t, logs.Len())
	for _, entry := range logs.All() {
		require.NotContains(t, entry.Message, "jane@example.com")
		for key, value := range entry.ContextMap() {
			require.NotContains(t, key+"="+fmt.Sprint(value), "jane@example.com", entry.Message)
		}
	}
}
